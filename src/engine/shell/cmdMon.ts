// Monitoring command-line tools: promtool (check config/rules, query instant)
// and amtool (alerts, silences, check-config, route tests), with the output and
// error texts of the Debian packages (Prometheus 2.42, Alertmanager 0.25).

import { readFile } from '../fs';
import { resolve } from '../sim/dns';
import {
  ALERTMANAGER_VERSION, AM_CONFIG, amApiAlerts, type AmLoaded, globFiles, loadAmConfig, loadPromConfig, loadRuleFile, PROM_CONFIG, PROMETHEUS_VERSION, type PromLoaded,
  promDataSource, routeAlert, silencedBy,
} from '../sim/monitor';
import { evaluate, formatSeries, formatValue, parsePromQL, PromQLError, parseDuration } from '../sim/promql';
import { allListeners } from '../sim/services';
import { formatVar, mibsLoaded, type Oid, oidName, resolveName, snmpExchange, timeoutHint, type VarBind } from '../sim/snmp';
import { tcpConnect } from '../sim/tcp';
import type { Host } from '../types';
import { sha256Hex } from '../util/sha256';
import { resolvePath } from './cmdFiles';
import { type CmdCtx, type CommandDef, err, ok } from './types';

/** Connect to the HTTP API behind URL from this host, as Go's http client reports failures. */
function apiHost(ctx: CmdCtx, url: string, process: string, op: string): { host: Host } | { error: string } {
  const m = /^(https?):\/\/(\[[^\]]+\]|[^/:]+)(?::(\d+))?(\/.*)?$/.exec(url);
  if (!m) return { error: `${op} "${url}": unsupported protocol scheme ""` };
  const name = m[2].replace(/^\[|\]$/g, '');
  const port = Number(m[3] ?? (m[1] === 'https' ? 443 : 80));
  const r = resolve(ctx.world, ctx.host, name === 'localhost' ? '127.0.0.1' : name, { family: 4 });
  if (!r.ok) {
    const ns = /^nameserver\s+(\S+)/m.exec(readFile(ctx.host, '/etc/resolv.conf') ?? '')?.[1] ?? '127.0.0.53';
    return { error: `${op} "${url}": dial tcp: lookup ${name} on ${ns}:53: no such host` };
  }
  const shown = name === 'localhost' ? '[::1]' : r.ip;
  const c = tcpConnect(ctx.world, ctx.host, r.ip, port, { timeoutMs: 30_000 });
  if (!c.ok) return { error: `${op} "${url}": dial tcp ${shown}:${port}: ${c.errno === 'ECONNREFUSED' ? 'connect: connection refused' : c.errno === 'ETIMEDOUT' ? 'i/o timeout' : 'connect: no route to host'}` };
  const server = c.conn.server;
  const l = allListeners(server).find((x) => x.proto === 'tcp' && x.port === c.conn.sv.localPort);
  c.conn.send('c2s', 180, { protocol: 'DATA', info: `${op === 'Post' ? 'POST' : 'GET'} ${m[4] ?? '/'} HTTP/1.1`, fields: [] });
  c.conn.close('client');
  if (l?.process !== process) return { error: `${op} "${url}": ${l ? 'EOF' : 'EOF'}` };
  return { host: server };
}

const fmtTime = (t: number) => new Date(Math.floor(t)).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

// ---------------------------------------------------------------------------
// promtool
// ---------------------------------------------------------------------------

function checkRules(ctx: CmdCtx, files: string[]): { out: string[]; failed: boolean } {
  const out: string[] = [];
  let failed = false;
  for (const f of files) {
    const p = resolvePath(ctx, f);
    out.push(`Checking ${f}`);
    if (!ctx.host.fs[p]) { out.push(`  FAILED:`, `open ${f}: no such file or directory`, ''); failed = true; continue; }
    const r = loadRuleFile(ctx.host, p);
    if (r.errors.length) {
      failed = true;
      out.push('  FAILED:', ...r.errors.map((e) => e.replace(p, f)), '');
    } else out.push(`  SUCCESS: ${r.rules.length} rules found`, '');
  }
  return { out, failed };
}

const promtool: CommandDef = {
  name: 'promtool',
  summary: 'Tooling for the Prometheus monitoring system (check config, check rules, query)',
  usage: 'promtool check config FILE… | promtool check rules FILE… | promtool query instant SERVER EXPR | promtool --version',
  run(args, ctx) {
    if (args[0] === '--version' || args[0] === 'version') return ok(`promtool, version ${PROMETHEUS_VERSION} (branch: debian/sid, revision: 2.42.0+ds-5+b5)\n  build user:       team+pkg-go@tracker.debian.org\n  go version:       go1.19.8\n  platform:         linux/amd64`);
    const [cmd, sub, ...rest] = args;
    if (cmd === 'check' && sub === 'config') {
      const files = rest.filter((a) => !a.startsWith('--'));
      if (!files.length) return err('promtool: error: required argument \'config-files\' not provided, try --help', 1);
      const out: string[] = [];
      let failed = false;
      for (const f of files) {
        const p = resolvePath(ctx, f);
        out.push(`Checking ${f}`);
        if (!ctx.host.fs[p]) { out.push(`  FAILED: open ${f}: no such file or directory`, ''); failed = true; continue; }
        const c = loadPromConfig(ctx.host, p, false);
        if (!c.config) { out.push(`  FAILED: ${c.error!.replace(p, f)}`, ''); failed = true; continue; }
        const base = p.slice(0, p.lastIndexOf('/')) || '/';
        const ruleFiles = c.config.ruleFiles.flatMap((pat) => globFiles(ctx.host, pat, base));
        if (c.config.ruleFiles.length) out.push(` SUCCESS: ${ruleFiles.length} rule files found`);
        out.push(` SUCCESS: ${f} is valid prometheus config file syntax`, '');
        const r = checkRules(ctx, ruleFiles);
        out.push(...r.out);
        failed ||= r.failed;
      }
      return { out: out.join('\n').replace(/\n+$/, ''), code: failed ? 1 : 0 };
    }
    if (cmd === 'check' && sub === 'rules') {
      const files = rest.filter((a) => !a.startsWith('--'));
      if (!files.length) return err('promtool: error: required argument \'rule-files\' not provided, try --help', 1);
      const r = checkRules(ctx, files);
      return { out: r.out.join('\n').replace(/\n+$/, ''), code: r.failed ? 1 : 0 };
    }
    if (cmd === 'query' && sub === 'instant') {
      const pos = rest.filter((a) => !a.startsWith('--'));
      const [server, expr] = pos;
      if (!server || expr === undefined) return err('promtool: error: required argument \'server\' not provided, try --help', 1);
      const url = `${server.replace(/\/$/, '')}/api/v1/query`;
      const a = apiHost(ctx, url, 'prometheus', 'Post');
      if ('error' in a) return err(`query error: ${a.error}`, 1);
      const l = a.host.services.prometheus?.loaded as PromLoaded | null;
      if (!l) return err(`query error: Post "${url}": EOF`, 1);
      try {
        const at = ctx.world.clock;
        const v = evaluate(promDataSource(l), parsePromQL(expr), at);
        const ts = (Math.round(at) / 1000).toFixed(3);
        if (v.kind === 'scalar') return ok(`scalar: ${formatValue(v.value)} @[${ts}]`);
        if (v.kind === 'string') return ok(`string: ${v.value} @[${ts}]`);
        if (v.kind === 'matrix') return ok(v.series.map((s) => `${formatSeries(s.labels)} =>\n${s.samples.map(([t, x]) => `${formatValue(x)} @[${(t / 1000).toFixed(3)}]`).join('\n')}`).join('\n'));
        return ok(v.samples.map((s) => `${formatSeries(s.labels)} => ${formatValue(s.value)} @[${ts}]`).join('\n'));
      } catch (e) {
        if (e instanceof PromQLError) return err(`query error: bad_data: ${e.message}`, 1);
        return err(`query error: execution: ${(e as Error).message}`, 1);
      }
    }
    if (cmd === 'check' && sub === 'metrics') {
      const text = ctx.stdin ?? '';
      const bad = text.split('\n').filter((l) => /^[a-zA-Z_:][\w:]*(\{.*\})?\s/.test(l)).map((l) => l.split(/[{\s]/)[0]).filter((n, i, a) => a.indexOf(n) === i && !new RegExp(`^# HELP ${n} `, 'm').test(text));
      return bad.length ? err(bad.map((n) => `${n} no help text`).join('\n'), 3) : ok('');
    }
    return err(`promtool: error: expected command but got "${args.join(' ')}", try --help`, 1);
  },
};

// ---------------------------------------------------------------------------
// amtool
// ---------------------------------------------------------------------------

function amtoolUrl(ctx: CmdCtx, flags: Map<string, string>): string | null {
  if (flags.has('alertmanager.url')) return flags.get('alertmanager.url')!;
  for (const f of [`${ctx.user.home}/.config/amtool/config.yml`, '/etc/amtool/config.yml']) {
    const m = /^\s*alertmanager\.url:\s*["']?([^"'\s]+)/m.exec(readFile(ctx.host, f) ?? '');
    if (m) return m[1];
  }
  return null;
}

function parseMatchers(list: string[]): { name: string; op: string; value: string }[] | string {
  const out: { name: string; op: string; value: string }[] = [];
  for (const raw of list) {
    // amtool: a bare word is shorthand for alertname=word.
    const m = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*"?(.*?)"?$/.exec(raw);
    if (m) out.push({ name: m[1], op: m[2], value: m[3] });
    else if (/^[a-zA-Z_][\w]*$/.test(raw)) out.push({ name: 'alertname', op: '=', value: raw });
    else return `bad matcher format: ${raw}`;
  }
  return out;
}

const matchesAll = (labels: Record<string, string>, ms: { name: string; op: string; value: string }[]) => ms.every((m) => {
  const v = labels[m.name] ?? '';
  if (m.op === '=') return v === m.value;
  if (m.op === '!=') return v !== m.value;
  const ok2 = new RegExp(`^(?:${m.value})$`).test(v);
  return m.op === '=~' ? ok2 : !ok2;
});

const uuid = (seed: string) => {
  const a = sha256Hex(seed);
  return `${a.slice(0, 8)}-${a.slice(8, 12)}-4${a.slice(13, 16)}-a${a.slice(17, 20)}-${a.slice(20, 32)}`;
};

function table(rows: string[][]): string {
  const w = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(w[i]))).join('  ').trimEnd()).join('\n');
}

const amtool: CommandDef = {
  name: 'amtool',
  summary: 'View and modify the current Alertmanager state',
  usage: 'amtool [--alertmanager.url=URL] alert [query] [MATCHER…] | silence add MATCHER… --comment=TEXT [--duration=2h] | silence query | silence expire ID | check-config FILE | config routes test LABEL=VALUE…',
  run(argv, ctx) {
    const flags = new Map<string, string>();
    const pos: string[] = [];
    for (let i = 0; i < argv.length; i++) {
      const a = argv[i];
      if (a.startsWith('--')) {
        const [k, v] = a.slice(2).split(/=(.*)/s);
        if (['active', 'silenced', 'inhibited', 'unprocessed', 'expired', 'quiet', 'tree', 'verify.receivers'].includes(k) || k.startsWith('no-')) flags.set(k, v ?? 'true');
        else flags.set(k, v ?? argv[++i] ?? '');
      } else if (a === '-o') flags.set('output', argv[++i] ?? '');
      else if (a === '-q') flags.set('quiet', 'true');
      else if (a === '-c') flags.set('comment', argv[++i] ?? '');
      else if (a === '-d') flags.set('duration', argv[++i] ?? '');
      else if (a === '-a') flags.set('author', argv[++i] ?? '');
      else if (a === '-s') flags.set('silenced', 'true');
      else pos.push(a);
    }
    if (flags.has('version')) return ok(`amtool, version ${ALERTMANAGER_VERSION} (branch: debian/sid, revision: 0.25.0+ds-2+b6)`);
    const [cmd, sub, ...rest] = pos;
    if (cmd === 'check-config') {
      const files = [sub, ...rest].filter(Boolean);
      if (!files.length) return err('amtool: error: required argument \'check-files\' not provided, try --help', 1);
      const out: string[] = [];
      let failed = 0;
      for (const f of files) {
        const p = resolvePath(ctx, f);
        if (!ctx.host.fs[p]) { out.push(`Checking '${f}'  FAILED: open ${f}: no such file or directory`, ''); failed++; continue; }
        const c = loadAmConfig(ctx.host, p);
        if (!c.config) { out.push(`Checking '${f}'  FAILED: ${c.error}`, ''); failed++; continue; }
        out.push(`Checking '${f}'  SUCCESS`, 'Found:', ' - global config', ' - route', ` - ${c.config.inhibit.length} inhibit rules`, ` - ${c.config.receivers.length} receivers`, ' - 0 templates', '');
      }
      if (failed) out.push(`amtool: error: failed to validate ${failed} file(s)`);
      return { out: out.join('\n').replace(/\n+$/, ''), code: failed ? 1 : 0 };
    }
    if (cmd === 'config' && sub === 'routes') {
      const file = flags.get('config.file') ?? AM_CONFIG;
      const c = loadAmConfig(ctx.host, resolvePath(ctx, file));
      if (!c.config) return err(`amtool: error: ${c.error}`, 1);
      if (rest[0] === 'test') {
        const ms = parseMatchers(rest.slice(1));
        if (typeof ms === 'string') return err(`amtool: error: ${ms}`, 1);
        const labels = Object.fromEntries(ms.map((m) => [m.name, m.value]));
        return ok(routeAlert(c.config.route, labels).map((r) => r.receiver).join(','));
      }
      const show = (r: typeof c.config.route, depth: number): string[] => [`${'  '.repeat(depth)}${depth === 0 ? 'Routing tree:\n└── default-route' : `└── {${r.matchers.map((m) => `${m.name}${m.op}"${m.value}"`).join(',')}}`}  receiver: ${r.receiver}`, ...r.routes.flatMap((x) => show(x, depth + 1))];
      return ok(show(c.config.route, 0).join('\n'));
    }
    const url = amtoolUrl(ctx, flags);
    if (!url) return err('amtool: error: required flag --alertmanager.url not provided', 1);
    const apiPath = cmd === 'silence' ? '/api/v2/silences' : '/api/v2/alerts';
    const a = apiHost(ctx, `${url.replace(/\/$/, '')}${apiPath}`, 'prometheus-aler', cmd === 'silence' && sub === 'add' ? 'Post' : 'Get');
    if ('error' in a) return err(`amtool: error: ${a.error}`, 1);
    const l = a.host.services['prometheus-alertmanager']?.loaded as AmLoaded | null;
    if (!l) return err('amtool: error: EOF', 1);
    const now = ctx.world.clock;
    if (cmd === 'alert' || cmd === 'alerts' || cmd === undefined) {
      const query = sub === 'query' ? rest : sub ? [sub, ...rest] : [];
      const ms = parseMatchers(query);
      if (typeof ms === 'string') return err(`amtool: error: ${ms}`, 1);
      const all = amApiAlerts(l, now).filter((x) => matchesAll(x.labels, ms));
      const shown = all.filter((x) => (flags.has('silenced') ? true : x.status.state === 'active'));
      if (flags.get('output') === 'json') return ok(JSON.stringify(shown));
      if (flags.get('output') === 'extended') {
        return ok(table([['Labels', 'Annotations', 'Starts At', 'Ends At', 'Generator URL', 'State'], ...shown.map((x) => [Object.entries(x.labels).sort().map(([k, v]) => `${k}="${v}"`).join(' '), Object.entries(x.annotations).sort().map(([k, v]) => `${k}="${v}"`).join(' '), fmtTime(Date.parse(x.startsAt)), fmtTime(Date.parse(x.endsAt)), x.generatorURL, x.status.state])]));
      }
      return ok(table([['Alertname', 'Starts At', 'Summary', 'State'], ...shown.map((x) => [x.labels.alertname ?? '', fmtTime(Date.parse(x.startsAt)), x.annotations.summary ?? '', x.status.state])]));
    }
    if (cmd === 'silence' || cmd === 'silences') {
      if (sub === 'add') {
        const ms = parseMatchers(rest);
        if (typeof ms === 'string') return err(`amtool: error: ${ms}`, 1);
        if (!ms.length) return err('amtool: error: no matchers specified', 1);
        const comment = flags.get('comment') ?? '';
        if (!comment) return err('amtool: error: comment required by config', 1);
        const d = parseDuration(flags.get('duration') ?? '1h');
        if (d === null) return err(`amtool: error: time: invalid duration "${flags.get('duration')}"`, 1);
        const id = uuid(`${a.host.id}:${Math.floor(now)}:${l.silences.length}`);
        l.silences.push({ id, matchers: ms, startsAt: now, endsAt: now + d, createdBy: flags.get('author') ?? ctx.user.name, comment });
        return ok(flags.has('quiet') ? id : id);
      }
      if (sub === 'expire') {
        const ids = rest;
        if (!ids.length) return err('amtool: error: no silence IDs specified', 1);
        for (const id of ids) {
          const s = l.silences.find((x) => x.id === id || x.id.startsWith(id));
          if (!s) return err(`amtool: error: silence ${id} not found`, 1);
          s.endsAt = now;
        }
        return ok('');
      }
      if (sub === undefined || sub === 'query') {
        const ms = parseMatchers(rest);
        if (typeof ms === 'string') return err(`amtool: error: ${ms}`, 1);
        const list = l.silences.filter((s) => (flags.has('expired') ? s.endsAt <= now : s.endsAt > now) && ms.every((m) => s.matchers.some((x) => x.name === m.name && x.value === m.value)));
        if (flags.has('quiet')) return ok(list.map((s) => s.id).join('\n'));
        return ok(table([['ID', 'Matchers', 'Ends At', 'Created By', 'Comment'], ...list.map((s) => [s.id, s.matchers.map((m) => `${m.name}${m.op}"${m.value}"`).join(' '), fmtTime(s.endsAt), s.createdBy, s.comment])]));
      }
    }
    void silencedBy;
    void PROM_CONFIG;
    return err(`amtool: error: expected command but got "${pos.join(' ')}", try --help`, 1);
  },
};

// ---------------------------------------------------------------------------
// net-snmp tools: snmpget, snmpwalk, snmpbulkwalk
// ---------------------------------------------------------------------------

function snmpTool(name: 'snmpget' | 'snmpwalk' | 'snmpbulkwalk'): CommandDef {
  return {
    name,
    summary: name === 'snmpget' ? 'Query an SNMP agent for specific OIDs' : 'Retrieve a subtree of management values from an SNMP agent',
    usage: `${name} -v 1|2c -c COMMUNITY AGENT ${name === 'snmpget' ? 'OID…' : '[OID]'} | ${name} -v 3 -l noAuthNoPriv|authNoPriv|authPriv -u USER [-a SHA -A PASS] [-x AES -X PASS] AGENT …  (-On numeric, -Oq quick, -Ov value only, -m ALL load MIBs)`,
    run(args, ctx) {
      const o: Record<string, string> = {};
      const out: string[] = [];
      const pos: string[] = [];
      for (let i = 0; i < args.length; i++) {
        const a = args[i];
        const m = /^-([vcuaAxXltrOmM])(.*)$/.exec(a);
        if (m) { const v = m[2] || args[++i] || ''; o[m[1]] = m[1] === 'O' ? (o.O ?? '') + v : v; continue; }
        if (a === '-h' || a === '--help') return ok(`USAGE: ${name} [OPTIONS] AGENT ${name === 'snmpget' ? 'OID [OID]...' : '[OID]'}`);
        if (a.startsWith('-') && a.length > 1) return err(`${a}: Invalid option`, 1);
        pos.push(a);
      }
      const [agent, ...oidArgs] = pos;
      if (!agent) return err(`${name}: No hostname specified.`, 1);
      if (name === 'snmpget' && !oidArgs.length) return err(`${name}: Missing object name`, 1);
      const version = (o.v ?? '3') as '1' | '2c' | '3';
      if (!['1', '2c', '3'].includes(version)) return err(`Invalid version specified after -v flag: ${version}`, 1);
      if (version === '3' && !o.u) return err(`${name}: No securityName specified`, 1);
      if (version !== '3' && o.c === undefined) return err(`No community name specified.`, 1);
      if (name === 'snmpbulkwalk' && version === '1') return err('snmpbulkwalk: Cannot send V2 PDU on V1 session', 1);
      const mibs = (mibsLoaded(ctx.host) || o.m === 'ALL' || o.m === '+ALL') && !!ctx.host.fs['/usr/share/snmp/mibs'];
      const numeric = (o.O ?? '').includes('n');
      const quick = (o.O ?? '').includes('q');
      const valueOnly = (o.O ?? '').includes('v');
      const roots: Oid[] = [];
      for (const t of oidArgs.length ? oidArgs : ['.1.3.6.1.2.1']) {
        const r = resolveName(t, mibs);
        if (r === 'unknown' || r === null) {
          const word = t.replace(/^[\w-]+::/, '').split('.')[0];
          out.push(`${t}: Unknown Object Identifier (Sub-id not found: (top) -> ${word})`);
          return err(out.join('\n'), 2);
        }
        roots.push(r);
      }
      const am = /^(?:udp:)?(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(agent);
      const hostName = am ? am[1].replace(/^\[|\]$/g, '') : agent;
      const port = Number(am?.[2] ?? 161);
      const res = resolve(ctx.world, ctx.host, hostName === 'localhost' ? '127.0.0.1' : hostName, { family: 4 });
      if (!res.ok) return err(`${name}: Unknown host (${hostName}) (Name or service not known)`, 1);
      const level = (o.l ?? 'noAuthNoPriv').toLowerCase();
      const lv = level === 'authpriv' ? 'priv' : level === 'authnopriv' ? 'auth' : level === 'noauthnopriv' ? 'noauth' : null;
      if (version === '3' && !lv) return err(`Invalid security level specified after -l flag: ${o.l}`, 1);
      if (version === '3' && lv !== 'noauth' && !o.A) return err(`${name}: No authentication passphrase specified`, 1);
      if (version === '3' && o.A !== undefined && o.A.length < 8) return err(`Error: passphrase chosen is below the length requirements of the USM (min=8).\n${name}:  (The supplied password length is too short.)\nError generating a key (Ku) from the supplied authentication pass phrase.`, 1);
      const base = { version, community: o.c, user: o.u, level: (lv ?? 'noauth') as 'noauth' | 'auth' | 'priv', authPass: o.A, authProto: o.a, privPass: o.X, privProto: o.x };
      const waitMs = (Number(o.t ?? 1) || 1) * 1000 * ((Number(o.r ?? 5) || 0) + 1);
      const show = (b: VarBind) => {
        const val = formatVar(b, mibs);
        if (valueOnly) return quick ? val.replace(/^[\w-]+: /, '') : val;
        return quick ? `${oidName(b.oid, mibs, numeric)} ${val.replace(/^[\w-]+: /, '')}` : `${oidName(b.oid, mibs, numeric)} = ${val}`;
      };
      const exchange = (op: 'get' | 'getnext', oids: Oid[]) => snmpExchange(ctx.world, ctx.host, res.ip, port, { ...base, op, oids });
      const failure = (r: Exclude<ReturnType<typeof exchange>, { kind: 'response' }>) => {
        if (r.kind === 'timeout') { ctx.world.clock += waitMs; return err([...out, timeoutHint(agent)].join('\n'), 1); }
        return err([...out, r.message.startsWith('Error in packet') ? r.message : `${name}: ${r.message}`].join('\n'), 1);
      };
      const missingText = (m: string) => (m === 'noSuchObject' ? 'No Such Object available on this agent at this OID' : m === 'noSuchInstance' ? 'No Such Instance currently exists at this OID' : 'No more variables left in this MIB View (It is past the end of the MIB tree)');
      if (name === 'snmpget') {
        const r = exchange('get', roots);
        if (r.kind !== 'response') return failure(r);
        for (const b of r.binds) out.push('missing' in b ? `${oidName(b.oid, mibs, numeric)} = ${missingText(b.missing)}` : show(b));
        return ok(out.join('\n'));
      }
      const root = roots[0];
      let cur = root;
      let count = 0;
      for (let guard = 0; guard < 2000; guard++) {
        const r = exchange('getnext', [cur]);
        if (r.kind !== 'response') return failure(r);
        const b = r.binds[0];
        const inside = !('missing' in b) && b.oid.length >= root.length && root.every((x, i) => b.oid[i] === x);
        if (!inside) {
          if (count === 0) {
            // Nothing below the root: snmpwalk asks for the root itself.
            const g = exchange('get', [root]);
            if (g.kind !== 'response') return failure(g);
            const gb = g.binds[0];
            out.push('missing' in gb ? `${oidName(root, mibs, numeric)} = ${missingText(gb.missing)}` : show(gb));
          }
          break;
        }
        out.push(show(b as VarBind));
        count++;
        cur = b.oid;
      }
      return ok(out.join('\n'));
    },
  };
}

export const MON_COMMANDS: CommandDef[] = [promtool, amtool, snmpTool('snmpget'), snmpTool('snmpwalk'), snmpTool('snmpbulkwalk')];
