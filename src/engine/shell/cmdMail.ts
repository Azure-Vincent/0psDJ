// Mail tools: swaks (SMTP test client), curl for imap:// and imaps:// URLs,
// the Postfix commands (postconf, postfix, mailq/postqueue, postsuper,
// newaliases) and Dovecot's (doveconf, doveadm). Output follows swaks
// 20240103.0, curl 7.88.1, Postfix 3.7.11 and Dovecot 2.3.19.1 on Debian 12.

import { readFile, writeFile } from '../fs';
import {
  dcSetting, DOVECOT_CONF, DOVECOT_DEFAULTS, DOVECOT_VERSION, dovecotAuth, dovecotLoaded, Imapd, inboxMessages, loadDovecotConf, type DcSection,
} from '../sim/dovecot';
import { resolve } from '../sim/dns';
import {
  bareAddr, domainOf, flushQueue, loadMainCf, MAIN_CF, mailListenerOwner, mailState, mainCfFatal, MASTER_CF, mxLookup, newaliases, param, parseMasterCf,
  postfixDefaults, postfixLoaded, queueTime, rawParam, replyLines, rfcDate, Smtpd, smtpConversation, unusedParams, type ConvStep,
} from '../sim/mail';
import { type Cert, matchesHost, parseCerts, trustStore, VERIFY_TEXT, verifyChain } from '../sim/pki';
import { reloadService, serviceDef, startService, stopService } from '../sim/services';
import { ERRNO_TEXT, type TcpConn, tcpConnect } from '../sim/tcp';
import { getFile, resolvePath } from './cmdFiles';
import { type CmdCtx, type CommandDef, type CmdResult, err, ok, parseFlags } from './types';

const notFound = (name: string): CmdResult => err(`-bash: ${name}: command not found`, 127);
const postfixInstalled = (ctx: CmdCtx) => !!ctx.host.fs['/etc/postfix'];
const dovecotInstalled = (ctx: CmdCtx) => !!ctx.host.fs['/etc/dovecot'];
const b64 = (s: string) => (typeof btoa === 'function' ? btoa(s) : s);

// ---------------------------------------------------------------------------
// swaks
// ---------------------------------------------------------------------------

const SWAKS_VERSION = 'v20240103.0';
const AUTH_TYPES = ['PLAIN', 'LOGIN', 'CRAM-MD5', 'DIGEST-MD5', 'NTLM', 'ANY'];
/** swaks' exit codes by the step that failed. */
const SWAKS_EXIT: Record<string, number> = { connect: 2, banner: 21, ehlo: 22, mail: 23, rcpt: 24, data: 25, tls: 29, auth: 28 };

interface SwaksOpts { to?: string; from?: string; server?: string; port?: number; tls: 'none' | 'opportunistic' | 'required' | 'wrapper'; auth?: string; authUser?: string; authPassword?: string; headers: string[]; body?: string; helo?: string; quitAfter?: string; errors: string[] }

function parseSwaks(args: string[]): SwaksOpts {
  const o: SwaksOpts = { tls: 'none', headers: [], errors: [] };
  const take = (i: number) => args[i + 1];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const [flag, inline] = a.includes('=') && a.startsWith('--') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, undefined];
    const val = () => (inline !== undefined ? inline : args[++i]);
    switch (flag.replace(/^--?/, '')) {
      case 't': case 'to': o.to = val(); break;
      case 'f': case 'from': o.from = val(); break;
      case 's': case 'server': o.server = val(); break;
      case 'p': case 'port': o.port = Number(val()); break;
      case 'tls': o.tls = 'required'; break;
      case 'tlso': case 'tls-optional': o.tls = 'opportunistic'; break;
      case 'tlsc': case 'tls-on-connect': o.tls = 'wrapper'; break;
      case 'a': case 'auth': {
        const next = inline ?? take(i);
        if (next && AUTH_TYPES.includes(next.toUpperCase())) { o.auth = next.toUpperCase(); if (inline === undefined) i++; } else o.auth = 'ANY';
        break;
      }
      case 'au': case 'auth-user': o.authUser = val(); o.auth ??= 'ANY'; break;
      case 'ap': case 'auth-password': o.authPassword = val(); o.auth ??= 'ANY'; break;
      case 'h': case 'header': case 'add-header': o.headers.push(val() ?? ''); break;
      case 'body': o.body = val(); break;
      case 'ehlo': case 'helo': case 'hello': o.helo = val(); break;
      case 'q': case 'quit': case 'quit-after': o.quitAfter = (val() ?? '').toLowerCase(); break;
      default:
        if (/^--?h-/.test(flag)) { o.headers.push(`${flag.replace(/^--?h-/, '')}: ${val()}`); break; }
        o.errors.push(`Unknown option: ${flag.replace(/^--?/, '')}`);
    }
  }
  return o;
}

/** Render a recorded SMTP conversation the way swaks prints it. */
function swaksTranscript(steps: ConvStep[], content: string, peer: { chain?: Cert[] }): string[] {
  const out: string[] = [];
  for (const s of steps) {
    const c = s.tls ? ' ~> ' : ' -> ';
    if (s.note === 'tls-started') {
      out.push('=== TLS started with cipher TLSv1.3:TLS_AES_256_GCM_SHA384:256', '=== TLS no local certificate set', `=== TLS peer DN="/CN=${peer.chain?.[0]?.subject.find(([k]) => k === 'CN')?.[1] ?? ''}"`);
      continue;
    }
    if (s.cmd === '.') {
      for (const line of content.replace(/\n$/, '').split('\n')) out.push(`${c}${line}`);
      out.push(`${c}`, `${c}.`);
    } else if (s.cmd) out.push(`${c}${s.cmd}`);
    if (!s.reply) {
      out.push('*** Remote host closed connection unexpectedly.');
      continue;
    }
    const bad = s.reply.code >= 400;
    const pre = s.tls ? (bad ? '<~* ' : '<~  ') : (bad ? '<** ' : '<-  ');
    for (const l of replyLines(s.reply)) out.push(`${pre}${l}`);
  }
  return out;
}

const swaks: CommandDef = {
  name: 'swaks',
  summary: 'Swiss Army Knife for SMTP: send a test message and show the dialogue',
  usage: 'swaks --to ADDR [--from ADDR] [--server HOST[:PORT]] [--port N] [--tls|--tls-on-connect] [--auth [TYPE] --auth-user U --auth-password P] [--header "Subject: x"] [--body TEXT] [--quit-after STEP]',
  run(args, ctx) {
    const o = parseSwaks(args);
    if (o.errors.length) return err(o.errors.join('\n'), 1);
    const to = o.to ?? ctx.ask('To: ', false);
    if (!to) return err('*** No recipient specified', 1);
    const rcpts = to.split(',').map((x) => bareAddr(x)).filter(Boolean);
    const from = o.from ?? `${ctx.user.name}@${ctx.host.hostname}${ctx.host.domain ? '.' + ctx.host.domain : ''}`;
    const helo = o.helo ?? `${ctx.host.hostname}${ctx.host.domain ? '.' + ctx.host.domain : ''}`;
    let server = o.server;
    let port = o.port;
    if (server && /^[^[]*:\d+$/.test(server)) { port ??= Number(server.slice(server.lastIndexOf(':') + 1)); server = server.slice(0, server.lastIndexOf(':')); }
    if (!server) {
      // No --server: swaks looks up the MX of the first recipient's domain.
      const dom = domainOf(rcpts[0]);
      const mx = dom ? mxLookup(ctx.world, ctx.host, dom) : null;
      server = mx?.ok ? mx.mx[0][1] : dom || 'localhost';
    }
    port ??= o.tls === 'wrapper' ? 465 : 25;
    if (o.auth && o.authUser === undefined) o.authUser = ctx.ask('Username: ', false);
    if (o.auth && o.authPassword === undefined) o.authPassword = ctx.ask('Password: ', true);
    const out = [`=== Trying ${server}:${port}...`];
    const r = resolve(ctx.world, ctx.host, server, { family: 4 });
    if (!r.ok) return err([...out, `*** Error connecting to ${server}:${port}:`, `***\tIO::Socket::INET6: getaddrinfo: ${r.message}`].join('\n'), 2);
    const c = tcpConnect(ctx.world, ctx.host, r.ip, port, { timeoutMs: 30_000 });
    if (!c.ok) {
      const why = c.errno === 'ETIMEDOUT' ? 'timeout' : ERRNO_TEXT[c.errno];
      return err([...out, `*** Error connecting to ${server}:${port}:`, `***\tIO::Socket::INET6: connect: ${why}`].join('\n'), 2);
    }
    out.push(`=== Connected to ${server}.`);
    const date = rfcDate(ctx.world.clock);
    const custom = Object.fromEntries(o.headers.map((h) => [h.slice(0, h.indexOf(':')).trim().toLowerCase(), h]));
    const hdr = (name: string, dflt: string) => custom[name.toLowerCase()] ?? `${name}: ${dflt}`;
    const extra = o.headers.filter((h) => !['date', 'to', 'from', 'subject', 'message-id', 'x-mailer'].includes(h.slice(0, h.indexOf(':')).trim().toLowerCase()));
    const mid = `<${new Date(Math.floor(ctx.world.clock)).toISOString().replace(/\D/g, '').slice(0, 14)}.${String(ctx.world.counter).padStart(6, '0')}@${helo}>`;
    const content = [hdr('Date', date), hdr('To', rcpts.join(', ')), hdr('From', from), hdr('Subject', `test ${date}`), hdr('Message-Id', mid), hdr('X-Mailer', `swaks ${SWAKS_VERSION} jetmore.org/john/code/swaks/`), ...extra, '', (o.body ?? 'This is a test mailing').replace(/\\n/g, '\n'), ''].join('\n');
    const owner = mailListenerOwner(c.conn.server, c.conn.sv.localPort);
    if (owner !== 'postfix') {
      // Not an SMTP server: nothing sensible arrives (an HTTP or IMAP server answers differently).
      c.conn.close('client');
      if (owner === 'dovecot') return err([...out, '<** * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot (Debian) ready.', `*** Unexpected banner from ${server}: not an SMTP server`].join('\n'), 21);
      return err([...out, '*** Remote host closed connection unexpectedly.'].join('\n'), 21);
    }
    const conv = smtpConversation(ctx.world, c.conn, {
      helo, from, to: rcpts, content, tls: o.tls, quitAfter: o.quitAfter,
      auth: o.auth ? { mech: o.auth, user: o.authUser ?? '', password: o.authPassword ?? '' } : undefined,
    });
    c.conn.close('client');
    const lines = swaksTranscript(conv.steps, content, { chain: conv.peerChain });
    // Messages swaks adds for the steps it could not do.
    if (conv.result === 'no-tls') {
      const idx = lines.findIndex((l) => /QUIT$/.test(l));
      lines.splice(idx < 0 ? lines.length : idx, 0, '*** Host did not advertise STARTTLS');
    } else if (conv.result === 'tls-failed' && o.tls !== 'wrapper') {
      const idx = lines.findIndex((l) => /QUIT$/.test(l));
      lines.splice(idx < 0 ? lines.length : idx, 0, '*** STARTTLS attempted but failed');
    } else if (conv.result === 'tls-failed') {
      lines.push('*** TLS startup failed (connect(): error:0A00010B:SSL routines::wrong version number)');
    } else if (conv.result === 'no-auth') {
      const idx = lines.findIndex((l) => /QUIT$/.test(l));
      lines.splice(idx < 0 ? lines.length : idx, 0, '*** Host did not advertise authentication');
    } else if (conv.result === 'auth-failed') {
      const idx = lines.findIndex((l) => /QUIT$/.test(l));
      lines.splice(idx < 0 ? lines.length : idx, 0, '*** No authentication type succeeded');
    }
    if (conv.result !== 'closed') lines.push('=== Connection closed with remote host.');
    const text = [...out, ...lines].join('\n');
    if (conv.result === 'sent') return ok(text);
    return err(text, SWAKS_EXIT[conv.failedAt ?? 'connect'] ?? 1);
  },
};

// ---------------------------------------------------------------------------
// Postfix: mailq / postqueue / postsuper / postconf / postfix / newaliases
// ---------------------------------------------------------------------------

function queueListing(ctx: CmdCtx): string {
  const q = mailState(ctx.host).queue;
  if (!q.length) return 'Mail queue is empty';
  const lines = ['-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------'];
  for (const m of q) {
    lines.push(`${(m.id + (m.deferred ? ' ' : '*')).padEnd(11)} ${String(m.size).padStart(8)} ${queueTime(m.arrival)}  ${m.from || 'MAILER-DAEMON'}`);
    const reasons = new Map<string, string[]>();
    for (const r of m.rcpts) reasons.set(r.reason ?? '', [...(reasons.get(r.reason ?? '') ?? []), r.addr]);
    for (const [reason, addrs] of reasons) {
      if (reason) lines.push(`(${reason})`);
      for (const a of addrs) lines.push(`${' '.repeat(41)}${a}`);
    }
    lines.push('');
  }
  const kb = Math.max(1, Math.ceil(q.reduce((n, m) => n + m.size, 0) / 1024));
  lines.push(`-- ${kb} Kbytes in ${q.length} Request${q.length === 1 ? '' : 's'}.`);
  return lines.join('\n');
}

const mailq: CommandDef = {
  name: 'mailq',
  summary: 'list the Postfix mail queue (same as postqueue -p)',
  usage: 'mailq',
  run(_args, ctx) {
    if (!postfixInstalled(ctx)) return notFound('mailq');
    if (!postfixLoaded(ctx.host)) return err('postqueue: fatal: Queue report unavailable - mail system is down', 69);
    return ok(queueListing(ctx));
  },
};

const postqueue: CommandDef = {
  name: 'postqueue',
  summary: 'Postfix queue control: list (-p), flush (-f), deliver one message (-i ID)',
  usage: 'postqueue -p | -f | -i QUEUE_ID',
  run(args, ctx) {
    if (!postfixInstalled(ctx)) return notFound('postqueue');
    const { flags } = parseFlags(args, ['-i']);
    const up = !!postfixLoaded(ctx.host);
    if (flags.has('-p')) return up ? ok(queueListing(ctx)) : err('postqueue: fatal: Queue report unavailable - mail system is down', 69);
    if (flags.has('-f')) {
      if (!up) return err('postqueue: fatal: Cannot flush mail queue - mail system is down', 69);
      flushQueue(ctx.world, ctx.host);
      return ok('');
    }
    if (flags.has('-i')) {
      if (!up) return err('postqueue: fatal: Cannot flush mail queue - mail system is down', 69);
      const id = flags.get('-i') as string;
      const m = mailState(ctx.host).queue.find((x) => x.id === id);
      if (!m) return err(`postqueue: fatal: invalid queue ID: ${id}`, 69);
      flushQueue(ctx.world, ctx.host);
      return ok('');
    }
    return err('postqueue: fatal: usage: postqueue -f | postqueue -i queueid | postqueue -j | postqueue -p | postqueue -s site', 64);
  },
};

const postsuper: CommandDef = {
  name: 'postsuper',
  summary: 'Postfix queue maintenance: delete (-d ID|ALL) or requeue (-r ID|ALL) messages',
  usage: 'postsuper -d QUEUE_ID|ALL [deferred] | -r QUEUE_ID|ALL',
  run(args, ctx) {
    if (!postfixInstalled(ctx)) return notFound('postsuper');
    if (ctx.user.uid !== 0) return err('postsuper: fatal: use of this command is reserved for the superuser', 1);
    const { flags, rest } = parseFlags(args, ['-d', '-r']);
    const st = mailState(ctx.host);
    const pick = (id: string, queue?: string) => st.queue.filter((m) => (id === 'ALL' || m.id === id || (id === '-' && false)) && (!queue || (queue === 'deferred' ? m.deferred : !m.deferred)));
    if (flags.has('-d')) {
      const id = flags.get('-d') as string;
      const hit = pick(id, rest[0]);
      st.queue = st.queue.filter((m) => !hit.includes(m));
      const out = hit.map((m) => `postsuper: ${m.id}: removed`);
      if (hit.length) out.push(`postsuper: Deleted: ${hit.length} message${hit.length === 1 ? '' : 's'}`);
      return ok(out.join('\n'));
    }
    if (flags.has('-r')) {
      const hit = pick(flags.get('-r') as string);
      for (const m of hit) { m.deferred = false; for (const r of m.rcpts) delete r.reason; }
      if (hit.length) flushQueue(ctx.world, ctx.host);
      return ok(hit.length ? `postsuper: Requeued: ${hit.length} message${hit.length === 1 ? '' : 's'}` : '');
    }
    return err('postsuper: fatal: usage: postsuper [-c config_dir] [-d queue_id (delete)] [-h queue_id (hold)] [-H queue_id (un-hold)] [-p (purge temporary files)] [-r queue_id (requeue)] [-s (structure fix)] [-S (structure fix and sync)] [-v (verbose)] [queue...]', 1);
  },
};

/** Set (or with value undefined, remove) a parameter in main.cf, keeping the other lines. */
function editMainCf(text: string, name: string, value: string | undefined): string {
  const lines = text.split('\n');
  const out: string[] = [];
  let done = false;
  for (let i = 0; i < lines.length; i++) {
    const m = /^([A-Za-z0-9_.-]+)\s*=/.exec(lines[i]);
    if (m && m[1] === name) {
      while (i + 1 < lines.length && /^\s+\S/.test(lines[i + 1]) && !/^\s*#/.test(lines[i + 1])) i++;
      if (value !== undefined && !done) out.push(`${name} = ${value}`);
      done = true;
      continue;
    }
    out.push(lines[i]);
  }
  if (!done && value !== undefined) {
    while (out.length && out[out.length - 1] === '') out.pop();
    out.push(`${name} = ${value}`, '');
  }
  return out.join('\n');
}

const postconf: CommandDef = {
  name: 'postconf',
  summary: 'show or change Postfix configuration (main.cf; -M master.cf)',
  usage: 'postconf [-n|-d|-h|-x] [NAME...] | postconf -e "NAME = VALUE" | postconf -X NAME | postconf -M [SERVICE]',
  run(args, ctx) {
    if (!postfixInstalled(ctx)) return notFound('postconf');
    const { flags, rest } = parseFlags(args);
    const h = ctx.host;
    const cf = loadMainCf(h);
    const defaults = postfixDefaults(h);
    if (flags.has('-e') || flags.has('-X') || flags.has('-#')) {
      if (ctx.user.uid !== 0) return err(`postconf: fatal: open ${MAIN_CF} for writing: Permission denied`, 1);
      let text = readFile(h, MAIN_CF) ?? '';
      for (const a of rest) {
        if (flags.has('-e')) {
          const m = /^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(a);
          if (!m) return err(`postconf: fatal: -e requires name=value input`, 1);
          text = editMainCf(text, m[1], m[2].trim());
        } else text = editMainCf(text, a.trim(), undefined);
      }
      writeFile(h, MAIN_CF, text, ctx.world.clock);
      return ok('');
    }
    if (flags.has('-M') || flags.has('-Mf')) {
      const mc = parseMasterCf(readFile(h, MASTER_CF) ?? '');
      const svc = mc.services.filter((s) => !rest.length || rest.some((r) => r === s.name || r === `${s.name}/${s.type}`));
      return ok(svc.map((s) => {
        const raw = (readFile(h, MASTER_CF) ?? '').split('\n')[s.line - 1].trim().split(/\s+/).slice(0, 8);
        const head = `${raw[0].padEnd(9)} ${raw[1].padEnd(5)} ${raw.slice(2, 7).map((x) => x.padEnd(7)).join(' ')} ${raw[7]}`;
        const opts = Object.entries(s.overrides).map(([k, v]) => ` -o ${k}=${v}`).join('');
        return `${head}${s.args.length ? ' ' + s.args.join(' ') : ''}${opts}`;
      }).join('\n'));
    }
    const warn = unusedParams(h, cf);
    const fmt = (n: string, v: string) => (flags.has('-h') ? v : `${n} = ${v}`);
    const value = (n: string) => {
      if (flags.has('-d')) return defaults[n];
      const raw = rawParam(h, cf, n);
      return raw === undefined ? undefined : flags.has('-x') ? param(h, cf, n) : raw;
    };
    if (flags.has('-n')) {
      const names = [...cf.order].sort();
      return ok([...warn, ...names.map((n) => fmt(n, flags.has('-x') ? param(h, cf, n) : cf.params[n]))].join('\n'));
    }
    if (rest.length) {
      const out: string[] = [];
      let code = 0;
      for (const n of rest) {
        const v = value(n);
        if (v === undefined) { out.push(`postconf: warning: ${n}: unknown parameter`); code = 0; continue; }
        out.push(fmt(n, v));
      }
      return { out: out.join('\n'), code };
    }
    const all = [...new Set([...Object.keys(defaults), ...cf.order])].sort();
    return ok(all.map((n) => fmt(n, value(n) ?? '')).join('\n'));
  },
};

const postfixCmd: CommandDef = {
  name: 'postfix',
  summary: 'Postfix control: check, start, stop, reload, status, flush',
  usage: 'postfix check|start|stop|reload|status|flush',
  run(args, ctx) {
    if (!postfixInstalled(ctx)) return notFound('postfix');
    const action = args.find((a) => !a.startsWith('-'));
    const def = serviceDef('postfix')!;
    const rt = ctx.host.services.postfix;
    const running = rt?.state === 'active';
    if (action !== 'status' && action !== 'check' && ctx.user.uid !== 0) return err('postfix: fatal: to submit mail, use the Postfix sendmail command\npostfix: fatal: the postfix command is reserved for the superuser', 1);
    switch (action) {
      case 'status':
        return running ? ok(`postfix/postfix-script: the Postfix mail system is running: PID: ${rt.pid}`) : err('postfix/postfix-script: the Postfix mail system is not running', 1);
      case 'check': {
        const cf = loadMainCf(ctx.host);
        const out = [...unusedParams(ctx.host, cf)];
        const fatal = mainCfFatal(ctx.host, cf) ?? parseMasterCf(readFile(ctx.host, MASTER_CF) ?? '').errors[0];
        if (fatal) return err([...out, `postfix: ${fatal}`].join('\n'), 1);
        const src = ctx.host.fs['/etc/aliases'];
        const db = ctx.host.fs['/etc/aliases.db'];
        if (src && db && src.mtime > db.mtime) out.push('postfix/postfix-script: warning: database /etc/aliases.db is older than source file /etc/aliases');
        if (src && !db) out.push('postfix/postfix-script: warning: /etc/aliases.db: No such file or directory');
        return ok(out.join('\n'));
      }
      case 'start':
        if (running) return err('postfix/postfix-script: fatal: the Postfix mail system is already running', 1);
        if (!rt) return err('postfix/postfix-script: fatal: Postfix is not installed', 1);
        return startService(ctx.world, ctx.host, def) ? ok('postfix/postfix-script: starting the Postfix mail system') : err(`postfix: ${mainCfFatal(ctx.host, loadMainCf(ctx.host)) ?? 'fatal: the Postfix mail system did not start'}`, 1);
      case 'stop':
        if (!running) return err('postfix/postfix-script: fatal: the Postfix mail system is not running', 1);
        stopService(ctx.world, ctx.host, def);
        return ok('postfix/postfix-script: stopping the Postfix mail system');
      case 'reload': {
        if (!running) return err('postfix/postfix-script: fatal: the Postfix mail system is not running', 1);
        const r = reloadService(ctx.world, ctx.host, def);
        return r.ok ? ok('postfix/postfix-script: refreshing the Postfix mail system') : err(`postfix: ${mainCfFatal(ctx.host, loadMainCf(ctx.host)) ?? 'fatal: reload failed'}`, 1);
      }
      case 'flush':
        if (!running) return err('postqueue: fatal: Cannot flush mail queue - mail system is down', 69);
        flushQueue(ctx.world, ctx.host);
        return ok('');
      default:
        return err('postfix: fatal: usage: postfix [-c config_dir] [-Dv] command', 1);
    }
  },
};

const newaliasesCmd: CommandDef = {
  name: 'newaliases',
  summary: 'rebuild /etc/aliases.db from /etc/aliases (postalias)',
  usage: 'newaliases',
  run(_args, ctx) {
    if (!postfixInstalled(ctx)) return notFound('newaliases');
    if (ctx.user.uid !== 0) return err('postalias: fatal: open database /etc/aliases.db: Permission denied', 1);
    const w = newaliases(ctx.world, ctx.host);
    return w.some((l) => l.includes('fatal')) ? err(w.join('\n'), 1) : ok(w.join('\n'));
  },
};

const postalias: CommandDef = {
  name: 'postalias',
  summary: 'build an alias database: postalias /etc/aliases',
  usage: 'postalias [hash:]/etc/aliases',
  run(args, ctx) {
    if (!postfixInstalled(ctx)) return notFound('postalias');
    const file = (args.find((a) => !a.startsWith('-')) ?? '').replace(/^\w+:/, '');
    if (file !== '/etc/aliases') return err(`postalias: fatal: open ${file || '(none)'}: the lab only builds /etc/aliases`, 1);
    return newaliasesCmd.run([], ctx);
  },
};

// ---------------------------------------------------------------------------
// Dovecot: doveconf, doveadm
// ---------------------------------------------------------------------------

/** doveconf -n: settings that differ from the defaults, sections nested, in name order. */
function doveconfN(host: CmdCtx['host'], showSecrets: boolean): string[] {
  const c = loadDovecotConf(host);
  if (c.errors.length) return c.errors;
  const merge = (secs: DcSection[]): DcSection[] => {
    const out: DcSection[] = [];
    for (const s of secs) {
      const ex = out.find((x) => x.type === s.type && x.name === s.name);
      if (ex) { Object.assign(ex.settings, s.settings); ex.sections.push(...s.sections); } else out.push({ ...s, settings: { ...s.settings }, sections: [...s.sections] });
    }
    return out.map((s) => ({ ...s, sections: merge(s.sections) }));
  };
  const show = (k: string, v: string) => (k === 'ssl_key' && !showSecrets ? '# hidden, use -P to show it' : /^\s|\s$/.test(v) ? `"${v}"` : v);
  const render = (s: DcSection, indent: string): string[] => {
    const items: [string, string[]][] = [
      ...Object.entries(s.settings).filter(([k, v]) => indent || DOVECOT_DEFAULTS[k] !== v).map(([k, v]) => [k, [`${indent}${k} = ${show(k, v)}`]] as [string, string[]]),
      ...merge(s.sections).map((x) => {
        const inner = render(x, indent + '  ');
        return [`${x.type} ${x.name}`, inner.length ? [`${indent}${x.type}${x.name ? ' ' + x.name : ''} {`, ...inner, `${indent}}`] : []] as [string, string[]];
      }),
    ];
    return items.sort((a, b) => a[0].localeCompare(b[0])).flatMap(([, l]) => l);
  };
  return [`# ${DOVECOT_VERSION}: ${DOVECOT_CONF}`, '# OS: Linux 6.1.0-26-amd64 x86_64 Debian 12.7 ', `# Hostname: ${host.hostname}.${host.domain}`, ...render(c.root, '')];
}

const doveconf: CommandDef = {
  name: 'doveconf',
  summary: 'show Dovecot configuration (-n: changed settings)',
  usage: 'doveconf [-n] [-P] [-h] [SETTING...]',
  run(args, ctx) {
    if (!dovecotInstalled(ctx)) return notFound('doveconf');
    const { flags, rest } = parseFlags(args);
    if (flags.has('-n') || !rest.length) {
      const lines = doveconfN(ctx.host, flags.has('-P'));
      return lines[0]?.startsWith('doveconf: Fatal') ? err(lines.join('\n'), 89) : ok(lines.join('\n'));
    }
    const c = loadDovecotConf(ctx.host);
    if (c.errors.length) return err(c.errors.join('\n'), 89);
    const out: string[] = [];
    for (const n of rest) {
      if (!(n in DOVECOT_DEFAULTS)) return err(`doveconf: Fatal: Unknown setting: ${n}`, 89);
      const v = dcSetting(c, n);
      out.push(flags.has('-h') ? v : `${n} = ${v}`);
    }
    return ok(out.join('\n'));
  },
};

const doveadm: CommandDef = {
  name: 'doveadm',
  summary: 'Dovecot administration: auth test, mailbox list/status, reload, stop',
  usage: 'doveadm auth test USER [PASSWORD] | doveadm mailbox list -u USER | doveadm mailbox status -u USER messages INBOX | doveadm reload',
  run(args, ctx) {
    if (!dovecotInstalled(ctx)) return notFound('doveadm');
    if (ctx.user.uid !== 0) return err(`Error: Failed to load configuration: doveconf: Fatal: Error in configuration file ${DOVECOT_CONF}: stat(${DOVECOT_CONF}) failed: Permission denied`, 89);
    const [cmd, sub, ...rest] = args;
    const l = dovecotLoaded(ctx.host);
    const down = (sock: string) => err(`doveadm(root): Error: ${sock === 'auth-client' ? '' : 'auth-master: '}connect(/run/dovecot/${sock}) failed: No such file or directory`, 75);
    if (cmd === 'reload' || cmd === 'stop') {
      const def = serviceDef('dovecot')!;
      if (!l) return err('Fatal: Dovecot is not running', 75);
      if (cmd === 'stop') { stopService(ctx.world, ctx.host, def); return ok(''); }
      const r = reloadService(ctx.world, ctx.host, def);
      return r.ok ? ok('') : err(r.message ?? 'reload failed', 75);
    }
    if (cmd === 'auth' && sub === 'test') {
      const user = rest.find((a) => !a.startsWith('-'));
      if (!user) return err('doveadm auth test: Usage: doveadm auth test [-a <auth socket path>] [-A <sasl mech>] [-x <auth info>] [-M <master user>] <user> [<password>]', 64);
      if (!l) return down('auth-client');
      const password = rest[rest.indexOf(user) + 1] ?? ctx.ask('Password: ', true);
      const u = dovecotAuth(ctx.world, ctx.host, user, password, '');
      return u ? ok(`passdb: ${user} auth succeeded\nextra fields:\n  user=${user}`) : err(`passdb: ${user} auth failed\nextra fields:\n  user=${user}`, 77);
    }
    if (cmd === 'mailbox' && (sub === 'list' || sub === 'status')) {
      const ui = rest.indexOf('-u');
      const name = ui >= 0 ? rest[ui + 1] : undefined;
      if (!name) return err(`doveadm mailbox ${sub}: Usage: doveadm mailbox ${sub} -u <user>`, 64);
      if (!l) return down('auth-userdb');
      const u = ctx.host.users[name];
      if (!u) return err(`doveadm(${name}): Error: User doesn't exist`, 67);
      if (sub === 'list') return ok('INBOX');
      const msgs = inboxMessages(ctx.host, l, u);
      const fields = rest.filter((a, i) => a !== '-u' && i !== ui + 1 && a !== 'INBOX');
      const val: Record<string, number> = { messages: msgs.length, unseen: msgs.filter((m) => !m.seen).length, recent: 0, uidnext: msgs.length + 1 };
      return ok((fields.length ? fields : ['messages']).map((f) => (f === 'all' ? Object.entries(val).map(([k, v]) => `${k}=${v}`).join(' ') : `${f}=${val[f] ?? 0}`)).join(' '));
    }
    return err('usage: doveadm [-Dv] [-f <formatter>] <command> [<args>]\n  auth test <user> [<password>]\n  mailbox list -u <user>\n  mailbox status -u <user> <fields> INBOX\n  reload\n  stop', 64);
  },
};

// ---------------------------------------------------------------------------
// curl imap:// imaps://
// ---------------------------------------------------------------------------

/** Called by curl for imap:// and imaps:// URLs. */
export function curlImap(args: string[], ctx: CmdCtx): CmdResult {
  const { flags, rest } = parseFlags(args, ['-u', '--user', '-X', '--request', '--cacert', '-m', '--max-time', '--connect-timeout', '--login-options']);
  const url = rest.find((a) => /^imaps?:\/\//i.test(a))!;
  const m = /^(imaps?):\/\/(?:([^@/]+)@)?(\[[0-9a-fA-F:.]+\]|[^/:?#;]+)(?::(\d+))?(\/[^?]*)?(?:\?(.*))?$/i.exec(url);
  const silent = flags.has('-s') || flags.has('--silent');
  const verbose = flags.has('-v') || flags.has('--verbose');
  const vlog: string[] = [];
  const fail = (code: number, msg: string) => err([verbose ? vlog.join('\n') : '', !silent || flags.has('-S') ? `curl: (${code}) ${msg}` : ''].filter(Boolean).join('\n'), code);
  if (!m) return fail(3, 'URL using bad/illegal format or missing URL');
  const imaps = m[1].toLowerCase() === 'imaps';
  const hostName = m[3];
  const port = Number(m[4] ?? (imaps ? 993 : 143));
  const path = decodeURIComponent(m[5] ?? '/');
  const query = m[6];
  const sslReqd = flags.has('--ssl-reqd');
  const sslTry = flags.has('--ssl') || sslReqd;
  const insecure = flags.has('-k') || flags.has('--insecure');
  let creds = (flags.get('-u') ?? flags.get('--user') ?? m[2]) as string | undefined;
  if (creds && !creds.includes(':')) creds = `${creds}:${ctx.ask(`Enter host password for user '${creds}':`, true)}`;
  const [user, password] = creds ? [creds.slice(0, creds.indexOf(':')), creds.slice(creds.indexOf(':') + 1)] : ['', ''];

  const r = resolve(ctx.world, ctx.host, hostName, { family: 4 });
  if (!r.ok) return fail(6, `Could not resolve host: ${hostName}`);
  vlog.push(`*   Trying ${r.ip}:${port}...`);
  const start = ctx.world.clock;
  const c = tcpConnect(ctx.world, ctx.host, r.ip, port, { timeoutMs: 130_000 });
  const elapsed = Math.round(ctx.world.clock - start);
  if (!c.ok) return fail(c.errno === 'ECONNREFUSED' || c.errno === 'ETIMEDOUT' ? (c.errno === 'ETIMEDOUT' ? 28 : 7) : 7, `Failed to connect to ${hostName} port ${port} after ${Math.max(1, elapsed)} ms: ${c.errno === 'ECONNREFUSED' || c.errno === 'ETIMEDOUT' ? "Couldn't connect to server" : ERRNO_TEXT[c.errno]}`);
  vlog.push(`* Connected to ${hostName} (${r.ip}) port ${port} (#0)`);
  const conn = c.conn;
  const server = conn.server;
  const l = dovecotLoaded(server);
  if (!l || mailListenerOwner(server, conn.sv.localPort) !== 'dovecot') {
    conn.close('client');
    return fail(8, 'Got unexpected imap-server response');
  }
  const imapd = new Imapd(ctx.world, server, l, conn.sv.peer, conn.sv.local, conn.sv.localPort);
  let tag = 0;
  const wire = (dir: 'c2s' | 's2c', text: string) => conn.send(dir, text.length + 2, { protocol: imapd.tlsActive ? 'TLS' : 'IMAP', info: imapd.tlsActive ? 'Application Data' : text.split('\n')[0].slice(0, 80), fields: [] });
  const send = (cmd: string) => { const t = `A${String(++tag).padStart(3, '0')}`; vlog.push(`> ${t} ${cmd.startsWith('AUTHENTICATE PLAIN') ? 'AUTHENTICATE PLAIN ' + b64(`\0${user}\0${password}`) : cmd}`); wire('c2s', `${t} ${cmd}`); return t; };
  const recv = (...lines: string[]) => { for (const x of lines) vlog.push(`< ${x}`); wire('s2c', lines.join('\n')); };
  const bye = (code: number, msg: string) => {
    if (!imapd.closed) { const t = send('LOGOUT'); recv('* BYE Logging out', `${t} OK Logout completed (0.001 + 0.000 secs).`); imapd.logout(); }
    conn.close('client');
    return fail(code, msg);
  };
  // TLS: verify the certificate like curl (trust store or --cacert, host name), unless -k.
  const tlsUp = (): CmdResult | null => {
    if (imapd.tlsFailed()) { conn.close('server'); return fail(35, 'OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to ' + `${hostName}:${port} `); }
    conn.send('c2s', 517, { protocol: 'TLS', info: 'Client Hello', fields: [{ name: 'Server Name Indication', value: hostName }] });
    conn.send('s2c', 2400, { protocol: 'TLS', info: 'Server Hello, Change Cipher Spec, Application Data', fields: [] });
    const chain = l.tls!.chain;
    vlog.push('* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384', '* Server certificate:', `*  subject: CN=${chain[0].subject.find(([k]) => k === 'CN')?.[1] ?? ''}`);
    if (insecure) return null;
    let trusted: Cert[] = trustStore(ctx.host);
    const ca = flags.get('--cacert');
    if (typeof ca === 'string') {
      const f = getFile(ctx, resolvePath(ctx, ca));
      trusted = f.content ? parseCerts(f.content).filter((x): x is Cert => !!x) : [];
      if (f.error || !trusted.length) return fail(77, `error setting certificate file: ${ca}`);
    }
    const v = verifyChain(chain[0], chain.slice(1), trusted, ctx.world.clock);
    if (!v.ok) { conn.close('client'); imapd.logout(); return fail(60, `SSL certificate problem: ${VERIFY_TEXT[v.errors[0].code]}\nMore details here: https://curl.se/docs/sslcerts.html\n\ncurl failed to verify the legitimacy of the server and therefore could not\nestablish a secure connection to it. To learn more about this situation and\nhow to fix it, please visit the web page mentioned above.`); }
    if (!/^[\d.]+$/.test(hostName) && !matchesHost(chain[0], hostName)) { conn.close('client'); imapd.logout(); return fail(60, `SSL: no alternative certificate subject name matches target host name '${hostName}'`); }
    return null;
  };
  if (imapd.tlsActive) { const e = tlsUp(); if (e) return e; }
  recv(imapd.greeting());
  let t = send('CAPABILITY');
  recv(`* CAPABILITY ${imapd.capabilities()}`, `${t} OK Pre-login capabilities listed, post-login capabilities have more.`);
  if (!imapd.tlsActive && sslTry) {
    if (!imapd.capabilities().includes('STARTTLS')) {
      if (sslReqd) return bye(64, 'Requested SSL level failed');
    } else {
      t = send('STARTTLS');
      recv(imapd.starttls(t));
      const e = tlsUp();
      if (e) return e;
      t = send('CAPABILITY');
      recv(`* CAPABILITY ${imapd.capabilities()}`, `${t} OK Pre-login capabilities listed, post-login capabilities have more.`);
    }
  }
  if (!user) return bye(67, 'Login denied');
  const caps = imapd.capabilities();
  if (caps.includes('LOGINDISABLED') && !/AUTH=/.test(caps)) return bye(67, 'Login denied');
  t = send(`AUTHENTICATE PLAIN`);
  const loginReply = imapd.login(t, user, password, 'PLAIN');
  recv(loginReply);
  if (!loginReply.includes(' OK ')) return bye(67, 'Login denied');

  // What the URL (and -X) ask for.
  const custom = (flags.get('-X') ?? flags.get('--request')) as string | undefined;
  const mailbox = path.replace(/^\//, '').split(/[;/]/)[0];
  const uid = /;UID=(\d+)/i.exec(path)?.[1] ?? /;MAILINDEX=(\d+)/i.exec(path)?.[1];
  let body = '';
  if (custom) {
    const verb = custom.trim().split(/\s+/)[0].toUpperCase();
    const argStr = custom.trim().slice(verb.length).trim();
    if ((verb === 'SEARCH' || verb === 'FETCH' || verb === 'UID') && mailbox) {
      const st = send(`SELECT ${mailbox}`);
      const sel = imapd.select(mailbox, false);
      if (!sel) { recv(`${st} NO Mailbox doesn't exist: ${mailbox}`); return bye(78, 'Remote file not found'); }
      recv(...sel, `${st} OK [READ-WRITE] Select completed (0.001 + 0.000 secs).`);
    }
    t = send(custom);
    let lines: string[] | null;
    if (verb === 'EXAMINE' || verb === 'SELECT') lines = imapd.select(argStr.replace(/"/g, ''), verb === 'EXAMINE');
    else if (verb === 'STATUS') { const mm = /^"?([^"\s]+)"?\s*\(([^)]*)\)/.exec(argStr); const s = mm ? imapd.status(mm[1], mm[2].split(/\s+/)) : null; lines = s ? [s] : null; }
    else if (verb === 'SEARCH') lines = [imapd.search(argStr || 'ALL')];
    else if (verb === 'LIST') lines = imapd.list();
    else if (verb === 'NOOP') lines = [];
    else { recv(`${t} BAD Error in IMAP command ${verb}: Unknown command.`); return bye(8, 'Got unexpected imap-server response'); }
    if (!lines) { recv(`${t} NO Mailbox doesn't exist: ${argStr}`); return bye(8, 'Got unexpected imap-server response'); }
    recv(...lines, `${t} OK ${verb.charAt(0) + verb.slice(1).toLowerCase()} completed (0.001 + 0.000 secs).`);
    body = lines.join('\n');
  } else if (!mailbox) {
    t = send('LIST "" *');
    const lines = imapd.list();
    recv(...lines, `${t} OK List completed (0.001 + 0.000 secs).`);
    body = lines.join('\n');
  } else {
    const st = send(`SELECT ${mailbox}`);
    const sel = imapd.select(mailbox, false);
    if (!sel) { recv(`${st} NO Mailbox doesn't exist: ${mailbox}`); return bye(78, 'Remote file not found'); }
    recv(...sel, `${st} OK [READ-WRITE] Select completed (0.001 + 0.000 secs).`);
    if (uid) {
      t = send(`UID FETCH ${uid} BODY[]`);
      const content = imapd.fetch(Number(uid));
      if (content === null) { recv(`${t} OK Fetch completed (0.001 + 0.000 secs).`); return bye(78, 'Remote file not found'); }
      recv(`* ${uid} FETCH (UID ${uid} BODY[] {${content.length}}`, `${t} OK Fetch completed (0.001 + 0.000 secs).`);
      body = content.replace(/\n$/, '');
    } else if (query) {
      t = send(`SEARCH ${query}`);
      const s = imapd.search(query);
      recv(s, `${t} OK Search completed (0.001 + 0.000 secs).`);
      body = s;
    } else {
      t = send(`LIST "${mailbox}" *`);
      const lines = imapd.list().filter((x) => x.endsWith(` ${mailbox.toUpperCase()}`));
      recv(...lines, `${t} OK List completed (0.001 + 0.000 secs).`);
      body = lines.join('\n');
    }
  }
  t = send('LOGOUT');
  recv('* BYE Logging out', `${t} OK Logout completed (0.001 + 0.000 secs).`);
  imapd.logout();
  conn.close('client');
  return ok([verbose ? vlog.join('\n') : '', body].filter(Boolean).join('\n'));
}

// ---------------------------------------------------------------------------
// openssl s_client on mail ports: -starttls smtp|imap, 465 and 993
// ---------------------------------------------------------------------------

/**
 * The TLS certificate chain a mail service offers on this connection:
 * undefined when the port is not Postfix's or Dovecot's; an error key when
 * TLS cannot start (no STARTTLS offered, or a plain-text port).
 */
export function mailTlsChain(world: CmdCtx['world'], conn: TcpConn, starttls: string | undefined): { chain?: Cert[]; error?: 'no-starttls' | 'plaintext' | 'handshake' } | undefined {
  const server = conn.server;
  const owner = mailListenerOwner(server, conn.sv.localPort);
  if (owner === 'postfix') {
    const loaded = postfixLoaded(server)!;
    const svc = loaded.services.find((s) => s.port === conn.sv.localPort);
    if (!svc) return { error: 'plaintext' };
    const smtpd = new Smtpd(world, server, loaded, svc, conn, conn.sv.peer);
    const banner = smtpd.connect();
    if (banner.closed) return { error: 'handshake' };
    if (smtpd.wrapper) { smtpd.disconnect('CONNECT'); return smtpd.tls ? { chain: smtpd.tls.chain } : { error: 'handshake' }; }
    if (starttls !== 'smtp') { smtpd.disconnect('CONNECT'); return { error: 'plaintext' }; }
    const e = smtpd.ehlo('openssl.client.net');
    const offered = e.text.includes('STARTTLS');
    if (!offered) { smtpd.disconnect('EHLO'); return { error: 'no-starttls' }; }
    smtpd.starttls();
    smtpd.tlsStarted();
    smtpd.disconnect('STARTTLS');
    return { chain: smtpd.tls!.chain };
  }
  if (owner === 'dovecot') {
    const l = dovecotLoaded(server)!;
    const imapd = new Imapd(world, server, l, conn.sv.peer, conn.sv.local, conn.sv.localPort);
    const done = <T>(v: T) => { imapd.logout(); return v; };
    if (imapd.tlsActive) return done(imapd.tlsFailed() ? { error: 'handshake' } : { chain: l.tls!.chain });
    if (starttls !== 'imap') return done({ error: 'plaintext' });
    if (!imapd.capabilities().includes('STARTTLS')) return done({ error: 'no-starttls' });
    return done({ chain: l.tls!.chain });
  }
  return undefined;
}

export const MAIL_COMMANDS: CommandDef[] = [swaks, mailq, postqueue, postsuper, postconf, postfixCmd, newaliasesCmd, postalias, doveconf, doveadm];
