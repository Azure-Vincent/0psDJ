// Network diagnostics: ip, ss, ping, traceroute, nc, tcpdump, conntrack,
// sysctl, hostname, uname, date, dig, nslookup, host, getent.

import { dnsQuery, lookupHostsFile, resolve } from '../sim/dns';
import { isoTime } from '../sim/journal';
import { maintainLeases } from '../sim/dhcp';
import { echoIcmp, hostAddresses, icmpMeaning, isFragNeeded, nextId, pathMtu, sourceAddress, transmit } from '../sim/network';
import { allListeners } from '../sim/services';
import { ERRNO_TEXT, tcpConnect } from '../sim/tcp';
import type { CapturedFrame, Packet } from '../types';
import { parseResolvConf } from '../config/netconf';
import { hostPort, inPrefix, normAddr, validPrefix } from '../net/addr';
import { normalizePath, readFile } from '../fs';
import { formatFrame } from './format';
import { ip } from './cmdIp';
import { hasCarrier } from '../sim/l2';
import { bridge, ifreload, rdisc6 } from './cmdL2';
import { virtualFile } from './cmdFiles';
import { type CmdCtx, type CommandDef, err, ok, parseFlags } from './types';

const ss: CommandDef = {
  name: 'ss',
  summary: 'socket statistics',
  usage: 'ss -tlnp | ss -ulnp | ss -tan',
  run(args, ctx) {
    const { flags } = parseFlags(args);
    const listening = flags.has('-l');
    const tcp = flags.has('-t') || (!flags.has('-u'));
    const udp = flags.has('-u');
    const withProc = flags.has('-p');
    const all = flags.has('-a');
    const rows: string[][] = [];
    const header = ['State', 'Recv-Q', 'Send-Q', 'Local Address:Port', 'Peer Address:Port', 'Process'];
    const addr = (a: string, p: number) => hostPort(a, p);
    if (listening || all) {
      for (const l of allListeners(ctx.host)) {
        if ((l.proto === 'tcp' && !tcp) || (l.proto === 'udp' && !udp)) continue;
        const proc = withProc && ctx.user.uid === 0 ? `users:(("${l.process}",pid=${l.pid},fd=${l.port === 22 ? 3 : 6}))` : '';
        rows.push([l.proto === 'udp' ? 'UNCONN' : 'LISTEN', '0', l.proto === 'udp' ? '0' : l.process === 'sshd' ? '128' : '511', addr(l.addr, l.port), l.addr === '::' ? '[::]:*' : '0.0.0.0:*', proc]);
      }
    }
    if (!listening && tcp) {
      for (const s of ctx.world.hosts[ctx.host.id] ? openSessionsOf(ctx) : []) rows.push(s);
    }
    const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
    const fmt = (r: string[]) => r.map((c, i) => (i === 3 ? c.padStart(widths[i]) : i === 5 ? c : c.padEnd(widths[i]))).join(' ');
    const showHeader = withProc ? header : header.slice(0, 5);
    return ok([fmt(showHeader), ...rows.map((r) => fmt(withProc ? r : r.slice(0, 5)))].join('\n').replace(/ +$/gm, ''));
  },
};

function openSessionsOf(ctx: CmdCtx): string[][] {
  const rows: string[][] = [];
  for (const s of ctx.world.sessions ?? []) {
    if (s.serverHostId === ctx.host.id) rows.push(['ESTAB', '0', '0', hostPort(s.serverIp, s.serverPort), hostPort(s.clientIp, s.clientPort), `users:(("sshd",pid=${s.pid},fd=4))`]);
    if (s.clientHostId === ctx.host.id) rows.push(['ESTAB', '0', '0', hostPort(s.clientIp, s.clientPort), hostPort(s.serverIp, s.serverPort), `users:(("ssh",pid=${s.pid + 1},fd=3))`]);
  }
  return rows;
}

function rtt(ms: number): string {
  return Math.max(0.2, ms).toFixed(3);
}

/** -4 / -6 command-line flags → address family for resolve(). */
function familyFlag(flags: Map<string, string | true>, forced?: 4 | 6): 0 | 4 | 6 {
  if (forced) return forced;
  return flags.has('-6') ? 6 : flags.has('-4') ? 4 : 0;
}

/** Strip an IPv6 zone index ("fe80::1%eth0"); the simulator routes link-local traffic by its routing table. */
function stripZone(target: string): string {
  return target.includes(':') ? target.replace(/%.*$/, '') : target;
}

const ICMP6_ERROR_TEXT: Record<string, string> = {
  net: 'Destination unreachable: No route', host: 'Destination unreachable: Address unreachable', port: 'Destination unreachable: Port unreachable',
  admin: 'Destination unreachable: Administratively prohibited', ttl: 'Time exceeded: Hop limit',
};
const ICMP4_ERROR_TEXT: Record<string, string> = {
  net: 'Destination Net Unreachable', host: 'Destination Host Unreachable', port: 'Destination Port Unreachable', admin: 'Packet filtered', ttl: 'Time to live exceeded',
};

function makePing(name: string, forced?: 6): CommandDef {
  return {
    name,
    summary: forced ? 'send ICMPv6 echo requests (same as ping -6)' : 'send ICMP / ICMPv6 echo requests',
    usage: `${name} [-4|-6] [-c COUNT] [-W TIMEOUT] [-s SIZE] [-M do|dont|want] HOST`,
    run(args, ctx) {
      const { flags, rest } = parseFlags(args, ['-c', '-W', '-i', '-s', '-I', '-M']);
      const target = rest[0] ? stripZone(rest[0]) : undefined;
      if (!target) return err('ping: usage error: Destination address required', 2);
      const count = Math.min(Number(flags.get('-c') ?? 4), 10);
      const r = resolve(ctx.world, ctx.host, target, { family: familyFlag(flags, forced) });
      if (!r.ok) return err(`ping: ${target}: ${r.message}`, 2);
      const dst = r.ip;
      const v6 = dst.includes(':');
      const named = r.fqdn !== dst;
      const size = flags.has('-s') ? Number(flags.get('-s')) : 56;
      if (!Number.isInteger(size) || size < 0 || size > 65507) return err(`ping: invalid argument: '${flags.get('-s')}': out of range: 0 <= value <= 65507`, 2);
      const pmtudisc = (flags.get('-M') as string | undefined) ?? 'dont';
      if (!['do', 'dont', 'want', 'probe'].includes(pmtudisc)) return err(`ping: invalid -M argument: ${pmtudisc}`, 2);
      const df = pmtudisc === 'do' || pmtudisc === 'probe';
      const out = [v6 ? `PING ${named ? `${r.fqdn}(${r.fqdn} (${dst}))` : `${dst}(${dst})`} ${size} data bytes` : `PING ${named ? r.fqdn : dst} (${dst}) ${size}(${size + 28}) bytes of data.`];
      let received = 0;
      let errors = 0;
      const times: number[] = [];
      const icmpId = (ctx.world.counter % 60000) + 1;
      const src = sourceAddress(ctx.host, dst);
      const errText = v6 ? ICMP6_ERROR_TEXT : ICMP4_ERROR_TEXT;
      for (let seq = 1; seq <= count; seq++) {
        const start = ctx.world.clock;
        const req: Packet = { id: nextId(ctx.world), src, dst, ttl: 64, proto: 'icmp', icmp: { ...echoIcmp(v6, false, icmpId, seq), size }, df };
        const d = transmit(ctx.world, ctx.host.id, req);
        if (d.status === 'local-error') {
          if (seq === 1 && d.errno === 'ENETUNREACH') return err('ping: connect: Network is unreachable', 2);
          if (d.errno === 'EMSGSIZE') {
            out.push(v6 ? `ping: local error: message too long, mtu: ${d.mtu}` : `ping: local error: message too long, mtu=${d.mtu}`);
            errors++;
          }
          if (d.errno === 'EHOSTUNREACH') {
            out.push(`From ${src} icmp_seq=${seq} ${errText.host}`);
            errors++;
          } else if (d.errno === 'EPERM') out.push('ping: sendmsg: Operation not permitted');
        } else if (d.status === 'delivered') {
          const target = ctx.world.hosts[d.host];
          const rep: Packet = { id: nextId(ctx.world), src: d.final.dst, dst: d.final.src, ttl: 64, proto: 'icmp', icmp: { ...echoIcmp(v6, true, icmpId, seq), size }, df };
          const back = transmit(ctx.world, target.id, rep);
          if (back.status === 'delivered') {
            const hopsBack = back.hops.filter((h) => h.egress && h.ingress).length;
            const t = ctx.world.clock - start + 0.15;
            times.push(t);
            received++;
            out.push(`${size + 8} bytes from ${dst}: icmp_seq=${seq} ttl=${64 - hopsBack} time=${rtt(t)} ms`);
          }
        } else if (d.error?.delivered) {
          const e = d.error.packet;
          errors++;
          if (isFragNeeded(e)) out.push(v6 ? `From ${e.src} icmp_seq=${seq} Packet too big: mtu=${e.icmp!.mtu}` : `From ${e.src} icmp_seq=${seq} Frag needed and DF set (mtu = ${e.icmp!.mtu})`);
          else out.push(`From ${e.src} icmp_seq=${seq} ${errText[icmpMeaning(e)] ?? errText.host}`);
        }
        ctx.world.clock = Math.max(ctx.world.clock, start + 1000);
      }
      out.push('', `--- ${named ? r.fqdn : dst} ping statistics ---`);
      const loss = Math.round(((count - received) / count) * 100);
      out.push(`${count} packets transmitted, ${received} received${errors ? `, +${errors} errors` : ''}, ${loss}% packet loss, time ${(count - 1) * 1000 + 3}ms`);
      if (times.length) {
        const min = Math.min(...times), max = Math.max(...times), avg = times.reduce((a, b) => a + b, 0) / times.length;
        out.push(`rtt min/avg/max/mdev = ${rtt(min)}/${rtt(avg)}/${rtt(max)}/${rtt((max - min) / 2)} ms`);
      }
      return { out: out.join('\n'), code: received ? 0 : 1 };
    },
  };
}

const ping = makePing('ping');
const ping6 = makePing('ping6', 6);

function makeTraceroute(name: string, forced?: 6): CommandDef {
 return {
  name,
  summary: 'print the route packets take (UDP by default, -T for TCP SYN, -I for ICMP)',
  usage: `${name} [-4|-6] [-n] [-T] [-I] [-p PORT] [-m MAXHOPS] [-q PROBES] HOST`,
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-p', '-m', '-w', '-q']);
    const target = rest[0] ? stripZone(rest[0]) : undefined;
    if (!target) return err('Specify "host" missing argument.', 2);
    const r = resolve(ctx.world, ctx.host, target, { family: familyFlag(flags, forced) });
    if (!r.ok) return err(`${target}: ${r.message}\nCannot handle "host" cmdline arg \`${target}' on position 1 (argc 1)`, 2);
    const mode = flags.has('-T') ? 'tcp' : flags.has('-I') ? 'icmp' : 'udp';
    if (mode !== 'udp' && ctx.user.uid !== 0) return err('You do not have enough privileges to use this traceroute method.\nsocket: Operation not permitted', 1);
    const maxHops = Math.min(Number(flags.get('-m') ?? 30), 30);
    const probes = Math.max(1, Math.min(Number(flags.get('-q') ?? 3), 10));
    const dst = r.ip;
    const src = sourceAddress(ctx.host, dst);
    const out = [`traceroute to ${target} (${dst}), ${maxHops} hops max, 60 byte packets`];
    let port = mode === 'tcp' ? Number(flags.get('-p') ?? 80) : Number(flags.get('-p') ?? 33434);
    let silentRun = 0;
    for (let ttl = 1; ttl <= maxHops; ttl++) {
      const cells: string[] = [];
      let hopIp: string | null = null;
      let reached = false;
      for (let q = 0; q < probes; q++) {
        const start = ctx.world.clock;
        const probe: Packet = mode === 'tcp'
          ? { id: nextId(ctx.world), src, dst, ttl, proto: 'tcp', tcp: { sport: 40000 + ttl * 3 + q, dport: port, seq: 1000 + ttl, ack: 0, flags: ['SYN'], window: 5840, len: 0 } }
          : mode === 'icmp'
            ? { id: nextId(ctx.world), src, dst, ttl, proto: 'icmp', icmp: echoIcmp(dst.includes(':'), false, 4242, ttl * 3 + q) }
            : { id: nextId(ctx.world), src, dst, ttl, proto: 'udp', udp: { sport: 40000 + q, dport: port, len: 32 } };
        if (mode === 'udp') port++;
        const d = transmit(ctx.world, ctx.host.id, probe);
        let replyFrom: string | null = null;
        let mark = '';
        if (d.status === 'local-error') return err(`connect: ${ERRNO_TEXT[d.errno === 'EPERM' ? 'EPERM' : d.errno]}`, 1);
        if (d.status === 'delivered') {
          const h = ctx.world.hosts[d.host];
          // Destination: UDP -> port unreachable, TCP -> SYN-ACK/RST, ICMP -> echo reply
          const fin = d.final;
          let reply: Packet;
          const v6 = dst.includes(':');
          if (mode === 'udp') reply = { id: nextId(ctx.world), src: fin.dst, dst: fin.src, ttl: 64, proto: 'icmp', icmp: { type: v6 ? 1 : 3, code: v6 ? 4 : 3, description: 'Port unreachable', quoted: { proto: 'udp', src: fin.src, dst: fin.dst, sport: probe.udp!.sport, dport: probe.udp!.dport } } };
          else if (mode === 'icmp') reply = { id: nextId(ctx.world), src: fin.dst, dst: fin.src, ttl: 64, proto: 'icmp', icmp: echoIcmp(v6, true, 4242, ttl * 3 + q) };
          else reply = { id: nextId(ctx.world), src: fin.dst, dst: fin.src, ttl: 64, proto: 'tcp', tcp: { sport: port, dport: probe.tcp!.sport, seq: 0, ack: probe.tcp!.seq + 1, flags: allListeners(h).some((l) => l.port === port && l.proto === 'tcp') ? ['SYN', 'ACK'] : ['RST', 'ACK'], window: 0, len: 0 } };
          const back = transmit(ctx.world, h.id, reply);
          if (back.status === 'delivered') { replyFrom = dst; reached = true; }
        } else if (d.error?.delivered) {
          replyFrom = d.error.packet.src;
          const m = icmpMeaning(d.error.packet);
          if (m !== 'ttl') {
            reached = true;
            mark = m === 'admin' ? ' !X' : m === 'host' ? ' !H' : m === 'net' ? ' !N' : '';
          }
        } else if (d.status === 'rejected' && d.rst?.delivered) {
          replyFrom = dst;
          reached = true;
        }
        if (replyFrom) {
          const t = ctx.world.clock - start + 0.2;
          cells.push(`${hopIp === replyFrom ? '' : `${replyFrom} (${replyFrom})  `}${t.toFixed(3)} ms${mark}`);
          hopIp = replyFrom;
        } else {
          ctx.world.clock += 5000;
          cells.push('*');
        }
      }
      out.push(`${String(ttl).padStart(2)}  ${cells.join(' ').replace(/\* \* \*/, '* * *')}`);
      if (cells.every((c) => c === '*')) silentRun++;
      else silentRun = 0;
      if (reached) break;
      if (silentRun >= 6 && ttl < maxHops) {
        out.push(`    ... (the simulator stops after 6 silent hops; real traceroute continues to ${maxHops} hops printing "* * *")`);
        break;
      }
    }
    return ok(out.join('\n'));
  },
 };
}

const traceroute = makeTraceroute('traceroute');
const traceroute6 = makeTraceroute('traceroute6', 6);

const nc: CommandDef = {
  name: 'nc',
  summary: 'test a TCP connection (netcat -z)',
  usage: 'nc -zv [-w SECONDS] HOST PORT',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-w']);
    const [target, portStr] = rest;
    if (!target || !portStr) return err('usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n\t  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]\n\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n\t  [destination] [port]', 1);
    if (!flags.has('-z')) return err('nc: this simulator only supports port scanning mode (-z)', 1);
    const port = Number(portStr);
    const r = resolve(ctx.world, ctx.host, stripZone(target), { family: familyFlag(flags) });
    if (!r.ok) return err(`nc: getaddrinfo for host "${target}" port ${port}: ${r.message}`, 1);
    const timeoutMs = flags.has('-w') ? Number(flags.get('-w')) * 1000 : undefined;
    const svc = port === 22 ? 'ssh' : port === 80 ? 'http' : port === 443 ? 'https' : port === 53 ? 'domain' : '*';
    // OpenBSD netcat tries each address returned by getaddrinfo() in turn.
    const lines: string[] = [];
    for (const addr of r.addrs) {
      const c = tcpConnect(ctx.world, ctx.host, addr, port, { timeoutMs });
      if (c.ok) {
        c.conn.close('client');
        lines.push(`Connection to ${target} (${addr}) ${port} port [tcp/${svc}] succeeded!`);
        return ok(flags.has('-v') ? lines.join('\n') : '');
      }
      const reason = c.errno === 'ETIMEDOUT' && timeoutMs ? 'Connection timed out' : ERRNO_TEXT[c.errno];
      lines.push(`nc: connect to ${target} (${addr}) port ${port} (tcp) failed: ${reason}`);
    }
    return err(flags.has('-v') ? lines.join('\n') : '', 1);
  },
};

function bpfMatch(f: CapturedFrame, expr: string[]): boolean {
  if (expr.length === 0) return true;
  // Evaluate "a and b or not c" left-to-right with and/or precedence (no parentheses).
  const orParts: string[][] = [[]];
  for (const t of expr) {
    if (t === 'or' || t === '||') orParts.push([]);
    else orParts[orParts.length - 1].push(t);
  }
  return orParts.some((part) => {
    const terms: string[][] = [[]];
    for (const t of part) {
      if (t === 'and' || t === '&&') terms.push([]);
      else terms[terms.length - 1].push(t);
    }
    return terms.every((term) => {
      let neg = false;
      let t = term;
      if (t[0] === 'not' || t[0] === '!') { neg = true; t = t.slice(1); }
      const res = primitive(f, t);
      return neg ? !res : res;
    });
  });
}

function primitive(f: CapturedFrame, t: string[]): boolean {
  const p = f.ip;
  const v6 = !!p && p.src.includes(':');
  const ports = p ? [p.tcp?.sport ?? p.udp?.sport, p.tcp?.dport ?? p.udp?.dport] : [];
  const [a, b, c] = t;
  const addr = (x: string | undefined) => (x ? normAddr(x) : x);
  switch (a) {
    case undefined: return true;
    case 'arp': return !!f.arp;
    case 'ip': return !!p && !v6;
    case 'ip6': return v6;
    case 'tcp': return p?.proto === 'tcp';
    case 'udp': return p?.proto === 'udp';
    case 'icmp': return p?.proto === 'icmp' && !v6;
    case 'icmp6': return p?.proto === 'icmp' && v6;
    case 'vlan': return f.vlan !== undefined && (b === undefined || f.vlan === Number(b));
    case 'host': return p ? p.src === addr(b) || p.dst === addr(b) : !!f.arp && (f.arp.senderIp === b || f.arp.targetIp === b);
    case 'port': return ports.includes(Number(b));
    case 'src':
      if (b === 'port') return ports[0] === Number(c);
      if (b === 'host') return p?.src === addr(c);
      return p?.src === addr(b);
    case 'dst':
      if (b === 'port') return ports[1] === Number(c);
      if (b === 'host') return p?.dst === addr(c);
      return p?.dst === addr(b);
    case 'net':
      return !!p && !!b && validPrefix(b) && [p.src, p.dst].some((x) => inPrefix(x, b));
    default: return false;
  }
}

const tcpdump: CommandDef = {
  name: 'tcpdump',
  summary: 'show captured packets on an interface',
  usage: 'tcpdump -i IFACE [-n] [-e] [-c COUNT] [expression]',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('tcpdump: eth0: You don\'t have permission to perform this capture on that device\n(socket: Operation not permitted)', 1);
    const { flags, rest } = parseFlags(args, ['-i', '-c', '-w', '-s']);
    const iface = (flags.get('-i') as string) ?? ctx.host.ifaces.find((i) => i.name !== 'lo')?.name ?? 'eth0';
    if (iface !== 'any' && !ctx.host.ifaces.some((i) => i.name === iface)) return err(`tcpdump: ${iface}: No such device exists\n(No such device exists)`, 1);
    const count = flags.has('-c') ? Number(flags.get('-c')) : 40;
    const frames = ctx.host.capture.filter((f) => (iface === 'any' || f.iface === iface) && bpfMatch(f, rest));
    const shown = frames.slice(-count);
    const isnByFlow = new Map<string, number>();
    for (const f of ctx.host.capture) {
      const t = f.ip?.tcp;
      if (t && t.flags.includes('SYN')) isnByFlow.set(`${f.ip!.src}:${t.sport}>${f.ip!.dst}:${t.dport}`, t.seq);
    }
    const lines = shown.map((f) => {
      let isn: { a: number; b: number } | undefined;
      const t = f.ip?.tcp;
      if (t && !flags.has('-S')) {
        const a = isnByFlow.get(`${f.ip!.src}:${t.sport}>${f.ip!.dst}:${t.dport}`);
        const b = isnByFlow.get(`${f.ip!.dst}:${t.dport}>${f.ip!.src}:${t.sport}`);
        if (a !== undefined && b !== undefined) isn = { a, b };
      }
      return formatFrame(f, { isn, ether: flags.has('-e') });
    });
    const head = [
      'tcpdump: verbose output suppressed, use -v[v]... for full protocol decode',
      `listening on ${iface}, link-type EN10MB (Ethernet), snapshot length 262144 bytes`,
      `[Infrastructure Lab: showing the last ${shown.length} matching frame(s) captured on ${iface} by the simulator. Real tcpdump only shows traffic that occurs while it runs; run your test (ssh, ping, dig) first, then tcpdump.]`,
    ];
    return ok([...head, ...lines, '', `${shown.length} packets captured`, `${shown.length} packets received by filter`, '0 packets dropped by kernel'].join('\n'));
  },
};

const conntrack: CommandDef = {
  name: 'conntrack',
  summary: 'list connection tracking entries',
  usage: 'conntrack -L',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('conntrack v1.4.7 (conntrack-tools): Operation failed: Operation not permitted', 1);
    if (args.includes('-F')) {
      ctx.host.conntrack = [];
      ctx.host.nat = [];
      return ok('conntrack v1.4.7 (conntrack-tools): connection tracking table has been emptied.');
    }
    // One line per flow. For translated flows the reply tuple shows the
    // translated addresses, as in real conntrack output.
    const same = (t: { src: string; sport: number; dst: string; dport: number }, e: { src: string; sport: number; dst: string; dport: number }) =>
      t.src === e.src && t.sport === e.sport && t.dst === e.dst && t.dport === e.dport;
    const used = new Set<object>();
    const proto = (p: string) => `${p.padEnd(4)} ${p === 'tcp' ? 6 : p === 'udp' ? 17 : 1} 117`;
    // ICMP flows are keyed by echo id (stored in the port fields), shown as type/code/id.
    const tuple = (p: string, t: { src: string; sport: number; dst: string; dport: number }, reply: boolean) =>
      p === 'icmp' ? `src=${t.src} dst=${t.dst} type=${reply ? 0 : 8} code=0 id=${t.sport}` : `src=${t.src} dst=${t.dst} sport=${t.sport} dport=${t.dport}`;
    const lines = ctx.host.conntrack.map((e) => {
      const st = e.proto === 'tcp' ? `${e.state === 'UNREPLIED' ? 'SYN_SENT' : e.state} ` : '';
      const n = ctx.host.nat.find((x) => x.proto === e.proto && (same(x.orig, e) || same(x.trans, e)));
      const o = n ? n.orig : e;
      const r = n ? { src: n.trans.dst, dst: n.trans.src, sport: n.trans.dport, dport: n.trans.sport } : { src: e.dst, dst: e.src, sport: e.dport, dport: e.sport };
      if (n) used.add(n);
      return `${proto(e.proto)} ${st}${tuple(e.proto, o, false)} ${e.state === 'UNREPLIED' ? '[UNREPLIED] ' : ''}${tuple(e.proto, r, true)} ${e.state === 'UNREPLIED' ? '' : '[ASSURED] '}mark=0 use=1${n ? `   # NAT: ${n.kind}` : ''}`;
    });
    for (const n of ctx.host.nat) {
      if (used.has(n)) continue;
      lines.push(`${proto(n.proto)} ${n.proto === 'tcp' ? 'ESTABLISHED ' : ''}${tuple(n.proto, n.orig, false)} ${tuple(n.proto, { src: n.trans.dst, dst: n.trans.src, sport: n.trans.dport, dport: n.trans.sport }, true)} [ASSURED] mark=0 use=1   # NAT: ${n.kind}`);
    }
    return ok([...lines, `conntrack v1.4.7 (conntrack-tools): ${lines.length} flow entries have been shown.`].join('\n'));
  },
};

/** Kernel parameters the simulator models, with getters/setters on the host. */
const SYSCTL_KEYS: Record<string, { get: (h: CmdCtx['host']) => boolean; set: (h: CmdCtx['host'], v: boolean) => void }> = {
  'net.ipv4.ip_forward': { get: (h) => h.ipForward, set: (h, v) => { h.ipForward = v; } },
  'net.ipv6.conf.all.forwarding': { get: (h) => !!h.ip6Forward, set: (h, v) => { h.ip6Forward = v; } },
};
const SYSCTL_RE = /^\s*(net\.ipv4\.ip_forward|net\.ipv6\.conf\.all\.forwarding)\s*=\s*([01])\s*$/gm;

const sysctl: CommandDef = {
  name: 'sysctl',
  summary: 'read or set kernel parameters (net.ipv4.ip_forward, net.ipv6.conf.all.forwarding)',
  usage: 'sysctl KEY | sysctl -w KEY=VALUE | sysctl --system | sysctl -p [FILE]',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const kv = rest[0] ?? '';
    if (flags.has('--system') || flags.has('-p')) {
      if (ctx.user.uid !== 0) return err('sysctl: permission denied on key "net.ipv4.ip_forward"', 1);
      // Same sources as boot (see bootHost); only the forwarding switches are modelled.
      const files = flags.has('-p')
        ? [rest[0] ? normalizePath(rest[0], ctx.frame.cwd, ctx.user.home) : '/etc/sysctl.conf']
        : Object.keys(ctx.host.fs).filter((p) => p === '/etc/sysctl.conf' || p.startsWith('/etc/sysctl.d/')).sort();
      const out: string[] = [];
      for (const f of files) {
        const node = ctx.host.fs[f];
        if (!node && flags.has('-p')) return err(`sysctl: cannot open "${f}": No such file or directory`, 255);
        if (!node || node.type !== 'file') continue;
        out.push(`* Applying ${f} ...`);
        for (const m of node.content.matchAll(SYSCTL_RE)) {
          SYSCTL_KEYS[m[1]].set(ctx.host, m[2] === '1');
          out.push(`${m[1]} = ${m[2]}`);
        }
      }
      return ok(out.join('\n'));
    }
    if (kv.includes('=') || flags.has('-w')) {
      if (ctx.user.uid !== 0) return err(`sysctl: permission denied on key "${kv.split('=')[0]}"`, 1);
      const [k, v] = kv.split('=');
      const key = SYSCTL_KEYS[k.trim()];
      if (!key) return err(`sysctl: cannot stat /proc/sys/${k.replace(/\./g, '/')}: No such file or directory (not modelled)`, 255);
      key.set(ctx.host, v.trim() === '1');
      return ok(`${k.trim()} = ${v.trim()}`);
    }
    if (SYSCTL_KEYS[kv]) return ok(`${kv} = ${SYSCTL_KEYS[kv].get(ctx.host) ? 1 : 0}`);
    if (kv === 'net.ipv4.tcp_syn_retries') return ok('net.ipv4.tcp_syn_retries = 6');
    return err(`sysctl: cannot stat /proc/sys/${kv.replace(/\./g, '/')}: No such file or directory (modelled: ${Object.keys(SYSCTL_KEYS).join(', ')}, net.ipv4.tcp_syn_retries)`, 255);
  },
};

const hostname: CommandDef = {
  name: 'hostname',
  summary: 'show the system host name / addresses',
  usage: 'hostname [-f | -I]',
  run(args, ctx) {
    if (args.includes('-I')) return ok(hostAddresses(ctx.host).filter((a) => !a.startsWith('127.')).join(' ') + ' ');
    if (args.includes('-f')) return ok(`${ctx.host.hostname}.${ctx.host.domain}`);
    return ok(ctx.host.hostname);
  },
};

const uname: CommandDef = {
  name: 'uname',
  summary: 'print system information',
  usage: 'uname [-a]',
  run: (args, ctx) => ok(args.includes('-a') ? `Linux ${ctx.host.hostname} 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux` : 'Linux'),
};

const date: CommandDef = {
  name: 'date',
  summary: 'print the simulated date and time',
  usage: 'date',
  run: (_a, ctx) => ok(new Date(Math.floor(ctx.world.clock)).toUTCString().replace('GMT', 'UTC')),
};

const sleep: CommandDef = {
  name: 'sleep',
  summary: 'let simulated time pass (timers such as DHCP renewals run meanwhile)',
  usage: 'sleep SECONDS[s|m|h]  (at most 2h in the simulator)',
  run(args, ctx) {
    const m = /^(\d+(?:\.\d+)?)([smh]?)$/.exec(args[0] ?? '');
    if (!m) return err(args[0] ? `sleep: invalid time interval '${args[0]}'\nTry 'sleep --help' for more information.` : "sleep: missing operand\nTry 'sleep --help' for more information.", 1);
    const ms = Number(m[1]) * ({ s: 1000, m: 60_000, h: 3_600_000 }[m[2] || 's'] as number);
    ctx.world.clock += Math.min(ms, 7_200_000);
    maintainLeases(ctx.world, true);
    return ok('');
  },
};

// ---------------------------------------------------------------------------
// DNS tools
// ---------------------------------------------------------------------------

const dig: CommandDef = {
  name: 'dig',
  summary: 'DNS lookup utility (queries a server directly; ignores /etc/hosts and search domains)',
  usage: 'dig [@SERVER] NAME [A|AAAA] [+short]',
  run(args, ctx) {
    const server = args.find((a) => a.startsWith('@'))?.slice(1);
    const short = args.includes('+short');
    const search = args.includes('+search');
    const qtype: 'A' | 'AAAA' = args.some((a) => a.toUpperCase() === 'AAAA') ? 'AAAA' : 'A';
    const names = args.filter((a) => !a.startsWith('@') && !a.startsWith('+') && !['A', 'AAAA', 'IN'].includes(a.toUpperCase()));
    const name = names[0] ?? '.';
    const rc = parseResolvConf(readFile(ctx.host, '/etc/resolv.conf'));
    const ns = server ?? rc.nameservers[0] ?? '127.0.0.1';
    let qname = name.endsWith('.') ? name : name + '.';
    if (search && !name.includes('.') && rc.search[0]) qname = `${name}.${rc.search[0]}.`;
    const out: string[] = [];
    if (!short) out.push('', `; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> ${args.join(' ')}`, ';; global options: +cmd');
    let ex = dnsQuery(ctx.world, ctx.host, ns, qname, 5, qtype);
    for (let i = 1; i < 3 && ex.outcome === 'timeout'; i++) {
      if (!short) out.push(`;; communications error to ${ns}#53: timed out`);
      ex = dnsQuery(ctx.world, ctx.host, ns, qname, 5, qtype);
    }
    if (ex.outcome === 'timeout' || ex.outcome === 'port-unreachable' || ex.outcome === 'unreachable') {
      const why = ex.outcome === 'timeout' ? 'timed out' : ex.outcome === 'port-unreachable' ? 'connection refused' : 'host unreachable';
      out.push(`;; communications error to ${ns}#53: ${why}`);
      if (ex.outcome !== 'timeout') out.push(`;; communications error to ${ns}#53: ${why}`, `;; communications error to ${ns}#53: ${why}`);
      if (!short) out.push('', `; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> ${args.join(' ')}`, ';; global options: +cmd');
      out.push(';; no servers could be reached');
      return err(out.join('\n'), 9);
    }
    const a = ex.answer!;
    if (short) return ok(a.answers.map((r) => r.data.replace(/\.$/, r.type === 'CNAME' ? '.' : '')).join('\n'));
    const id = (ctx.world.counter * 31) & 0xffff;
    const flagsTxt = `qr ${a.authoritative ? 'aa ' : ''}rd`;
    out.push(';; Got answer:', `;; ->>HEADER<<- opcode: QUERY, status: ${a.rcode}, id: ${id}`, `;; flags: ${flagsTxt}; QUERY: 1, ANSWER: ${a.answers.length}, AUTHORITY: ${a.rcode === 'NXDOMAIN' ? 1 : 0}, ADDITIONAL: 0`);
    out.push(';; WARNING: recursion requested but not available', '', ';; QUESTION SECTION:', `;${qname}\t\t\tIN\t${qtype}`);
    if (a.answers.length) {
      out.push('', ';; ANSWER SECTION:');
      for (const r of a.answers) out.push(`${r.name}\t\t${r.ttl}\tIN\t${r.type}\t${r.data}`);
    }
    if (a.rcode === 'NXDOMAIN' && 'soa' in a && a.soa) {
      out.push('', ';; AUTHORITY SECTION:', `${a.soa.name}\t\t${a.soa.ttl}\tIN\tSOA\t${a.soa.data}`);
    }
    out.push('', `;; Query time: ${Math.round(ex.rttMs)} msec`, `;; SERVER: ${ns}#53(${ns}) (UDP)`, `;; WHEN: ${new Date(Math.floor(ctx.world.clock)).toUTCString().replace('GMT', 'UTC')}`, `;; MSG SIZE  rcvd: ${40 + a.answers.length * 16}`, '');
    return ok(out.join('\n'));
  },
};

const nslookup: CommandDef = {
  name: 'nslookup',
  summary: 'query DNS (applies the resolv.conf search list)',
  usage: 'nslookup NAME [SERVER]',
  run(args, ctx) {
    const [name, server] = args;
    if (!name) return err('nslookup: interactive mode is not supported in this simulator', 1);
    const rc = parseResolvConf(readFile(ctx.host, '/etc/resolv.conf'));
    const ns = server ?? rc.nameservers[0] ?? '127.0.0.1';
    const candidates = name.endsWith('.') ? [name] : name.includes('.') ? [name + '.', ...rc.search.map((s) => `${name}.${s}.`)] : [...rc.search.map((s) => `${name}.${s}.`), name + '.'];
    let last = '';
    for (const q of candidates) {
      const ex = dnsQuery(ctx.world, ctx.host, ns, q, 5);
      if (ex.outcome === 'timeout' || ex.outcome === 'port-unreachable' || ex.outcome === 'unreachable') {
        return err(`;; communications error to ${ns}#53: ${ex.outcome === 'timeout' ? 'timed out' : 'connection refused'}\n;; communications error to ${ns}#53: ${ex.outcome === 'timeout' ? 'timed out' : 'connection refused'}\n;; no servers could be reached\n`, 1);
      }
      if (ex.outcome === 'answer') {
        const a = ex.answer!.answers;
        const out = [`Server:\t\t${ns}`, `Address:\t${ns}#53`, ''];
        for (const r of a) {
          if (r.type === 'CNAME') out.push(`${r.name.replace(/\.$/, '')}\tcanonical name = ${r.data}`);
          else out.push(`Name:\t${r.name.replace(/\.$/, '')}`, `Address: ${r.data}`);
        }
        return ok(out.join('\n') + '\n');
      }
      last = ex.outcome === 'refused' ? 'REFUSED' : ex.outcome === 'servfail' ? 'SERVFAIL' : 'NXDOMAIN';
      if (last === 'SERVFAIL') break;
    }
    return err(`Server:\t\t${ns}\nAddress:\t${ns}#53\n\n** server can't find ${name}: ${last}\n`, 1);
  },
};

const hostCmd: CommandDef = {
  name: 'host',
  summary: 'simple DNS lookup',
  usage: 'host NAME [SERVER]',
  run(args, ctx) {
    const r = nslookup.run(args, ctx);
    const name = args[0];
    const m = /Address: (\d+\.\d+\.\d+\.\d+)/.exec(r.out);
    if (m) return ok(`${/Name:\t(\S+)/.exec(r.out)?.[1] ?? name} has address ${m[1]}`);
    if (/no servers could be reached/.test(r.out)) return err(`;; connection timed out; no servers could be reached`, 1);
    const code = /: (\w+)\n$/.exec(r.out)?.[1] ?? 'NXDOMAIN';
    return err(`Host ${name} not found: ${code === 'NXDOMAIN' ? '3(NXDOMAIN)' : code === 'REFUSED' ? '5(REFUSED)' : '2(SERVFAIL)'}`, 1);
  },
};

const getent: CommandDef = {
  name: 'getent',
  summary: 'query NSS databases: hosts (files then DNS, like ssh does), passwd, group',
  usage: 'getent hosts NAME | getent ahosts|ahostsv4|ahostsv6 NAME | getent passwd [USER] | getent group [GROUP]',
  run(args, ctx) {
    const [db, key] = args;
    // Simplification: "hosts" uses the same getaddrinfo() selection as applications
    // (glibc's getent hosts actually asks for AF_INET6 first).
    if (db === 'hosts' || db === 'ahosts' || db === 'ahostsv4' || db === 'ahostsv6') {
      if (!key) return err('', 2);
      const r = resolve(ctx.world, ctx.host, key, { family: db === 'ahostsv4' ? 4 : db === 'ahostsv6' ? 6 : 0 });
      if (!r.ok) return err('', 2);
      const name = r.source === 'hosts' ? key : r.fqdn;
      if (db === 'hosts') return ok(`${r.ip.padEnd(15)} ${name}`);
      return ok(r.addrs.flatMap((a, i) => [`${a.padEnd(15)} STREAM ${i === 0 ? name : ''}`, `${a.padEnd(15)} DGRAM  `, `${a.padEnd(15)} RAW    `]).join('\n'));
    }
    if (db === 'passwd' || db === 'group') {
      const lines = virtualFile(ctx.host, db === 'passwd' ? '/etc/passwd' : '/etc/group')!.split('\n').filter((l) => l && (!key || l.startsWith(key + ':')));
      return { out: lines.join('\n'), code: lines.length ? 0 : 2 };
    }
    return err(`Unknown database: ${db}`, 1);
  },
};

// tracepath: UDP probes with increasing TTL, like traceroute, but needs no
// privileges and also reports the path MTU (always 1500 in the lab: no
// links with a smaller MTU are modelled).
const tracepath: CommandDef = {
  name: 'tracepath',
  summary: 'trace the path to a host, discovering the MTU (no root needed)',
  usage: 'tracepath [-4|-6] [-n] [-m MAXHOPS] HOST',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-m', '-p', '-l']);
    if (!rest[0]) return err('Usage\n  tracepath [options] <destination>', 255);
    const fam = flags.has('-6') ? ['-6'] : flags.has('-4') ? ['-4'] : [];
    const r = traceroute.run([...fam, '-q', '1', '-m', String(flags.get('-m') ?? 30), rest[0]], ctx);
    if (r.code !== 0) {
      const msg = r.out.split('\n')[0];
      return err(`${rest[0]}: ${/Name or service not known|Temporary failure/.test(msg) ? msg.split(': ').slice(1).join(': ') : msg}`, 1);
    }
    // Path MTU discovery: send full-size UDP probes with DF set; each "fragmentation needed"
    // lowers the probe size. Routers that report a smaller MTU are annotated on their hop line.
    const target = /\(([^)]+)\)/.exec(r.out.split('\n')[0])?.[1] ?? rest[0];
    const startMtu = pathMtu(ctx.host, target);
    let pmtu = startMtu;
    const pmtuAt: Record<string, number> = {};
    for (let i = 0; i < 5; i++) {
      const v6 = target.includes(':');
      const probe: Packet = { id: nextId(ctx.world), src: sourceAddress(ctx.host, target), dst: target, ttl: 64, proto: 'udp', udp: { sport: 44444, dport: 44444, len: pmtu - (v6 ? 48 : 28) }, df: true };
      const d = transmit(ctx.world, ctx.host.id, probe);
      const e = d.status === 'local-error' && d.errno === 'EMSGSIZE' ? null : d.error?.delivered && isFragNeeded(d.error.packet) ? d.error.packet : null;
      if (d.status === 'local-error' && d.errno === 'EMSGSIZE' && d.mtu && d.mtu < pmtu) { pmtu = d.mtu; continue; }
      if (!e || e.icmp!.mtu! >= pmtu) break;
      pmtu = e.icmp!.mtu!;
      pmtuAt[e.src] = pmtu;
    }
    const out = [` 1?: [LOCALHOST]                      pmtu ${startMtu}`];
    let hops = 0;
    let reached = false;
    for (const line of r.out.split('\n').slice(1)) {
      const m = /^\s*(\d+)\s+(.*)$/.exec(line);
      if (!m) {
        if (line.trim().startsWith('...')) out.push(line.replace('traceroute', 'tracepath').replace('printing "* * *"', 'printing "no reply"'));
        continue;
      }
      const ttl = Number(m[1]);
      const cell = m[2].trim();
      if (cell.startsWith('*')) { out.push(`${String(ttl).padStart(2)}:  no reply`); continue; }
      const hm = /^(\S+) \(\S+\)\s+([\d.]+) ms( !\w)?/.exec(cell);
      if (!hm) continue;
      hops = ttl;
      const last = r.out.trim().endsWith(line.trim()) && !hm[3];
      const err = hm[3] ? ` ${hm[3].trim() === '!H' ? '!H' : hm[3].trim() === '!N' ? '!N' : '!A'}` : '';
      if (pmtuAt[hm[1]]) out.push(`${String(ttl).padStart(2)}:  ${hm[1].padEnd(48)} ${(Number(hm[2]) - 0.05).toFixed(3)}ms pmtu ${pmtuAt[hm[1]]}`);
      out.push(`${String(ttl).padStart(2)}:  ${hm[1].padEnd(48)} ${(Number(hm[2]) - 0.05).toFixed(3)}ms ${last ? 'reached' : err.trim()}`.trimEnd());
      if (last) reached = true;
    }
    out.push(reached ? `     Resume: pmtu ${pmtu} hops ${hops} back ${hops} ` : `     Too many hops: pmtu ${pmtu}\n     Resume: pmtu ${pmtu} `);
    return ok(out.join('\n'));
  },
};

// ethtool: link settings of a NIC. Lab NICs are emulated Intel 82540EM (e1000).
const ethtool: CommandDef = {
  name: 'ethtool',
  summary: 'show NIC link settings (speed, duplex, link detected) or driver (-i)',
  usage: 'ethtool IFACE | ethtool -i IFACE',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const name = rest[0];
    if (!name) return err('ethtool: bad command line argument(s)\nFor more information run ethtool -h', 1);
    const i = ctx.host.ifaces.find((x) => x.name === name);
    if (!i) return err(`netlink error: no device matches name (offset 24)\nnetlink error: No such device`, 1);
    if (flags.has('-i')) {
      if (i.name === 'lo') return err('Cannot get driver information: Operation not supported', 71);
      if (i.vlan) return ok('driver: 802.1Q VLAN Support\nversion: 1.8\nfirmware-version: N/A\nexpansion-rom-version: \nbus-info: \nsupports-statistics: no\nsupports-test: no\nsupports-eeprom-access: no\nsupports-register-dump: no\nsupports-priv-flags: no');
      return ok('driver: e1000\nversion: 6.1.0-28-amd64\nfirmware-version: \nexpansion-rom-version: \nbus-info: 0000:00:03.0\nsupports-statistics: yes\nsupports-test: yes\nsupports-eeprom-access: yes\nsupports-register-dump: yes\nsupports-priv-flags: no');
    }
    const link = hasCarrier(ctx.world, ctx.host, i);
    if (i.name === 'lo' || i.vlan) return ok(`Settings for ${i.name}:\n\tLink detected: ${link ? 'yes' : 'no'}`);
    const lines = [
      `Settings for ${i.name}:`,
      '\tSupported ports: [ TP ]',
      '\tSupported link modes:   10baseT/Half 10baseT/Full',
      '\t                        100baseT/Half 100baseT/Full',
      '\t                        1000baseT/Full',
      '\tSupported pause frame use: No',
      '\tSupports auto-negotiation: Yes',
      '\tSupported FEC modes: Not reported',
      '\tAdvertised link modes:  10baseT/Half 10baseT/Full',
      '\t                        100baseT/Half 100baseT/Full',
      '\t                        1000baseT/Full',
      '\tAdvertised pause frame use: No',
      '\tAdvertised auto-negotiation: Yes',
      '\tAdvertised FEC modes: Not reported',
      `\tSpeed: ${link ? '1000Mb/s' : 'Unknown!'}`,
      `\tDuplex: ${link ? 'Full' : 'Unknown! (255)'}`,
      '\tAuto-negotiation: on',
      '\tPort: Twisted Pair',
      '\tPHYAD: 0',
      '\tTransceiver: internal',
      '\tMDI-X: off (auto)',
    ];
    if (ctx.user.uid === 0) lines.push('\tSupports Wake-on: umbg', '\tWake-on: d', '\tCurrent message level: 0x00000007 (7)', '\t\t\t       drv probe link');
    else lines.push('netlink error: Operation not permitted');
    lines.push(`\tLink detected: ${link ? 'yes' : 'no'}`);
    return ok(lines.join('\n'));
  },
};

export const NET_COMMANDS: CommandDef[] = [ip, bridge, ifreload, rdisc6, ss, ping, ping6, traceroute, traceroute6, tracepath, ethtool, nc, tcpdump, conntrack, sysctl, hostname, uname, date, sleep, dig, nslookup, hostCmd, getent];
export { isoTime, lookupHostsFile };
