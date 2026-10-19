// Network diagnostics: ip, ss, ping, traceroute, nc, curl, tcpdump, conntrack,
// sysctl, hostname, uname, date, dig, nslookup, host, getent.

import { parseCidr, broadcastOf, parseIp } from '../net/ip';
import { dnsQuery, lookupHostsFile, resolve } from '../sim/dns';
import { isoTime } from '../sim/journal';
import { hostAddresses, lookupRoute, nextId, routeTable, sourceAddress, transmit } from '../sim/network';
import { allListeners } from '../sim/services';
import { ERRNO_TEXT, tcpConnect } from '../sim/tcp';
import type { CapturedFrame, Packet, Route } from '../types';
import { parseResolvConf } from '../config/netconf';
import { readFile } from '../fs';
import { formatFrame } from './format';
import { virtualFile } from './cmdFiles';
import { type CmdCtx, type CommandDef, err, ok, parseFlags } from './types';

const needRoot = (ctx: CmdCtx, what: string) => (ctx.user.uid !== 0 ? err(what, 2) : null);

function renderRoute(r: Route): string {
  if (r.dest === 'default') return `default via ${r.via} dev ${r.dev} onlink `;
  if (r.proto === 'kernel') return `${r.dest} dev ${r.dev} proto kernel scope link src ${r.src} `;
  return `${r.dest}${r.via ? ` via ${r.via}` : ''} dev ${r.dev} ${r.proto === 'static' ? 'proto static ' : ''}`;
}

const ip: CommandDef = {
  name: 'ip',
  summary: 'show / manipulate routing, devices and neighbours (iproute2)',
  usage: 'ip addr [add|del ADDR/PREFIX dev DEV] | ip route [get ADDR | add PREFIX via GW | del PREFIX] | ip neigh | ip link set DEV up|down',
  run(args, ctx) {
    const [objRaw, ...rest] = args.filter((a) => a !== '-br' && a !== '-4');
    const obj = objRaw ?? 'help';
    const host = ctx.host;
    if ('address'.startsWith(obj) && obj.length >= 1 && obj[0] === 'a' && (rest[0] === 'add' || rest[0] === 'del' || rest[0] === 'flush')) {
      const deny = needRoot(ctx, 'RTNETLINK answers: Operation not permitted');
      if (deny) return deny;
      const dev = rest.indexOf('dev') >= 0 ? rest[rest.indexOf('dev') + 1] : undefined;
      const iface = host.ifaces.find((i) => i.name === dev);
      if (!iface) return err(`Cannot find device "${dev ?? ''}"`, 1);
      if (rest[0] === 'flush') {
        iface.address = null;
        iface.prefix = null;
        host.routes = host.routes.filter((r) => r.dev !== iface.name);
        return ok('');
      }
      const c = parseCidr(rest[1] ?? '');
      if (!c || !rest[1].includes('/')) return err(`Error: any valid prefix is expected rather than "${rest[1] ?? ''}".`, 1);
      const addr = rest[1].split('/')[0];
      if (rest[0] === 'add') {
        if (iface.address) return err('RTNETLINK answers: File exists (this simulator models one IPv4 address per interface: delete the old one first)', 2);
        iface.address = addr;
        iface.prefix = c.prefix;
        return ok('');
      }
      if (iface.address !== addr) return err('RTNETLINK answers: Cannot assign requested address', 2);
      iface.address = null;
      iface.prefix = null;
      host.routes = host.routes.filter((r) => r.dev !== iface.name || !r.via);
      return ok('');
    }
    if ('address'.startsWith(obj) && obj.length >= 1 && obj[0] === 'a') {
      const out: string[] = [];
      host.ifaces.forEach((i, idx) => {
        const lo = i.name === 'lo';
        const flags = lo ? 'LOOPBACK,UP,LOWER_UP' : i.up ? 'BROADCAST,MULTICAST,UP,LOWER_UP' : 'BROADCAST,MULTICAST';
        out.push(`${idx + 1}: ${i.name}: <${flags}> mtu ${lo ? 65536 : 1500} qdisc ${lo ? 'noqueue' : 'fq_codel'} state ${lo ? 'UNKNOWN' : i.up ? 'UP' : 'DOWN'} group default qlen 1000`);
        out.push(`    link/${lo ? 'loopback' : 'ether'} ${i.mac} brd ${lo ? '00:00:00:00:00:00' : 'ff:ff:ff:ff:ff:ff'}`);
        if (!lo) out.push(`    altname enp${idx}s0`);
        if (i.address && (i.up || lo)) {
          out.push(`    inet ${i.address}/${i.prefix}${lo ? '' : ` brd ${broadcastOf(i.address, i.prefix!)}`} scope ${lo ? 'host' : 'global'} ${i.name}`);
          out.push('       valid_lft forever preferred_lft forever');
        }
      });
      return ok(out.join('\n'));
    }
    if (obj === 'r' || 'route'.startsWith(obj) && obj[0] === 'r') {
      const sub = rest[0] ?? 'show';
      if (sub === 'show' || sub === 'list' || sub === 'ls') return ok(routeTable(host).map(renderRoute).join('\n'));
      if (sub === 'get') {
        const dst = rest[1];
        if (!dst || parseIp(dst) === null) return err('Error: any valid prefix is expected rather than "' + (dst ?? '') + '".');
        if (hostAddresses(host).includes(dst) || dst.startsWith('127.')) return ok(`local ${dst} dev lo src ${dst.startsWith('127.') ? '127.0.0.1' : dst} uid ${ctx.user.uid} \n    cache <local> `);
        const rd = lookupRoute(host, dst);
        if (!rd) return err('RTNETLINK answers: Network is unreachable', 2);
        return ok(`${dst} ${rd.route.via ? `via ${rd.route.via} ` : ''}dev ${rd.dev} src ${rd.src} uid ${ctx.user.uid} \n    cache `);
      }
      if (sub === 'add' || sub === 'del' || sub === 'delete' || sub === 'replace') {
        const deny = needRoot(ctx, 'RTNETLINK answers: Operation not permitted');
        if (deny) return deny;
        const prefix = rest[1];
        const via = rest.indexOf('via') >= 0 ? rest[rest.indexOf('via') + 1] : undefined;
        let dev = rest.indexOf('dev') >= 0 ? rest[rest.indexOf('dev') + 1] : undefined;
        if (!prefix || (prefix !== 'default' && !parseCidr(prefix))) return err(`Error: any valid prefix is expected rather than "${prefix ?? ''}".`);
        const dest = prefix === 'default' || prefix === '0.0.0.0/0' ? 'default' : prefix.includes('/') ? prefix : `${prefix}/32`;
        if (sub === 'del' || sub === 'delete') {
          const idx = host.routes.findIndex((r) => r.dest === dest && (!via || r.via === via));
          if (idx < 0) return err('RTNETLINK answers: No such process', 2);
          host.routes.splice(idx, 1);
          return ok('');
        }
        if (via) {
          const onlink = host.ifaces.find((i) => i.up && i.address && i.prefix !== null && parseCidr(`${i.address}/${i.prefix}`) && parseCidr(`${i.address}/${i.prefix}`)!.network === (parseCidr(`${via}/${i.prefix}`)!.network));
          if (!onlink) return err('Error: Nexthop has invalid gateway.', 2);
          dev = dev ?? onlink.name;
        }
        if (!dev) return err('Error: Device for nexthop is not up.', 2);
        if (sub === 'add' && host.routes.some((r) => r.dest === dest)) return err('RTNETLINK answers: File exists', 2);
        host.routes = host.routes.filter((r) => r.dest !== dest);
        host.routes.push({ dest, via, dev, proto: 'static' });
        return ok('');
      }
      return err(`Command "${sub}" is unknown, try "ip route help".`, 255);
    }
    if (obj === 'n' || obj === 'neigh' || obj === 'neighbor' || obj === 'neighbour') {
      if (rest[0] === 'flush') {
        host.neighbors = [];
        return ok('');
      }
      return ok(host.neighbors.map((n) => `${n.ip} dev ${n.dev} ${n.mac ? `lladdr ${n.mac} ` : ''}${n.state}`).join('\n'));
    }
    if (obj === 'l' || obj === 'link') {
      if (rest[0] === 'set') {
        const deny = needRoot(ctx, 'RTNETLINK answers: Operation not permitted');
        if (deny) return deny;
        const name = rest[1] === 'dev' ? rest[2] : rest[1];
        const iface = host.ifaces.find((i) => i.name === name);
        if (!iface) return err(`Cannot find device "${name}"`);
        if (rest.includes('up')) iface.up = true;
        if (rest.includes('down')) {
          iface.up = false;
          host.routes = host.routes.filter((r) => r.dev !== name);
        }
        return ok('');
      }
      return ok(host.ifaces.map((i, idx) => `${idx + 1}: ${i.name}: <${i.name === 'lo' ? 'LOOPBACK,UP,LOWER_UP' : i.up ? 'BROADCAST,MULTICAST,UP,LOWER_UP' : 'BROADCAST,MULTICAST'}> mtu ${i.name === 'lo' ? 65536 : 1500} state ${i.name === 'lo' ? 'UNKNOWN' : i.up ? 'UP' : 'DOWN'}\n    link/${i.name === 'lo' ? 'loopback' : 'ether'} ${i.mac}`).join('\n'));
    }
    return err('Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\nwhere  OBJECT := { address | route | neigh | link }', 255);
  },
};

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
    const addr = (a: string, p: number) => `${a === '::' ? '[::]' : a}:${p}`;
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
    if (s.serverHostId === ctx.host.id) rows.push(['ESTAB', '0', '0', `${s.serverIp}:${s.serverPort}`, `${s.clientIp}:${s.clientPort}`, `users:(("sshd",pid=${s.pid},fd=4))`]);
    if (s.clientHostId === ctx.host.id) rows.push(['ESTAB', '0', '0', `${s.clientIp}:${s.clientPort}`, `${s.serverIp}:${s.serverPort}`, `users:(("ssh",pid=${s.pid + 1},fd=3))`]);
  }
  return rows;
}

function rtt(ms: number): string {
  return Math.max(0.2, ms).toFixed(3);
}

const ping: CommandDef = {
  name: 'ping',
  summary: 'send ICMP echo requests',
  usage: 'ping [-c COUNT] [-W TIMEOUT] HOST',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-c', '-W', '-i', '-s']);
    const target = rest[0];
    if (!target) return err('ping: usage error: Destination address required', 2);
    const count = Math.min(Number(flags.get('-c') ?? 4), 10);
    const r = resolve(ctx.world, ctx.host, target);
    if (!r.ok) return err(`ping: ${target}: ${r.message}`, 2);
    const dst = r.ip;
    const out = [`PING ${r.fqdn === dst ? dst : r.fqdn} (${dst}) 56(84) bytes of data.`];
    let received = 0;
    let errors = 0;
    const times: number[] = [];
    const icmpId = (ctx.world.counter % 60000) + 1;
    const src = sourceAddress(ctx.host, dst);
    for (let seq = 1; seq <= count; seq++) {
      const start = ctx.world.clock;
      const req: Packet = { id: nextId(ctx.world), src, dst, ttl: 64, proto: 'icmp', icmp: { type: 8, code: 0, description: 'Echo (ping) request', id: icmpId, seq } };
      const d = transmit(ctx.world, ctx.host.id, req);
      if (d.status === 'local-error') {
        if (seq === 1 && d.errno === 'ENETUNREACH') return err('ping: connect: Network is unreachable', 2);
        if (d.errno === 'EHOSTUNREACH') {
          out.push(`From ${src} icmp_seq=${seq} Destination Host Unreachable`);
          errors++;
        } else if (d.errno === 'EPERM') out.push('ping: sendmsg: Operation not permitted');
      } else if (d.status === 'delivered') {
        const target = ctx.world.hosts[d.host];
        const rep: Packet = { id: nextId(ctx.world), src: dst, dst: src, ttl: 64, proto: 'icmp', icmp: { type: 0, code: 0, description: 'Echo (ping) reply', id: icmpId, seq } };
        const back = transmit(ctx.world, target.id, rep);
        if (back.status === 'delivered') {
          const hopsBack = back.hops.filter((h) => h.egress && h.ingress).length;
          const t = ctx.world.clock - start + 0.15;
          times.push(t);
          received++;
          out.push(`64 bytes from ${dst}: icmp_seq=${seq} ttl=${64 - hopsBack} time=${rtt(t)} ms`);
        }
      } else if (d.error?.delivered) {
        const e = d.error.packet;
        errors++;
        const text = e.icmp!.type === 11 ? 'Time to live exceeded' : e.icmp!.code === 13 ? 'Packet filtered' : e.icmp!.code === 0 ? 'Destination Net Unreachable' : e.icmp!.code === 3 ? 'Destination Port Unreachable' : 'Destination Host Unreachable';
        out.push(`From ${e.src} icmp_seq=${seq} ${text}`);
      }
      ctx.world.clock = Math.max(ctx.world.clock, start + 1000);
    }
    out.push('', `--- ${r.fqdn === dst ? dst : r.fqdn} ping statistics ---`);
    const loss = Math.round(((count - received) / count) * 100);
    out.push(`${count} packets transmitted, ${received} received${errors ? `, +${errors} errors` : ''}, ${loss}% packet loss, time ${(count - 1) * 1000 + 3}ms`);
    if (times.length) {
      const min = Math.min(...times), max = Math.max(...times), avg = times.reduce((a, b) => a + b, 0) / times.length;
      out.push(`rtt min/avg/max/mdev = ${rtt(min)}/${rtt(avg)}/${rtt(max)}/${rtt((max - min) / 2)} ms`);
    }
    return { out: out.join('\n'), code: received ? 0 : 1 };
  },
};

const traceroute: CommandDef = {
  name: 'traceroute',
  summary: 'print the route packets take (UDP by default, -T for TCP SYN, -I for ICMP)',
  usage: 'traceroute [-n] [-T] [-I] [-p PORT] [-m MAXHOPS] [-q PROBES] HOST',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-p', '-m', '-w', '-q']);
    const target = rest[0];
    if (!target) return err('Specify "host" missing argument.', 2);
    const r = resolve(ctx.world, ctx.host, target);
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
            ? { id: nextId(ctx.world), src, dst, ttl, proto: 'icmp', icmp: { type: 8, code: 0, description: 'Echo (ping) request', id: 4242, seq: ttl * 3 + q } }
            : { id: nextId(ctx.world), src, dst, ttl, proto: 'udp', udp: { sport: 40000 + q, dport: port, len: 32 } };
        if (mode === 'udp') port++;
        const d = transmit(ctx.world, ctx.host.id, probe);
        let replyFrom: string | null = null;
        let mark = '';
        if (d.status === 'local-error') return err(`connect: ${ERRNO_TEXT[d.errno === 'EPERM' ? 'EPERM' : d.errno]}`, 1);
        if (d.status === 'delivered') {
          const h = ctx.world.hosts[d.host];
          // Destination: UDP -> port unreachable, TCP -> SYN-ACK/RST, ICMP -> echo reply
          let reply: Packet;
          if (mode === 'udp') reply = { id: nextId(ctx.world), src: dst, dst: src, ttl: 64, proto: 'icmp', icmp: { type: 3, code: 3, description: 'Port unreachable', quoted: { proto: 'udp', src, dst, sport: probe.udp!.sport, dport: probe.udp!.dport } } };
          else if (mode === 'icmp') reply = { id: nextId(ctx.world), src: dst, dst: src, ttl: 64, proto: 'icmp', icmp: { type: 0, code: 0, description: 'Echo reply', id: 4242, seq: ttl * 3 + q } };
          else reply = { id: nextId(ctx.world), src: dst, dst: src, ttl: 64, proto: 'tcp', tcp: { sport: port, dport: probe.tcp!.sport, seq: 0, ack: probe.tcp!.seq + 1, flags: allListeners(h).some((l) => l.port === port && l.proto === 'tcp') ? ['SYN', 'ACK'] : ['RST', 'ACK'], window: 0, len: 0 } };
          const back = transmit(ctx.world, h.id, reply);
          if (back.status === 'delivered') { replyFrom = dst; reached = true; }
        } else if (d.error?.delivered) {
          replyFrom = d.error.packet.src;
          const ic = d.error.packet.icmp!;
          if (ic.type === 3) {
            reached = true;
            mark = ic.code === 13 ? ' !X' : ic.code === 1 ? ' !H' : ic.code === 0 ? ' !N' : '';
            if (ic.code === 3 && mode === 'udp') mark = '';
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
    const r = resolve(ctx.world, ctx.host, target);
    if (!r.ok) return err(`nc: getaddrinfo for host "${target}" port ${port}: ${r.message}`, 1);
    const timeoutMs = flags.has('-w') ? Number(flags.get('-w')) * 1000 : undefined;
    const c = tcpConnect(ctx.world, ctx.host, r.ip, port, { timeoutMs });
    const svc = port === 22 ? 'ssh' : port === 80 ? 'http' : port === 443 ? 'https' : port === 53 ? 'domain' : '*';
    if (c.ok) {
      c.conn.close('client');
      return ok(flags.has('-v') ? `Connection to ${target} (${r.ip}) ${port} port [tcp/${svc}] succeeded!` : '');
    }
    const reason = c.errno === 'ETIMEDOUT' && timeoutMs ? 'Connection timed out' : ERRNO_TEXT[c.errno];
    return err(flags.has('-v') ? `nc: connect to ${target} (${r.ip}) port ${port} (tcp) failed: ${reason}` : '', 1);
  },
};

const curl: CommandDef = {
  name: 'curl',
  summary: 'transfer a URL (HTTP only in this simulator)',
  usage: 'curl [-I] [-v] [-m SECONDS] http://HOST[:PORT]/',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-m', '--max-time', '--connect-timeout']);
    const url = rest[0];
    const m = url ? /^(?:(https?):\/\/)?([^/:]+)(?::(\d+))?/.exec(url) : null;
    if (!m) return err('curl: no URL specified!', 2);
    const scheme = m[1] ?? 'http';
    const port = Number(m[3] ?? (scheme === 'https' ? 443 : 80));
    const r = resolve(ctx.world, ctx.host, m[2]);
    if (!r.ok) return err(`curl: (6) Could not resolve host: ${m[2]}`, 6);
    const max = flags.get('-m') ?? flags.get('--max-time') ?? flags.get('--connect-timeout');
    const c = tcpConnect(ctx.world, ctx.host, r.ip, port, { timeoutMs: max ? Number(max) * 1000 : undefined });
    if (!c.ok) {
      const text = c.errno === 'ECONNREFUSED' ? `Failed to connect to ${m[2]} port ${port} after 1 ms: Couldn't connect to server`
        : c.errno === 'ETIMEDOUT' ? `Failed to connect to ${m[2]} port ${port} after ${Math.round(c.elapsedMs)} ms: Couldn't connect to server`
        : `Failed to connect to ${m[2]} port ${port} after 3 ms: ${ERRNO_TEXT[c.errno]}`;
      return err(`curl: (${c.errno === 'ETIMEDOUT' && max ? 28 : 7}) ${text}`, 7);
    }
    const server = c.conn.server;
    const listener = allListeners(server).find((l) => l.port === port && l.proto === 'tcp');
    c.conn.send('c2s', 78, { protocol: 'DATA', info: `GET / HTTP/1.1 Host: ${m[2]}`, fields: [] });
    if (scheme === 'https' || listener?.process !== 'nginx') {
      c.conn.close('server');
      if (listener?.process === 'sshd') return err('curl: (1) Received HTTP/0.9 when not allowed', 1);
      return err('curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection', 35);
    }
    c.conn.send('s2c', 850, { protocol: 'DATA', info: 'HTTP/1.1 200 OK', fields: [] });
    c.conn.close('client');
    const headers = ['HTTP/1.1 200 OK', 'Server: nginx/1.22.1', `Date: ${new Date(Math.floor(ctx.world.clock)).toUTCString()}`, 'Content-Type: text/html', 'Content-Length: 615', 'Connection: keep-alive'];
    if (flags.has('-I')) return ok(headers.join('\n'));
    return ok('<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...\n</html>');
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
  const ports = p ? [p.tcp?.sport ?? p.udp?.sport, p.tcp?.dport ?? p.udp?.dport] : [];
  const [a, b, c] = t;
  switch (a) {
    case undefined: return true;
    case 'arp': return !!f.arp;
    case 'ip': return !!p;
    case 'tcp': return p?.proto === 'tcp';
    case 'udp': return p?.proto === 'udp';
    case 'icmp': return p?.proto === 'icmp';
    case 'host': return p ? p.src === b || p.dst === b : !!f.arp && (f.arp.senderIp === b || f.arp.targetIp === b);
    case 'port': return ports.includes(Number(b));
    case 'src':
      if (b === 'port') return ports[0] === Number(c);
      if (b === 'host') return p?.src === c;
      return p?.src === b;
    case 'dst':
      if (b === 'port') return ports[1] === Number(c);
      if (b === 'host') return p?.dst === c;
      return p?.dst === b;
    case 'net': {
      const cidr = parseCidr(b);
      return !!p && !!cidr && [p.src, p.dst].some((x) => parseIp(x) !== null && ((parseIp(x)! >>> (32 - cidr.prefix)) === (cidr.network >>> (32 - cidr.prefix))));
    }
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
      return ok('conntrack v1.4.7 (conntrack-tools): connection tracking table has been emptied.');
    }
    const lines = ctx.host.conntrack.map((e) => {
      const st = e.proto === 'tcp' ? `${e.state === 'UNREPLIED' ? 'SYN_SENT' : e.state} ` : '';
      return `${e.proto.padEnd(4)} ${e.proto === 'tcp' ? 6 : e.proto === 'udp' ? 17 : 1} 117 ${st}src=${e.src} dst=${e.dst} sport=${e.sport} dport=${e.dport} ${e.state === 'UNREPLIED' ? '[UNREPLIED] ' : ''}src=${e.dst} dst=${e.src} sport=${e.dport} dport=${e.sport} ${e.state === 'UNREPLIED' ? '' : '[ASSURED] '}mark=0 use=1`;
    });
    return ok([...lines, `conntrack v1.4.7 (conntrack-tools): ${lines.length} flow entries have been shown.`].join('\n'));
  },
};

const sysctl: CommandDef = {
  name: 'sysctl',
  summary: 'read or set kernel parameters (net.ipv4.ip_forward)',
  usage: 'sysctl net.ipv4.ip_forward | sysctl -w net.ipv4.ip_forward=1',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const kv = rest[0] ?? '';
    if (kv.includes('=') || flags.has('-w')) {
      if (ctx.user.uid !== 0) return err(`sysctl: permission denied on key "${kv.split('=')[0]}"`, 1);
      const [k, v] = kv.split('=');
      if (k !== 'net.ipv4.ip_forward') return err(`sysctl: cannot stat /proc/sys/${k.replace(/\./g, '/')}: No such file or directory (not modelled)`, 255);
      ctx.host.ipForward = v.trim() === '1';
      return ok(`${k} = ${v.trim()}`);
    }
    if (kv === 'net.ipv4.ip_forward') return ok(`net.ipv4.ip_forward = ${ctx.host.ipForward ? 1 : 0}`);
    if (kv === 'net.ipv4.tcp_syn_retries') return ok('net.ipv4.tcp_syn_retries = 6');
    return err(`sysctl: cannot stat /proc/sys/${kv.replace(/\./g, '/')}: No such file or directory (only ip_forward and tcp_syn_retries are modelled)`, 255);
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

// ---------------------------------------------------------------------------
// DNS tools
// ---------------------------------------------------------------------------

const dig: CommandDef = {
  name: 'dig',
  summary: 'DNS lookup utility (queries a server directly; ignores /etc/hosts and search domains)',
  usage: 'dig [@SERVER] NAME [A] [+short]',
  run(args, ctx) {
    const server = args.find((a) => a.startsWith('@'))?.slice(1);
    const short = args.includes('+short');
    const search = args.includes('+search');
    const names = args.filter((a) => !a.startsWith('@') && !a.startsWith('+') && !['A', 'IN', 'a'].includes(a));
    const name = names[0] ?? '.';
    const rc = parseResolvConf(readFile(ctx.host, '/etc/resolv.conf'));
    const ns = server ?? rc.nameservers[0] ?? '127.0.0.1';
    let qname = name.endsWith('.') ? name : name + '.';
    if (search && !name.includes('.') && rc.search[0]) qname = `${name}.${rc.search[0]}.`;
    const out: string[] = [];
    if (!short) out.push('', `; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> ${args.join(' ')}`, ';; global options: +cmd');
    let ex = dnsQuery(ctx.world, ctx.host, ns, qname, 5);
    for (let i = 1; i < 3 && ex.outcome === 'timeout'; i++) {
      if (!short) out.push(`;; communications error to ${ns}#53: timed out`);
      ex = dnsQuery(ctx.world, ctx.host, ns, qname, 5);
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
    out.push(';; WARNING: recursion requested but not available', '', ';; QUESTION SECTION:', `;${qname}\t\t\tIN\tA`);
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
  usage: 'getent hosts NAME | getent passwd [USER] | getent group [GROUP]',
  run(args, ctx) {
    const [db, key] = args;
    if (db === 'hosts' || db === 'ahosts') {
      if (!key) return err('', 2);
      const r = resolve(ctx.world, ctx.host, key);
      if (!r.ok) return err('', 2);
      return ok(`${r.ip.padEnd(15)} ${r.source === 'hosts' ? key : r.fqdn}`);
    }
    if (db === 'passwd' || db === 'group') {
      const lines = virtualFile(ctx.host, db === 'passwd' ? '/etc/passwd' : '/etc/group')!.split('\n').filter((l) => l && (!key || l.startsWith(key + ':')));
      return { out: lines.join('\n'), code: lines.length ? 0 : 2 };
    }
    return err(`Unknown database: ${db}`, 1);
  },
};

export const NET_COMMANDS: CommandDef[] = [ip, ss, ping, traceroute, nc, curl, tcpdump, conntrack, sysctl, hostname, uname, date, dig, nslookup, hostCmd, getent];
export { isoTime, lookupHostsFile };
