// Console programs a Windows administrator runs from PowerShell: ipconfig,
// ping, tracert, netstat, nslookup, netsh advfirewall, sc.exe, net, route,
// arp, w32tm, whoami, hostname, systeminfo and shutdown. They take string
// arguments and print text, exactly like their real counterparts.

import { isIp } from '../../../net/ip';
import { dnsQuery } from '../../../sim/dns';
import { applyFirewall, FW_PROFILES, startWinService, stopWinService, winEvent, winListeners, winResolver, type FwProfile, type WinFwRule } from '../../model';
import { echo, maskOf, resolve4, winMac } from '../netops';
import { native, type PsCtx } from '../runtime';
import { findReg, regKey, regValueChanged } from './files';
import { GROUPS, setDisabled, userDisabled } from './system';
import { readFile, writeFile } from '../../../fs';
import { RDP_TCP_KEY } from '../../model';
import { domainDn, locateDc, secureChannel } from '../../ad';
import { smbConnect, type SmbError } from '../../../sim/smb';

const ok = (out: string, code = 0) => ({ out, code });

function admin(ctx: PsCtx): boolean {
  return ctx.user.uid === 500 || ctx.user.groups.includes('Administrators');
}

const has = (args: string[], ...flags: string[]) => args.some((a) => flags.includes(a.toLowerCase().replace(/^-/, '/')));

native({
  name: 'findstr', synopsis: 'Searches for strings in piped text or files (/i ignore case, /c:"literal").',
  run(args, ctx, input) {
    const ci = args.some((a) => a.toLowerCase() === '/i');
    const literal = args.find((a) => /^\/c:/i.test(a))?.slice(3);
    const words = literal !== undefined ? [literal] : args.filter((a) => !a.startsWith('/')).slice(0, 1).flatMap((a) => a.split(' '));
    if (!words.length) return ok('FINDSTR: Bad command line', 2);
    const norm = (t: string) => (ci ? t.toLowerCase() : t);
    const hits = input.filter((l) => words.some((w) => norm(l).includes(norm(w))));
    void ctx;
    return ok(hits.join('\n'), hits.length ? 0 : 1);
  },
});

// ---------------------------------------------------------------------------
// ipconfig
// ---------------------------------------------------------------------------

native({
  name: 'ipconfig', synopsis: 'Displays TCP/IP network configuration (/all, /flushdns, /displaydns).',
  run(args, ctx) {
    const host = ctx.host;
    const w = host.win!;
    if (has(args, '/flushdns')) return ok('\nWindows IP Configuration\n\nSuccessfully flushed the DNS Resolver Cache.');
    if (has(args, '/displaydns')) return ok('\nWindows IP Configuration\n');
    if (has(args, '/release', '/renew')) return ok(`\nWindows IP Configuration\n\nThe operation failed as no adapter is in the state permissible for\nthis operation.`, 1);
    if (args.length && !has(args, '/all')) return ok(`Error: unrecognized or incomplete command line.\n\nUSAGE:\n    ipconfig [/allcompartments] [/? | /all |\n                                 /renew [adapter] | /release [adapter] |\n                                 /flushdns | /displaydns | /registerdns ]`, 1);
    const all = has(args, '/all');
    // Dot leaders: the label, then '.' on even columns, up to the colon at column 34.
    const dot = (label: string, v: string) => `   ${Array.from({ length: 34 }, (_, i) => (i < label.length ? label[i] : i % 2 === 0 ? '.' : ' ')).join('')}: ${v}`;
    const out = ['', 'Windows IP Configuration', ''];
    if (all) {
      out.push(dot('Host Name ', host.hostname.toUpperCase()), dot('Primary Dns Suffix ', host.win!.domain?.domain ?? ''), dot('Node Type ', 'Hybrid'), dot('IP Routing Enabled. ', 'No'), dot('WINS Proxy Enabled. ', 'No'));
      const search = winResolver(host).search;
      if (search.length) out.push(dot('DNS Suffix Search List. ', search[0]), ...search.slice(1).map((s) => `${' '.repeat(39)}${s}`));
      out.push('');
    }
    for (const a of w.adapters) {
      const i = host.ifaces.find((x) => x.name === a.alias);
      out.push('', `Ethernet adapter ${a.alias}:`, '');
      if (!i?.up || !i.segment) {
        out.push(dot('Media State ', 'Media disconnected'), dot('Connection-specific DNS Suffix  ', a.dnsSuffix));
        continue;
      }
      const ll = i.addrs6?.find((x) => x.scope === 'link')?.address;
      out.push(dot('Connection-specific DNS Suffix  ', a.dnsSuffix));
      if (all) out.push(dot('Description ', a.description), dot('Physical Address. ', winMac(i.mac)), dot('DHCP Enabled. ', a.dhcp ? 'Yes' : 'No'), dot('Autoconfiguration Enabled ', 'Yes'));
      if (ll) out.push(dot('Link-local IPv6 Address ', `${ll}%${a.ifIndex}${all ? '(Preferred) ' : ''}`));
      if (a.address && a.prefix !== null) out.push(dot(all ? 'IPv4 Address. ' : 'IPv4 Address. ', `${a.address}${all ? '(Preferred) ' : ''}`), dot('Subnet Mask ', maskOf(a.prefix)));
      else out.push(dot('Autoconfiguration IPv4 Address. ', '169.254.12.34(Preferred) '), dot('Subnet Mask ', '255.255.0.0'));
      out.push(dot('Default Gateway ', a.gateway ?? ''));
      if (all) {
        out.push(dot('DNS Servers ', a.dns[0] ?? ''), ...a.dns.slice(1).map((d) => `${' '.repeat(39)}${d}`), dot('NetBIOS over Tcpip. ', 'Enabled'));
      }
    }
    return ok(out.join('\n'));
  },
});

// ---------------------------------------------------------------------------
// ping, tracert
// ---------------------------------------------------------------------------

native({
  name: 'ping', synopsis: 'Sends ICMP echo requests (-n count, -l size, -t continuous, -4).',
  run(args, ctx) {
    let count = 4;
    let size = 32;
    let target: string | undefined;
    for (let i = 0; i < args.length; i++) {
      const a = args[i].toLowerCase();
      if (a === '-n' || a === '/n') count = Math.min(Number(args[++i]), 10);
      else if (a === '-l' || a === '/l') size = Number(args[++i]);
      else if (a === '-t' || a === '/t') count = 10;
      else if (a === '-4' || a === '-6' || a === '-a') continue;
      else if (a === '-w' || a === '-i') i++;
      else target = args[i];
    }
    if (!target) return ok('\nUsage: ping [-t] [-a] [-n count] [-l size] [-f] [-i TTL] [-v TOS]\n            [-r count] [-s count] [[-j host-list] | [-k host-list]]\n            [-w timeout] [-R] [-S srcaddr] [-c compartment] [-p]\n            [-4] [-6] target_name', 1);
    if (!Number.isInteger(count) || count < 1) return ok('Bad value for option -n, valid range is from 1 to 4294967295.', 1);
    const r = resolve4(ctx.world, ctx.host, target);
    if (!r.ok) return ok(`Ping request could not find host ${target}. Please check the name and try again.`, 1);
    const named = !isIp(target);
    const out = ['', `Pinging ${named ? `${r.fqdn.replace(/\.$/, '')} [${r.ip}]` : r.ip} with ${size} bytes of data:`];
    let received = 0;
    let replies = 0;
    const times: number[] = [];
    for (let seq = 1; seq <= count; seq++) {
      const start = ctx.world.clock;
      const e = echo(ctx.world, ctx.host, r.ip, size, seq);
      if (e.kind === 'reply') {
        received++;
        replies++;
        times.push(e.ms);
        out.push(`Reply from ${r.ip}: bytes=${size} time${e.ms < 1 ? '<1' : `=${e.ms}`}ms TTL=${e.ttl}`);
      } else if (e.kind === 'timeout') out.push('Request timed out.');
      else if (e.kind === 'unreachable') {
        received++;
        out.push(`Reply from ${e.from}: ${e.text}`);
      } else {
        out.push(e.text);
      }
      ctx.world.clock = Math.max(ctx.world.clock, start + 1000);
    }
    const lost = count - received;
    out.push('', `Ping statistics for ${r.ip}:`, `    Packets: Sent = ${count}, Received = ${received}, Lost = ${lost} (${Math.round((lost / count) * 100)}% loss),`);
    if (times.length) {
      out.push('Approximate round trip times in milli-seconds:', `    Minimum = ${Math.min(...times)}ms, Maximum = ${Math.max(...times)}ms, Average = ${Math.round(times.reduce((a, b) => a + b, 0) / times.length)}ms`);
    }
    return ok(out.join('\n'), replies ? 0 : 1);
  },
});

native({
  name: 'tracert', synopsis: 'Traces the route to a destination (-d: no name lookups, -h max hops).',
  run(args, ctx) {
    let maxHops = 30;
    let target: string | undefined;
    for (let i = 0; i < args.length; i++) {
      const a = args[i].toLowerCase();
      if (a === '-h' || a === '/h') maxHops = Math.min(Number(args[++i]), 30);
      else if (a === '-w' || a === '-j') i++;
      else if (!a.startsWith('-') && !a.startsWith('/')) target = args[i];
    }
    if (!target) return ok('\nUsage: tracert [-d] [-h maximum_hops] [-j host-list] [-w timeout]\n               [-R] [-S srcaddr] [-4] [-6] target_name', 1);
    const r = resolve4(ctx.world, ctx.host, target);
    if (!r.ok) return ok(`Unable to resolve target system name ${target}.`, 1);
    const named = !isIp(target);
    const out = ['', `Tracing route to ${named ? `${r.fqdn.replace(/\.$/, '')} [${r.ip}]` : r.ip}`, `over a maximum of ${maxHops} hops:`, ''];
    let silent = 0;
    for (let ttl = 1; ttl <= maxHops; ttl++) {
      const cells: string[] = [];
      let from = '';
      let done = false;
      let note = '';
      for (let q = 0; q < 3; q++) {
        const start = ctx.world.clock;
        const e = echo(ctx.world, ctx.host, r.ip, 32, ttl * 3 + q, ttl);
        if (e.kind === 'reply') { cells.push(e.ms < 1 ? '<1 ms' : `${e.ms} ms`); from = r.ip; done = true; }
        else if (e.kind === 'unreachable') {
          cells.push(`${Math.max(0, Math.round(ctx.world.clock - start))} ms`.replace(/^0 ms$/, '<1 ms'));
          from = e.from;
          if (!/TTL expired/.test(e.text)) { done = true; note = ` reports: ${e.text}`; }
        } else cells.push('*');
      }
      const line = `${String(ttl).padStart(3)}  ${cells.map((x) => x.padStart(6)).join('  ')}  `;
      if (!from) { out.push(`${line}Request timed out.`); silent++; }
      else { out.push(`${line}${from}${note}`); silent = 0; }
      if (done) break;
      if (silent >= 5) { out.push('', '[Infrastructure Lab: stopped after 5 silent hops; real tracert continues to the hop limit.]'); break; }
    }
    out.push('', 'Trace complete.');
    return ok(out.join('\n'));
  },
});

// ---------------------------------------------------------------------------
// netstat, route, arp
// ---------------------------------------------------------------------------

native({
  name: 'netstat', synopsis: 'Displays protocol statistics and connections (-a, -n, -o, -an, -ano).',
  run(args, ctx) {
    const flags = args.join('').toLowerCase().replace(/[-/]/g, '');
    const withPid = flags.includes('o');
    const listening = flags.includes('a');
    const out = ['', 'Active Connections', '', `  Proto  Local Address          Foreign Address        State${withPid ? '           PID' : ''}`];
    if (!listening) return ok(out.join('\n'));
    const ls = winListeners(ctx.host).sort((a, b) => (a.proto === b.proto ? (a.addr === b.addr ? a.port - b.port : b.addr.length - a.addr.length) : a.proto === 'tcp' ? -1 : 1));
    for (const l of ls) {
      const local = l.addr === '::' ? `[::]:${l.port}` : `${l.addr}:${l.port}`;
      const remote = l.proto === 'udp' ? '*:*' : l.addr === '::' ? '[::]:0' : '0.0.0.0:0';
      out.push(`  ${l.proto.toUpperCase().padEnd(7)}${local.padEnd(23)}${remote.padEnd(23)}${(l.proto === 'tcp' ? 'LISTENING' : '').padEnd(16)}${withPid ? l.pid : ''}`.replace(/\s+$/, ''));
    }
    return ok(out.join('\n'));
  },
});

native({
  name: 'route', synopsis: 'Displays the routing table (route print).',
  run(args, ctx) {
    if ((args[0] ?? '').toLowerCase() !== 'print') return ok('\nManipulates network routing tables.\n\nROUTE [-f] [-p] [-4|-6] command [destination]\n                  [MASK netmask]  [gateway] [METRIC metric]  [IF interface]\n\n  command      One of these:\n                 PRINT     Prints  a route\n                 ADD       Adds    a route\n                 DELETE    Deletes a route\n                 CHANGE    Modifies an existing route', args.length ? 1 : 0);
    const host = ctx.host;
    const sep = '='.repeat(75);
    const out = [sep, 'Interface List'];
    for (const a of host.win!.adapters) out.push(`  ${a.ifIndex}...${winMac(host.ifaces.find((i) => i.name === a.alias)?.mac ?? '').replace(/-/g, ' ').toLowerCase()} ......${a.description}`);
    out.push('  1...........................Software Loopback Interface 1', sep, '', 'IPv4 Route Table', sep, 'Active Routes:', 'Network Destination        Netmask          Gateway       Interface  Metric');
    const fmt = (d: string, m: string, g: string, i: string, metric: number) => `${d.padStart(17)}${m.padStart(17)}${g.padStart(17)}${i.padStart(17)}${String(metric).padStart(7)}`;
    for (const r of host.routes) {
      const a = host.win!.adapters.find((x) => x.alias === r.dev);
      if (!a?.address) continue;
      if (r.dest === 'default') out.push(fmt('0.0.0.0', '0.0.0.0', r.via ?? 'On-link', a.address, 271));
      else {
        const [net, len] = r.dest.split('/');
        out.push(fmt(net, maskOf(Number(len)), 'On-link', a.address, 271));
      }
    }
    out.push(fmt('127.0.0.0', '255.0.0.0', 'On-link', '127.0.0.1', 331), fmt('127.0.0.1', '255.255.255.255', 'On-link', '127.0.0.1', 331), sep, 'Persistent Routes:', '  None');
    return ok(out.join('\n'));
  },
});

native({
  name: 'arp', synopsis: 'Displays the ARP cache (arp -a).',
  run(args, ctx) {
    if (!has(args, '/a', '/g')) return ok('\nDisplays and modifies the IP-to-Physical address translation tables used by\naddress resolution protocol (ARP).\n\nARP -s inet_addr eth_addr [if_addr]\nARP -d inet_addr [if_addr]\nARP -a [inet_addr] [-N if_addr] [-v]', 1);
    const host = ctx.host;
    const out: string[] = [];
    for (const a of host.win!.adapters) {
      if (!a.address) continue;
      out.push('', `Interface: ${a.address} --- 0x${a.ifIndex.toString(16)}`, '  Internet Address      Physical Address      Type');
      for (const n of host.neighbors.filter((x) => x.dev === a.alias && x.mac && !x.ip.includes(':'))) out.push(`  ${n.ip.padEnd(22)}${winMac(n.mac!).toLowerCase().padEnd(22)}dynamic`);
    }
    if (!out.length) return ok('No ARP Entries Found.', 1);
    return ok(out.join('\n'));
  },
});

// ---------------------------------------------------------------------------
// nslookup
// ---------------------------------------------------------------------------

native({
  name: 'nslookup', synopsis: 'Queries DNS: nslookup NAME [SERVER].',
  run(args, ctx) {
    const pos = args.filter((a) => !a.startsWith('-'));
    const typeArg = args.find((a) => /^-(type|q|querytype)=/i.test(a));
    const qtype = (typeArg?.split('=')[1] ?? 'A').toUpperCase();
    const [name, serverArg] = pos;
    if (!name) return ok('Default Server:  UnKnown\nAddress:  ' + (winResolver(ctx.host).nameservers[0] ?? '') + '\n\n> [Infrastructure Lab: interactive nslookup is not simulated; pass the name to look up]', 1);
    const host = ctx.host;
    const server = serverArg ?? winResolver(host).nameservers[0];
    if (!server) return ok('*** Can\'t find server address for \'\':\n*** Default servers are not available\nServer:  UnKnown\nAddress:  127.0.0.1\n\n*** UnKnown can\'t find ' + name + ': No response from server', 1);
    const out: string[] = [];
    // nslookup first asks the server for its own name (a PTR query).
    const rev = `${server.split('.').reverse().join('.')}.in-addr.arpa.`;
    const ptr = dnsQuery(ctx.world, host, server, rev, 2, 'PTR');
    if (ptr.outcome === 'timeout' || ptr.outcome === 'unreachable' || ptr.outcome === 'port-unreachable') {
      out.push('DNS request timed out.', '    timeout was 2 seconds.', 'Server:  UnKnown', `Address:  ${server}`, '');
      const again = dnsQuery(ctx.world, host, server, name.includes('.') ? `${name}.` : `${name}.${winResolver(host).search[0] ?? ''}.`, 2, 'A');
      if (again.outcome !== 'answer') {
        out.push('DNS request timed out.', '    timeout was 2 seconds.', 'DNS request timed out.', '    timeout was 2 seconds.', `*** Request to UnKnown timed-out`);
        return ok(out.join('\n'), 1);
      }
    }
    const serverName = ptr.outcome === 'answer' ? ptr.answer!.answers.find((r) => r.type === 'PTR')?.data.replace(/\.$/, '') ?? 'UnKnown' : 'UnKnown';
    if (!out.length) out.push(`Server:  ${serverName}`, `Address:  ${server}`, '');
    const suffixes = winResolver(host).search;
    const qtypeOk = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'SRV', 'CNAME', 'PTR'].includes(qtype) ? (qtype as 'A') : 'A';
    // Windows nslookup appends the suffix search list to single-label names (and never asks for the bare label).
    const candidates = name.endsWith('.') ? [name] : name.includes('.') ? [`${name}.`, ...suffixes.map((s) => `${name}.${s}.`)] : suffixes.map((s) => `${name}.${s}.`);
    for (const q of isIp(name) ? [`${name.split('.').reverse().join('.')}.in-addr.arpa.`] : candidates) {
      const ex = dnsQuery(ctx.world, host, server, q, 2, isIp(name) ? 'PTR' : qtypeOk);
      if (ex.outcome === 'timeout' || ex.outcome === 'unreachable' || ex.outcome === 'port-unreachable') {
        out.push('DNS request timed out.', '    timeout was 2 seconds.', `*** Request to ${serverName} timed-out`);
        return ok(out.join('\n'), 1);
      }
      if (ex.outcome === 'answer') {
        if (!ex.answer!.authoritative) out.push('Non-authoritative answer:');
        const recs = ex.answer!.answers;
        if (isIp(name)) out.push(`Name:    ${recs[0].data.replace(/\.$/, '')}`, `Address:  ${name}`);
        else if (qtypeOk === 'A' || qtypeOk === 'AAAA') {
          const addrs = recs.filter((r) => r.type === 'A' || r.type === 'AAAA').map((r) => r.data);
          out.push(`Name:    ${(recs.find((r) => r.type === 'A' || r.type === 'AAAA')?.name ?? q).replace(/\.$/, '')}`, `Address${addrs.length > 1 ? 'es' : ''}:  ${addrs[0] ?? ''}`, ...addrs.slice(1).map((x) => `          ${x}`));
          const cn = recs.filter((r) => r.type === 'CNAME');
          if (cn.length) out.push(`Aliases:  ${cn[0].name.replace(/\.$/, '')}`);
        } else for (const r of recs) out.push(`${r.name.replace(/\.$/, '')}\t${r.type === 'TXT' ? 'text =\n\n\t' : `${r.type} = `}${r.data}`);
        return ok(out.join('\n') + '\n');
      }
      if (ex.outcome === 'refused') { out.push(`*** ${serverName} can't find ${name}: Query refused`); return ok(out.join('\n'), 1); }
      if (ex.outcome === 'servfail') { out.push(`*** ${serverName} can't find ${name}: Server failed`); return ok(out.join('\n'), 1); }
    }
    out.push(`*** ${serverName} can't find ${name}: Non-existent domain`);
    return ok(out.join('\n'), 1);
  },
});

// ---------------------------------------------------------------------------
// Identity and system
// ---------------------------------------------------------------------------

native({ name: 'hostname', synopsis: 'Prints the name of the current host.', run: (_a, ctx) => ok(ctx.host.hostname.toUpperCase()) });

native({
  name: 'whoami', synopsis: 'Displays the current user (/groups, /user).',
  run(args, ctx) {
    // On a domain controller the console account is the domain's Administrator.
    const who = `${(ctx.host.win!.ad ? ctx.host.win!.ad.netbios : ctx.host.hostname).toLowerCase()}\\${ctx.user.name.toLowerCase()}`;
    if (has(args, '/groups')) {
      const out = ['', 'GROUP INFORMATION', '-----------------', '', 'Group Name                             Type             SID          Attributes', '====================================== ================ ============ ==================================================', 'Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group'];
      for (const g of ctx.user.groups) out.push(`${`BUILTIN\\${g}`.padEnd(39)}Alias            S-1-5-32-5xx Mandatory group, Enabled by default, Enabled group`);
      return ok(out.join('\n'));
    }
    if (has(args, '/user')) return ok(['', 'USER INFORMATION', '----------------', '', 'User Name'.padEnd(20) + ' SID', '='.repeat(20) + ' ' + '='.repeat(46), `${who.padEnd(20)} S-1-5-21-3623811015-3361044348-30300820-${ctx.user.uid}`].join('\n'));
    return ok(who);
  },
});

native({
  name: 'systeminfo', synopsis: 'Displays operating system configuration information.',
  run(_a, ctx) {
    const h = ctx.host;
    const w = h.win!;
    const row = (k: string, v: string) => `${(k + ':').padEnd(27)}${v}`;
    const a = w.adapters[0];
    return ok(['', row('Host Name', h.hostname.toUpperCase()), row('OS Name', `Microsoft ${w.productName}`), row('OS Version', `10.0.${w.build} N/A Build ${w.build}`), row('OS Manufacturer', 'Microsoft Corporation'),
      row('OS Configuration', w.ad ? 'Primary Domain Controller' : w.domain ? 'Member Server' : 'Standalone Server'), row('System Boot Time', new Date(h.bootTime).toISOString().replace('T', ', ').slice(0, 20)), row('System Manufacturer', 'Microsoft Corporation'), row('System Model', 'Virtual Machine'),
      row('Total Physical Memory', '4,095 MB'), row('Domain', w.domain?.domain ?? w.workgroup), row('Logon Server', `\\\\${h.hostname.toUpperCase()}`), row('Hotfix(s)', '2 Hotfix(s) Installed.'), '                           [01]: KB5041948', '                           [02]: KB5042881',
      row('Network Card(s)', '1 NIC(s) Installed.'), `                           [01]: ${a?.description ?? ''}`, `                                 Connection Name: ${a?.alias ?? ''}`, '                                 DHCP Enabled:    No', '                                 IP address(es)', `                                 [01]: ${a?.address ?? ''}`].join('\n'));
  },
});

native({
  name: 'shutdown', synopsis: 'Restarts or shuts down the computer (/r /t 0).',
  run(args, ctx) {
    if (!has(args, '/r', '/s')) return ok('Usage: shutdown [/i | /l | /s | /sg | /r | /g | /a | /p | /h | /e | /o] [/hybrid] [/soft] [/fw] [/f]\n    [/m \\\\computer][/t xxx][/d [p|u:]xx:yy [/c "comment"]]', has(args, '/?') ? 0 : 1);
    if (!admin(ctx)) return ok(`${ctx.host.hostname.toUpperCase()}: Access is denied.(5)`, 5);
    if (has(args, '/s')) return ok('[Infrastructure Lab: shutting the server down would end the lab; use shutdown /r to restart it]', 1);
    winEvent(ctx.world, ctx.host, 'System', 1074, 'User32', `The process C:\\Windows\\system32\\shutdown.exe (${ctx.host.hostname.toUpperCase()}) has initiated the restart of computer ${ctx.host.hostname.toUpperCase()} on behalf of user ${ctx.host.hostname.toUpperCase()}\\${ctx.user.name} for the following reason: No title for this reason could be found`);
    ctx.reboot = true;
    return ok('');
  },
});

native({
  name: 'w32tm', synopsis: 'Windows Time service tool (/query /status, /resync).',
  run(args, ctx) {
    const w = ctx.host.win!;
    const running = w.services.W32Time?.status === 'Running';
    if (!running) return ok('The following error occurred: The service has not been started. (0x80070426)', 1);
    if (has(args, '/resync')) {
      if (!admin(ctx)) return ok('The following error occurred: Access is denied. (0x80070005)', 1);
      ctx.host.clockOffset = 0;
      return ok('Sending resync command to local computer\nThe command completed successfully.');
    }
    if (has(args, '/query')) return ok(['Leap Indicator: 0(no warning)', 'Stratum: 3 (secondary reference - syncd by (S)NTP)', 'Precision: -23 (119.209ns per tick)', 'Root Delay: 0.0010000s', 'Root Dispersion: 7.7766000s', `ReferenceId: 0x0A000A35 (source IP:  ${w.adapters[0]?.dns[0] ?? '10.0.10.53'})`, `Source: ${w.adapters[0]?.dns[0] ?? '10.0.10.53'}`, 'Poll Interval: 10 (1024s)'].join('\n'));
    return ok('w32tm [/? | /register | /unregister ]\n  /query [/computer:<target>] {/source | /configuration | /peers | /status}\n  /resync [/computer:<computer>] [/nowait] [/rediscover] [/soft]', 1);
  },
});

// ---------------------------------------------------------------------------
// sc.exe
// ---------------------------------------------------------------------------

const SC_STATE: Record<string, string> = { Running: '4  RUNNING', Stopped: '1  STOPPED' };
const SC_START: Record<string, string> = { Automatic: '2   AUTO_START', AutomaticDelayedStart: '2   AUTO_START  (DELAYED)', Manual: '3   DEMAND_START', Disabled: '4   DISABLED' };

native({
  name: 'sc', synopsis: 'Service control: sc.exe query|qc|start|stop|config NAME [start= auto|demand|disabled]. (In PowerShell, "sc" is Set-Content: type sc.exe.)',
  run(args, ctx) {
    const [verbRaw, nameRaw, ...rest] = args;
    const verb = (verbRaw ?? '').toLowerCase();
    const w = ctx.host.win!;
    const svc = nameRaw ? Object.values(w.services).find((s) => s.name.toLowerCase() === nameRaw.toLowerCase()) : undefined;
    const usage = 'DESCRIPTION:\n        SC is a command line program used for communicating with the\n        Service Control Manager and services.\nUSAGE:\n        sc <server> [command] [service name] <option1> <option2>...\n\n        query-----------Queries the status for a service.\n        qc--------------Queries the configuration information for a service.\n        start-----------Starts a service.\n        stop------------Sends a STOP request to a service.\n        config----------Changes the configuration of a service (persistent).';
    if (!['query', 'queryex', 'qc', 'start', 'stop', 'config'].includes(verb)) return ok(usage, verb ? 1639 : 0);
    if (verb === 'query' && !nameRaw) {
      const out: string[] = [];
      for (const s of Object.values(w.services).filter((x) => x.status === 'Running')) out.push('', `SERVICE_NAME: ${s.name}`, `DISPLAY_NAME: ${s.displayName}`, '        TYPE               : 30  WIN32', `        STATE              : ${SC_STATE[s.status]}`);
      return ok(out.join('\n'));
    }
    if (!svc) return ok(`[SC] ${verb.startsWith('query') ? 'EnumQueryServicesStatus:OpenService' : 'OpenService'} FAILED 1060:\n\nThe specified service does not exist as an installed service.\n`, 1060);
    const type = svc.process === 'svchost' ? '20  WIN32_SHARE_PROCESS' : '10  WIN32_OWN_PROCESS';
    const status = () => ['', `SERVICE_NAME: ${svc.name}`, `        TYPE               : ${type}`, `        STATE              : ${verb === 'start' ? '2  START_PENDING' : verb === 'stop' ? '3  STOP_PENDING' : SC_STATE[svc.status]}`,
      `                                (${svc.status === 'Running' && !svc.protected ? 'STOPPABLE' : 'NOT_STOPPABLE'}, NOT_PAUSABLE, ${svc.status === 'Running' ? 'ACCEPTS_SHUTDOWN' : 'IGNORES_SHUTDOWN'})`,
      '        WIN32_EXIT_CODE    : 0  (0x0)', '        SERVICE_EXIT_CODE  : 0  (0x0)', '        CHECKPOINT         : 0x0', '        WAIT_HINT          : 0x0', ...(verb === 'start' ? [`        PID                : ${svc.pid ?? 0}`, '        FLAGS              :'] : [])].join('\n');
    if (verb === 'query') return ok(status());
    if (verb === 'queryex') return ok(`${status()}\n        PID                : ${svc.pid ?? 0}\n        FLAGS              :`);
    if (verb === 'qc') {
      return ok(['[SC] QueryServiceConfig SUCCESS', '', `SERVICE_NAME: ${svc.name}`, `        TYPE               : ${type}`, `        START_TYPE         : ${SC_START[svc.startType]}`, '        ERROR_CONTROL      : 1   NORMAL',
        `        BINARY_PATH_NAME   : C:\\Windows\\system32\\${svc.process === 'svchost' ? 'svchost.exe -k netsvcs -p' : `${svc.process}.exe`}`, '        LOAD_ORDER_GROUP   :', '        TAG                : 0', `        DISPLAY_NAME       : ${svc.displayName}`,
        `        DEPENDENCIES       : ${svc.dependsOn[0] ?? ''}`, ...svc.dependsOn.slice(1).map((d) => `                           : ${d}`), '        SERVICE_START_NAME : LocalSystem'].join('\n'));
    }
    if (!admin(ctx)) return ok('[SC] OpenService FAILED 5:\n\nAccess is denied.\n', 5);
    if (verb === 'config') {
      const i = rest.findIndex((x) => x.toLowerCase() === 'start=' || x.toLowerCase().startsWith('start='));
      const val = i < 0 ? undefined : rest[i].includes('=') && rest[i].length > 6 ? rest[i].slice(6) : rest[i + 1];
      if (i >= 0 && rest[i].length > 6) return ok('[SC] ChangeServiceConfig: The parameter is incorrect.\n\n[Infrastructure Lab: sc.exe needs a space after "start=": sc.exe config NAME start= auto]', 87);
      const map: Record<string, typeof svc.startType> = { auto: 'Automatic', 'delayed-auto': 'AutomaticDelayedStart', demand: 'Manual', disabled: 'Disabled' };
      if (!val || !map[val.toLowerCase()]) return ok('[SC] ChangeServiceConfig: The parameter is incorrect.', 87);
      svc.startType = map[val.toLowerCase()];
      winEvent(ctx.world, ctx.host, 'System', 7040, 'Service Control Manager', `The start type of the ${svc.displayName} service was changed from ${'demand start'} to ${val.toLowerCase() === 'demand' ? 'demand start' : val.toLowerCase() === 'disabled' ? 'disabled' : 'auto start'}.`);
      return ok('[SC] ChangeServiceConfig SUCCESS');
    }
    if (verb === 'start') {
      if (svc.status === 'Running') return ok('[SC] StartService FAILED 1056:\n\nAn instance of the service is already running.\n', 1056);
      const r = startWinService(ctx.world, ctx.host, svc.name);
      if (!r.ok) return r.error === 'disabled' ? ok('[SC] StartService FAILED 1058:\n\nThe service cannot be started, either because it is disabled or because it has no enabled devices associated with it.\n', 1058) : ok('[SC] StartService FAILED 1068:\n\nThe dependency service or group failed to start.\n', 1068);
      return ok(status());
    }
    if (svc.status === 'Stopped') return ok('[SC] ControlService FAILED 1062:\n\nThe service has not been started.\n', 1062);
    const deps = Object.values(w.services).filter((x) => x.dependsOn.includes(svc.name) && x.status === 'Running');
    if (deps.length) return ok('[SC] ControlService FAILED 1051:\n\nA stop control has been sent to a service that other running services are dependent on.\n', 1051);
    const r = stopWinService(ctx.world, ctx.host, svc.name);
    if (!r.ok) return ok('[SC] ControlService FAILED 1052:\n\nThe requested control is not valid for this service.\n', 1052);
    return ok(status());
  },
});

// ---------------------------------------------------------------------------
// net user / localgroup / start / stop
// ---------------------------------------------------------------------------

const DONE = 'The command completed successfully.\n';

function columns(names: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < names.length; i += 3) out.push(names.slice(i, i + 3).map((n) => n.padEnd(25)).join('').replace(/\s+$/, ''));
  return out;
}

// net use: map a drive letter (or just connect) to \\SERVER\SHARE over SMB.
const SYS_ERR: Partial<Record<SmbError, [number, string]>> = {
  NT_STATUS_LOGON_FAILURE: [1326, 'The user name or password is incorrect.'],
  NT_STATUS_ACCOUNT_DISABLED: [1331, "This user can't sign in because this account is currently disabled."],
  NT_STATUS_ACCESS_DENIED: [5, 'Access is denied.'],
  NT_STATUS_BAD_NETWORK_NAME: [67, 'The network name cannot be found.'],
};

function netUse(args: string[], ctx: PsCtx) {
  const w = ctx.host.win!;
  const maps = (w.smbMappings ??= []);
  const pos = args.filter((a) => !a.startsWith('/'));
  const sw = args.filter((a) => a.startsWith('/'));
  if (!pos.length) {
    if (!maps.length) return ok('New connections will be remembered.\n\nThere are no entries in the list.\n\n');
    return ok(['New connections will be remembered.', '', '', 'Status       Local     Remote                    Network', '', '-'.repeat(79),
      ...maps.map((m) => `${'OK'.padEnd(13)}${m.local.padEnd(10)}${m.remote.padEnd(26)}Microsoft Windows Network`), DONE].join('\n'));
  }
  const local = /^[a-z]:$/i.test(pos[0]) ? pos[0].toUpperCase() : '';
  if (sw.some((x) => /^\/d(elete)?$/i.test(x))) {
    const i = maps.findIndex((m) => (local ? m.local === local : m.remote.toLowerCase() === pos[0].toLowerCase()));
    if (i < 0) return ok('The network connection could not be found.\n\nMore help is available by typing NET HELPMSG 2250.\n', 2);
    maps.splice(i, 1);
    return ok(`${local || pos[0]} was deleted successfully.\n\n`);
  }
  const remote = local ? pos[1] : pos[0];
  const m = /^\\\\([^\\]+)\\([^\\]+)\\?$/.exec(remote ?? '');
  if (!m) return ok('The syntax of this command is:\n\nNET USE\n[devicename | *] [\\\\computername\\sharename[\\volume] [password | *]]\n        [/USER:[domainname\\]username]\n        [/PERSISTENT:{YES | NO}] [/DELETE]\n', 1);
  if (local && maps.some((x) => x.local === local)) return ok('System error 85 has occurred.\n\nThe local device name is already in use.\n\n', 2);
  const userSw = sw.find((x) => /^\/u(ser)?:/i.test(x));
  let user = userSw ? userSw.replace(/^\/u(ser)?:/i, '').replace(/^.*\\/, '') : ctx.user.name;
  let password = (local ? pos[2] : pos[1]) ?? (userSw ? undefined : ctx.user.password ?? '');
  if (password === '*' || password === undefined) password = ctx.ask(`Enter the password for '${user}' to connect to '${m[1]}': `, true);
  let r = smbConnect(ctx.world, ctx.host, m[1], user, password, m[2]);
  // With the signed-in user's credentials refused, Windows asks for others.
  if (!r.ok && r.error === 'NT_STATUS_LOGON_FAILURE' && !userSw) {
    user = ctx.ask(`Enter the user name for '${m[1]}': `, false).trim().replace(/^.*\\/, '');
    password = ctx.ask(`Enter the password for ${m[1]}: `, true);
    r = smbConnect(ctx.world, ctx.host, m[1], user, password, m[2]);
  }
  if (!r.ok) {
    const [code, text] = SYS_ERR[r.error] ?? [53, 'The network path was not found.'];
    return ok(`System error ${code} has occurred.\n\n${text}\n\n`, 2);
  }
  maps.push({ local, remote, user, server: r.session.server.id, share: r.session.share!.name });
  return ok(DONE);
}

native({
  name: 'net', synopsis: 'net user | net localgroup | net start | net stop.',
  run(args, ctx) {
    const host = ctx.host;
    const w = host.win!;
    const sub = (args[0] ?? '').toLowerCase();
    const pos = args.slice(1).filter((a) => !a.startsWith('/'));
    const sw = args.slice(1).filter((a) => a.startsWith('/')).map((a) => a.toLowerCase());
    const denied = () => ok('System error 5 has occurred.\n\nAccess is denied.\n', 2);
    const findUser = (n: string) => Object.keys(host.users).find((u) => u.toLowerCase() === n.toLowerCase());
    if (sub === 'user') {
      if (!pos.length) return ok(['', `User accounts for \\\\${host.hostname.toUpperCase()}`, '', '-'.repeat(79), ...columns(Object.keys(host.users).sort()), DONE].join('\n'));
      const name = findUser(pos[0]);
      if (sw.includes('/add')) {
        if (!admin(ctx)) return denied();
        if (name) return ok('The account already exists.\n\nMore help is available by typing NET HELPMSG 2224.\n', 2);
        const pw = pos[1] === '*' ? ctx.ask('Type a password for the user: ', true) : pos[1] ?? null;
        host.users[pos[0]] = { name: pos[0], uid: 1000 + Object.keys(host.users).length + 1, gid: 513, primaryGroup: 'Users', groups: ['Users'], home: `C:\\Users\\${pos[0]}`, shell: 'powershell.exe', gecos: '', password: pw };
        winEvent(ctx.world, host, 'Security', 4720, 'Microsoft-Windows-Security-Auditing', `A user account was created.\n\nNew Account:\n\tAccount Name:\t\t${pos[0]}`);
        return ok(DONE);
      }
      if (!name) return ok('The user name could not be found.\n\nMore help is available by typing NET HELPMSG 2221.\n', 2);
      if (sw.includes('/delete')) {
        if (!admin(ctx)) return denied();
        delete host.users[name];
        return ok(DONE);
      }
      const active = sw.find((s) => s.startsWith('/active:'));
      if (active || pos[1]) {
        if (!admin(ctx)) return denied();
        if (active) setDisabled(host, name, active.endsWith(':no'));
        if (pos[1]) host.users[name].password = pos[1] === '*' ? ctx.ask('Type a password for the user: ', true) : pos[1];
        return ok(DONE);
      }
      const u = host.users[name];
      const row = (k: string, v: string) => `${k.padEnd(29)}${v}`;
      const local = u.groups.filter((g) => GROUPS[g]).map((g) => `*${g}`);
      return ok([row('User name', u.name), row('Full Name', ''), row('Comment', u.gecos), row('Account active', userDisabled(host, name) ? 'No' : 'Yes'), row('Account expires', 'Never'), '',
        row('Password required', 'Yes'), row('User may change password', 'Yes'), '', row('Workstations allowed', 'All'), row('Logon script', ''), row('User profile', ''), row('Home directory', ''), '',
        row('Local Group Memberships', local.slice(0, 2).map((g) => g.padEnd(21)).join('').trim()), ...(local.length > 2 ? [row('', local.slice(2).join('  '))] : []), row('Global Group memberships', '*None'), DONE].join('\n'));
    }
    if (sub === 'use') return netUse(args.slice(1), ctx);
    if (sub === 'localgroup') {
      if (!pos.length) return ok(['', `Aliases for \\\\${host.hostname.toUpperCase()}`, '', '-'.repeat(79), ...Object.keys(GROUPS).sort().map((g) => `*${g}`), DONE].join('\n'));
      const g = Object.keys(GROUPS).find((x) => x.toLowerCase() === pos[0].toLowerCase());
      if (!g) return ok('The specified local group does not exist.\n\nMore help is available by typing NET HELPMSG 3780.\n', 2);
      if (sw.includes('/add') || sw.includes('/delete')) {
        if (!admin(ctx)) return denied();
        const add = sw.includes('/add');
        for (const m of pos.slice(1)) {
          const k = findUser(m.replace(/^.*\\/, ''));
          if (!k) return ok('There is no such global user or group: ' + m + '.\n\nMore help is available by typing NET HELPMSG 3783.\n', 2);
          const u = host.users[k];
          if (add && u.groups.includes(g)) return ok('System error 1378 has occurred.\n\nThe specified account name is already a member of the group.\n', 2);
          if (!add && !u.groups.includes(g)) return ok('System error 1377 has occurred.\n\nThe specified account name is not a member of the group.\n', 2);
          u.groups = add ? [...u.groups, g] : u.groups.filter((x) => x !== g);
          winEvent(ctx.world, host, 'Security', add ? 4732 : 4733, 'Microsoft-Windows-Security-Auditing', `A member was ${add ? 'added to' : 'removed from'} a security-enabled local group.\n\nMember:\n\tAccount Name:\t\t${host.hostname.toUpperCase()}\\${k}\n\nGroup:\n\tGroup Name:\t\t${g}`);
        }
        return ok(DONE);
      }
      const members = Object.values(host.users).filter((u) => u.groups.includes(g)).map((u) => u.name);
      return ok([`Alias name     ${g}`, `Comment        ${GROUPS[g]}`, '', 'Members', '', '-'.repeat(79), ...members, DONE].join('\n'));
    }
    if (sub === 'start' || sub === 'stop') {
      if (!pos.length) {
        if (sub === 'stop') return ok('The syntax of this command is:\n\nNET STOP\nservice\n', 1);
        return ok(['These Windows services are started:', '', ...Object.values(w.services).filter((s) => s.status === 'Running').map((s) => `   ${s.displayName}`).sort(), '', DONE].join('\n'));
      }
      const n = pos.join(' ');
      const svc = Object.values(w.services).find((s) => s.name.toLowerCase() === n.toLowerCase() || s.displayName.toLowerCase() === n.toLowerCase());
      if (!svc) return ok('The service name is invalid.\n\nMore help is available by typing NET HELPMSG 2185.\n', 2);
      if (!admin(ctx)) return denied();
      if (sub === 'start') {
        if (svc.status === 'Running') return ok('The requested service has already been started.\n\nMore help is available by typing NET HELPMSG 2182.\n', 2);
        const r = startWinService(ctx.world, host, svc.name);
        if (!r.ok) return ok(r.error === 'disabled' ? 'System error 1058 has occurred.\n\nThe service cannot be started, either because it is disabled or because it has no enabled devices associated with it.\n' : 'System error 1068 has occurred.\n\nThe dependency service or group failed to start.\n', 2);
        return ok(`The ${svc.displayName} service is starting.\nThe ${svc.displayName} service was started successfully.\n`);
      }
      if (svc.status === 'Stopped') return ok(`The ${svc.displayName} service is not started.\n\nMore help is available by typing NET HELPMSG 3521.\n`, 2);
      if (svc.protected) return ok('System error 5 has occurred.\n\nAccess is denied.\n', 2);
      const deps = Object.values(w.services).filter((x) => x.dependsOn.includes(svc.name) && x.status === 'Running');
      const out: string[] = [];
      if (deps.length) {
        const ans = ctx.ask(`The following services are dependent on the ${svc.displayName} service.\nStopping the ${svc.displayName} service will also stop these services.\n\n${deps.map((d) => `   ${d.displayName}`).join('\n')}\n\nDo you want to continue this operation? (Y/N) [N]: `, false);
        if (!/^y/i.test(ans.trim())) return ok('', 2);
        for (const d of deps) { stopWinService(ctx.world, host, d.name); out.push(`The ${d.displayName} service is stopping.`, `The ${d.displayName} service was stopped successfully.`, ''); }
      }
      stopWinService(ctx.world, host, svc.name);
      out.push(`The ${svc.displayName} service is stopping.`, `The ${svc.displayName} service was stopped successfully.`, '');
      return ok(out.join('\n'));
    }
    return ok('The syntax of this command is:\n\nNET\n    [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |\n      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |\n      STATISTICS | STOP | TIME | USE | USER | VIEW ]\n', 1);
  },
});

// ---------------------------------------------------------------------------
// netsh advfirewall
// ---------------------------------------------------------------------------

function kv(args: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of args) {
    const m = /^([a-z]+)=(.*)$/i.exec(a);
    if (m) out[m[1].toLowerCase()] = m[2].replace(/^"(.*)"$/, '$1');
  }
  return out;
}

function profileBlock(ctx: PsCtx, p: FwProfile, onlyState: boolean): string[] {
  const s = ctx.host.win!.firewall.profiles[p];
  const out = ['', `${p} Profile Settings: `, '-'.repeat(70), `${'State'.padEnd(38)}${s.enabled ? 'ON' : 'OFF'}`];
  if (!onlyState) {
    out.push(`${'Firewall Policy'.padEnd(38)}${s.defaultInbound}Inbound,${s.defaultOutbound}Outbound`, `${'LocalFirewallRules'.padEnd(38)}N/A (GPO-store only)`, `${'LocalConSecRules'.padEnd(38)}N/A (GPO-store only)`, `${'InboundUserNotification'.padEnd(38)}Disable`, `${'RemoteManagement'.padEnd(38)}Disable`, `${'UnicastResponseToMulticast'.padEnd(38)}Enable`, '', 'Logging:', `${'LogAllowedConnections'.padEnd(38)}Disable`, `${'LogDroppedConnections'.padEnd(38)}${s.logBlocked ? 'Enable' : 'Disable'}`, `${'FileName'.padEnd(38)}%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log`, `${'MaxFileSize'.padEnd(38)}4096`);
  }
  return out;
}

function showRule(r: WinFwRule): string[] {
  const row = (k: string, v: string) => `${(k + ':').padEnd(38)}${v}`;
  return ['', row('Rule Name', r.displayName), '-'.repeat(70), row('Enabled', r.enabled ? 'Yes' : 'No'), row('Direction', r.direction === 'Inbound' ? 'In' : 'Out'), row('Profiles', r.profiles === 'Any' ? 'Domain,Private,Public' : r.profiles.join(',')),
    row('Grouping', r.group), row('LocalIP', 'Any'), row('RemoteIP', r.remoteAddress === 'Any' ? 'Any' : r.remoteAddress.join(',')), row('Protocol', r.protocol), ...(r.protocol === 'TCP' || r.protocol === 'UDP' ? [row('LocalPort', r.localPort === 'Any' ? 'Any' : r.localPort.join(',')), row('RemotePort', 'Any')] : []),
    row('Edge traversal', 'No'), row('Action', r.action)];
}

native({
  name: 'netsh', synopsis: 'netsh advfirewall show|set allprofiles ..., netsh advfirewall firewall add|delete|set|show rule ...',
  run(args, ctx) {
    const a = args.map((x) => x.toLowerCase());
    const w = ctx.host.win!;
    if (a[0] !== 'advfirewall') return ok(`The following command was not found: ${args.join(' ')}.\n\n[Infrastructure Lab: netsh advfirewall is simulated; use the NetTCPIP cmdlets (Get-NetIPAddress, Set-DnsClientServerAddress) for interface settings.]`, 1);
    const profileArg = (p: string): FwProfile[] | null => (p === 'allprofiles' ? FW_PROFILES : p === 'currentprofile' ? [w.adapters[0]?.category ?? 'Public'] : p === 'domainprofile' ? ['Domain'] : p === 'privateprofile' ? ['Private'] : p === 'publicprofile' ? ['Public'] : null);
    if (a[1] === 'show') {
      const ps = profileArg(a[2] ?? '');
      if (!ps) return ok('The syntax supplied for this command is not valid. Check help for the correct syntax.\n\nUsage: show allprofiles|currentprofile|domainprofile|privateprofile|publicprofile [state|firewallpolicy|logging]', 1);
      return ok([...ps.flatMap((p) => profileBlock(ctx, p, a[3] === 'state')), 'Ok.', ''].join('\n'));
    }
    if (a[1] === 'set') {
      const ps = profileArg(a[2] ?? '');
      if (!ps || a[3] !== 'state' || !['on', 'off'].includes(a[4] ?? '')) return ok('The syntax supplied for this command is not valid. Check help for the correct syntax.\n\nUsage: set allprofiles|currentprofile|domainprofile|privateprofile|publicprofile state on|off', 1);
      if (!admin(ctx)) return ok('The requested operation requires elevation (Run as administrator).\n', 1);
      for (const p of ps) w.firewall.profiles[p].enabled = a[4] === 'on';
      applyFirewall(ctx.host);
      return ok('Ok.\n');
    }
    if (a[1] === 'firewall') {
      const verb = a[2];
      const o = kv(args.slice(4));
      const match = (r: WinFwRule) => (o.name === undefined || o.name.toLowerCase() === 'all' || r.displayName.toLowerCase() === o.name.toLowerCase()) && (o.group === undefined || r.group.toLowerCase() === o.group.toLowerCase()) && (o.dir === undefined || r.direction.toLowerCase().startsWith(o.dir.toLowerCase()));
      if (a[3] !== 'rule' || !['add', 'delete', 'set', 'show'].includes(verb)) return ok('The following command was not found: ' + args.join(' ') + '.', 1);
      if (verb === 'show') {
        if (!o.name) return ok('One or more essential parameters were not entered.\nVerify the required parameters, and reenter them.\n', 1);
        const rules = w.firewall.rules.filter(match);
        if (!rules.length) return ok('No rules match the specified criteria.\n', 1);
        return ok([...rules.flatMap(showRule), 'Ok.', ''].join('\n'));
      }
      if (!admin(ctx)) return ok('The requested operation requires elevation (Run as administrator).\n', 1);
      if (verb === 'add') {
        if (!o.name || !o.dir || !o.action) return ok('One or more essential parameters were not entered.\nVerify the required parameters, and reenter them.\n', 1);
        const proto = (o.protocol ?? 'any').toUpperCase();
        const protocol: WinFwRule['protocol'] = proto === 'TCP' ? 'TCP' : proto === 'UDP' ? 'UDP' : proto.startsWith('ICMPV4') ? 'ICMPv4' : proto.startsWith('ICMPV6') ? 'ICMPv6' : 'Any';
        if (o.localport && protocol !== 'TCP' && protocol !== 'UDP') return ok('A specified port value is not valid.\n\nUsage: add rule name=<string> dir=in|out action=allow|block|bypass [protocol=0-255|icmpv4|icmpv6|icmpv4:type,code|icmpv6:type,code|tcp|udp|any] [localport=0-65535|any]', 1);
        const icmp = /^icmpv[46]:(\d+),/.exec(o.protocol?.toLowerCase() ?? '')?.[1];
        w.firewall.rules.push({ name: `{netsh-${w.firewall.rules.length}}`, displayName: o.name, group: '', direction: o.dir.toLowerCase() === 'out' ? 'Outbound' : 'Inbound', action: o.action.toLowerCase() === 'block' ? 'Block' : 'Allow', enabled: (o.enable ?? 'yes').toLowerCase() !== 'no', profiles: !o.profile || o.profile === 'any' ? 'Any' : o.profile.split(',').map((p) => FW_PROFILES.find((x) => x.toLowerCase() === p.trim().toLowerCase())!).filter(Boolean), protocol, localPort: o.localport ? o.localport.split(',') : 'Any', remoteAddress: o.remoteip ? o.remoteip.split(',') : 'Any', icmpType: icmp });
        winEvent(ctx.world, ctx.host, 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 2004, 'Microsoft-Windows-Windows Firewall With Advanced Security', `A rule has been added to the Windows Defender Firewall exception list.\n\nAdded Rule:\n\tRule Name:\t${o.name}`);
        applyFirewall(ctx.host);
        return ok('Ok.\n');
      }
      if (!o.name && !o.group) return ok('One or more essential parameters were not entered.\nVerify the required parameters, and reenter them.\n', 1);
      const rules = w.firewall.rules.filter(match);
      if (!rules.length) return ok('No rules match the specified criteria.\n', 1);
      if (verb === 'delete') {
        w.firewall.rules = w.firewall.rules.filter((r) => !rules.includes(r));
        applyFirewall(ctx.host);
        return ok(`\nDeleted ${rules.length} rule(s).\nOk.\n`);
      }
      const nw = args.findIndex((x) => x.toLowerCase() === 'new');
      if (nw < 0) return ok('One or more essential parameters were not entered.\nVerify the required parameters, and reenter them.\n', 1);
      const n = kv(args.slice(nw + 1));
      for (const r of rules) {
        if (n.enable) r.enabled = n.enable.toLowerCase() === 'yes';
        if (n.action) r.action = n.action.toLowerCase() === 'block' ? 'Block' : 'Allow';
        if (n.localport) r.localPort = n.localport.toLowerCase() === 'any' ? 'Any' : n.localport.split(',');
        if (n.remoteip) r.remoteAddress = n.remoteip.toLowerCase() === 'any' ? 'Any' : n.remoteip.split(',');
      }
      applyFirewall(ctx.host);
      return ok(`\nUpdated ${rules.length} rule(s).\nOk.\n`);
    }
    return ok('The following command was not found: ' + args.join(' ') + '.', 1);
  },
});

// ---------------------------------------------------------------------------
// reg, qwinsta, gpupdate
// ---------------------------------------------------------------------------

const REG_ROOT: Record<string, string> = { hklm: 'HKLM:', hkey_local_machine: 'HKLM:', hkcu: 'HKCU:', hkey_current_user: 'HKCU:' };

/** "HKLM\SYSTEM\..." (reg.exe syntax) → the registry key name the model uses. */
function regPath(p: string): string | null {
  const m = /^([A-Za-z_]+)\\?(.*)$/.exec(p);
  if (!m || !REG_ROOT[m[1].toLowerCase()]) return null;
  return regKey(`${REG_ROOT[m[1].toLowerCase()]}\\${m[2]}`);
}

function regLine(name: string, v: string | number): string {
  return typeof v === 'number' ? `    ${name}    REG_DWORD    0x${v.toString(16)}` : `    ${name}    REG_SZ    ${v}`;
}

function fullName(key: string): string {
  return key.replace(/^HKLM:/, 'HKEY_LOCAL_MACHINE').replace(/^HKCU:/, 'HKEY_CURRENT_USER');
}

native({
  name: 'reg', synopsis: 'Registry tool: reg query KEY [/v NAME], reg add KEY /v NAME /t REG_DWORD /d DATA /f, reg export KEY FILE, reg import FILE.',
  run(args, ctx) {
    const host = ctx.host;
    const w = host.win!;
    const verb = (args[0] ?? '').toLowerCase();
    const flag = (f: string) => { const i = args.findIndex((a) => a.toLowerCase() === f); return i >= 0 ? args[i + 1] : undefined; };
    const usage = 'ERROR: Invalid syntax.\nType "REG /?" for usage.';
    const notFound = 'ERROR: The system was unable to find the specified registry key or value.';
    if (!['query', 'add', 'export', 'import'].includes(verb)) return ok(usage, 1);
    if (verb === 'import') {
      if (!admin(ctx)) return ok('ERROR: Error accessing the registry.', 1);
      const file = args[1] ? (/^[A-Za-z]:\\/.test(args[1]) ? args[1] : `${ctx.session.cwd.replace(/\\$/, '')}\\${args[1]}`) : '';
      const k = Object.keys(host.fs).find((x) => x.toLowerCase() === file.toLowerCase());
      const text = k ? readFile(host, k) : undefined;
      if (text === undefined) return ok('ERROR: Error opening the file. There may be a disk or file system error.', 1);
      let cur: string | null = null;
      for (const line of text.split(/\r?\n/)) {
        const km = /^\[(.*)\]$/.exec(line.trim());
        if (km) { cur = regPath(km[1]); if (cur) w.registry[findReg(host, cur) ?? cur] ??= {}; continue; }
        const vm = /^"([^"]+)"=(?:dword:([0-9a-fA-F]{8})|"(.*)")$/.exec(line.trim());
        if (cur && vm) {
          const key = findReg(host, cur) ?? cur;
          w.registry[key][vm[1]] = vm[2] !== undefined ? parseInt(vm[2], 16) : vm[3];
          regValueChanged(ctx.world, host, key, vm[1]);
        }
      }
      return ok('The operation completed successfully.');
    }
    const keyArg = args[1] ?? '';
    const key = regPath(keyArg);
    if (!key) return ok('ERROR: Invalid key name.\nType "REG QUERY /?" for usage.', 1);
    const real = findReg(host, key);
    if (verb === 'query') {
      if (!real) return ok(notFound, 1);
      const vals = w.registry[real];
      const name = flag('/v');
      const shown = name ? Object.keys(vals).filter((n) => n.toLowerCase() === name.toLowerCase()) : Object.keys(vals);
      if (name && !shown.length) return ok(notFound, 1);
      const subs = name ? [] : Object.keys(w.registry).filter((k) => k.toLowerCase().startsWith(real.toLowerCase() + '\\') && !k.slice(real.length + 1).includes('\\') && !k.startsWith('__'));
      return ok(['', fullName(real), ...shown.map((n) => regLine(n, vals[n])), '', ...subs.map(fullName)].join('\n'));
    }
    if (verb === 'export') {
      if (!real) return ok(notFound, 1);
      const file = args[2];
      if (!file) return ok(usage, 1);
      const keys = Object.keys(w.registry).filter((k) => k.toLowerCase() === real.toLowerCase() || k.toLowerCase().startsWith(real.toLowerCase() + '\\'));
      const body = ['Windows Registry Editor Version 5.00', '', ...keys.flatMap((k) => [`[${fullName(k)}]`, ...Object.entries(w.registry[k]).map(([n, v]) => (typeof v === 'number' ? `"${n}"=dword:${v.toString(16).padStart(8, '0')}` : `"${n}"="${v}"`)), ''])].join('\r\n');
      const path = /^[A-Za-z]:\\/.test(file) ? file : `${ctx.session.cwd.replace(/\\$/, '')}\\${file}`;
      const parent = path.slice(0, path.lastIndexOf('\\'));
      if (parent.length > 2 && !Object.keys(host.fs).some((x) => x.toLowerCase() === parent.toLowerCase())) return ok('ERROR: The system was unable to find the specified registry key or value.', 1);
      writeFile(host, path, body, ctx.world.clock, { owner: ctx.user.name, group: ctx.user.name });
      return ok('The operation completed successfully.');
    }
    // add
    if (!admin(ctx)) return ok('ERROR: Access is denied.', 1);
    const name = flag('/v');
    const type = (flag('/t') ?? 'REG_SZ').toUpperCase();
    const data = flag('/d') ?? '';
    const k = real ?? key;
    w.registry[k] ??= {};
    if (name) {
      if (Object.keys(w.registry[k]).some((n) => n.toLowerCase() === name.toLowerCase()) && !args.some((a) => a.toLowerCase() === '/f')) {
        const ans = ctx.ask(`Value ${name} exists, overwrite(Yes/No)? `, false);
        if (!/^y/i.test(ans.trim())) return ok('The operation was cancelled by the user.');
      }
      const existing = Object.keys(w.registry[k]).find((n) => n.toLowerCase() === name.toLowerCase()) ?? name;
      if (type === 'REG_DWORD') {
        const n = /^0x/i.test(data) ? parseInt(data, 16) : Number(data);
        if (!Number.isFinite(n)) return ok('ERROR: Invalid syntax.\nType "REG ADD /?" for usage.', 1);
        w.registry[k][existing] = n;
      } else w.registry[k][existing] = data;
      regValueChanged(ctx.world, host, k, existing);
    }
    return ok('The operation completed successfully.');
  },
});

native({
  name: 'qwinsta', synopsis: 'Lists Remote Desktop sessions and listeners (query session).',
  run(_args, ctx) {
    const host = ctx.host;
    const port = host.win!.rdpPort ?? Number(host.win!.registry[RDP_TCP_KEY]?.PortNumber ?? 3389);
    const listening = winListeners(host).some((l) => l.service === 'TermService' && l.port === port);
    const rows = [' SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE', ' services                                    0  Disc', `>console           ${ctx.user.name.padEnd(20)}     1  Active`];
    if (listening) rows.push(' rdp-tcp                                 65536  Listen');
    return ok(rows.join('\n'));
  },
});

native({
  name: 'gpupdate', synopsis: 'Refreshes Group Policy (/force) from a domain controller (local policy only on a workgroup server).',
  run(_args, ctx) {
    const m = ctx.host.win!.domain;
    if (m && !locateDc(ctx.world, ctx.host, m.domain).ok) {
      return ok('Updating policy...\n\nComputer policy could not be updated successfully. The following errors were encountered:\n\nThe processing of Group Policy failed. Windows could not resolve the computer name. This could be caused by one of more of the following: \na) Name Resolution failure on the current domain controller. \nb) Active Directory Replication Latency (an account created on another domain controller has not replicated to the current domain controller).\nUser Policy could not be updated successfully. The following errors were encountered:\n\nThe processing of Group Policy failed. Windows could not resolve the user name.\n\nTo diagnose the failure, review the event log or run GPRESULT /H GPReport.html from the command line to access information about Group Policy results.', 1);
    }
    return ok('Updating policy...\n\nComputer Policy update has completed successfully.\nUser Policy update has completed successfully.\n');
  },
});

native({
  name: 'gpresult', synopsis: 'Displays the Resultant Set of Policy (/r).',
  run(args, ctx) {
    if (!args.some((a) => /^[/-]r$/i.test(a))) return ok('ERROR: Invalid syntax.\nType "GPRESULT /?" for usage.', 1);
    const h = ctx.host;
    const w = h.win!;
    const m = w.domain;
    const loc = m ? locateDc(ctx.world, h, m.domain) : null;
    const name = h.hostname.toUpperCase();
    const dn = m ? `CN=${name},${w.ad ? 'OU=Domain Controllers' : 'CN=Computers'},${domainDn(m.domain)}` : name;
    return ok(['', 'Microsoft (R) Windows (R) Operating System Group Policy Result tool v2.0', '\u00a9 Microsoft Corporation. All rights reserved.', '', `Created on ${new Date(ctx.world.clock).toLocaleDateString('en-US', { timeZone: 'UTC' })} at ${new Date(ctx.world.clock).toLocaleTimeString('en-US', { timeZone: 'UTC' })}`, '', '',
      `RSOP data for ${name}\\${ctx.user.name} on ${name} : Logging Mode`, '-'.repeat(58), '', `OS Configuration:            ${w.ad ? 'Primary Domain Controller' : m ? 'Member Server' : 'Standalone Server'}`, `OS Version:                  10.0.${w.build}`,
      `Site Name:                   ${m ? 'Default-First-Site-Name' : 'N/A'}`, 'Roaming Profile:             N/A', `Local Profile:               ${ctx.user.home}`, 'Connected over a slow link?: No', '', '',
      'COMPUTER SETTINGS', '------------------', `    ${dn}`, `    Last time Group Policy was applied: ${new Date(h.bootTime).toLocaleString('en-US', { timeZone: 'UTC' })}`,
      `    Group Policy was applied from:      ${loc?.ok ? loc.name : 'N/A'}`, '    Group Policy slow link threshold:   500 kbps', `    Domain Name:                        ${m?.netbios ?? name}`, `    Domain Type:                        ${m ? 'Windows 2008 or later' : '<Local Computer>'}`, '',
      '    Applied Group Policy Objects', '    -----------------------------', ...(m ? ['        Default Domain Policy', ...(w.ad ? ['        Default Domain Controllers Policy'] : [])] : ['        Local Group Policy']), '',
      '    The computer is a part of the following security groups', '    ---------------------------------------------------', '        BUILTIN\\Administrators', '        Everyone', '        Authenticated Users', ...(m ? ['        Domain Computers'] : []), ''].join('\n'));
  },
});

// ---------------------------------------------------------------------------
// nltest
// ---------------------------------------------------------------------------

native({
  name: 'nltest', synopsis: 'Domain controller and secure channel diagnostics: /sc_query:DOMAIN, /sc_verify:DOMAIN, /dsgetdc:DOMAIN.',
  run(args, ctx) {
    const a = args[0] ?? '';
    const m = /^\/(sc_query|sc_verify|dsgetdc|sc_reset):(.+)$/i.exec(a);
    if (!m) return ok('Usage: nltest [/OPTIONS]\n\n    /SERVER:<ServerName> - Specify <ServerName>\n\n    /SC_QUERY:<DomainName> - Query secure channel for <Domain> on <ServerName>\n    /SC_RESET:<DomainName>[\\<DcName>] - Reset secure channel for <Domain> on <ServerName> to <DcName>\n    /SC_VERIFY:<DomainName> - Verify secure channel for <Domain> on <ServerName>\n    /DSGETDC:<DomainName> - Call DsGetDcName', a ? 87 : 0);
    const op = m[1].toLowerCase();
    const dom = m[2].toLowerCase();
    const host = ctx.host;
    const mem = host.win!.domain;
    const known = mem && (dom === mem.domain || dom === mem.netbios.toLowerCase());
    if (op === 'dsgetdc') {
      const loc = locateDc(ctx.world, host, mem && dom === mem.netbios.toLowerCase() ? mem.domain : dom);
      if (!loc.ok) return ok('Getting DC name failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN', 1355);
      return ok([`           DC: \\\\${loc.name}`, `      Address: \\\\${loc.ip}`, `     Dom Guid: 7c2b5e0e-4f0a-4f3c-9d7a-${loc.dc.id.padEnd(12, '0').slice(0, 12)}`, `     Dom Name: ${loc.dc.win!.ad!.domain}`, `  Forest Name: ${loc.dc.win!.ad!.domain}`,
        ' Dc Site Name: Default-First-Site-Name', 'Our Site Name: Default-First-Site-Name', '        Flags: PDC GC DS LDAP KDC TIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST', 'The command completed successfully'].join('\n'));
    }
    if (!known) return ok(`Flags: 0\nTrusted DC Name\nTrusted DC Connection Status Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN\nThe command completed successfully`);
    if (op === 'sc_reset' && !admin(ctx)) return ok('I_NetLogonControl failed: Status = 5 0x5 ERROR_ACCESS_DENIED', 5);
    const ch = secureChannel(ctx.world, host);
    const dcName = ch.dc?.ok ? `\\\\${ch.dc.name}` : '';
    const status = ch.state === 'ok' ? '0 0x0 NERR_Success' : ch.state === 'no-dc' ? '1311 0x51f ERROR_NO_LOGON_SERVERS' : '5 0x5 ERROR_ACCESS_DENIED';
    const flags = ch.state === 'ok' ? '30 HAS_IP  HAS_TIMESERV' : '0';
    const lines = [`Flags: ${flags}`, `Trusted DC Name ${ch.state === 'no-dc' ? '' : dcName}`.trimEnd(), `Trusted DC Connection Status Status = ${ch.state === 'denied' && op === 'sc_query' ? '0 0x0 NERR_Success' : status}`];
    if (op === 'sc_verify') lines.push(`Trust Verification Status = ${status}`);
    lines.push('The command completed successfully');
    return ok(lines.join('\n'), op === 'sc_verify' && ch.state !== 'ok' ? 1 : 0);
  },
});
