// Switch and IPv6 neighbour-discovery tools: `bridge` (iproute2), `ifreload`
// (ifupdown2) and `rdisc6` (ndisc6).

import { formatBridgeVlans, recomputeL2 } from '../sim/l2';
import { applyNetworkConfig } from '../sim/services';
import { routerSolicit } from '../sim/slaac';
import { type CommandDef, err, ok, parseFlags } from './types';

const hex = (n: number, w: number) => `0x${n.toString(16).padStart(w, '0')}`;

export const bridge: CommandDef = {
  name: 'bridge',
  summary: 'show / change VLAN membership and the MAC table of a Linux bridge (switch)',
  usage: 'bridge vlan show | bridge vlan add|del dev PORT vid VID [pvid] [untagged] | bridge link show | bridge fdb show',
  run(args, ctx) {
    const h = ctx.host;
    if (!h.bridge) return err(h.kind === 'switch' ? 'bridge: no bridge configured (check /etc/network/interfaces, then ifreload -a)' : 'This host has no bridge (it is not a switch).', 1);
    const [obj, sub = 'show', ...rest] = args;
    if (obj === 'vlan' || obj === 'v') {
      if (sub === 'show' || sub === 'list') return ok(formatBridgeVlans(h));
      if (sub === 'add' || sub === 'del' || sub === 'delete') {
        if (ctx.user.uid !== 0) return err('RTNETLINK answers: Operation not permitted', 2);
        const dev = rest[rest.indexOf('dev') + 1];
        const vid = Number(rest[rest.indexOf('vid') + 1]);
        if (rest.indexOf('dev') < 0 || rest.indexOf('vid') < 0) return err('Usage: bridge vlan { add | del } vid VLAN_ID dev DEV [ pvid ] [ untagged ]', 255);
        const port = h.bridge.ports[dev];
        if (!port) return err(dev && h.ifaces.some((i) => i.name === dev) ? `RTNETLINK answers: Operation not supported (${dev} is not a bridge port)` : `Cannot find device "${dev}"`, 1);
        if (!Number.isInteger(vid) || vid < 1 || vid > 4094) return err(`Invalid VLAN id "${rest[rest.indexOf('vid') + 1]}"`, 255);
        if (sub === 'add') {
          if (!port.vids.includes(vid)) port.vids.push(vid);
          if (rest.includes('pvid')) {
            if (port.pvid !== null && port.pvid !== vid) port.untagged = port.untagged.filter((v) => v !== port.pvid || rest.includes('untagged'));
            port.pvid = vid;
          }
          if (rest.includes('untagged')) { if (!port.untagged.includes(vid)) port.untagged.push(vid); }
          else port.untagged = port.untagged.filter((v) => v !== vid);
        } else {
          if (!port.vids.includes(vid)) return err('RTNETLINK answers: No such file or directory', 2);
          port.vids = port.vids.filter((v) => v !== vid);
          port.untagged = port.untagged.filter((v) => v !== vid);
          if (port.pvid === vid) port.pvid = null;
        }
        recomputeL2(ctx.world);
        return ok('');
      }
      return err(`Command "${sub}" is unknown, try "bridge vlan help".`, 255);
    }
    if (obj === 'link' || obj === 'l') {
      return ok(Object.keys(h.bridge.ports).map((p) => {
        const i = h.ifaces.findIndex((x) => x.name === p);
        const up = h.ifaces[i]?.up;
        return `${i + 1}: ${p}: <BROADCAST,MULTICAST${up ? ',UP,LOWER_UP' : ''}> mtu 1500 master ${h.bridge!.name} state ${up ? 'forwarding' : 'disabled'} priority 32 cost 100 `;
      }).join('\n'));
    }
    if (obj === 'fdb') {
      return ok((h.bridge.fdb ?? []).map((e) => `${e.mac} dev ${e.port} vlan ${e.vlan} master ${h.bridge!.name} `).join('\n'));
    }
    return err('Usage: bridge [ OPTIONS ] OBJECT { COMMAND | help }\nwhere  OBJECT := { link | fdb | vlan }', 255);
  },
};

export const ifreload: CommandDef = {
  name: 'ifreload',
  summary: 'ifupdown2: re-apply /etc/network/interfaces to the running system',
  usage: 'ifreload -a',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('error: must be root to run this command', 1);
    if (!args.includes('-a')) return err('usage: ifreload -a (reload all auto interfaces)', 1);
    const errors = applyNetworkConfig(ctx.world, ctx.host);
    return errors.length ? err(errors.map((e) => `error: ${e}`).join('\n'), 1) : ok('');
  },
};

export const rdisc6: CommandDef = {
  name: 'rdisc6',
  summary: 'IPv6 router discovery: send a Router Solicitation and print the advertisements (ndisc6)',
  usage: 'rdisc6 IFACE',
  run(args, ctx) {
    const { rest } = parseFlags(args);
    const name = rest[0];
    if (!name) return err('Usage: rdisc6 [options] [IPv6 address] <interface>', 1);
    const iface = ctx.host.ifaces.find((i) => i.name === name);
    if (!iface) return err(`${name}: No such device`, 1);
    if (ctx.user.uid !== 0) return err('rdisc6: Operation not permitted (raw ICMPv6 socket needs root)', 1);
    const out = [`Soliciting ff02::2 (ff02::2) on ${name}...`, ''];
    if (!iface.up || !(iface.addrs6 ?? []).some((a) => a.scope === 'link')) return err(`${out[0]}\nSending ICMPv6 packet: Network is unreachable`, 1);
    const r = routerSolicit(ctx.world, ctx.host, iface);
    if (!r.routers.length) {
      ctx.world.clock += 3000;
      return err([out[0], 'Timed out.', 'Timed out.', 'Timed out.', 'No response.'].join('\n'), 2);
    }
    for (const rt of r.routers) {
      const lt = rt.cfg.routerLifetime;
      out.push(
        `Hop limit                 :           64 (      0x40)`,
        'Stateful address conf.    :           No',
        'Stateful other conf.      :           No',
        'Mobile home agent         :           No',
        'Router preference         :       medium',
        'Neighbor discovery proxy  :           No',
        `Router lifetime           : ${String(lt).padStart(12)} (${hex(lt, 8)}) seconds`,
        'Reachable time            :  unspecified (0x00000000)',
        'Retransmit time           :  unspecified (0x00000000)',
      );
      for (const p of rt.cfg.prefixes) {
        out.push(` Prefix                   : ${p.prefix}`, `  On-link                 : ${(p.onLink ? 'Yes' : 'No').padStart(12)}`, `  Autonomous address conf.: ${(p.autonomous ? 'Yes' : 'No').padStart(12)}`,
          `  Valid time              : ${'86400'.padStart(12)} (0x00015180) seconds`, `  Pref. time              : ${'14400'.padStart(12)} (0x00003840) seconds`);
      }
      for (const d of rt.cfg.rdnss) out.push(` Recursive DNS server     : ${d}`, `  DNS server lifetime     : ${'600'.padStart(12)} (0x00000258) seconds`);
      out.push(` Source link-layer address: ${rt.mac.toUpperCase()}`, ` from ${rt.address}`, '');
    }
    return ok(out.join('\n').trimEnd());
  },
};
