// Parsers for persistent network configuration on Debian-style hosts:
//   /etc/network/interfaces (ifupdown, including inet6 stanzas, VLAN sub-interfaces
//   and the ifupdown2 bridge-* options used on the switch), /etc/resolv.conf, /etc/hosts.

import { parseCidr, parseIp } from '../net/ip';
import { canonicalIp6, parseCidr6, parseIp6 } from '../net/ip6';

export interface IfaceConfig {
  name: string;
  auto: boolean;
  /** Address family of the stanza ("iface eth0 inet6 static"); ifupdown2 also allows bare "iface swp1". */
  family: 'inet' | 'inet6';
  method: 'static' | 'dhcp' | 'loopback' | 'manual' | 'auto';
  address?: string;
  prefix?: number;
  gateway?: string;
  routes: { dest: string; via: string }[];
  /** "vlan-raw-device eth3" (implied by the name eth3.30 when absent). */
  vlanRawDevice?: string;
  /** Every option line, by keyword (e.g. bridge-ports, bridge-vids, bridge-access). */
  options: Record<string, string>;
}

export interface IfupdownResult {
  ifaces: IfaceConfig[];
  errors: string[];
}

export function parseInterfaces(text: string): IfupdownResult {
  const ifaces: IfaceConfig[] = [];
  const auto = new Set<string>();
  const errors: string[] = [];
  let cur: IfaceConfig | null = null;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    const parts = line.split(/\s+/);
    switch (parts[0]) {
      case 'auto':
      case 'allow-hotplug':
        parts.slice(1).forEach((n) => auto.add(n));
        break;
      case 'source':
        break;
      case 'iface': {
        const fam = parts[2] === 'inet6' ? 'inet6' : 'inet';
        cur = { name: parts[1], auto: false, family: fam, method: (parts[3] as IfaceConfig['method']) ?? 'manual', routes: [], options: {} };
        ifaces.push(cur);
        break;
      }
      case 'address': {
        if (!cur) { errors.push(`line ${i + 1}: option outside stanza`); break; }
        const v6 = cur.family === 'inet6';
        const ok = parts[1] && (v6 ? parseCidr6(parts[1]) : parseCidr(parts[1]));
        if (!ok || (!v6 && !parts[1].includes('/')) || (v6 && parts[1].includes('.'))) { errors.push(`line ${i + 1}: invalid address ${parts[1]}`); break; }
        cur.address = v6 ? canonicalIp6(parts[1].split('/')[0])! : parts[1].split('/')[0];
        cur.prefix = parts[1].includes('/') ? Number(parts[1].split('/')[1]) : 64;
        break;
      }
      case 'netmask': {
        if (!cur) break;
        if (cur.family === 'inet6') { cur.prefix = Number(parts[1]); break; }
        const m = parseIp(parts[1]);
        if (m !== null) cur.prefix = m.toString(2).replace(/0+$/, '').length;
        break;
      }
      case 'gateway':
        if (!cur) break;
        if (cur.family === 'inet6' ? parseIp6(parts[1]) === null : parseIp(parts[1]) === null) errors.push(`line ${i + 1}: invalid gateway ${parts[1]}`);
        else cur.gateway = cur.family === 'inet6' ? canonicalIp6(parts[1])! : parts[1];
        break;
      case 'vlan-raw-device':
      case 'vlan_raw_device':
        if (cur) cur.vlanRawDevice = parts[1];
        break;
      case 'up':
      case 'post-up': {
        // e.g. "up ip route add 10.0.30.0/24 via 10.0.20.1"
        const m = /ip (?:-6 )?route add (\S+) via (\S+)/.exec(line);
        if (cur && m) cur.routes.push({ dest: m[1], via: m[2] });
        break;
      }
      default:
        if (cur) cur.options[parts[0]] = parts.slice(1).join(' ');
        break;
    }
  });
  for (const f of ifaces) f.auto = auto.has(f.name);
  return { ifaces, errors };
}

/** VLAN id and parent for "eth3.30" style names or an explicit vlan-raw-device. */
export function vlanOf(cfg: Pick<IfaceConfig, 'name' | 'vlanRawDevice'>): { parent: string; id: number } | null {
  const m = /^(.+)\.(\d+)$/.exec(cfg.name);
  if (m) return { parent: cfg.vlanRawDevice ?? m[1], id: Number(m[2]) };
  const v = /^vlan(\d+)$/.exec(cfg.name);
  if (v && cfg.vlanRawDevice) return { parent: cfg.vlanRawDevice, id: Number(v[1]) };
  return null;
}

export interface ResolvConf {
  nameservers: string[];
  search: string[];
  timeout: number;
  attempts: number;
}

export function parseResolvConf(text: string | undefined): ResolvConf {
  const rc: ResolvConf = { nameservers: [], search: [], timeout: 5, attempts: 2 };
  for (const raw of (text ?? '').split('\n')) {
    const line = raw.replace(/[#;].*$/, '').trim();
    const [k, ...v] = line.split(/\s+/);
    if (k === 'nameserver' && v[0] && rc.nameservers.length < 3) rc.nameservers.push(v[0]);
    if (k === 'search' || k === 'domain') rc.search = v;
    if (k === 'options') {
      for (const o of v) {
        const m = /^(timeout|attempts):(\d+)$/.exec(o);
        if (m) rc[m[1] as 'timeout' | 'attempts'] = Number(m[2]);
      }
    }
  }
  return rc;
}

export function parseHostsFile(text: string | undefined): { ip: string; names: string[] }[] {
  const out: { ip: string; names: string[] }[] = [];
  for (const raw of (text ?? '').split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const [ip, ...names] = line.split(/\s+/);
    if (parseIp(ip) !== null) out.push({ ip, names });
    else if (parseIp6(ip) !== null) out.push({ ip: canonicalIp6(ip)!, names });
  }
  return out;
}
