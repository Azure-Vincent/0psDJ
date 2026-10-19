// Parsers for persistent network configuration on Debian-style hosts:
//   /etc/network/interfaces (ifupdown), /etc/resolv.conf, /etc/hosts.

import { parseCidr, parseIp } from '../net/ip';

export interface IfaceConfig {
  name: string;
  auto: boolean;
  method: 'static' | 'dhcp' | 'loopback' | 'manual';
  address?: string;
  prefix?: number;
  gateway?: string;
  routes: { dest: string; via: string }[];
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
      case 'iface':
        cur = { name: parts[1], auto: false, method: (parts[3] as IfaceConfig['method']) ?? 'manual', routes: [] };
        ifaces.push(cur);
        break;
      case 'address': {
        if (!cur) { errors.push(`line ${i + 1}: option outside stanza`); break; }
        const c = parseCidr(parts[1]);
        if (!c || !parts[1].includes('/')) { errors.push(`line ${i + 1}: invalid address ${parts[1]}`); break; }
        cur.address = parts[1].split('/')[0];
        cur.prefix = c.prefix;
        break;
      }
      case 'netmask': {
        if (!cur) break;
        const m = parseIp(parts[1]);
        if (m !== null) cur.prefix = m.toString(2).replace(/0+$/, '').length;
        break;
      }
      case 'gateway':
        if (!cur) break;
        if (parseIp(parts[1]) === null) errors.push(`line ${i + 1}: invalid gateway ${parts[1]}`);
        else cur.gateway = parts[1];
        break;
      case 'up':
      case 'post-up': {
        // e.g. "up ip route add 10.0.30.0/24 via 10.0.20.1"
        const m = /ip route add (\S+) via (\S+)/.exec(line);
        if (cur && m) cur.routes.push({ dest: m[1], via: m[2] });
        break;
      }
      default:
        break;
    }
  });
  for (const f of ifaces) f.auto = auto.has(f.name);
  return { ifaces, errors };
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
  }
  return out;
}
