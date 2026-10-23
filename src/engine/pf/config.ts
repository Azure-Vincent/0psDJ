// pfSense's configuration (/conf/config.xml) as a typed model: interfaces,
// gateways and static routes, aliases, firewall rules, port forwards and
// outbound NAT. fromXml() reads the file the way pfSense's config loader does
// (missing optional elements take their defaults); toXml() writes it back in
// pfSense's layout, so the webConfigurator and the CLI tools edit the same file.

import { child, children, el, parseXml, printXml, textOf, type XmlNode } from './xml';

export const PF_CONFIG = '/conf/config.xml';

export interface PfIface {
  /** Config key: wan, lan, opt1, opt2... */
  key: string;
  /** Physical interface (vtnet0...). */
  if: string;
  descr: string;
  enable: boolean;
  ipaddr: string | null;
  subnet: number | null;
  /** Name of the gateway (WAN). */
  gateway?: string;
  blockpriv?: boolean;
  blockbogons?: boolean;
}

export interface PfGateway { name: string; interface: string; gateway: string; descr: string; defaultgw: boolean }
export interface PfRoute { network: string; gateway: string; descr: string }
export interface PfAlias { name: string; type: 'host' | 'network' | 'port'; address: string[]; descr: string }

/** <source>/<destination>: any, an interface macro (lan, lanip, wanip, (self)...) or an address/alias, with an optional port. */
export interface PfAddr {
  any?: boolean;
  network?: string;
  address?: string;
  port?: string;
  not?: boolean;
}

export interface PfRule {
  tracker: string;
  type: 'pass' | 'block' | 'reject';
  interface: string;
  /** tcp, udp, tcp/udp, icmp; undefined = any. */
  protocol?: string;
  icmptype?: string;
  source: PfAddr;
  destination: PfAddr;
  descr: string;
  disabled: boolean;
  log: boolean;
  /** Created together with a port forward ("Add associated filter rule"). */
  associatedRuleId?: string;
}

export interface PfNatRule {
  interface: string;
  protocol: string;
  source: PfAddr;
  destination: PfAddr;
  target: string;
  localPort: string;
  descr: string;
  disabled: boolean;
  associatedRuleId?: string;
}

export interface PfOutboundRule {
  interface: string;
  source: string;
  destination: string;
  /** Translation address; '' = the interface address. */
  target: string;
  descr: string;
  disabled: boolean;
}

export interface PfConfig {
  hostname: string;
  domain: string;
  dnsservers: string[];
  sshEnabled: boolean;
  /** Anti-lockout rule on LAN (webConfigurator/SSH always reachable from LAN). */
  antiLockout: boolean;
  interfaces: PfIface[];
  gateways: PfGateway[];
  routes: PfRoute[];
  aliases: PfAlias[];
  filter: PfRule[];
  nat: PfNatRule[];
  outbound: { mode: 'automatic' | 'hybrid' | 'advanced' | 'disabled'; rules: PfOutboundRule[] };
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

const flag = (n: XmlNode | undefined, name: string) => !!child(n, name);

function addrFrom(n: XmlNode | undefined): PfAddr {
  const a: PfAddr = {};
  if (!n) return { any: true };
  if (flag(n, 'any')) a.any = true;
  const net = textOf(n, 'network');
  if (net) a.network = net;
  const addr = textOf(n, 'address');
  if (addr) a.address = addr;
  const port = textOf(n, 'port');
  if (port) a.port = port;
  if (flag(n, 'not')) a.not = true;
  if (!a.network && !a.address) a.any = true;
  return a;
}

export function fromXml(text: string): PfConfig {
  const root = parseXml(text);
  if (root.name !== 'pfsense') throw new Error(`XML error: the root element is <${root.name}>, expected <pfsense>`);
  const sys = child(root, 'system');
  const ifs = child(root, 'interfaces');
  const nat = child(root, 'nat');
  const out = child(nat, 'outbound');
  return {
    hostname: textOf(sys, 'hostname') ?? 'pfSense',
    domain: textOf(sys, 'domain') ?? 'home.arpa',
    dnsservers: children(sys, 'dnsserver').map((d) => d.text.trim()).filter(Boolean),
    sshEnabled: textOf(child(sys, 'ssh'), 'enable') === 'enabled',
    antiLockout: !flag(child(sys, 'webgui'), 'noantilockout'),
    interfaces: (ifs?.children ?? []).map((n) => ({
      key: n.name, if: textOf(n, 'if') ?? '', descr: textOf(n, 'descr') ?? n.name.toUpperCase(), enable: flag(n, 'enable'),
      ipaddr: textOf(n, 'ipaddr') || null, subnet: textOf(n, 'subnet') ? Number(textOf(n, 'subnet')) : null,
      gateway: textOf(n, 'gateway') || undefined, blockpriv: flag(n, 'blockpriv'), blockbogons: flag(n, 'blockbogons'),
    })),
    gateways: children(child(root, 'gateways'), 'gateway_item').map((g) => ({ name: textOf(g, 'name') ?? '', interface: textOf(g, 'interface') ?? '', gateway: textOf(g, 'gateway') ?? '', descr: textOf(g, 'descr') ?? '', defaultgw: flag(g, 'defaultgw') })),
    routes: children(child(root, 'staticroutes'), 'route').map((r) => ({ network: textOf(r, 'network') ?? '', gateway: textOf(r, 'gateway') ?? '', descr: textOf(r, 'descr') ?? '' })),
    aliases: children(child(root, 'aliases'), 'alias').map((a) => ({ name: textOf(a, 'name') ?? '', type: (textOf(a, 'type') ?? 'host') as PfAlias['type'], address: (textOf(a, 'address') ?? '').split(/\s+/).filter(Boolean), descr: textOf(a, 'descr') ?? '' })),
    filter: children(child(root, 'filter'), 'rule').map((r) => ({
      tracker: textOf(r, 'tracker') ?? '', type: (textOf(r, 'type') ?? 'pass') as PfRule['type'], interface: textOf(r, 'interface') ?? '',
      protocol: textOf(r, 'protocol') || undefined, icmptype: textOf(r, 'icmptype') || undefined, source: addrFrom(child(r, 'source')), destination: addrFrom(child(r, 'destination')),
      descr: textOf(r, 'descr') ?? '', disabled: flag(r, 'disabled'), log: flag(r, 'log'), associatedRuleId: textOf(r, 'associated-rule-id') || undefined,
    })),
    nat: children(nat, 'rule').map((r) => ({
      interface: textOf(r, 'interface') ?? 'wan', protocol: textOf(r, 'protocol') ?? 'tcp', source: addrFrom(child(r, 'source')), destination: addrFrom(child(r, 'destination')),
      target: textOf(r, 'target') ?? '', localPort: textOf(r, 'local-port') ?? '', descr: textOf(r, 'descr') ?? '', disabled: flag(r, 'disabled'), associatedRuleId: textOf(r, 'associated-rule-id') || undefined,
    })),
    outbound: {
      mode: (textOf(out, 'mode') ?? 'automatic') as PfConfig['outbound']['mode'],
      rules: children(out, 'rule').map((r) => ({
        interface: textOf(r, 'interface') ?? 'wan', source: textOf(child(r, 'source'), 'network') ?? 'any', destination: flag(child(r, 'destination'), 'any') ? 'any' : textOf(child(r, 'destination'), 'network') ?? textOf(child(r, 'destination'), 'address') ?? 'any',
        target: textOf(r, 'target') ?? '', descr: textOf(r, 'descr') ?? '', disabled: flag(r, 'disabled'),
      })),
    },
  };
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

const opt = (cond: boolean | undefined, n: XmlNode): XmlNode[] => (cond ? [n] : []);

function addrTo(name: string, a: PfAddr): XmlNode {
  return el(name, [
    ...opt(a.any && !a.network && !a.address, el('any')),
    ...opt(!!a.network, el('network', a.network)),
    ...opt(!!a.address, el('address', a.address)),
    ...opt(!!a.port, el('port', a.port)),
    ...opt(a.not, el('not')),
  ]);
}

export function toXml(c: PfConfig): string {
  const root = el('pfsense', [
    el('version', '23.3'),
    el('lastchange'),
    el('system', [
      el('optimization', 'normal'), el('hostname', c.hostname), el('domain', c.domain), ...c.dnsservers.map((d) => el('dnsserver', d)),
      el('group', [el('name', 'admins'), el('description', 'System Administrators'), el('scope', 'system'), el('gid', '1999'), el('member', '0'), el('priv', 'page-all')]),
      el('user', [el('name', 'admin'), el('descr', 'System Administrator'), el('scope', 'system'), el('groupname', 'admins'), el('bcrypt-hash', '$2y$10$Uw0Ac2yW7oBzmkWCGT3hVu6xc1hDS.n7Z0NFqoMeHuD3jMxR5fAqm'), el('uid', '0'), el('priv', 'user-shell-access')]),
      el('timezone', 'Etc/UTC'),
      el('webgui', [el('protocol', 'https'), el('loginautocomplete'), el('ssl-certref', '5f0a1b2c3d4e5'), el('port'), el('max_procs', '2'), ...opt(!c.antiLockout, el('noantilockout'))]),
      ...(c.sshEnabled ? [el('ssh', [el('enable', 'enabled')])] : []),
    ]),
    el('interfaces', c.interfaces.map((i) => el(i.key, [
      ...opt(i.enable, el('enable')), el('if', i.if), el('descr', i.descr), el('ipaddr', i.ipaddr ?? ''), el('subnet', i.subnet === null ? '' : String(i.subnet)),
      ...opt(!!i.gateway, el('gateway', i.gateway)), ...opt(i.blockpriv, el('blockpriv')), ...opt(i.blockbogons, el('blockbogons')),
    ]))),
    el('staticroutes', c.routes.map((r) => el('route', [el('network', r.network), el('gateway', r.gateway), el('descr', r.descr)]))),
    el('gateways', c.gateways.map((g) => el('gateway_item', [el('interface', g.interface), el('gateway', g.gateway), el('name', g.name), el('weight', '1'), el('ipprotocol', 'inet'), el('descr', g.descr), ...opt(g.defaultgw, el('defaultgw'))]))),
    el('aliases', c.aliases.map((a) => el('alias', [el('name', a.name), el('type', a.type), el('address', a.address.join(' ')), el('descr', a.descr), el('detail', a.address.map(() => 'Entry added').join('||'))]))),
    el('nat', [
      el('outbound', [el('mode', c.outbound.mode), ...c.outbound.rules.map((r) => el('rule', [
        el('source', [el('network', r.source)]), el('sourceport'), el('descr', r.descr), el('target', r.target), el('interface', r.interface), el('poolopts'),
        el('destination', r.destination === 'any' ? [el('any')] : [el('network', r.destination)]), ...opt(r.disabled, el('disabled')),
      ]))]),
      ...c.nat.map((r) => el('rule', [
        addrTo('source', r.source), addrTo('destination', r.destination), el('ipprotocol', 'inet'), el('protocol', r.protocol), el('target', r.target), el('local-port', r.localPort),
        el('interface', r.interface), el('descr', r.descr), ...opt(!!r.associatedRuleId, el('associated-rule-id', r.associatedRuleId)), ...opt(r.disabled, el('disabled')),
      ])),
    ]),
    el('filter', c.filter.map((r) => el('rule', [
      el('tracker', r.tracker), el('type', r.type), el('interface', r.interface), el('ipprotocol', 'inet'), el('tag'), el('tagged'), el('max'), el('max-src-nodes'), el('max-src-conn'), el('max-src-states'), el('statetimeout'), el('statetype', 'keep state'), el('os'),
      ...opt(!!r.protocol, el('protocol', r.protocol)), ...opt(!!r.icmptype, el('icmptype', r.icmptype)), addrTo('source', r.source), addrTo('destination', r.destination),
      ...opt(r.log, el('log')), el('descr', r.descr), ...opt(r.disabled, el('disabled')), ...opt(!!r.associatedRuleId, el('associated-rule-id', r.associatedRuleId)),
    ]))),
    el('revision', [el('time', '1729684800'), el('description', 'admin@10.0.20.1 (Local Database): Firewall: Rules - saved/edited a firewall rule.'), el('username', 'admin@10.0.20.1 (Local Database)')]),
  ]);
  return `<?xml version="1.0"?>\n${printXml(root)}\n`;
}

/** Address of an interface by key (wan, lan, opt1) or description (WAN, DMZ). */
export function ifaceOf(c: PfConfig, name: string): PfIface | undefined {
  const n = name.toLowerCase();
  return c.interfaces.find((i) => i.key === n || i.descr.toLowerCase() === n || i.if === n);
}

/** A new tracker id (pfSense uses the creation time in seconds). */
export function newTracker(c: PfConfig, clock: number): string {
  let t = Math.floor(clock / 1000);
  while (c.filter.some((r) => r.tracker === String(t))) t++;
  return String(t);
}
