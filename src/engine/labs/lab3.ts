// Lab 3: Perimeter firewall (pfSense). fw01 comes as the setup wizard leaves
// it: WAN and LAN only. Bring up the DMZ on the third port, define aliases,
// write the DMZ policy (DNS to ns1, nothing else inside, Internet allowed),
// publish dmz01's web server on the WAN address, let the internal networks
// reach the DMZ, and prove it survives a restart. The webConfigurator (a
// browser on ws01) is the main tool; fw01's console has pfctl and the logs.

import { DMZ01_IP, factoryConfig, FW01_ADMIN_PASSWORD, FW01_LAN_IP, installFw01 } from '../lab/pfLab';
import { buildSshLab } from '../lab/sshLab';
import type { PfAlias, PfConfig } from '../pf/config';
import { FILTER_LOG, PF_VERSION, readConfig, RULES_DEBUG } from '../pf/model';
import { assignInterface, browse, guiApply, guiSave, saveAlias, saveInterface, savePortForward, saveRule, type Subsystem } from '../pf/webgui';
import { Shell } from '../shell/shell';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import type { GuidedLab, LabCheck } from './types';

const OK = (detail: string) => ({ ok: true, detail });
const NO = (detail: string) => ({ ok: false, detail });

export function buildLab3World(): World {
  const world = buildSshLab();
  // fw01 as delivered: pfSense installed, setup wizard done (WAN, LAN), nothing else.
  delete world.hosts.fw01;
  const fw = installFw01(world, factoryConfig());
  bootHost(world, fw);
  world.clock += 5 * 60_000;
  return world;
}

/** Run a command on a copy of the world; return the output, exit code and the copy (to look at logs afterwards). */
function run(world: World, host: string, user: string, line: string): { output: string; code: number; world: World } {
  let w = structuredClone(world);
  const home = w.hosts[host].users[user]?.home ?? '/';
  const sh = new Shell(() => w, (n) => (w = n), { hostId: host, user, cwd: home });
  const r = sh.execute(line);
  return { output: r.output, code: r.code, world: w };
}

const cfgOf = (w: World): PfConfig | null => {
  try { return readConfig(w.hosts.fw01); } catch { return null; }
};
const pending = (w: World) => w.hosts.fw01.pf?.pending ?? [];
const notApplied = (w: World, sub: Subsystem) => pending(w).includes(sub) ? ' Saved but not applied yet: click "Apply Changes".' : '';

// ---------------------------------------------------------------- checks

const dmzIface: LabCheck = {
  id: 'dmz-iface', description: 'fw01: vtnet2 is assigned, enabled, named DMZ, with the address 172.16.50.1/24 (and applied)',
  check(w) {
    const c = cfgOf(w);
    if (!c) return NO('config.xml cannot be read.');
    const i = c.interfaces.find((x) => x.if === 'vtnet2');
    if (!i) return NO('vtnet2 is not assigned (Interfaces > Assignments).');
    if (!i.enable) return NO(`vtnet2 is assigned as ${i.descr} but not enabled.`);
    if (i.descr !== 'DMZ') return NO(`vtnet2 is named ${i.descr}; the plan calls it DMZ.`);
    if (i.ipaddr !== '172.16.50.1' || i.subnet !== 24) return NO(`DMZ address: ${i.ipaddr ?? 'none'}/${i.subnet ?? ''}; the plan is 172.16.50.1/24.`);
    const hi = w.hosts.fw01.ifaces.find((x) => x.name === 'vtnet2');
    if (hi?.address !== '172.16.50.1') return NO(`config.xml is right but vtnet2 has no address yet.${notApplied(w, 'interfaces')}`);
    return OK(`DMZ (${i.key}, vtnet2): 172.16.50.1/24, up.`);
  },
};

const PLANNED_ALIASES: { name: string; type: PfAlias['type']; address: string[] }[] = [
  { name: 'INTERNAL_NETS', type: 'network', address: ['10.0.0.0/16'] },
  { name: 'DMZ_WEB', type: 'host', address: [DMZ01_IP] },
  { name: 'WEB_PORTS', type: 'port', address: ['80', '443'] },
];

const aliasesCheck: LabCheck = {
  id: 'aliases', description: 'fw01: the aliases INTERNAL_NETS (10.0.0.0/16), DMZ_WEB (172.16.50.10) and WEB_PORTS (80, 443) exist and are loaded',
  check(w) {
    const c = cfgOf(w);
    if (!c) return NO('config.xml cannot be read.');
    for (const p of PLANNED_ALIASES) {
      const a = c.aliases.find((x) => x.name === p.name);
      if (!a) return NO(`Alias ${p.name} is missing (Firewall > Aliases).`);
      if (a.type !== p.type) return NO(`${p.name} is a ${a.type} alias; it should be a ${p.type} alias.`);
      if ([...a.address].sort().join(' ') !== [...p.address].sort().join(' ')) return NO(`${p.name} contains ${a.address.join(', ')}; the plan is ${p.address.join(', ')}.`);
    }
    const dbg = w.hosts.fw01.fs[RULES_DEBUG]?.content ?? '';
    if (!dbg.includes('table <INTERNAL_NETS>')) return NO(`The aliases are saved but pf does not have them yet.${notApplied(w, 'filter')}`);
    return OK('INTERNAL_NETS, DMZ_WEB and WEB_PORTS are defined; pfctl -t INTERNAL_NETS -T show lists 10.0.0.0/16.');
  },
};

const dmzDns: LabCheck = {
  id: 'dmz-dns', description: 'dmz01 resolves names through ns1 (10.0.10.53): host srv01.corp.lab',
  check(w) {
    const r = run(w, 'dmz01', 'alice', 'host srv01.corp.lab');
    return /10\.0\.20\.10/.test(r.output) ? OK('srv01.corp.lab has address 10.0.20.10 (DNS from the DMZ to ns1 is allowed).') : NO(r.output.split('\n')[0] || 'no answer');
  },
};

const dmzIsolated: LabCheck = {
  id: 'dmz-isolated', description: 'dmz01 cannot open anything else on the internal networks (ping srv01 and ns1 fail) and the attempts are logged',
  check(w) {
    for (const ip of ['10.0.20.10', '10.0.10.53']) {
      const r = run(w, 'dmz01', 'alice', `ping -c 1 -W 1 ${ip}`);
      if (r.code === 0) return NO(`dmz01 can ping ${ip}: the DMZ reaches the internal networks.`);
    }
    const r = run(w, 'dmz01', 'alice', 'ping -c 1 -W 1 10.0.20.10');
    const log = r.world.hosts.fw01.fs[FILTER_LOG]?.content ?? '';
    const last = log.split('\n').filter((l) => l.includes(',172.16.50.10,10.0.20.10,')).at(-1);
    if (!last) return NO('The ping is dropped but nothing is logged in /var/log/filter.log: enable "Log" on the block rule.');
    if (/,1000000103,/.test(last)) return NO('Only the default deny rule stops the DMZ: add an explicit, logged block rule for INTERNAL_NETS (the policy must be visible in the rules).');
    return OK('Blocked and logged by the DMZ block rule.');
  },
};

const dmzInternet: LabCheck = {
  id: 'dmz-internet', description: 'dmz01 reaches the Internet (ping ext01, 203.0.113.80), translated to the WAN address',
  check(w) {
    const r = run(w, 'dmz01', 'alice', 'ping -c 1 -W 1 203.0.113.80');
    return r.code === 0 ? OK('203.0.113.80 answers (outbound NAT to 203.0.113.10).') : NO(r.output.split('\n').filter(Boolean).slice(-2).join(' ') || 'no reply');
  },
};

const published: LabCheck = {
  id: 'published', description: 'From the Internet (ext01), http://portal.corp.lab/ (fw01\'s WAN address) shows dmz01\'s portal',
  check(w) {
    const r = run(w, 'ext01', 'guest', 'curl -s -m 5 http://portal.corp.lab/');
    return /customer portal/.test(r.output) ? OK('ext01: "Corp Lab customer portal" through 203.0.113.10 → 172.16.50.10.') : NO(`curl exit ${r.code}${r.output ? `: ${r.output.split('\n')[0]}` : ''} (no answer through the WAN address).`);
  },
};

const wanTight: LabCheck = {
  id: 'wan-tight', description: 'fw01\'s WAN rules pass only the web ports to dmz01 (nothing else is published)',
  check(w) {
    const c = cfgOf(w);
    if (!c) return NO('config.xml cannot be read.');
    const wide = c.filter.filter((r) => r.interface === 'wan' && r.type === 'pass' && !r.disabled && (!r.destination.port || r.destination.any));
    if (wide.length) return NO(`The WAN rule "${wide[0].descr || wide[0].tracker}" passes every port or every destination.`);
    const r = run(w, 'ext01', 'guest', 'curl -s -m 3 telnet://203.0.113.10:22');
    if (r.code === 0) return NO('ext01 can connect to 203.0.113.10:22.');
    return OK('WAN passes TCP 80/443 to DMZ_WEB only.');
  },
};

const lanToDmz: LabCheck = {
  id: 'lan-dmz', description: 'From ws01 (office network), http://portal.corp.lab/ (172.16.50.10) works through fw01\'s LAN',
  check(w) {
    const r = run(w, 'ws01', 'alice', 'curl -s -m 5 http://portal.corp.lab/');
    return /customer portal/.test(r.output) ? OK('ws01 → rtr01 → fw01 LAN → dmz01: portal page received.') : NO(`curl exit ${r.code}: the office network (10.0.10.0/24) does not reach the DMZ. Look at Status > System Logs > Firewall.`);
  },
};

const guiReachable: LabCheck = {
  id: 'gui-reachable', description: `The webConfigurator still answers from ws01 (https://${FW01_LAN_IP}/): nobody is locked out`,
  check(w) {
    const r = browse(w, 'ws01', 'alice', `https://${FW01_LAN_IP}/`);
    return r.ok ? OK('HTTPS 200 from ws01.') : NO(`${r.error}: ${r.detail}`);
  },
};

// ---------------------------------------------------------------- reference solutions (webConfigurator)

function gui(w: World, sub: Subsystem, edit: (c: PfConfig, clock: number) => string[]): World {
  const r = guiSave(w, 'fw01', sub, edit, 'lab3');
  if (r.errors.length) throw new Error(r.errors.join('; '));
  return r.world;
}
const apply = (w: World): World => guiApply(w, 'fw01').world;

// ---------------------------------------------------------------- the lab

export const LAB3: GuidedLab = {
  id: 'lab3',
  title: 'Lab 3: Perimeter firewall (pfSense)',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Turn a freshly installed pfSense into the perimeter firewall: bring up a DMZ, define aliases, write a DMZ policy (DNS only to the inside, Internet allowed, everything else blocked and logged), publish the web server with a port forward, open the DMZ to the office, and prove it survives a restart.',
  brief: `The web team needs the customer portal online (CHG-1580). **dmz01** (${DMZ01_IP}) is installed and cabled to fw01's third port; **fw01** is a fresh pfSense ${PF_VERSION} with only the setup wizard done: WAN (203.0.113.10) and LAN (${FW01_LAN_IP}, on the server network). Build the DMZ on vtnet2 (172.16.50.1/24, named DMZ). The DMZ may ask ns1 for DNS and go to the Internet, but must not reach anything else inside, and attempts must be logged. Publish the portal on fw01's WAN address (HTTP and HTTPS only), and let the office reach it too. Administer fw01 from the webConfigurator in ws01's browser (admin / ${FW01_ADMIN_PASSWORD}); the console shell has pfctl and the logs. The change is only done when everything still works after a restart of every machine.`,
  objectives: [
    'Assign and address a new interface on pfSense and apply the change.',
    'Use aliases to keep rules readable and to change addresses in one place.',
    'Write an interface policy with first-match rules: what is allowed, what is blocked and logged, in the right order.',
    'Publish an internal server with a port forward and its associated filter rule, and understand rdr before filtering.',
    'Read the firewall log and pfctl to see which rule decided.',
  ],
  prerequisites: [
    { label: 'Perimeter firewalls with pfSense', link: 'lesson/pfsense/what' },
    { label: 'Firewalls (nftables)', link: 'lesson/nftables/what' },
    { label: 'NAT', link: 'lesson/nat/what' },
  ],
  terminals: [
    { kind: 'pfweb', hostId: 'fw01', user: 'alice', fromHost: 'ws01', label: 'fw01 webConfigurator (browser on ws01)', banner: 'Alice\'s browser on ws01, opened on fw01\'s webConfigurator. Log in as admin (password Fw01-Adm1n-2026).' },
    { hostId: 'fw01', user: 'root', label: 'fw01 console (shell)', banner: `pfSense ${PF_VERSION} amd64 - fw01.corp.lab console, option 8 (Shell).\nUseful: pfctl -sr, pfctl -sn, pfctl -ss, pfctl -t ALIAS -T show, tail /var/log/filter.log, cat /tmp/rules.debug.` },
    { hostId: 'dmz01', user: 'alice', label: 'dmz01 (alice)', banner: `dmz01 (${DMZ01_IP}/24, gateway 172.16.50.1): the portal's web server. Test with ping, host, curl.` },
    { hostId: 'ext01', user: 'guest', label: 'ext01 (Internet)', banner: 'ext01 (203.0.113.80), a machine on the Internet. portal.corp.lab resolves to fw01\'s WAN address 203.0.113.10 here.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'alice\'s workstation on the office network (10.0.10.0/24). portal.corp.lab resolves to 172.16.50.10 internally.' },
  ],
  build: buildLab3World,
  setupNote: `This lab uses **fw01** (pfSense: WAN vtnet0 203.0.113.10, LAN vtnet1 ${FW01_LAN_IP}, vtnet2 cabled to the DMZ but unassigned) and **dmz01** (${DMZ01_IP}) in the DMZ. rtr01 already routes 172.16.50.0/24 to fw01.`,
  steps: [
    {
      id: 'dmz-iface', title: 'Bring up the DMZ interface',
      objective: 'Assign **vtnet2** as a new interface, enable it, name it **DMZ** and give it **172.16.50.1/24**, then apply.',
      background: 'pfSense names interfaces by role: WAN, LAN, then OPT1, OPT2... for the extra ports (in config.xml: `<wan>`, `<lan>`, `<opt1>`). Assigning a port creates OPTn, disabled and without an address; the description becomes its name in the menus, the rule tabs and the macros ("DMZ net", "DMZ address"). Like most pages, saving only writes config.xml: **Apply Changes** reconfigures the interface. A new interface has **no rules**: everything entering it is blocked by the default deny until pass rules are added.',
      tasks: [
        'Log in to the webConfigurator (ws01\'s browser tab) as admin.',
        'Interfaces > Assignments: Available network ports **vtnet2**, **+ Add** (it becomes OPT1).',
        'Open OPT1: Enable, Description **DMZ**, IPv4 Address **172.16.50.1** /**24**, Save, then **Apply Changes**.',
        'On the console: `ifconfig vtnet2`, `netstat -rn`. From dmz01: `ping -c 2 172.16.50.1` still fails: no rules on DMZ yet (Status > System Logs > Firewall shows the default deny).',
      ],
      hints: ['If the address is in config.xml but `ifconfig vtnet2` shows none, the change was saved but not applied.', 'The description may only contain letters, digits and underscores.'],
      checks: [dmzIface],
      solution: [],
      gui: {
        steps: ['Interfaces > Assignments: vtnet2, + Add', 'Interfaces > OPT1: Enable; Description DMZ; IPv4 172.16.50.1 / 24; Save', 'Apply Changes'],
        apply(w) {
          w = gui(w, 'interfaces', (c) => assignInterface(c, 'vtnet2'));
          const key = cfgOf(w)!.interfaces.find((i) => i.if === 'vtnet2')!.key;
          w = gui(w, 'interfaces', (c) => saveInterface(c, key, { enable: true, descr: 'DMZ', ipaddr: '172.16.50.1', subnet: 24 }));
          return apply(w);
        },
      },
      learn: [{ label: 'Perimeter firewalls with pfSense: how it works', link: 'lesson/pfsense/internals' }],
      concepts: ['net.interfaces'],
    },
    {
      id: 'aliases', title: 'Define the aliases',
      objective: 'Create **INTERNAL_NETS** (network 10.0.0.0/16), **DMZ_WEB** (host 172.16.50.10) and **WEB_PORTS** (ports 80 and 443), and apply.',
      background: 'An alias is a named list of hosts, networks or ports. In the generated ruleset host and network aliases become pf **tables** (`table <INTERNAL_NETS>`), port aliases become macros. Rules that use aliases read like the policy ("block DMZ net to INTERNAL_NETS"), and when an address changes you edit one alias instead of every rule. pfSense refuses to delete an alias that a rule still uses.',
      tasks: [
        'Firewall > Aliases: **+ Add** each alias with its type (Network(s), Host(s), Port(s)) and a description.',
        'Apply Changes, then on the console: `pfctl -s tables` and `pfctl -t INTERNAL_NETS -T show`.',
      ],
      hints: ['A network alias needs CIDR notation: 10.0.0.0/16.', 'Port aliases hold one port or range per entry: 80, then 443.'],
      checks: [aliasesCheck],
      solution: [],
      gui: {
        steps: ['Firewall > Aliases > Add: INTERNAL_NETS, Network(s), 10.0.0.0/16', 'Add: DMZ_WEB, Host(s), 172.16.50.10', 'Add: WEB_PORTS, Port(s), 80 and 443', 'Apply Changes'],
        apply(w) {
          w = gui(w, 'filter', (c) => saveAlias(c, { name: 'INTERNAL_NETS', type: 'network', address: ['10.0.0.0/16'], descr: 'Office, server and development networks' }, null));
          w = gui(w, 'filter', (c) => saveAlias(c, { name: 'DMZ_WEB', type: 'host', address: [DMZ01_IP], descr: 'dmz01: public web server' }, null));
          w = gui(w, 'filter', (c) => saveAlias(c, { name: 'WEB_PORTS', type: 'port', address: ['80', '443'], descr: 'HTTP and HTTPS' }, null));
          return apply(w);
        },
      },
      learn: [{ label: 'Perimeter firewalls with pfSense: configure', link: 'lesson/pfsense/config' }],
      concepts: ['pfsense.rules'],
    },
    {
      id: 'dmz-rules', title: 'Write the DMZ policy',
      objective: 'On the **DMZ** tab: allow DNS (TCP/UDP 53) to ns1 (10.0.10.53), **block and log** everything else to INTERNAL_NETS, then allow the rest (the Internet). The DMZ must not reach anything else inside.',
      background: 'pfSense filters traffic as it **enters** an interface, so the DMZ policy lives on the DMZ tab and decides what dmz01 may open. Rules are evaluated top to bottom and the **first match wins**: the narrow exception (DNS to ns1) goes first, then the block of the internal networks, then the broad "anything else" pass. Put the pass above the block and the DMZ reaches everything. Replies to allowed connections pass on their state, so ws01 can still reach dmz01 later without a DMZ rule for the replies. Outbound NAT (automatic) already translates every internal interface network, the new DMZ included, to the WAN address.',
      tasks: [
        'Firewall > Rules > DMZ, **Add**: Pass, TCP/UDP, source **DMZ net**, destination single host **10.0.10.53** port **53**, description "DMZ to internal DNS".',
        'Add below it: Block, protocol Any, source DMZ net, destination **INTERNAL_NETS**, **Log** enabled, "Block DMZ to internal networks".',
        'Add below it: Pass, protocol Any, source DMZ net, destination any, "DMZ to the Internet". Apply Changes.',
        'From dmz01: `host srv01.corp.lab` works, `ping -c 1 10.0.20.10` fails, `ping -c 1 203.0.113.80` works. Status > System Logs > Firewall shows the block with your rule\'s description.',
      ],
      hints: [
        'Order matters: if dmz01 can ping srv01, the "DMZ to the Internet" pass is above the block (use the ↑ ↓ buttons).',
        'If the block is not logged, edit the rule and tick "Log packets that are handled by this rule".',
        'If DNS fails: the DNS pass must be above the block, with protocol TCP/UDP and port 53.',
      ],
      checks: [dmzDns, dmzIsolated, dmzInternet],
      solution: [],
      gui: {
        steps: [
          'Firewall > Rules > DMZ > Add: Pass, TCP/UDP, DMZ net → 10.0.10.53 port 53, "DMZ to internal DNS"',
          'Add: Block, any protocol, DMZ net → INTERNAL_NETS, Log, "Block DMZ to internal networks"',
          'Add: Pass, any protocol, DMZ net → any, "DMZ to the Internet"',
          'Apply Changes',
        ],
        apply(w) {
          const key = cfgOf(w)!.interfaces.find((i) => i.descr === 'DMZ')!.key;
          w = gui(w, 'filter', (c, t) => saveRule(c, { tracker: '', type: 'pass', interface: key, protocol: 'tcp/udp', source: { network: key }, destination: { address: '10.0.10.53', port: '53' }, descr: 'DMZ to internal DNS', disabled: false, log: false }, null, t));
          w = gui(w, 'filter', (c, t) => saveRule(c, { tracker: '', type: 'block', interface: key, source: { network: key }, destination: { address: 'INTERNAL_NETS' }, descr: 'Block DMZ to internal networks', disabled: false, log: true }, null, t + 1000));
          w = gui(w, 'filter', (c, t) => saveRule(c, { tracker: '', type: 'pass', interface: key, source: { network: key }, destination: { any: true }, descr: 'DMZ to the Internet', disabled: false, log: false }, null, t + 2000));
          return apply(w);
        },
      },
      learn: [{ label: 'Perimeter firewalls with pfSense: troubleshooting', link: 'lesson/pfsense/troubleshoot' }],
      concepts: ['pfsense.rules', 'fw.stateful'],
    },
    {
      id: 'publish', title: 'Publish the portal on the WAN address',
      objective: 'Forward TCP **WEB_PORTS** on the **WAN address** to **DMZ_WEB**, with its associated filter rule, so that http://portal.corp.lab/ works from the Internet. Nothing else may be open on WAN.',
      background: 'A port forward is a **rdr** (destination NAT) rule: connections to 203.0.113.10:80 are rewritten to 172.16.50.10:80 **before** the filter sees them. The filter rule must therefore allow the **translated** destination (DMZ_WEB, WEB_PORTS) on WAN. "Add associated filter rule" creates and keeps that rule in sync with the forward (the 🔗 in the list); without it, the forward translates the packets and the default deny drops them. Replies go back through fw01, which reverses the translation.',
      tasks: [
        'Firewall > NAT > Port Forward, **Add**: interface WAN, protocol TCP, destination **WAN address**, port **WEB_PORTS**, redirect target **DMZ_WEB**, target port empty (same), description "Publish dmz01 (portal.corp.lab)", filter rule association **Add associated filter rule**. Save, Apply Changes.',
        'Firewall > Rules > WAN now shows the "NAT Publish dmz01" rule. Console: `pfctl -sn` (the rdr) and `pfctl -sr`.',
        'From ext01: `curl -s http://portal.corp.lab/`. Console: `pfctl -ss` shows the translated state.',
      ],
      hints: ['If ext01 gets no answer but the forward exists: is there a pass rule on WAN to the translated address (172.16.50.10), not to the WAN address?', 'Never pass "any to any" on WAN: only the forwarded ports to the one server.'],
      checks: [published, wanTight],
      solution: [],
      gui: {
        steps: ['Firewall > NAT > Port Forward > Add: WAN, TCP, dest WAN address port WEB_PORTS → DMZ_WEB, "Publish dmz01 (portal.corp.lab)", Add associated filter rule', 'Apply Changes'],
        apply(w) {
          w = gui(w, 'filter', (c, t) => savePortForward(c, { interface: 'wan', protocol: 'tcp', source: { any: true }, destination: { network: 'wanip', port: 'WEB_PORTS' }, target: 'DMZ_WEB', localPort: '', descr: 'Publish dmz01 (portal.corp.lab)', disabled: false }, null, 'associated', t));
          return apply(w);
        },
      },
      learn: [{ label: 'Perimeter firewalls with pfSense: how it works', link: 'lesson/pfsense/internals' }],
      concepts: ['pfsense.nat', 'net.nat'],
    },
    {
      id: 'lan-access', title: 'Let the office reach the DMZ',
      objective: 'Make **http://portal.corp.lab/** work from ws01 (office network 10.0.10.0/24, routed by rtr01 through fw01\'s LAN). Use the INTERNAL_NETS alias, and keep the webConfigurator reachable.',
      background: 'The wizard\'s default LAN rule passes **LAN net** only, the server network fw01 sits on (10.0.20.0/24). Office traffic arrives on the same LAN interface (rtr01 routes 172.16.50.0/24 to fw01) but from 10.0.10.0/24, so the default deny drops it: the log shows the source and the interface. The fix is the source of the LAN rule: **INTERNAL_NETS** instead of LAN net. Careful with LAN rules: the **anti-lockout rule** keeps the webConfigurator reachable from the LAN whatever the rules say, but a mistake can still cut the routed office networks off.',
      tasks: [
        'From ws01: `curl -s -m 5 http://portal.corp.lab/` times out. Status > System Logs > Firewall: blocked on LAN from 10.0.10.x by the default deny.',
        'Firewall > Rules > LAN: edit "Default allow LAN to any rule": source **Single host or alias** **INTERNAL_NETS**, description "Internal networks to anywhere". Save, Apply Changes.',
        'From ws01 again: the portal page loads. dmz01 still cannot ping 10.0.20.10 (the DMZ policy decides what enters from the DMZ).',
      ],
      hints: ['The rule is evaluated on the interface the packets enter: office traffic enters fw01 on LAN, from rtr01.', 'An alias name in the source "Single host or alias" field is fine: INTERNAL_NETS.'],
      checks: [lanToDmz, guiReachable],
      solution: [],
      gui: {
        steps: ['Firewall > Rules > LAN: edit the default allow rule: source INTERNAL_NETS, "Internal networks to anywhere"', 'Apply Changes'],
        apply(w) {
          const r = cfgOf(w)!.filter.find((x) => x.interface === 'lan' && x.type === 'pass')!;
          w = gui(w, 'filter', (c, t) => saveRule(c, { ...r, source: { address: 'INTERNAL_NETS' }, descr: 'Internal networks to anywhere' }, r.tracker, t));
          return apply(w);
        },
      },
      learn: [{ label: 'Perimeter firewalls with pfSense: operate', link: 'lesson/pfsense/operate' }],
      concepts: ['pfsense.rules', 'net.routing'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Restart every machine (fw01 included) and confirm everything above still holds.',
      background: 'pfSense rebuilds everything from config.xml at boot: interfaces, routes, aliases, rules and NAT. A change that was saved but never applied works after a reboot; a change made only at runtime (pfctl -d, a rule loaded by hand) disappears. If config.xml were broken, pfSense would restore the last good configuration from /cf/conf/backup.',
      tasks: ['Run "Check" on this step: it restarts every machine on a copy of the lab and re-runs all checks.'],
      hints: ['If only the reboot test fails, something was configured at runtime only (pfctl on the console).'],
      checks: [],
      solution: [],
      learn: [{ label: 'Safe configuration change', link: 'reference?id=proc:safe-config-change' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
};
