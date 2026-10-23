// pfSense tickets: fw01 is the perimeter firewall between the Internet, the
// server network (LAN) and the DMZ, where dmz01 serves the customer portal.
// The faults are the classic ones of a GUI-managed pf ruleset: a port forward
// without its filter rule, rule order, manual outbound NAT that forgot a
// network, an alias with a wrong address, and a rule that matches only the
// interface's own subnet. Each one is found from the firewall log and pfctl,
// and fixed in config.xml (webConfigurator, or the console).

import { readConfig, writeConfig, filterConfigure } from '../pf/model';
import type { PfConfig } from '../pf/config';
import { Shell } from '../shell/shell';
import type { World } from '../types';
import type { Constraint, Goal, Scenario } from './types';

const PORTAL_INTERNET: Goal = { kind: 'http', description: 'From the Internet (ext01), http://portal.corp.lab/ (fw01\'s WAN address) returns the portal: "curl -I http://portal.corp.lab/".', fromHost: 'ext01', fromUser: 'guest', url: 'http://portal.corp.lab/' };

const TERMINALS = [
  { kind: 'pfweb' as const, hostId: 'fw01', user: 'alice', fromHost: 'ws01', label: 'fw01 webConfigurator (browser on ws01)', banner: 'Alice\'s browser on ws01, opened on fw01\'s webConfigurator. Log in as admin (password Fw01-Adm1n-2026).' },
  { hostId: 'fw01', user: 'root', label: 'fw01 console (shell)', banner: 'pfSense 2.7.2-RELEASE amd64 - fw01.corp.lab console, option 8 (Shell). Try: pfctl -sr, pfctl -sn, pfctl -ss, pfctl -vvsr, tail /var/log/filter.log, pfctl -t DMZ_WEB -T show. Changes: viconfig (config.xml), then /etc/rc.filter_configure.' },
  { hostId: 'ext01', user: 'guest', label: 'ext01 (Internet)', banner: 'ext01 (203.0.113.80), a machine on the Internet. portal.corp.lab resolves to fw01\'s WAN address 203.0.113.10 here.' },
  { hostId: 'dmz01', user: 'alice', label: 'dmz01 (alice)', banner: 'dmz01 (172.16.50.10), the portal\'s web server in the DMZ (gateway fw01, 172.16.50.1). sudo password: dmz01-alice.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'alice\'s workstation on the office network (10.0.10.0/24). portal.corp.lab resolves to 172.16.50.10 internally.' },
];

const BRIEFING = [
  'fw01 (pfSense 2.7.2) is the perimeter firewall: WAN vtnet0 203.0.113.10 (Internet), LAN vtnet1 10.0.20.254 (server network; rtr01 routes the office, server and development networks 10.0.0.0/16 to it), DMZ (opt1) vtnet2 172.16.50.1/24.',
  'dmz01 (172.16.50.10) serves the customer portal portal.corp.lab: published on fw01\'s WAN address for the Internet, reached directly by the office. The DMZ may use ns1 (10.0.10.53) for DNS and the Internet; nothing else inside.',
  'Aliases: INTERNAL_NETS (10.0.0.0/16), DMZ_WEB (172.16.50.10), WEB_PORTS (80, 443), INTERNAL_DNS (10.0.10.53). The webConfigurator is used from ws01 (admin / Fw01-Adm1n-2026); the console shell has pfctl and the logs.',
  'Fixes go into config.xml (webConfigurator, or viconfig + /etc/rc.filter_configure) and must survive a restart of every machine. pf stays enabled, the DMZ stays isolated from the inside, and nothing else is published on WAN.',
];

const CANDIDATES = ['pf-forward-no-rule', 'pf-rule-order', 'pf-outbound-manual', 'pf-alias-wrong', 'pf-rule-source', 'web-not-running', 'nat-wrong-dnat', 'nat-missing-masquerade', 'dns-client-config'];

/** Change fw01's config.xml and apply it, as an earlier change did. */
function pfChange(world: World, edit: (c: PfConfig) => void): void {
  const fw = world.hosts.fw01;
  const c = readConfig(fw);
  edit(c);
  writeConfig(world, fw, c);
  filterConfigure(world, fw);
  world.clock += 60_000;
}

function run(world: World, host: string, user: string, line: string): { output: string; code: number } {
  let w = structuredClone(world);
  const sh = new Shell(() => w, (n) => (w = n), { hostId: host, user, cwd: w.hosts[host].users[user]?.home ?? '/' });
  const r = sh.execute(line);
  return { output: r.output, code: r.code };
}

function pfEnabled(): Constraint {
  return {
    id: 'pf-enabled', required: true,
    description: 'pf stays enabled on fw01 (pfctl -d is not a fix: it turns off filtering and NAT for every network).',
    check(world) {
      const ok = !!world.hosts.fw01.pf?.enabled;
      return { id: this.id, ok, required: true, message: ok ? 'fw01: pf enabled.' : 'fw01: pf is disabled (pfctl -d): everything passes unfiltered and nothing is translated.' };
    },
  };
}

function dmzIsolated(): Constraint {
  return {
    id: 'dmz-isolated', required: true,
    description: 'The DMZ stays isolated: dmz01 cannot reach the internal networks except DNS on ns1.',
    check(world) {
      const r = run(world, 'dmz01', 'alice', 'ping -c 1 -W 1 10.0.20.10');
      return { id: this.id, ok: r.code !== 0, required: true, message: r.code !== 0 ? 'dmz01 cannot reach srv01 (10.0.20.10).' : 'dmz01 can ping srv01: the DMZ reaches the internal networks.' };
    },
  };
}

function wanTight(): Constraint {
  return {
    id: 'wan-tight', required: true,
    description: 'WAN passes only the published web ports to dmz01: no rule passes every port or every destination.',
    check(world) {
      let c: PfConfig;
      try { c = readConfig(world.hosts.fw01); } catch { return { id: this.id, ok: false, required: true, message: 'config.xml cannot be read.' }; }
      const wide = c.filter.filter((r) => r.interface === 'wan' && r.type === 'pass' && !r.disabled && (r.destination.any || !r.destination.port));
      return { id: this.id, ok: !wide.length, required: true, message: wide.length ? `WAN rule "${wide[0].descr}" passes every port or destination.` : 'WAN passes only TCP 80/443 to dmz01.' };
    },
  };
}

export const PF_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'pf-forward-no-rule',
    title: 'The WAN clean-up',
    difficulty: 'beginner',
    ticket: 'Customer support: "Since this morning customers say the portal (portal.corp.lab) times out. It works from the office." Security (SEC-52): "Yesterday we cleaned up the WAN rules on fw01: removed everything that looked like a leftover. The port forwards were not touched."',
    briefing: BRIEFING,
    goals: [PORTAL_INTERNET],
    terminals: TERMINALS,
    setup(world) {
      pfChange(world, (c) => {
        c.filter = c.filter.filter((r) => !(r.interface === 'wan' && r.associatedRuleId));
        for (const n of c.nat) n.associatedRuleId = undefined;
      });
    },
    rootCauses: ['pf-forward-no-rule'],
    candidates: CANDIDATES,
    feedback: {
      'pf-rule-order': 'There is no pass rule at all on WAN for the portal: nothing to reorder (Firewall > Rules > WAN only shows the automatic rules).',
      'pf-outbound-manual': 'Outbound NAT is for connections leaving through WAN; this one comes in. dmz01 itself reaches the Internet fine.',
      'pf-alias-wrong': 'DMZ_WEB holds 172.16.50.10 (pfctl -t DMZ_WEB -T show) and pfctl -sn shows the rdr to it.',
      'pf-rule-source': 'The LAN rules are not involved: the office reaches the portal. The connection comes in on WAN.',
      'web-not-running': 'The portal answers from ws01 and from fw01 itself: nginx on dmz01 is fine.',
      'nat-wrong-dnat': 'pfctl -sn shows the rdr to 172.16.50.10, the right address. The translated packets are dropped after it.',
      'nat-missing-masquerade': 'Outbound NAT is in automatic mode and dmz01 reaches the Internet: it is the inbound side that fails.',
      'dns-client-config': 'ext01 resolves portal.corp.lab to 203.0.113.10, fw01\'s WAN address.',
    },
    hints: [
      'It works from inside, not from the Internet: what does fw01 do with the connection on WAN? Status > System Logs > Firewall (or tail /var/log/filter.log on the console) while ext01 tries.',
      'The log shows the default deny on vtnet0 with the destination already rewritten to 172.16.50.10:80. The port forward still works (pfctl -sn): what is missing after it?',
      'A port forward only translates; a pass rule must allow the translated destination on WAN. Edit the port forward and choose "Add associated filter rule" (or add a WAN rule: TCP to DMZ_WEB port WEB_PORTS), then Apply.',
    ],
    explanation: {
      rootCause: 'The WAN clean-up deleted the filter rule associated with the port forward "Publish dmz01". pf translates the connection (rdr to 172.16.50.10) before filtering, and without a pass rule for the translated destination the default deny rule drops it.',
      manifestation: 'From the Internet the portal times out (curl: Couldn\'t connect, after 10 s): the SYN is silently dropped. Inside, ws01 reaches dmz01 directly through the LAN rule, so "it works from the office".',
      evidence: 'filter.log: block on vtnet0 by tracker 1000000103 (Default deny rule IPv4), 203.0.113.80 → 172.16.50.10:80 (destination already translated). pfctl -sn shows the rdr; pfctl -sr has no pass on vtnet0 to <DMZ_WEB>; Firewall > NAT > Port Forward has no 🔗 for the entry.',
      prevention: 'Keep port forwards and their rules linked ("Add associated filter rule"): deleting the rule then requires touching the forward. Review rule clean-ups against the NAT entries, and test published services from outside after every WAN change.',
    },
    solution: [{ host: 'fw01', user: 'root', commands: ['easyrule pass wan tcp any 172.16.50.10 80', 'easyrule pass wan tcp any 172.16.50.10 443'], note: 'In the webConfigurator: edit the port forward, Filter rule association "Add associated filter rule", Save, Apply Changes.' }],
    constraints: [pfEnabled(), wanTight(), dmzIsolated()],
    concepts: ['pfsense.nat', 'pfsense.rules'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'pf-rule-order',
    title: 'Block first, to be safe',
    difficulty: 'beginner',
    ticket: 'Web team: "dmz01 cannot resolve anything since yesterday afternoon: the portal\'s calls to the API on srv01.corp.lab and the package updates all fail with \'Temporary failure in name resolution\'." Security (SEC-55): "Audit finding closed: the DMZ block rule was moved to the top of the DMZ rules so it is evaluated first."',
    briefing: BRIEFING,
    goals: [{ kind: 'resolve', description: 'dmz01 resolves srv01.corp.lab through ns1 ("getent hosts srv01.corp.lab" returns 10.0.20.10).', fromHost: 'dmz01', name: 'srv01.corp.lab', expect: '10.0.20.10' }],
    terminals: TERMINALS,
    setup(world) {
      pfChange(world, (c) => {
        const blk = c.filter.findIndex((r) => r.interface === 'opt1' && r.type === 'block');
        const [rule] = c.filter.splice(blk, 1);
        const first = c.filter.findIndex((r) => r.interface === 'opt1');
        c.filter.splice(first, 0, rule);
      });
    },
    rootCauses: ['pf-rule-order'],
    candidates: CANDIDATES,
    feedback: {
      'pf-forward-no-rule': 'The portal is reachable from the Internet; the failing traffic starts in the DMZ.',
      'pf-outbound-manual': 'dmz01 reaches the Internet by address (curl http://203.0.113.80/ works): only DNS to ns1 fails.',
      'pf-alias-wrong': 'INTERNAL_DNS still holds 10.0.10.53, and the DNS pass rule is still there: the log names another rule.',
      'pf-rule-source': 'The DNS pass rule\'s source is DMZ net, which contains dmz01. It is never reached.',
      'web-not-running': 'nginx is not involved: name resolution fails on dmz01.',
      'nat-wrong-dnat': 'No translation is involved between the DMZ and ns1.',
      'nat-missing-masquerade': 'Internal traffic is not translated; dmz01 reaches the Internet.',
      'dns-client-config': 'dmz01\'s resolv.conf points at ns1 (10.0.10.53), like before; the queries leave dmz01 and are dropped on fw01.',
    },
    hints: [
      'From dmz01: dig @10.0.10.53 srv01.corp.lab times out. Where are the queries dropped? Look at the firewall log on fw01.',
      'The log names the rule: "Block DMZ to internal networks", for UDP 172.16.50.10 → 10.0.10.53:53. The pass rule for DNS exists: where is it in the list?',
      'pf uses the first matching rule. Move "DMZ to internal DNS" above the block (Firewall > Rules > DMZ, the ↑ button), Save, Apply.',
    ],
    explanation: {
      rootCause: 'The block rule "Block DMZ to internal networks" was moved to the top of the DMZ rules. pfSense rules are evaluated top to bottom and the first match wins (quick), so DNS queries to ns1 (inside INTERNAL_NETS) are blocked before the "DMZ to internal DNS" exception is reached.',
      manifestation: 'Every name lookup on dmz01 times out ("Temporary failure in name resolution"); connections by address to the Internet still work, since the Internet pass is below a block that does not match it.',
      evidence: 'filter.log: block on vtnet2 by the tracker of "Block DMZ to internal networks", 172.16.50.10 → 10.0.10.53:53 UDP. pfctl -vvsr: the block rule (@n) above the DNS pass, whose counters stay at 0.',
      prevention: 'Order rules from the most specific exception to the broadest: exceptions (pass DNS to ns1), then the block of the internal networks, then the general pass. Read "evaluated first" as "decides first". Test the DMZ\'s dependencies after every change.',
    },
    solution: [{ host: 'fw01', user: 'root', commands: ['easyrule pass opt1 tcp/udp 172.16.50.0/24 10.0.10.53 53'], note: 'Cleaner in the webConfigurator: Firewall > Rules > DMZ, move "DMZ to internal DNS" above "Block DMZ to internal networks", Save, Apply Changes.' }],
    constraints: [pfEnabled(), dmzIsolated()],
    concepts: ['pfsense.rules'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'pf-outbound-manual',
    title: 'Manual mode, old mappings',
    difficulty: 'intermediate',
    ticket: 'Web team: "dmz01 cannot reach anything on the Internet since the weekend: apt update and the payment provider\'s API time out. DNS works." Network team (NET-230): "On Saturday we switched fw01\'s outbound NAT to Manual for the new VPN and restored the mappings from our standard template."',
    briefing: BRIEFING,
    goals: [{ kind: 'http', description: 'dmz01 reaches a server on the Internet: "curl -I http://203.0.113.80/".', fromHost: 'dmz01', fromUser: 'alice', url: 'http://203.0.113.80/' }],
    terminals: TERMINALS,
    setup(world) {
      pfChange(world, (c) => {
        c.outbound = {
          mode: 'advanced',
          rules: [
            { interface: 'wan', source: '10.0.0.0/16', destination: 'any', target: '', descr: 'Internal networks to the Internet (template)', disabled: false },
            { interface: 'wan', source: '127.0.0.0/8', destination: 'any', target: '', descr: 'Localhost (template)', disabled: false },
          ],
        };
      });
    },
    rootCauses: ['pf-outbound-manual'],
    acceptable: { 'nat-missing-masquerade': 'Yes, in general terms: the DMZ\'s connections leave untranslated. On pfSense the cause is the Manual outbound NAT mode without a mapping for 172.16.50.0/24.' },
    candidates: CANDIDATES,
    feedback: {
      'pf-forward-no-rule': 'Port forwards handle connections coming in; this one goes out from dmz01.',
      'pf-rule-order': 'The DMZ rules pass the connection (the log shows no block, pfctl -ss shows the state): it leaves fw01, but untranslated.',
      'pf-alias-wrong': 'No alias is involved in outbound NAT here: the mappings list networks.',
      'pf-rule-source': 'The DMZ pass rule matches (DMZ net to any) and creates a state.',
      'web-not-running': 'The server on the Internet works for everybody else.',
      'nat-wrong-dnat': 'No port forward is involved.',
      'dns-client-config': 'DNS works on dmz01; connections by address fail.',
    },
    hints: [
      'DNS works, outgoing connections time out. Is the connection blocked (firewall log), or does it leave? On fw01: pfctl -ss while dmz01 tries.',
      'The state shows 172.16.50.10 leaving on vtnet0 with its own private address: no translation. pfctl -sn lists the nat rules: which networks are translated?',
      'Firewall > NAT > Outbound: Manual mode with mappings for 10.0.0.0/16 only. Add a mapping for the DMZ (WAN, source 172.16.50.0/24, interface address), or switch to Hybrid so the automatic rules cover every internal interface. Apply.',
    ],
    explanation: {
      rootCause: 'Outbound NAT was switched to Manual (Advanced Outbound NAT) with mappings from a template that predates the DMZ. In Manual mode only the listed networks are translated, so connections from 172.16.50.0/24 leave the WAN with their private source address and the replies never come back.',
      manifestation: 'Everything from the DMZ to the Internet times out, while DNS (to ns1, inside) works and the published portal (inbound, translated by the rdr) still works.',
      evidence: 'pfctl -sn: nat on vtnet0 from { 10.0.0.0/16 } and 127.0.0.0/8 only; pfctl -ss: 172.16.50.10:port → 203.0.113.80:80 without a translated source; Firewall > NAT > Outbound mode "Manual". No block in the firewall log.',
      prevention: 'Prefer Hybrid mode when only a few manual mappings are needed: the automatic rules keep covering new interfaces. In Manual mode, add a mapping with every new internal network and test Internet access from it.',
    },
    solution: [{ host: 'fw01', user: 'root', commands: ["sed -i 's|<mode>advanced</mode>|<mode>hybrid</mode>|' /conf/config.xml", '/etc/rc.filter_configure'], note: 'In the webConfigurator: Firewall > NAT > Outbound, Hybrid mode (or a manual mapping for 172.16.50.0/24), Save, Apply Changes.' }],
    constraints: [pfEnabled(), dmzIsolated()],
    concepts: ['pfsense.nat', 'net.nat'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'pf-alias-wrong',
    title: 'Tidying the aliases',
    difficulty: 'intermediate',
    ticket: 'Customer support: "The portal is down for customers again." Network team (NET-236): "Yesterday evening we tidied the aliases on fw01: better descriptions, and DMZ_WEB re-typed from the IPAM export. No rule or NAT changes."',
    briefing: BRIEFING,
    goals: [PORTAL_INTERNET],
    terminals: TERMINALS,
    setup(world) {
      pfChange(world, (c) => {
        const a = c.aliases.find((x) => x.name === 'DMZ_WEB')!;
        a.address = ['172.16.5.10'];
        a.descr = 'Public web server (portal.corp.lab)';
      });
    },
    rootCauses: ['pf-alias-wrong'],
    acceptable: { 'nat-wrong-dnat': 'Yes: the port forward now rewrites to the wrong inside address. It does so because its target is the alias DMZ_WEB, which holds a wrong address.' },
    candidates: CANDIDATES,
    feedback: {
      'pf-forward-no-rule': 'The WAN rule associated with the forward is there and passes the connection (its counters increase in pfctl -vvsr).',
      'pf-rule-order': 'The connection is passed, not blocked: no block appears in the log.',
      'pf-outbound-manual': 'Outbound NAT is in automatic mode; this connection comes in.',
      'pf-rule-source': 'The office reaches the portal; only the published path fails.',
      'web-not-running': 'The portal answers from ws01: nginx on dmz01 is fine.',
      'nat-missing-masquerade': 'dmz01 reaches the Internet; the inbound forward is what fails.',
      'dns-client-config': 'ext01 resolves portal.corp.lab to fw01\'s WAN address as before.',
    },
    hints: [
      'From ext01 the connection fails with "No route to host". On fw01: pfctl -ss while ext01 tries. Where is the connection sent?',
      'The state shows 203.0.113.80 → 203.0.113.10:80 translated to 172.16.5.10:80, an address that exists nowhere. Where does the forward\'s target come from? pfctl -sn, then pfctl -t DMZ_WEB -T show.',
      'DMZ_WEB holds 172.16.5.10 instead of 172.16.50.10. Fix the alias (Firewall > Aliases), Save, Apply: the forward and its rule follow.',
    ],
    explanation: {
      rootCause: 'While tidying the aliases, DMZ_WEB was re-typed as 172.16.5.10 instead of 172.16.50.10. The port forward and its filter rule both use the alias, so connections are translated to, and passed towards, an address that does not exist; fw01 routes it to its default gateway on WAN, which answers "host unreachable".',
      manifestation: 'From the Internet the portal fails with "No route to host" (ICMP unreachable from the upstream router) instead of a timeout. From the office it works (portal.corp.lab resolves to 172.16.50.10 directly).',
      evidence: 'pfctl -sn: rdr ... -> 172.16.5.10; pfctl -t DMZ_WEB -T show: 172.16.5.10; pfctl -ss: 203.0.113.80:x -> 172.16.5.10:80 (203.0.113.10:80); netstat -rn: 172.16.5.10 matches only the default route.',
      prevention: 'An alias change changes every rule that uses it: review aliases like rules (diff config.xml, Diagnostics > Backup & Restore > Config History) and test the published services after the change.',
    },
    solution: [{ host: 'fw01', user: 'root', commands: ["sed -i 's|<address>172.16.5.10</address>|<address>172.16.50.10</address>|' /conf/config.xml", '/etc/rc.filter_configure'], note: 'In the webConfigurator: Firewall > Aliases, edit DMZ_WEB, 172.16.50.10, Save, Apply Changes.' }],
    constraints: [pfEnabled(), wanTight(), dmzIsolated()],
    concepts: ['pfsense.nat', 'pfsense.rules'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'pf-rule-source',
    title: 'Back to the defaults',
    difficulty: 'intermediate',
    ticket: 'Alice (office): "I can\'t open portal.corp.lab from my PC any more, it just spins. My colleagues on the server network say it works for them." Network team (NET-241): "We simplified fw01\'s LAN rule back to the wizard default: LAN net to any. Same thing, fewer aliases."',
    briefing: BRIEFING,
    goals: [{ kind: 'http', description: 'From the office (ws01), http://portal.corp.lab/ (172.16.50.10) works: "curl -I http://portal.corp.lab/".', fromHost: 'ws01', fromUser: 'alice', url: 'http://portal.corp.lab/' }],
    terminals: TERMINALS,
    setup(world) {
      pfChange(world, (c) => {
        const r = c.filter.find((x) => x.interface === 'lan' && x.type === 'pass')!;
        r.source = { network: 'lan' };
        r.descr = 'Default allow LAN to any rule';
      });
    },
    rootCauses: ['pf-rule-source'],
    candidates: CANDIDATES,
    feedback: {
      'pf-forward-no-rule': 'The office does not use the port forward: it reaches 172.16.50.10 directly through fw01\'s LAN.',
      'pf-rule-order': 'There is only one pass rule on LAN; it does not match the office\'s source address.',
      'pf-outbound-manual': 'No outbound NAT is involved between the office and the DMZ.',
      'pf-alias-wrong': 'The aliases are right; the LAN rule no longer uses INTERNAL_NETS.',
      'web-not-running': 'The portal works from the Internet and from srv01.',
      'nat-wrong-dnat': 'No translation is involved between the office and the DMZ.',
      'nat-missing-masquerade': 'No translation is involved between the office and the DMZ.',
      'dns-client-config': 'ws01 resolves portal.corp.lab to 172.16.50.10, the right internal address.',
    },
    hints: [
      'It works from the server network, not from the office. Both reach fw01 on the same interface: what differs? Look at the firewall log while ws01 tries.',
      'The log shows the default deny on vtnet1 (LAN) for 10.0.10.x → 172.16.50.10:80. Which sources does the LAN pass rule accept? "LAN net" is 10.0.20.0/24.',
      'The office (10.0.10.0/24) is routed to fw01 by rtr01: it enters on LAN but is not "LAN net". Set the rule\'s source back to INTERNAL_NETS, Save, Apply.',
    ],
    explanation: {
      rootCause: 'The LAN rule\'s source was changed from INTERNAL_NETS (10.0.0.0/16) to the macro "LAN net", which is only fw01\'s own LAN subnet 10.0.20.0/24. Traffic from the routed office network (10.0.10.0/24) enters fw01 on LAN but matches no pass rule, so the default deny drops it.',
      manifestation: 'Hosts on the server network (directly on LAN) still reach the DMZ; hosts on the office and development networks, which reach fw01 through rtr01, time out. The webConfigurator keeps working from the office thanks to the anti-lockout rule, which hides the problem from the admins.',
      evidence: 'filter.log: block on vtnet1 by 1000000103 (Default deny), 10.0.10.25 → 172.16.50.10:80. pfctl -sr: pass in quick on vtnet1 from 10.0.20.0/24 to any. Firewall > Rules > LAN: source "LAN net".',
      prevention: '"LAN net" means the interface\'s own subnet, not everything behind it. When routers sit behind an interface, use an alias of the routed networks. Test from each network after rule changes, not only from the admin\'s machine.',
    },
    solution: [{ host: 'fw01', user: 'root', commands: ["sed -i 's|<network>lan</network>|<address>INTERNAL_NETS</address>|' /conf/config.xml", '/etc/rc.filter_configure'], note: 'In the webConfigurator: Firewall > Rules > LAN, edit the rule, Source: Single host or alias INTERNAL_NETS, Save, Apply Changes.' }],
    constraints: [pfEnabled(), dmzIsolated()],
    concepts: ['pfsense.rules', 'net.routing'],
  },
];
