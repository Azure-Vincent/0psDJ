// Integrated Lab 6: Configure Network Segmentation With pfSense. Builds on the
// Perimeter firewall lab (DMZ interface, aliases, the DMZ policy, the port
// forward, office access) and frames it as segmentation: which zones may talk
// to which, and why each allowed flow is needed. The incident: a "safety"
// block rule placed above a pass rule interrupts a legitimate service (DNS
// from the DMZ).

import type { GuidedLab } from '../types';
import { LAB3 } from '../lab3';
import { cmdCheck, hop } from './common';
import { reuseStep, ticketFault } from './tickets';

const flows = [
  cmdCheck('dmz-dns', 'The DMZ resolves internal names through ns1 (allowed: DNS only)', 'dmz01', 'alice', 'getent hosts srv01.corp.lab', (o) => (/^10\.0\.20\.10\s/m.test(o) ? null : 'dmz01 cannot resolve through ns1.'), 'DNS from the DMZ works.'),
  cmdCheck('dmz-no-office', 'The DMZ cannot open connections into the office (blocked)', 'dmz01', 'alice', 'nc -z -w 3 10.0.10.25 22', (_o, c) => (c !== 0 ? null : 'dmz01 reaches ws01: the DMZ must not open connections inward.'), 'DMZ → office is blocked.'),
  cmdCheck('internet-portal', 'The Internet reaches the portal on fw01\'s WAN address (published HTTP)', 'ext01', 'guest', 'curl -sI -m 5 http://203.0.113.10/', (o) => (/^HTTP\/1\.1 200/.test(o) ? null : 'ext01 does not get the portal through the port forward.'), 'The portal is published.'),
  cmdCheck('office-portal', 'The office reaches the portal directly', 'ws01', 'alice', 'curl -sI -m 5 http://172.16.50.10/', (o) => (/^HTTP\/1\.1 200/.test(o) ? null : 'ws01 cannot reach the portal in the DMZ.'), 'Office → DMZ works.'),
];

export const ILAB6: GuidedLab = {
  id: 'ilab6',
  title: 'Integrated Lab 6: Configure Network Segmentation With pfSense',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Separate the networks by trust: a DMZ for the public portal on pfSense, with a written policy of which flows are allowed (DNS to ns1, the Internet, HTTP from outside through a port forward, the office to the portal) and everything else blocked and logged. Then find out why the DMZ lost DNS after a "safety" rule was added.',
  brief: `${LAB3.brief}

Before you write rules, write the **flow matrix**: for each pair of zones (Internet, DMZ, office/servers), which connections are needed and why. Each pass rule must correspond to one line of it; everything else is blocked and logged.`,
  objectives: [
    ...LAB3.objectives,
    'Turn a segmentation requirement into a flow matrix and a first-match rule set, and verify allowed and blocked flows from each zone.',
  ],
  prerequisites: LAB3.prerequisites,
  setupNote: LAB3.setupNote,
  terminals: LAB3.terminals,
  build: LAB3.build,
  steps: [
    reuseStep(LAB3, 'dmz-iface'),
    reuseStep(LAB3, 'aliases'),
    reuseStep(LAB3, 'dmz-rules', {
      commands: [{ host: 'fw01', command: 'pfctl -sr', what: 'Shows the filter rules pf actually loaded from the GUI\'s configuration, in evaluation order.', why: 'The GUI shows intent; pfctl shows what is enforced. On pfSense the first matching rule on the interface where the packet enters decides.', where: 'Generated into /tmp/rules.debug from /cf/conf/config.xml.', success: 'Your DMZ rules in order: pass DNS to ns1, block (log) to the internal networks, pass to any.', verify: 'Test from dmz01 (DNS works, ws01 blocked) and read /var/log/filter.log for the blocks.' }],
    }),
    reuseStep(LAB3, 'publish', {
      commands: [{ host: 'fw01', command: 'pfctl -sn', what: 'Shows the NAT rules (rdr for port forwards, nat for outbound).', why: 'A port forward rewrites the destination before filtering: the WAN filter rule must allow the translated (internal) address and port.', where: 'Firewall > NAT > Port Forward in the GUI; /tmp/rules.debug.', success: 'rdr on vtnet0 … port 80 -> 172.16.50.10', verify: 'curl from ext01 to 203.0.113.10.' }],
    }),
    reuseStep(LAB3, 'lan-access'),
    {
      id: 'verify', title: 'Verify every zone pair, and after a reboot', stage: 'verify',
      objective: 'The allowed flows work and the blocked ones are blocked, from each zone, and everything survives a restart of every machine.',
      background: 'Segmentation is verified in both directions: every allowed flow from its source zone, and at least one forbidden flow from each zone that must be blocked. A rule set that allows everything passes the first half; one that blocks everything passes the second.',
      tasks: ['From dmz01: getent hosts srv01.corp.lab (works), nc -z -w 3 10.0.10.25 22 (blocked).', 'From ext01: curl -sI http://203.0.113.10/. From ws01: curl -sI http://172.16.50.10/.', 'Run the check (reboots every machine on a copy and repeats every check).'],
      hints: ['/var/log/filter.log on fw01 shows which rule blocked a flow that should pass.'],
      checks: flows,
      solution: [],
      learn: [{ label: 'pfSense rules', link: 'lesson/pfsense/internals' }],
      concepts: ['pfsense.rules', 'pfsense.nat'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 6,
    scenario: {
      organisation: 'corp.lab: a customer portal must be reachable from the Internet, while the internal networks stay private.',
      situation: 'The portal server dmz01 is cabled to a new, unassigned port of the pfSense firewall fw01. Nothing separates it yet, and nothing reaches it.',
      goal: 'A DMZ that the Internet can reach for HTTP/HTTPS only, that can use DNS and the Internet but cannot open connections into the internal networks, and that the office can reach.',
      whyItMatters: 'Segmentation limits what an attacker can reach after compromising one machine (in competitions: the public web server). It only helps if each allowed flow is deliberate and every legitimate dependency (here DNS) is in the policy.',
    },
    technologies: ['pfSense interfaces and aliases', 'First-match firewall rules per interface', 'Port forwards (rdr) and outbound NAT', 'DNS from a DMZ', 'Firewall logging', 'Routing between zones'],
    systems: [
      { host: 'fw01', role: 'pfSense: WAN 203.0.113.10, LAN 10.0.20.254, DMZ (vtnet2) to be configured' },
      { host: 'dmz01', role: 'The portal web server (172.16.50.10) in the DMZ' },
      { host: 'ns1', role: 'Internal DNS (10.0.10.53): the only internal service the DMZ may use' },
      { host: 'ws01', role: 'The office: must reach the portal' },
      { host: 'ext01', role: 'A machine on the Internet' },
      { host: 'rtr01', role: 'Routes 172.16.50.0/24 to fw01' },
    ],
    startingState: ['fw01 after the setup wizard: WAN and LAN configured, vtnet2 unassigned, default rules.', 'dmz01 configured for 172.16.50.10/24 with gateway 172.16.50.1, unreachable.'],
    tools: [
      { command: 'webConfigurator: Interfaces, Firewall > Aliases / Rules / NAT', platform: 'pfSense', use: 'The configuration (config.xml)', refId: 'pfsense-console' },
      { command: 'pfctl -sr, pfctl -sn, pfctl -ss', platform: 'pfSense', use: 'Loaded rules, NAT rules and states', refId: 'pfctl' },
      { command: 'tail /var/log/filter.log', platform: 'pfSense', use: 'Which rule blocked a packet', refId: 'file:pfsense-filter-log' },
      { command: 'getent hosts, nc -z -w 3, curl -sI', platform: 'Linux', use: 'Test each flow from its source zone', refId: 'nc' },
      { command: 'show access-lists, show ip nat translations', platform: 'Cisco IOS', use: 'The equivalent on a Cisco router (not simulated)', refId: 'ios-show-run' },
    ],
    dependencies: {
      explanation: `The flow matrix this lab implements:

| From \\ To | Internet | DMZ | Internal (office, servers) |
|---|---|---|---|
| **Internet** | n/a | HTTP/HTTPS to the portal only (port forward on the WAN address) | nothing |
| **DMZ** | allowed (updates, APIs), via outbound NAT | n/a | **DNS to ns1 only**; everything else blocked and logged |
| **Internal** | allowed | the portal (office access) | n/a |

pfSense filters **on the interface where a packet enters**, first match wins: the DMZ's rules decide what the DMZ may open; replies to allowed connections pass by state. The portal depends on DNS for its own calls: a block rule placed above the DNS pass rule breaks it, although "nothing changed" for HTTP.`,
      paths: [
        {
          id: 'dmz-dns', label: 'dmz01 resolves an internal name (allowed)',
          nodes: [
            hop('gw', 'DMZ gateway answers', 'fw01\'s DMZ address 172.16.50.1.', 'dmz01', 'alice', 'ping -c 1 -W 2 172.16.50.1', (_o, c) => c === 0),
            hop('dns', 'ns1 answers through fw01', 'The DMZ pass rule for DNS to ns1 (above the block rule).', 'dmz01', 'alice', 'getent hosts srv01.corp.lab', (o) => /^10\.0\.20\.10\s/m.test(o)),
          ],
        },
        {
          id: 'internet', label: 'a customer opens the portal from the Internet',
          nodes: [
            hop('wan', 'fw01\'s WAN answers HTTP', 'The port forward (rdr) and its WAN filter rule.', 'ext01', 'guest', 'curl -sI -m 5 http://203.0.113.10/', (o) => /^HTTP\/1\.1 200/.test(o)),
          ],
        },
        {
          id: 'office', label: 'the office opens the portal directly',
          nodes: [
            hop('route', 'The DMZ is routed', 'rtr01 → fw01 for 172.16.50.0/24.', 'ws01', 'alice', 'ping -c 1 -W 2 172.16.50.10', (_o, c) => c === 0),
            hop('http', 'The portal answers', 'fw01\'s LAN rules let the office in.', 'ws01', 'alice', 'curl -sI -m 5 http://172.16.50.10/', (o) => /^HTTP\/1\.1 200/.test(o)),
          ],
        },
      ],
    },
    mistakes: [
      'A pass any rule on the DMZ "for now": the DMZ can then reach every internal machine.',
      'Blocking the internal networks above the DNS exception: the portal loses name resolution.',
      'A port forward without the matching filter rule (or a rule written for the public address instead of the translated one).',
      'Testing only the allowed flows: a policy that allows everything passes those tests too.',
    ],
    verification: 'Checks read fw01\'s configuration and loaded rules and test real flows from each zone: DNS from the DMZ, a blocked connection from the DMZ into the office, HTTP from the Internet through the port forward, HTTP from the office. The final check reboots everything and repeats them. The incident is repaired when the DMZ resolves names again with the block rule still in place.',
    fault: ticketFault('pf-rule-order', {
      title: 'The portal cannot resolve names after the "safety" rule',
      report: 'Web team (Thursday): "dmz01 cannot resolve anything since yesterday afternoon: the portal\'s calls to the API on srv01.corp.lab and the package updates all fail with \'Temporary failure in name resolution\'." Security: "We only added a block rule to the DMZ, to be safe."',
    }),
    review: [
      { id: 'q1', question: 'On pfSense, which rules decide whether dmz01 may open a connection to ns1?', choices: ['The rules on the DMZ interface (where the packet enters), first match wins', 'The rules on the LAN interface', 'The WAN rules', 'All interfaces\' rules, the last match wins'], answer: 0, explanation: 'pfSense filters inbound on the interface where traffic arrives. Replies return by state.', concepts: ['pfsense.rules'] },
      { id: 'q2', question: 'A block rule "DMZ → internal networks" is placed above "pass DMZ → ns1 port 53". What happens to DNS from the DMZ?', choices: ['It is blocked: the first matching rule (the block) wins', 'It still works: pass rules win', 'It works only over TCP', 'It works until the states expire'], answer: 0, explanation: 'First match wins. Exceptions must come before the broader block.', concepts: ['pfsense.rules'] },
      { id: 'q3', question: 'Why does the WAN rule for the published portal name the internal address 172.16.50.10, not 203.0.113.10?', choices: ['The port forward (rdr) translates the destination before the filter rules are evaluated', 'The WAN address is not routable', 'pfSense ignores public addresses', 'For logging only'], answer: 0, explanation: 'rdr happens first; the filter sees the translated destination.', concepts: ['pfsense.nat'] },
      { id: 'q4', question: 'Which test proves that the segmentation works, not just the services?', choices: ['A connection from the DMZ to an internal host is refused/blocked while DNS from the DMZ still works', 'The portal answers from the Internet', 'The office reaches the portal', 'fw01 answers ping'], answer: 0, explanation: 'Allowed-flow tests pass with "allow everything" too; only a blocked-flow test shows the boundary exists.', concepts: ['pfsense.rules'] },
    ],
    after: ['pfsense', 'nat', 'nftables', 'vlan'],
  },
};
