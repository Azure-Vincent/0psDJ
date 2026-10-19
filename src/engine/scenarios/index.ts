import { FIREWALL_SCENARIOS } from './firewallScenarios';
import { NETWORK_SCENARIOS } from './networkScenarios';
import { DHCP_NAT_SCENARIOS } from './dhcpNatScenarios';
import { SSH_SCENARIOS } from './sshScenarios';
import type { Scenario } from './types';

/** Every troubleshooting scenario, grouped by the lesson that introduces it. */
export const SCENARIO_SETS: { id: string; title: string; scenarios: Scenario[] }[] = [
  { id: 'network', title: 'Networking fundamentals', scenarios: NETWORK_SCENARIOS },
  { id: 'dhcp-nat', title: 'DHCP and NAT', scenarios: DHCP_NAT_SCENARIOS },
  { id: 'ssh', title: 'SSH', scenarios: SSH_SCENARIOS },
  { id: 'nftables', title: 'Firewalls (nftables)', scenarios: FIREWALL_SCENARIOS },
];

export const ALL_SCENARIOS: Scenario[] = SCENARIO_SETS.flatMap((s) => s.scenarios);

export function findScenario(id: string): Scenario | undefined {
  return ALL_SCENARIOS.find((s) => s.id === id);
}
