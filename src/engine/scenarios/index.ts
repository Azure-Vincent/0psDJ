import { FIREWALL_SCENARIOS } from './firewallScenarios';
import { SSH_SCENARIOS } from './sshScenarios';
import type { Scenario } from './types';

/** Every troubleshooting scenario, grouped by the lesson that introduces it. */
export const SCENARIO_SETS: { id: string; title: string; scenarios: Scenario[] }[] = [
  { id: 'ssh', title: 'SSH', scenarios: SSH_SCENARIOS },
  { id: 'nftables', title: 'Firewalls (nftables)', scenarios: FIREWALL_SCENARIOS },
];

export const ALL_SCENARIOS: Scenario[] = SCENARIO_SETS.flatMap((s) => s.scenarios);

export function findScenario(id: string): Scenario | undefined {
  return ALL_SCENARIOS.find((s) => s.id === id);
}
