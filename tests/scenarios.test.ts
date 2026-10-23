import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { checkGoal, gradeDiagnosis, verifyScenario } from '../src/engine/scenarios/engine';
import { ALL_SCENARIOS as SSH_SCENARIOS } from '../src/engine/scenarios';
import { CAUSES } from '../src/engine/scenarios/catalog';
import { Lab } from './helpers';

const SYMPTOM: Record<string, RegExp> = {
  'ssh-config-typo': /Connection refused/,
  'ssh-port-moved': /Connection refused/,
  'ssh-firewall-drop': /Connection timed out/,
  'ssh-firewall-reject': /No route to host/,
  'ssh-dns-stale': /No route to host/,
  'ssh-missing-gateway': /Connection timed out/,
  'ssh-perms-strictmodes': /Permission denied \(publickey\)/,
  'ssh-hostkey-changed': /REMOTE HOST IDENTIFICATION HAS CHANGED/,
  'ssh-allowusers': /Permission denied \(publickey\)/,
  'ssh-kex-legacy': /no matching key exchange method found/,
  'ssh-client-key-perms': /UNPROTECTED PRIVATE KEY FILE/,
  'ssh-bob-password': /Permission denied \(publickey\)/,
  'ssh-dns-zone-error': /Temporary failure in name resolution/,
  'ssh-monday-reboot': /Connection timed out/,
  'fw-nginx-stopped': /Couldn't connect to server/,
  'fw-tcp-reset': /Couldn't connect to server/,
  'fw-cidr-guest': /Connection timed out/,
  'fw-no-established': /\$ getent hosts ns1.corp.lab\n\(no output\)/,
  'fw-router-forward': /curl: \(28\)|after \d+ ms/,
  'net-wrong-mask': /No route to host/,
  'net-wrong-gateway': /No route to host/,
  'net-ip-forward': /No route to host/,
  'net-dns-resolvconf': /Temporary failure in name resolution/,
  'net-hosts-override': /No route to host/,
  'net-nginx-loopback': /Couldn't connect to server/,
  'dhcp-interface': /Could not resolve host|Network is unreachable/,
  'dhcp-pool-exhausted': /Could not resolve host|Network is unreachable/,
  'dhcp-wrong-router': /No route to host/,
  'nat-no-masquerade': /curl: \(28\)/,
  'nat-dnat-typo': /No route to host/,
  'nat-filter-order': /curl: \(28\)/,
  'vlan-access-port': /Could not resolve host/,
  'vlan-trunk-pruned': /Could not resolve host/,
  'vlan-subif-id': /Could not resolve host/,
  'ipv6-icmp-hardening': /No route to host/,
  'ipv6-forwarding-hardening': /curl: \(28\)/,
  'ipv6-server-gateway': /curl: \(28\)/,
  'case-no-internet': /curl: \(28\)/,
  'case-dns-outage': /Temporary failure in name resolution/,
  'tls-expired': /certificate has expired/,
  'tls-key-mismatch': /certificate has expired/,
  'tls-wrong-cert': /no alternative certificate subject name matches target host name 'www\.corp\.lab'/,
  'tls-missing-intermediate': /unable to get local issuer certificate/,
  'tls-untrusted-root': /unable to get local issuer certificate/,
  'dhcp-relay-server': /Could not resolve host|Network is unreachable/,
  'dhcp-relay-iu': /Could not resolve host|Network is unreachable/,
  'dhcp-relay-subnet': /Could not resolve host|Network is unreachable/,
  'dhcp-lease-expiry': /Could not resolve host|Network is unreachable/,
  'dhcp6-client-firewall': /No route to host/,
  'dhcp6-server-firewall': /No route to host/,
  'dhcp6-wrong-interface': /No route to host/,
  'krb-clock-skew': /kinit: Clock skew too great while getting initial credentials/,
  'krb-missing-srv': /kinit: Cannot find KDC for realm "CORP.LAB" while getting initial credentials/,
  'krb-kdc-firewall': /kinit: Cannot contact any KDC for realm 'CORP.LAB' while getting initial credentials/,
  'krb-stale-keytab': /Permission denied \(publickey,gssapi-keyex,gssapi-with-mic\)/,
  'netif-renamed-nic': /Couldn't connect to server|No route to host/,
  'netif-bridge-port': /Couldn't connect to server|No route to host/,
  'mtu-uplink-mismatch': /curl: \(28\) Operation timed out after 30000 milliseconds with 0 out of 4718592 bytes received/,
};

describe.each(SSH_SCENARIOS.map((s) => [s.id, s] as const))('scenario %s', (id, scenario) => {
  it('is well-formed', () => {
    expect(SYMPTOM[id]).toBeDefined();
    for (const c of [...scenario.rootCauses, ...scenario.candidates, ...Object.keys(scenario.acceptable ?? {})]) expect(CAUSES[c], c).toBeDefined();
    for (const c of scenario.rootCauses) expect(scenario.candidates).toContain(c);
    expect(scenario.hints.length).toBeGreaterThanOrEqual(3);
  });

  it('breaks the baseline with the expected symptom, and the reference fix passes verification (incl. reboot)', () => {
    const world = buildSshLab();
    scenario.setup(world);
    const before = scenario.goals.map((g) => checkGoal(world, g));
    expect(before.some((g) => !g.ok)).toBe(true);
    expect(before.flatMap((g) => g.lines).join('\n')).toMatch(SYMPTOM[id]);
    expect(verifyScenario(world, scenario).passed).toBe(false);

    const lab = new Lab(world);
    for (const step of scenario.solution) {
      for (const cmd of step.commands) {
        const r = lab.run(step.host, step.user ?? 'root', cmd);
        expect(r.needInput, `${step.host}: ${cmd}`).toBeUndefined();
      }
    }
    const v = verifyScenario(lab.world, scenario);
    expect(v.now.map((g) => g.lines.at(-1)), 'goal now').toEqual(v.now.map((g) => (g.ok ? g.lines.at(-1) : 'ok')));
    expect(v.afterReboot.every((g) => g.ok), 'goal after reboot').toBe(true);
    expect([...v.constraints, ...v.constraintsAfterReboot].filter((c) => c.required && !c.ok)).toEqual([]);
    expect(v.passed).toBe(true);
  });

  it('grades the reference diagnosis as correct and a wrong one as wrong', () => {
    expect(gradeDiagnosis(scenario, scenario.rootCauses).correct).toBe(true);
    const wrong = scenario.candidates.find((c) => !scenario.rootCauses.includes(c) && !scenario.acceptable?.[c])!;
    const g = gradeDiagnosis(scenario, [wrong]);
    expect(g.correct).toBe(false);
    expect(g.wrong[0].explanation.length).toBeGreaterThan(20);
  });
});

describe('security constraints catch bad "fixes"', () => {
  it('opening the firewall completely is rejected even though SSH works', () => {
    const s = SSH_SCENARIOS.find((x) => x.id === 'ssh-firewall-drop')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    lab.run('srv01', 'root', "sed -i 's/policy drop;/policy accept;/' /etc/nftables.conf");
    lab.run('srv01', 'root', 'nft -f /etc/nftables.conf');
    const v = verifyScenario(lab.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
    expect(v.constraints.find((c) => c.id === 'fw-restrictive-srv01')?.ok).toBe(false);
  });

  it('a runtime-only firewall fix fails the reboot test', () => {
    const s = SSH_SCENARIOS.find((x) => x.id === 'ssh-firewall-drop')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    lab.run('srv01', 'root', 'nft insert rule inet filter input ip saddr 10.0.10.0/24 tcp dport 22 accept');
    const v = verifyScenario(lab.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.afterReboot.every((g) => g.ok)).toBe(false);
    expect(v.passed).toBe(false);
  });

  it('enabling password authentication to let bob in violates the policy', () => {
    const s = SSH_SCENARIOS.find((x) => x.id === 'ssh-bob-password')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    lab.run('srv01', 'root', "sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/10-hardening.conf");
    lab.run('srv01', 'root', 'systemctl reload ssh');
    expect(verifyScenario(lab.world, s).constraints.find((c) => c.id === 'sshd-policy')?.ok).toBe(false);
  });

  it('multi-fault: fixing only the firewall changes the symptom from timeout to refused', () => {
    const s = SSH_SCENARIOS.find((x) => x.id === 'ssh-monday-reboot')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    lab.run('srv01', 'root', 'nft add rule inet filter input tcp dport 22 accept');
    const r = lab.run('ws01', 'alice', 'ssh -o BatchMode=yes srv01.corp.lab');
    expect(r.output).toMatch(/Connection refused/);
  });
});
