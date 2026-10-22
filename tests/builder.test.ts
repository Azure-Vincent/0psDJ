import { describe, expect, it } from 'vitest';
import { buildDesignWorld, nftablesFile, rebootDesignWorld, traceCommand } from '../src/engine/builder/build';
import { freeIface, validateDesign, type Design } from '../src/engine/builder/design';
import { DESIGN_TEMPLATES } from '../src/engine/builder/templates';
import { missingParents } from '../src/engine/lab/builder';
import type { World } from '../src/engine/types';
import { Lab } from './helpers';

const tpl = (id: string) => DESIGN_TEMPLATES.find((t) => t.id === id)!.design();

function build(d: Design): Lab {
  const r = buildDesignWorld(d);
  expect(r.diagnostics.filter((x) => x.level === 'error')).toEqual([]);
  return new Lab(r.world as World);
}

describe('infrastructure builder', () => {
  it.each(DESIGN_TEMPLATES.map((t) => t.id))('%s: builds without errors and every service starts', (id) => {
    const lab = build(tpl(id));
    for (const h of Object.values(lab.world.hosts)) {
      expect(missingParents(h), h.id).toEqual([]);
      for (const [name, s] of Object.entries(h.services)) expect(s.state, `${h.id} ${name}`).toBe('active');
    }
  });

  it('two networks: hosts reach the server through the router; the firewall decides SSH by source', () => {
    const lab = build(tpl('two-networks'));
    expect(lab.run('pc1', 'admin', 'ping -c 1 10.0.2.10').output).toMatch(/1 received/);
    expect(lab.run('pc1', 'admin', 'curl -s http://web1/').output).toMatch(/Hello from web1/);
    expect(lab.run('pc1', 'root', 'traceroute -n -I 10.0.2.10').output).toMatch(/10\.0\.1\.1[\s\S]*10\.0\.2\.10/);
    // web1 only accepts SSH from the office network: gw's own address on the server side is refused.
    const before = JSON.stringify(lab.world);
    const t = traceCommand(lab.world, 'gw', 'root', 'ssh -o ConnectTimeout=3 admin@10.0.2.10');
    expect(t.decisions.some((d) => d.host === 'web1' && /filter input/.test(d.note) && /drop/.test(d.note))).toBe(true);
    // Tracing works on a copy: the learner's world is unchanged.
    expect(JSON.stringify(lab.world)).toBe(before);
  });

  it('router-on-a-stick: VLANs are separate broadcast domains and the forward policy filters between them', () => {
    const lab = build(tpl('vlans'));
    expect(lab.world.hosts.staff1.ifaces.find((i) => i.name === 'eth0')!.segment).toBe('sw1-vlan10');
    expect(lab.world.hosts.app1.ifaces.find((i) => i.name === 'eth0')!.segment).toBe('sw1-vlan20');
    expect(lab.run('staff1', 'admin', 'ping -c 1 192.168.10.22').output).toMatch(/1 received/);
    expect(lab.run('staff1', 'admin', 'ping -c 1 192.168.20.10').output).toMatch(/1 received/);
    expect(lab.run('staff1', 'admin', 'curl -s http://192.168.20.10/').output).toMatch(/Hello from app1/);
    const ssh = traceCommand(lab.world, 'staff1', 'admin', 'ssh -o ConnectTimeout=3 admin@192.168.20.20');
    expect(ssh.decisions.some((d) => d.host === 'rtr' && /filter forward/.test(d.note) && /policy drop/.test(d.note))).toBe(true);
  });

  it('DMZ: the office is masqueraded to the Internet; the Internet cannot open connections inward', () => {
    const lab = build(tpl('dmz'));
    const t = traceCommand(lab.world, 'laptop', 'admin', 'curl -s http://198.51.100.1/');
    expect(t.output).toMatch(/Hello from internet/);
    expect(t.decisions.some((d) => d.host === 'fw' && /masquerade/i.test(d.note))).toBe(true);
    expect(lab.run('laptop', 'admin', 'curl -s http://www/').output).toMatch(/Hello from www/);
    // From the DMZ to the office: nothing allows it.
    const back = traceCommand(lab.world, 'www', 'admin', 'ping -c 1 -W 1 10.1.0.50');
    expect(back.output).toMatch(/0 received/);
    expect(back.decisions.some((d) => d.host === 'fw' && /filter forward/.test(d.note))).toBe(true);
  });

  it('everything comes back after rebooting all machines', () => {
    const lab = new Lab(rebootDesignWorld(build(tpl('vlans')).world));
    expect(lab.run('staff2', 'admin', 'curl -s http://app1/').output).toMatch(/Hello from app1/);
  });

  it('validation catches duplicate addresses, unreachable gateways and switch-to-switch cables', () => {
    const d = tpl('two-networks');
    d.nodes.find((n) => n.name === 'pc2')!.ifaces[0].address = '10.0.1.10/24';
    d.nodes.find((n) => n.name === 'web1')!.gateway = '10.0.9.1';
    d.links.push({ id: 'x', a: { node: 'sw1', iface: 'swp3' }, b: { node: 'sw2', iface: 'swp3' } });
    const msgs = validateDesign(d).filter((x) => x.level === 'error').map((x) => x.message).join('\n');
    expect(msgs).toMatch(/Duplicate address 10\.0\.1\.10/);
    expect(msgs).toMatch(/gateway 10\.0\.9\.1 is not in the subnet/);
    expect(msgs).toMatch(/cables between switches/);
    expect(buildDesignWorld(d).world).toBeNull();
  });

  it('validation warns about a blocked web server and a VLAN missing on the trunk', () => {
    const d = tpl('vlans');
    d.nodes.find((n) => n.name === 'app1')!.firewall = { enabled: true, allow: [{ proto: 'tcp', port: 22 }] };
    d.nodes.find((n) => n.name === 'sw1')!.ports!.find((p) => p.mode === 'trunk')!.vlans = [10];
    const warns = validateDesign(d).filter((x) => x.level === 'warning').map((x) => x.message).join('\n');
    expect(warns).toMatch(/app1 runs a web server but its firewall does not allow tcp 80/);
    expect(warns).toMatch(/eth0\.20 sends VLAN 20 tagged/);
    // …and the simulation agrees: staff cannot reach the server VLAN.
    const lab = build(d);
    expect(lab.run('staff1', 'admin', 'ping -c 1 -W 1 192.168.20.10').output).toMatch(/0 received|Unreachable/);
  });

  it('generated nftables configuration loads and lists like a hand-written one', () => {
    const d = tpl('dmz');
    const conf = nftablesFile(d.nodes.find((n) => n.name === 'fw')!);
    expect(conf).toMatch(/policy drop;/);
    expect(conf).toMatch(/oifname "eth0" masquerade/);
    const lab = build(d);
    expect(lab.run('fw', 'root', 'nft -c -f /etc/nftables.conf').code).toBe(0);
    expect(lab.run('fw', 'root', 'nft list chain inet filter forward').output).toMatch(/ip saddr 10\.1\.0\.0\/24 accept/);
  });

  it('freeIface picks the next uncabled interface or port', () => {
    const d = tpl('two-networks');
    expect(freeIface(d, d.nodes.find((n) => n.id === 'sw1')!)).toBe('swp3');
    expect(freeIface(d, d.nodes.find((n) => n.id === 'h1')!)).toBeNull();
  });
});
