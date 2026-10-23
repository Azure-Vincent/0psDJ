import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { fromXml, toXml } from '../src/engine/pf/config';
import { FILTER_LOG, readConfig } from '../src/engine/pf/model';
import { browse, guiApply, guiSave, moveRule, saveAlias, saveInterface, saveRule } from '../src/engine/pf/webgui';
import { rebootAll } from '../src/engine/scenarios/engine';
import { Lab } from './helpers';

describe('pfSense (fw01)', () => {
  it('config.xml round-trips through the model', () => {
    const w = buildSshLab();
    const text = w.hosts.fw01.fs['/conf/config.xml'].content;
    const cfg = fromXml(text);
    expect(cfg.interfaces.map((i) => `${i.key}:${i.if}:${i.descr}`)).toEqual(['wan:vtnet0:WAN', 'lan:vtnet1:LAN', 'opt1:vtnet2:DMZ']);
    expect(fromXml(toXml(cfg))).toEqual(cfg);
  });

  it('publishes the portal, isolates the DMZ and logs the block with the rule\'s tracker', () => {
    const lab = new Lab(buildSshLab());
    expect(lab.run('ext01', 'guest', 'curl -s http://portal.corp.lab/').output).toMatch(/customer portal/);
    expect(lab.run('ws01', 'alice', 'curl -s http://portal.corp.lab/').output).toMatch(/customer portal/);
    expect(lab.run('dmz01', 'alice', 'ping -c 1 -W 1 10.0.20.10').code).not.toBe(0);
    expect(lab.run('dmz01', 'alice', 'ping -c 1 -W 1 203.0.113.80').code).toBe(0);
    const blk = readConfig(lab.world.hosts.fw01).filter.find((r) => r.type === 'block')!;
    expect(lab.world.hosts.fw01.fs[FILTER_LOG].content).toContain(`,${blk.tracker},vtnet2,match,block,in,4,`);
    expect(lab.run('fw01', 'root', 'pfctl -sn').output).toMatch(/^rdr on vtnet0 inet proto tcp from any to 203\.0\.113\.10 port \$WEB_PORTS -> 172\.16\.50\.10$/m);
    expect(lab.run('fw01', 'root', 'pfctl -t INTERNAL_NETS -T show').output.trim()).toBe('10.0.0.0/16');
  });

  it('keeps the previous ruleset when the new one has errors, and restores config.xml at boot', () => {
    const lab = new Lab(buildSshLab());
    lab.run('fw01', 'root', "sed -i 's|<address>DMZ_WEB</address>|<address>NO_SUCH_ALIAS</address>|' /conf/config.xml");
    const r = lab.run('fw01', 'root', '/etc/rc.filter_configure');
    expect(r.code).not.toBe(0);
    expect(r.output).toMatch(/rules\.debug:\d+: unknown|syntax error/);
    expect(lab.run('ext01', 'guest', 'curl -s http://portal.corp.lab/').output).toMatch(/customer portal/);
    lab.run('fw01', 'root', 'echo broken > /conf/config.xml');
    const w = rebootAll(lab.world);
    expect(w.hosts.fw01.fs['/conf/config.xml'].content).toContain('<pfsense>');
    expect(new Lab(w).run('ext01', 'guest', 'curl -s http://portal.corp.lab/').output).toMatch(/customer portal/);
  });

  it('pfctl -d opens the firewall at runtime only', () => {
    const lab = new Lab(buildSshLab());
    expect(lab.run('fw01', 'root', 'pfctl -d').output).toBe('pf disabled');
    expect(lab.run('dmz01', 'alice', 'ping -c 1 -W 1 10.0.20.10').code).toBe(0);
    const w = rebootAll(lab.world);
    expect(w.hosts.fw01.pf!.enabled).toBe(true);
  });

  it('webConfigurator: saving validates and marks pending; Apply loads; first match wins', () => {
    let w = buildSshLab();
    const bad = guiSave(w, 'fw01', 'filter', (c) => saveAlias(c, { name: 'X', type: 'host', address: ['10.0.0.0/8'], descr: '' }, null), 't');
    expect(bad.errors).toEqual(['10.0.0.0/8 is not a valid host alias.']);
    expect(guiSave(w, 'fw01', 'interfaces', (c) => saveInterface(c, 'opt1', { enable: true, descr: 'DMZ', ipaddr: '10.0.20.9', subnet: 24 }), 't').errors[0]).toMatch(/overlaps with: LAN/);
    // Move the DMZ "pass to the Internet" above the block: the DMZ reaches the inside once applied.
    const pass = readConfig(w.hosts.fw01).filter.find((r) => r.descr === 'DMZ to the Internet')!;
    w = guiSave(w, 'fw01', 'filter', (c) => moveRule(c, pass.tracker, -1), 't').world;
    expect(w.hosts.fw01.pf!.pending).toEqual(['filter']);
    expect(new Lab(w).run('dmz01', 'alice', 'ping -c 1 -W 1 10.0.20.10').code).not.toBe(0);
    w = guiApply(w, 'fw01').world;
    expect(w.hosts.fw01.pf!.pending).toEqual([]);
    expect(new Lab(w).run('dmz01', 'alice', 'ping -c 1 -W 1 10.0.20.10').code).toBe(0);
  });

  it('webConfigurator: a LAN block can lock out the routed office, but not the LAN itself (anti-lockout)', () => {
    let w = buildSshLab();
    w = guiSave(w, 'fw01', 'filter', (c, t) => saveRule(c, { tracker: '', type: 'block', interface: 'lan', source: { any: true }, destination: { any: true }, descr: 'block all', disabled: false, log: false }, null, t, 'top'), 't').world;
    w = guiApply(w, 'fw01').world;
    // ws01 reaches fw01's LAN address through rtr01: the anti-lockout rule matches on LAN, whatever the source.
    expect(browse(w, 'ws01', 'alice', 'https://10.0.20.254/').ok).toBe(true);
    // From the Internet, 443 on the WAN address is forwarded to dmz01, which does not serve HTTPS.
    expect(browse(w, 'ext01', 'guest', 'https://203.0.113.10/')).toMatchObject({ ok: false, error: 'ERR_CONNECTION_REFUSED' });
    expect(new Lab(w).run('ws01', 'alice', 'curl -s -m 3 http://portal.corp.lab/').code).toBe(28);
  });
});
