import { describe, expect, it } from 'vitest';
import { runSsh } from '../src/engine/sim/ssh';
import { tcpConnect } from '../src/engine/sim/tcp';
import { Recorder, withRecorder } from '../src/engine/sim/trace';
import { Lab } from './helpers';

describe('baseline lab', () => {
  it('alice can log in with her key', () => {
    const lab = new Lab();
    const r = runSsh(lab.world, { clientHostId: 'ws01', localUser: 'alice', target: 'srv01.corp.lab', batchMode: true });
    expect(r.outcome).toBe('session');
    expect(r.authMethod).toBe('publickey');
    expect(lab.world.hosts.srv01.journal.at(-3)?.message).toMatch(/^Accepted publickey for alice from 10.0.10.25 port \d+ ssh2: ED25519 SHA256:/);
  });

  it('records a protocol-ordered trace: DNS, ARP, TCP handshake, SSH, with consistent sequence numbers', () => {
    const lab = new Lab();
    const rec = new Recorder();
    withRecorder(rec, () => runSsh(lab.world, { clientHostId: 'ws01', localUser: 'alice', target: 'srv01.corp.lab', batchMode: true }));
    const packets = rec.events.filter((e) => e.kind === 'packet');
    const phases = [...new Set(rec.events.map((e) => e.phase))];
    expect(phases[0]).toBe('DNS');
    expect(phases.indexOf('TCP')).toBeGreaterThan(0);
    const syn = packets.find((p) => p.packet?.tcp?.flags.join() === 'SYN')!;
    const synack = packets.find((p) => p.packet?.tcp?.flags.join() === 'SYN,ACK')!;
    expect(synack.packet!.tcp!.ack).toBe(syn.packet!.tcp!.seq + 1);
    const titles = packets.map((p) => p.title);
    expect(titles).toContain('SSH_MSG_KEXINIT (server)');
    expect(titles.indexOf('SSH2_MSG_NEWKEYS (client)')).toBeGreaterThan(titles.indexOf('SSH2_MSG_KEX_ECDH_REPLY'));
    // Everything after NEWKEYS is marked encrypted on the wire.
    const after = packets.slice(titles.indexOf('SSH2_MSG_NEWKEYS (server)') + 1).filter((p) => p.packet?.app?.protocol === 'SSH');
    expect(after.length).toBeGreaterThan(5);
    expect(after.every((p) => p.packet!.app!.encrypted)).toBe(true);
    // Data sequence numbers continue from the handshake.
    const firstData = packets.find((p) => p.from === 'ws01' && (p.packet?.tcp?.len ?? 0) > 0)!;
    expect(firstData.packet!.tcp!.seq).toBe(syn.packet!.tcp!.seq + 1);
  });

  it('no listener → RST → ECONNREFUSED; firewall drop → retransmits for ~127s → ETIMEDOUT', () => {
    const lab = new Lab();
    const ws = lab.world.hosts.ws01;
    const refused = tcpConnect(lab.world, ws, '10.0.20.10', 8080);
    // srv01 drops unknown ports by policy, so this one times out:
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.errno).toBe('ETIMEDOUT');
      expect(refused.attempts).toBe(7);
      expect(Math.round(refused.elapsedMs / 1000)).toBe(127);
    }
    // ns1 has a permissive firewall and nothing on 8080 → RST.
    const rst = tcpConnect(lab.world, ws, '10.0.10.53', 8080);
    expect(rst.ok === false && rst.errno).toBe('ECONNREFUSED');
  });

  it('a stopped sshd turns the result into Connection refused; state is reflected in ss and the journal', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', 'systemctl stop ssh');
    expect(lab.run('srv01', 'root', 'ss -tln').output).not.toContain(':22 ');
    const r = lab.run('ws01', 'alice', 'ssh srv01.corp.lab');
    expect(r.output).toBe('ssh: connect to host srv01.corp.lab port 22: Connection refused');
    expect(lab.run('srv01', 'root', 'journalctl -u ssh -n 2').output).toMatch(/Stopped ssh.service/);
  });

  it('firewall changes immediately change connection results and counters', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', 'nft insert rule inet filter input tcp dport 22 counter drop');
    const r = lab.run('ws01', 'alice', 'ssh -o ConnectTimeout=5 srv01.corp.lab');
    expect(r.output).toMatch(/Connection timed out/);
    expect(lab.run('srv01', 'root', 'nft list chain inet filter input').output).toMatch(/tcp dport 22 counter packets [1-9]\d* bytes \d+ drop/);
    lab.run('srv01', 'root', 'nft flush chain inet filter input');
    // flushed chain with policy drop: still blocked
    expect(lab.run('ws01', 'alice', 'ssh -o ConnectTimeout=3 srv01.corp.lab').output).toMatch(/timed out/);
  });

  it('host key prompt is interactive and adds the key to known_hosts', () => {
    const lab = new Lab();
    const first = lab.run('ws01', 'alice', 'ssh srv01');
    expect(first.needInput?.text).toMatch(/Are you sure you want to continue connecting/);
    expect(first.needInput?.partial).toMatch(/ED25519 key fingerprint is SHA256:/);
    const second = lab.run('ws01', 'alice', 'ssh srv01', ['yes']);
    expect(second.output).toMatch(/Permanently added 'srv01' \(ED25519\)/);
    expect(lab.world.hosts.ws01.fs['/home/alice/.ssh/known_hosts'].content).toMatch(/^srv01 ssh-ed25519 /m);
  });

  it('runtime-only changes disappear after reboot', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', 'ip route del default');
    expect(lab.run('srv01', 'root', 'ip route').output).not.toMatch(/default/);
    lab.run('srv01', 'root', 'reboot');
    expect(lab.run('srv01', 'root', 'ip route').output).toMatch(/default via 10.0.20.1/);
  });

  it('sudo asks for the password and permission checks apply', () => {
    const lab = new Lab();
    expect(lab.run('ws01', 'alice', 'cat /etc/shadow').output).toBe('cat: /etc/shadow: Permission denied');
    const ask = lab.run('ws01', 'alice', 'sudo cat /etc/shadow');
    expect(ask.needInput?.text).toBe('[sudo] password for alice: ');
    expect(lab.run('ws01', 'alice', 'sudo cat /etc/shadow', ['ws01-alice']).output).toMatch(/^root:/);
  });

  it('dig ignores /etc/hosts and the search list, getent does not', () => {
    const lab = new Lab();
    lab.run('ws01', 'root', 'echo "10.0.20.99 srv01.corp.lab" >> /etc/hosts');
    expect(lab.run('ws01', 'alice', 'getent hosts srv01.corp.lab').output).toMatch(/^10.0.20.99/);
    expect(lab.run('ws01', 'alice', 'dig +short srv01.corp.lab').output).toBe('10.0.20.10');
    expect(lab.run('ws01', 'alice', 'dig srv01').output).toMatch(/status: REFUSED/);
  });
});
