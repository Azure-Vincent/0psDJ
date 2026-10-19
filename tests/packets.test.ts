import { describe, expect, it } from 'vitest';
import { buildPcap, checksum, frameBytes } from '../src/engine/pcap';
import { matchFilter, parseFilter } from '../src/engine/filter';
import { CAPTURE_PRESETS, runCapture } from '../src/engine/lab/captures';
import { OUTCOME_LABELS, SSH_DEPENDENCIES, runWithFault } from '../src/engine/lab/dependencies';

describe('capture presets', () => {
  it.each(CAPTURE_PRESETS.map((p) => p.id))('%s produces frames', (id) => {
    const { frames } = runCapture(id);
    expect(frames.length).toBeGreaterThan(2);
  });
  it('the login capture contains ARP, DNS, a handshake, plaintext KEXINIT and a FIN teardown', () => {
    const { frames } = runCapture('ssh-login');
    expect(frames.some((f) => f.arp?.op === 'request' && f.arp.targetIp === '10.0.10.1')).toBe(true);
    expect(frames.some((f) => f.ip?.app?.protocol === 'DNS')).toBe(true);
    expect(frames.some((f) => f.ip?.app?.info === 'Client: Key Exchange Init')).toBe(true);
    expect(frames.some((f) => f.ip?.tcp?.flags.includes('FIN'))).toBe(true);
    expect(frames.some((f) => f.ip?.app?.encrypted)).toBe(true);
  });
  it('the timeout capture shows SYN retransmissions with the same sequence number', () => {
    const syns = runCapture('ssh-timeout').frames.filter((f) => f.ip?.tcp?.flags.join() === 'SYN');
    expect(syns.length).toBeGreaterThanOrEqual(4);
    expect(new Set(syns.map((f) => f.ip!.tcp!.seq)).size).toBe(1);
    const gaps = syns.slice(1).map((f, i) => Math.round((f.time - syns[i].time) / 1000));
    expect(gaps.slice(0, 3)).toEqual([1, 2, 4]);
  });
});

describe('pcap writer', () => {
  it('writes a valid global header and records with correct IP checksums', () => {
    const { frames } = runCapture('ssh-login');
    const pcap = buildPcap(frames);
    const dv = new DataView(pcap.buffer);
    expect(dv.getUint32(0, true)).toBe(0xa1b2c3d4);
    expect(dv.getUint32(20, true)).toBe(1); // LINKTYPE_ETHERNET
    let off = 24;
    let n = 0;
    while (off < pcap.length) {
      const incl = dv.getUint32(off + 8, true);
      const frame = pcap.slice(off + 16, off + 16 + incl);
      if (frame[12] === 0x08 && frame[13] === 0x00) {
        const ihl = (frame[14] & 0x0f) * 4;
        expect(checksum([...frame.slice(14, 14 + ihl)])).toBe(0);
        const total = (frame[16] << 8) | frame[17];
        expect(total).toBeLessThanOrEqual(frame.length - 14);
      }
      off += 16 + incl;
      n++;
    }
    expect(n).toBe(frames.length);
  });
  it('TCP checksums verify with the pseudo-header', () => {
    const f = runCapture('ssh-login').frames.find((x) => x.ip?.tcp && x.ip.tcp.len > 0)!;
    const b = [...frameBytes(f)];
    const ip = b.slice(14, 34);
    const total = (ip[2] << 8) | ip[3];
    const seg = b.slice(34, 14 + total);
    const pseudo = [...ip.slice(12, 20), 0, 6, seg.length >> 8, seg.length & 255];
    expect(checksum([...pseudo, ...seg])).toBe(0);
  });
});

describe('display filters', () => {
  const { frames } = runCapture('ssh-login');
  const count = (f: string) => frames.filter((fr, i) => matchFilter(parseFilter(f), fr, i)).length;
  it('filters by protocol, fields and boolean logic', () => {
    expect(count('arp')).toBeGreaterThan(0);
    expect(count('dns')).toBe(2);
    expect(count('tcp.flags.syn == 1')).toBe(2);
    expect(count('tcp.flags.syn == 1 && tcp.flags.ack == 1')).toBe(1);
    expect(count('ip.addr == 10.0.10.53 || arp')).toBe(count('dns') + count('arp'));
    expect(count('not tcp')).toBe(frames.length - count('tcp'));
    expect(count('(ssh)')).toBe(count('ssh'));
  });
  it('rejects unknown fields with a helpful message', () => {
    expect(() => parseFilter('http.host == x')).toThrow(/neither a field nor a protocol/);
  });
});

describe('dependency map', () => {
  const expected: Record<string, keyof typeof OUTCOME_LABELS> = {
    dns: 'resolve-temp', 'dns-record': 'resolve-nx', 'client-route': 'netunreach', router: 'noroute', 'server-route': 'timeout',
    firewall: 'timeout', sshd: 'refused', algorithms: 'negotiate', hostkey: 'hostkey', authz: 'denied', authkeys: 'denied', shell: 'shell',
  };
  it.each(SSH_DEPENDENCIES.map((d) => d.id))('switching off %s produces the expected client symptom', (id) => {
    expect(runWithFault(id).outcome).toBe(expected[id]);
  });
  it('baseline succeeds and the trace starts with name resolution and ARP', () => {
    const r = runWithFault(null);
    expect(r.outcome).toBe('success');
    expect(r.trace[0].phase).toBe('DNS');
    expect(r.trace.some((e) => e.kind === 'arp')).toBe(true);
  });
});
