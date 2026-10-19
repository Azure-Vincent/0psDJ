import { describe, expect, it } from 'vitest';
import { parseCidr, inCidr, formatIp, parseIp } from '../src/engine/net/ip';
import { sha256, base64Encode, utf8 } from '../src/engine/util/sha256';
import { effectiveConfig, parseSshdConfig } from '../src/engine/config/sshdConfig';
import { evaluate, parseRulesetFile, renderRuleset } from '../src/engine/config/nft';
import { answerQuery, parseZone } from '../src/engine/config/zone';
import { parseInterfaces } from '../src/engine/config/netconf';
import { makeKeyPair, parsePublicKey } from '../src/engine/sim/keys';
import { SRV01_NFT, CORP_ZONE } from '../src/engine/lab/sshLab';
import { parseCommandLine } from '../src/engine/shell/tokenize';

describe('ip helpers', () => {
  it('parses and formats addresses and CIDRs', () => {
    expect(formatIp(parseIp('10.0.20.10')!)).toBe('10.0.20.10');
    const c = parseCidr('10.0.20.77/24')!;
    expect(c.prefix).toBe(24);
    expect(inCidr('10.0.20.200', c)).toBe(true);
    expect(inCidr('10.0.21.1', c)).toBe(false);
    expect(parseIp('300.1.1.1')).toBeNull();
  });
});

describe('sha256 / fingerprints', () => {
  it('matches the FIPS 180-4 test vector', () => {
    const h = sha256(utf8('abc'));
    expect([...h].map((b) => b.toString(16).padStart(2, '0')).join('')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  it('produces OpenSSH-style fingerprints that round-trip through parsing', () => {
    const k = makeKeyPair('ed25519', 'seed', 'me@host');
    expect(k.publicLine.startsWith('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI')).toBe(true);
    expect(k.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    expect(parsePublicKey(k.publicLine)!.fingerprint).toBe(k.fingerprint);
    expect(base64Encode(new Uint8Array([1, 2, 3, 4]))).toBe('AQIDBA==');
  });
});

describe('sshd_config semantics', () => {
  const files: Record<string, string> = {
    '/etc/ssh/sshd_config': 'Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPort 22\nMatch User bob\n  PasswordAuthentication yes\n',
    '/etc/ssh/sshd_config.d/10-a.conf': 'PasswordAuthentication no\nAllowUsers alice\n',
    '/etc/ssh/sshd_config.d/20-b.conf': 'AllowUsers bob\nKexAlgorithms +diffie-hellman-group14-sha1\n',
  };
  const parse = () => parseSshdConfig('/etc/ssh/sshd_config', (p) => files[p], () => Object.keys(files));
  it('first obtained value wins, includes are expanded in place', () => {
    const eff = effectiveConfig(parse());
    expect(eff.passwordAuthentication).toBe(false);
  });
  it('AllowUsers accumulates across files', () => {
    expect(effectiveConfig(parse()).allowUsers).toEqual(['alice', 'bob']);
  });
  it('+ appends to the default algorithm list', () => {
    const k = effectiveConfig(parse()).kexAlgorithms;
    expect(k[0]).toBe('sntrup761x25519-sha512@openssh.com');
    expect(k[k.length - 1]).toBe('diffie-hellman-group14-sha1');
  });
  it('Match blocks override for matching connections', () => {
    expect(effectiveConfig(parse(), { user: 'bob', groups: [], address: '10.0.10.25' }).passwordAuthentication).toBe(true);
    expect(effectiveConfig(parse(), { user: 'alice', groups: [], address: '10.0.10.25' }).passwordAuthentication).toBe(false);
  });
  it('reports bad options with file and line like sshd -t', () => {
    files['/etc/ssh/sshd_config.d/30-c.conf'] = '\nPubkeyAuthentcation yes\n';
    const p = parse();
    delete files['/etc/ssh/sshd_config.d/30-c.conf'];
    expect(p.errors[0]).toMatchObject({ file: '/etc/ssh/sshd_config.d/30-c.conf', line: 2, message: 'Bad configuration option: PubkeyAuthentcation' });
  });
});

describe('nftables model', () => {
  const rs = () => parseRulesetFile(SRV01_NFT);
  const pkt = (over: Partial<Parameters<typeof evaluate>[2]>) => ({ src: '10.0.10.25', dst: '10.0.20.10', proto: 'tcp' as const, sport: 50000, dport: 22, ctState: 'new' as const, len: 60, iif: 'eth0', ...over });
  it('accepts ssh, drops other ports by policy, counts', () => {
    const r = rs();
    expect(evaluate(r, 'input', pkt({})).verdict).toBe('accept');
    const d = evaluate(r, 'input', pkt({ dport: 3306 }));
    expect(d.verdict).toBe('drop');
    expect(d.decidedBy?.policy).toBe(true);
  });
  it('established traffic is accepted by the conntrack rule', () => {
    expect(evaluate(rs(), 'input', pkt({ dport: 3306, ctState: 'established' })).verdict).toBe('accept');
  });
  it('round-trips through the list format', () => {
    const text = renderRuleset(rs());
    expect(text).toContain('policy drop;');
    expect(renderRuleset(parseRulesetFile(text))).toBe(text);
  });
  it('supports reject verdicts and sets', () => {
    const r = parseRulesetFile('table inet t {\n chain input {\n type filter hook input priority 0; policy accept;\n ip saddr { 10.0.10.0/24, 10.0.99.0/24 } tcp dport 22 reject with icmpx type admin-prohibited\n }\n}\n');
    const e = evaluate(r, 'input', pkt({}));
    expect(e.verdict).toBe('reject');
    expect(e.rejectWith).toBe('admin-prohibited');
  });
  it('raises an error with file/line for bad syntax', () => {
    expect(() => parseRulesetFile('table inet f {\n chain input {\n tcp dprt 22 accept\n }\n}\n')).toThrow(/:3:/);
  });
});

describe('zone files', () => {
  it('parses the lab zone and answers queries, following CNAMEs', () => {
    const z = parseZone(CORP_ZONE, 'corp.lab', 'db');
    expect(z.serial).toBe(2026101901);
    const a = answerQuery([z], 'www.corp.lab');
    expect(a.rcode).toBe('NOERROR');
    expect(a.answers.map((r) => r.data)).toEqual(['srv01.corp.lab.', '10.0.20.10']);
    expect(answerQuery([z], 'nope.corp.lab').rcode).toBe('NXDOMAIN');
    expect(answerQuery([z], 'example.com').rcode).toBe('REFUSED');
  });
  it('rejects a bad dotted quad', () => {
    expect(() => parseZone(CORP_ZONE.replace('10.0.20.10', '10.0.20.1O'), 'corp.lab', 'db')).toThrow(/bad dotted quad/);
  });
});

describe('ifupdown and shell tokenizer', () => {
  it('parses static interfaces', () => {
    const r = parseInterfaces('auto eth0\niface eth0 inet static\n    address 10.0.20.10/24\n    gateway 10.0.20.1\n');
    expect(r.ifaces[0]).toMatchObject({ name: 'eth0', auto: true, address: '10.0.20.10', prefix: 24, gateway: '10.0.20.1' });
  });
  it('handles quotes, pipes, redirects and &&', () => {
    const l = parseCommandLine(`sshd -T | grep -i "pass word" > /tmp/x && echo 'a;b'`);
    expect(l).toHaveLength(2);
    expect(l[0].pipeline[1]).toEqual({ argv: ['grep', '-i', 'pass word'], redirect: { file: '/tmp/x', append: false } });
    expect(l[1].pipeline[0].argv).toEqual(['echo', 'a;b']);
  });
});
