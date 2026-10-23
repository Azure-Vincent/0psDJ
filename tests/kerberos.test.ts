import { describe, expect, it } from 'vitest';
import { parseProfile, ProfileError } from '../src/engine/config/krb5';
import { parseZone } from '../src/engine/config/zone';
import { KRB_RUNS, runVisual } from '../src/engine/lab/visualRuns';
import { Lab } from './helpers';

const PW = 'Corp-Lab-2026';
const ADMIN_PW = 'Corp-Admin-2026';

function sso(lab: Lab) {
  lab.run('srv01', 'root', 'printf "GSSAPIAuthentication yes\\n" > /etc/ssh/sshd_config.d/20-kerberos.conf && systemctl reload ssh');
}

describe('DNS SRV records', () => {
  it('parses SRV records and rejects malformed ones', () => {
    const z = parseZone('$ORIGIN corp.lab.\n@ IN SOA ns1 h 1 2 3 4 5\n_kerberos._udp IN SRV 0 0 88 ns1\n', 'corp.lab', 'f');
    expect(z.records.find((r) => r.type === 'SRV')).toMatchObject({ name: '_kerberos._udp.corp.lab.', data: '0 0 88 ns1.corp.lab.' });
    expect(() => parseZone('$ORIGIN corp.lab.\n@ IN SOA ns1 h 1 2 3 4 5\n_x._tcp IN SRV 0 88 ns1\n', 'corp.lab', 'f')).toThrow(/bad SRV record|unexpected end/);
  });

  it('host -t and dig TYPE query SRV and TXT records', () => {
    const lab = new Lab();
    expect(lab.run('ws01', 'alice', 'host -t SRV _kerberos._udp.corp.lab').output).toBe('_kerberos._udp.corp.lab has SRV record 0 0 88 ns1.corp.lab.');
    expect(lab.run('ws01', 'alice', 'host -t TXT _kerberos.corp.lab').output).toBe('_kerberos.corp.lab descriptive text "CORP.LAB"');
    expect(lab.run('ws01', 'alice', 'dig +short _kerberos-adm._tcp.corp.lab SRV').output).toBe('0 0 749 ns1.corp.lab.');
    expect(lab.run('ws01', 'alice', 'host -t SRV _ldap._tcp.corp.lab').output).toMatch(/not found: 3\(NXDOMAIN\)/);
  });
});

describe('Kerberos', () => {
  it('krb5.conf syntax errors are detected', () => {
    expect(() => parseProfile('[realms]\n CORP.LAB = {\n kdc = x\n')).toThrow(ProfileError);
  });

  it('kinit: pre-authentication, wrong password, unknown principal, KDC log', () => {
    const lab = new Lab();
    expect(lab.run('ws01', 'alice', 'kinit', ['nope']).output).toBe('Password for alice@CORP.LAB: \nkinit: Password incorrect while getting initial credentials');
    expect(lab.run('ws01', 'alice', 'kinit carol', ['x']).output).toBe("kinit: Client 'carol@CORP.LAB' not found in Kerberos database while getting initial credentials");
    expect(lab.run('ws01', 'alice', 'kinit', [PW]).code).toBe(0);
    expect(lab.run('ws01', 'alice', 'klist').output).toMatch(/Default principal: alice@CORP.LAB\n\nValid starting {7}Expires {14}Service principal\n\S+ \S+  \S+ \S+  krbtgt\/CORP.LAB@CORP.LAB\n\trenew until/);
    const log = lab.run('ns1', 'root', 'journalctl -u krb5-kdc').output;
    expect(log).toMatch(/PREAUTH_FAILED: alice@CORP.LAB for krbtgt\/CORP.LAB@CORP.LAB, Preauthentication failed/);
    expect(log).toMatch(/CLIENT_NOT_FOUND: carol@CORP.LAB/);
    expect(log).toMatch(/NEEDED_PREAUTH[\s\S]*ISSUE: authtime \d+, .* alice@CORP.LAB for krbtgt\/CORP.LAB@CORP.LAB/);
  });

  it('tickets last max_life (10 h) by the KDC clock, and kvno reuses a cached ticket', () => {
    const lab = new Lab();
    lab.run('ws01', 'alice', 'kinit', [PW]);
    const m = /(\d\d:\d\d:\d\d)  \S+ (\d\d:\d\d:\d\d)  krbtgt/.exec(lab.run('ws01', 'alice', 'klist').output)!;
    expect((Number(m[2].slice(0, 2)) - Number(m[1].slice(0, 2)) + 24) % 24).toBe(10);
    expect(lab.run('ws01', 'alice', 'kvno host/srv01.corp.lab').output).toBe('host/srv01.corp.lab@CORP.LAB: kvno = 2');
    lab.run('ns1', 'root', 'kadmin.local -q "cpw -randkey host/srv01.corp.lab"');
    expect(lab.run('ws01', 'alice', 'kvno host/srv01.corp.lab').output).toMatch(/kvno = 2$/);
    lab.run('ws01', 'alice', 'kdestroy');
    lab.run('ws01', 'alice', 'kinit', [PW]);
    expect(lab.run('ws01', 'alice', 'kvno host/srv01.corp.lab').output).toMatch(/kvno = 3$/);
  });

  it('clock skew beyond 5 minutes fails; NTP fixes it and survives a reboot', () => {
    const lab = new Lab();
    lab.run('ws01', 'root', 'timedatectl set-ntp false');
    expect(lab.run('ws01', 'root', 'timedatectl set-time "2026-10-19 09:45:00"').code).toBe(0);
    expect(lab.run('ws01', 'alice', 'kinit', [PW]).output).toMatch(/Clock skew too great/);
    expect(lab.run('ns1', 'root', 'journalctl -u krb5-kdc -n 2').output).toMatch(/Clock skew too great/);
    expect(lab.run('ws01', 'alice', 'timedatectl').output).toMatch(/System clock synchronized: no\n\s+NTP service: inactive/);
    lab.run('ws01', 'root', 'timedatectl set-ntp true');
    expect(lab.run('ws01', 'alice', 'kinit', [PW]).code).toBe(0);
    expect(lab.run('ws01', 'alice', 'date').output).toMatch(/^\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d UTC 2026$/);
  });

  it('a firewall dropping port 88 makes kinit slow; a stopped KDC makes it fast', () => {
    const lab = new Lab();
    lab.run('ns1', 'root', 'systemctl stop krb5-kdc');
    let t0 = lab.world.clock;
    expect(lab.run('ws01', 'alice', 'kinit', [PW]).output).toBe("kinit: Cannot contact any KDC for realm 'CORP.LAB' while getting initial credentials");
    const fast = lab.world.clock - t0;
    lab.run('ns1', 'root', 'systemctl start krb5-kdc');
    for (const c of ['nft insert rule inet filter input udp dport 88 drop', 'nft insert rule inet filter input tcp dport 88 drop']) lab.run('ns1', 'root', c);
    t0 = lab.world.clock;
    expect(lab.run('ws01', 'alice', 'kinit', [PW]).output).toMatch(/Cannot contact any KDC/);
    expect(lab.world.clock - t0).toBeGreaterThan(fast + 5000);
  });

  it('kadmin: ACL, remote ktadd into the local keytab (root only), kadmin.local listprincs', () => {
    const lab = new Lab();
    expect(lab.run('ws01', 'alice', 'kadmin -p bob -q "addprinc -pw x carol"', ['Summer2026!']).output).toMatch(/Operation requires ``add'' privilege/);
    expect(lab.run('ns1', 'root', 'journalctl -u krb5-admin-server -n 1').output).toMatch(/Unauthorized request: addprinc/);
    expect(lab.run('ws01', 'alice', 'kadmin -q "addprinc -pw Carol-1 carol"', [ADMIN_PW]).output).toMatch(/Password for alice\/admin@CORP.LAB: \nNo policy specified[\s\S]*Principal "carol@CORP.LAB" created\./);
    expect(lab.run('ws01', 'alice', 'kinit carol', ['Carol-1']).code).toBe(0);
    expect(lab.run('srv01', 'alice', 'kadmin -p alice/admin -q "ktadd host/srv01.corp.lab"', [ADMIN_PW]).output).toMatch(/kadmin: Permission denied while adding key to keytab|Permission denied/);
    expect(lab.run('srv01', 'root', 'kadmin -p alice/admin -w Corp-Admin-2026 -q "ktadd host/srv01.corp.lab"').output).toMatch(/with kvno 4, encryption type aes256-cts-hmac-sha1-96 added to keytab FILE:\/etc\/krb5.keytab/);
    expect(lab.run('srv01', 'root', 'klist -k').output.match(/^ +\d /gm)!.map((s) => s.trim())).toEqual(['2', '2', '4', '4']);
    expect(lab.world.hosts.srv01.fs['/etc/krb5.keytab'].mode).toBe(0o600);
    expect(lab.run('ns1', 'root', 'kadmin.local -q "listprincs host/*"').output).toBe('Authenticating as principal root/admin@CORP.LAB with password.\nhost/srv01.corp.lab@CORP.LAB');
    expect(lab.run('ws01', 'alice', 'kadmin.local -q listprincs').output).toMatch(/No such file or directory|Permission denied/);
  });

  it('SSH with GSSAPI: off by default, works with a ticket, fails on a stale keytab and on an IP address', () => {
    const lab = new Lab();
    const kssh = (target: string) => lab.run('ws01', 'alice', `ssh -o PubkeyAuthentication=no -o PasswordAuthentication=no -o BatchMode=yes -o StrictHostKeyChecking=accept-new ${target} hostname`).output;
    lab.run('ws01', 'alice', 'kinit', [PW]);
    expect(kssh('srv01.corp.lab')).toMatch(/Permission denied \(publickey\)/);
    sso(lab);
    expect(lab.run('srv01', 'root', 'sshd -T').output).toMatch(/gssapiauthentication yes/);
    expect(kssh('srv01.corp.lab')).toBe('srv01');
    expect(lab.run('srv01', 'root', 'journalctl -u ssh').output).toMatch(/Accepted gssapi-with-mic for alice from 10\.0\.10\.25 port \d+ ssh2: alice@CORP.LAB/);
    expect(kssh('www.corp.lab')).toMatch(/srv01$/);
    expect(kssh('10.0.20.10')).toMatch(/Permission denied \(publickey,gssapi-keyex,gssapi-with-mic\)/);
    lab.run('ns1', 'root', 'kadmin.local -q "cpw -randkey host/srv01.corp.lab"');
    lab.run('ws01', 'alice', 'kdestroy');
    lab.run('ws01', 'alice', 'kinit', [PW]);
    expect(kssh('srv01.corp.lab')).toMatch(/Permission denied/);
    // With keys still allowed, ssh silently falls back to publickey.
    expect(lab.run('ws01', 'alice', 'ssh -v srv01.corp.lab hostname').output).toMatch(/Next authentication method: gssapi-with-mic[\s\S]*Next authentication method: publickey[\s\S]*using "publickey"/);
  });

  it('.k5login decides which principals may log in to an account', () => {
    const lab = new Lab();
    sso(lab);
    lab.run('ns1', 'root', 'kadmin.local -q "addprinc -pw Bob-K5 bob"', []);
    lab.run('ws01', 'alice', 'kdestroy');
    lab.run('ws01', 'alice', 'kinit bob', ['Summer2026!']);
    const asAlice = () => lab.run('ws01', 'alice', 'ssh -o PubkeyAuthentication=no -o PasswordAuthentication=no -o BatchMode=yes srv01.corp.lab hostname').output;
    expect(asAlice()).toMatch(/Permission denied/);
    lab.run('srv01', 'root', 'printf "alice@CORP.LAB\\nbob@CORP.LAB\\n" > /home/alice/.k5login');
    expect(asAlice()).toBe('srv01');
  });

  it('visual runs record the Kerberos exchanges', () => {
    const titles = (id: string) => runVisual(KRB_RUNS.find((r) => r.id === id)!).trace.map((e) => e.title);
    expect(titles('kinit')).toEqual(expect.arrayContaining(['Kerberos AS-REQ', 'Kerberos error: KDC_ERR_PREAUTH_REQUIRED', 'Kerberos AS-REQ with pre-authentication', 'Kerberos AS-REP: TGT issued']));
    expect(titles('kvno')).toEqual(expect.arrayContaining(['Kerberos TGS-REQ', 'Kerberos TGS-REP: service ticket issued']));
    expect(titles('ssh-gssapi')).toEqual(expect.arrayContaining(['GSSAPI authentication (Kerberos ticket)', 'sshd accepts the Kerberos ticket', 'USERAUTH_SUCCESS']));
    expect(titles('skew')).toContain('Kerberos error: KRB_AP_ERR_SKEW');
    expect(titles('stale-keytab')).toContain('sshd cannot accept the Kerberos ticket');
    expect(titles('no-srv').filter((t) => /^Kerberos/.test(t))).toEqual([]);
  });
});
