import { describe, expect, it } from 'vitest';
import { readFile, writeFile } from '../src/engine/fs';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { script, verifyScenario } from '../src/engine/scenarios/engine';
import { CORP_ROOT_FINGERPRINT } from '../src/engine/scenarios/tlsMtuScenarios';
import { parseTcpdumpMss } from './tls-mtu.helpers';
import { Lab } from './helpers';
import { MTU_RUNS, TLS_RUNS, runVisual } from '../src/engine/lab/visualRuns';

function setMtu(lab: Lab, host: string, iface: string, mtu: number) {
  lab.run(host, 'root', `ip link set dev ${iface} mtu ${mtu}`);
}

describe('HTTPS and certificates (baseline)', () => {
  it('serves www.corp.lab over HTTPS with a verifiable chain', () => {
    const lab = new Lab();
    expect(lab.run('ws01', 'alice', 'curl -I https://www.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(lab.run('ws02', 'dana', 'curl -I https://srv01.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    const v = lab.run('ws01', 'alice', 'curl -v -I https://www.corp.lab/').output;
    expect(v).toMatch(/TLSv1\.3 \(IN\), TLS handshake, Certificate \(11\)/);
    expect(v).toMatch(/subjectAltName: host "www\.corp\.lab" matched cert's "www\.corp\.lab"/);
    expect(v).toMatch(/SSL certificate verify ok\./);
    const s = lab.run('ws01', 'alice', 'openssl s_client -connect www.corp.lab:443 </dev/null').output;
    expect(s).toMatch(/ 0 s:CN = www\.corp\.lab\n {3}i:C = US, O = Corp Lab, CN = Corp Lab Issuing CA 1/);
    expect(s).toMatch(/ 1 s:C = US, O = Corp Lab, CN = Corp Lab Issuing CA 1/);
    expect(s).toMatch(/Verify return code: 0 \(ok\)/);
  });

  it('rejects names not in the certificate unless -k is used, and plain HTTP to the TLS port gets a 400', () => {
    const lab = new Lab();
    const r = lab.run('ws01', 'alice', 'curl -I https://10.0.20.10/');
    expect(r.code).toBe(60);
    expect(r.output).toMatch(/no alternative certificate subject name matches target host name '10\.0\.20\.10'/);
    expect(lab.run('ws01', 'alice', 'curl -k -I https://10.0.20.10/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(lab.run('ws01', 'alice', 'curl -I http://www.corp.lab:443/').output).toMatch(/^HTTP\/1\.1 400 Bad Request/);
    expect(lab.run('ws01', 'alice', 'curl -I https://www.corp.lab:80/').output).toMatch(/\(35\) .*wrong version number/);
  });

  it('--cacert replaces the trust store', () => {
    const lab = new Lab();
    lab.run('ws01', 'alice', 'curl -s -o root.crt http://www.corp.lab/pki/corp-lab-root-ca.crt');
    expect(lab.run('ws01', 'alice', 'curl -I --cacert root.crt https://www.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(lab.run('ws01', 'alice', 'curl -I --cacert root.crt https://203.0.113.80/').output).toMatch(/unable to get local issuer certificate/);
  });

  it('serves files with status codes and keeps Debian\'s default page', () => {
    const lab = new Lab();
    const h = lab.run('ws01', 'alice', 'curl -I http://srv01.corp.lab/').output;
    expect(h).toMatch(/Content-Length: 615/);
    expect(lab.run('ws01', 'alice', 'curl http://srv01.corp.lab/').output).toMatch(/<title>Welcome to nginx!<\/title>/);
    expect(lab.run('ws01', 'alice', 'curl -I http://srv01.corp.lab/missing.html').output).toMatch(/^HTTP\/1\.1 404 Not Found/);
    expect(lab.run('ws01', 'alice', 'curl -I http://srv01.corp.lab/pki').output).toMatch(/^HTTP\/1\.1 301 Moved Permanently[\s\S]*Location: http:\/\/srv01\.corp\.lab\/pki\//);
    lab.run('srv01', 'root', 'chmod 600 /var/www/html/pki/corp-lab-root-ca.crt');
    expect(lab.run('ws01', 'alice', 'curl -I http://srv01.corp.lab/pki/corp-lab-root-ca.crt').output).toMatch(/^HTTP\/1\.1 403 Forbidden/);
  });
});

describe('openssl', () => {
  it('inspects certificates and matches keys by modulus', () => {
    const lab = new Lab();
    const x = lab.run('srv01', 'root', 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -subject -enddate -ext subjectAltName').output;
    expect(x).toBe('subject=CN = www.corp.lab\nnotAfter=Jul  4 09:14:00 2027 GMT\nX509v3 Subject Alternative Name: \n    DNS:www.corp.lab, DNS:srv01.corp.lab');
    const a = lab.run('srv01', 'root', 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -modulus | openssl md5').output;
    const b = lab.run('srv01', 'root', 'openssl rsa -in /etc/ssl/private/www.corp.lab.key -noout -modulus | openssl md5').output;
    expect(a).toMatch(/^MD5\(stdin\)= [0-9a-f]{32}$/);
    expect(a).toBe(b);
    expect(lab.run('srv01', 'alice', 'openssl rsa -in /etc/ssl/private/www.corp.lab.key -noout -modulus').output).toMatch(/Permission denied/);
    expect(lab.run('srv01', 'root', 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -checkend 86400').output).toBe('Certificate will not expire');
  });

  it('verify needs the intermediate as -untrusted', () => {
    const lab = new Lab();
    const r = lab.run('srv01', 'root', 'openssl verify /etc/ssl/certs/www.corp.lab.crt');
    expect(r.code).toBe(2);
    expect(r.output).toMatch(/error 20 at 0 depth lookup: unable to get local issuer certificate/);
    expect(lab.run('srv01', 'root', 'openssl verify -untrusted /etc/ssl/certs/corp-lab-issuing-ca-1.crt /etc/ssl/certs/www.corp.lab.crt').output).toBe('/etc/ssl/certs/www.corp.lab.crt: OK');
  });

  it('x509 -req drops the CSR\'s subjectAltName unless the extensions are copied (OpenSSL 3.0)', () => {
    const lab = new Lab();
    lab.run('ws01', 'alice', 'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 -subj "/CN=Test CA"');
    expect(lab.world.hosts.ws01.fs['/home/alice/ca.key'].mode).toBe(0o600);
    lab.run('ws01', 'alice', 'openssl req -new -newkey rsa:2048 -nodes -keyout app.key -out app.csr -subj "/CN=app.corp.lab" -addext "subjectAltName=DNS:app.corp.lab,DNS:api.corp.lab"');
    expect(lab.run('ws01', 'alice', 'openssl req -in app.csr -noout -text').output).toMatch(/DNS:app\.corp\.lab, DNS:api\.corp\.lab/);
    expect(lab.run('ws01', 'alice', 'openssl x509 -req -in app.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out app.crt -days 30').output).toMatch(/^Certificate request self-signature ok\nsubject=CN = app\.corp\.lab$/);
    expect(lab.run('ws01', 'alice', 'openssl x509 -in app.crt -noout -ext subjectAltName').output).toBe('');
    lab.run('ws01', 'alice', 'openssl x509 -req -in app.csr -CA ca.crt -CAkey ca.key -out app.crt -days 30 -copy_extensions copy');
    expect(lab.run('ws01', 'alice', 'openssl x509 -in app.crt -noout -ext subjectAltName').output).toMatch(/DNS:api\.corp\.lab/);
    expect(lab.run('ws01', 'alice', 'openssl verify -CAfile ca.crt app.crt').output).toBe('app.crt: OK');
    expect(lab.run('ws01', 'alice', 'openssl x509 -req -in app.csr -CA ca.crt -CAkey app.key -out x.crt').output).toMatch(/CA certificate and CA private key do not match/);
  });
});

describe('update-ca-certificates', () => {
  it('adds .crt files from /usr/local/share/ca-certificates and ignores other extensions', () => {
    const lab = new Lab();
    lab.run('ws02', 'root', `rm ${'/usr/local/share/ca-certificates/corp-lab-root-ca.crt'}`);
    expect(lab.run('ws02', 'root', 'update-ca-certificates').output).toMatch(/0 added, 1 removed; done\./);
    expect(lab.run('ws02', 'dana', 'curl -I https://www.corp.lab/').output).toMatch(/\(60\) SSL certificate problem: unable to get local issuer certificate/);
    lab.run('ws02', 'root', 'curl -s -o /usr/local/share/ca-certificates/corp.pem http://www.corp.lab/pki/corp-lab-root-ca.crt');
    expect(lab.run('ws02', 'root', 'update-ca-certificates').output).toMatch(/0 added, 0 removed/);
    lab.run('ws02', 'root', 'cp /usr/local/share/ca-certificates/corp.pem /usr/local/share/ca-certificates/corp.crt');
    expect(lab.run('ws02', 'root', 'update-ca-certificates').output).toBe('Updating certificates in /etc/ssl/certs...\n1 added, 0 removed; done.\nRunning hooks in /etc/ca-certificates/update.d...\ndone.');
    expect(lab.run('ws02', 'root', 'openssl x509 -in /usr/local/share/ca-certificates/corp.crt -noout -fingerprint -sha256').output).toBe(`sha256 Fingerprint=${CORP_ROOT_FINGERPRINT}`);
    expect(lab.run('ws02', 'dana', 'curl -I https://www.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(lab.run('ws02', 'dana', 'update-ca-certificates').code).not.toBe(0);
  });
});

describe('nginx TLS configuration', () => {
  it('nginx -t reports a key mismatch, a failed reload keeps serving the old certificate, a restart takes HTTPS down', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', 'openssl req -new -newkey rsa:2048 -nodes -keyout /root/other.key -out /root/other.csr -subj "/CN=www.corp.lab"');
    lab.run('srv01', 'root', 'cp /root/other.key /etc/ssl/private/www.corp.lab.key');
    const t = lab.run('srv01', 'root', 'nginx -t');
    expect(t.code).toBe(1);
    expect(t.output).toBe('nginx: [emerg] SSL_CTX_use_PrivateKey("/etc/ssl/private/www.corp.lab.key") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)\nnginx: configuration file /etc/nginx/nginx.conf test failed');
    expect(lab.run('srv01', 'root', 'systemctl reload nginx').code).not.toBe(0);
    expect(lab.run('ws01', 'alice', 'curl -I https://www.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(lab.run('srv01', 'root', 'journalctl -u nginx').output).toMatch(/key values mismatch/);
    lab.run('srv01', 'root', 'systemctl restart nginx');
    expect(lab.run('ws01', 'alice', 'curl -I https://www.corp.lab/').output).toMatch(/Couldn't connect to server/);
  });

  it('reports missing certificate files and missing ssl_certificate', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', 'mv /etc/ssl/certs/www.corp.lab.crt /root/');
    expect(lab.run('srv01', 'root', 'nginx -t').output).toMatch(/^nginx: \[emerg\] cannot load certificate "\/etc\/ssl\/certs\/www\.corp\.lab\.crt": BIO_new_file\(\) failed/);
    lab.run('srv01', 'root', 'mv /root/www.corp.lab.crt /etc/ssl/certs/');
    lab.run('srv01', 'root', "sed -i '/ssl_certificate \\/etc/d' /etc/nginx/nginx.conf");
    expect(lab.run('srv01', 'root', 'nginx -t').output).toMatch(/no "ssl_certificate" is defined for the "listen \.\.\. ssl" directive in \/etc\/nginx\/nginx\.conf:\d+/);
  });

  it('bash truncates the redirect target first: "cat cert chain > cert" loses the certificate', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', 'cat /etc/ssl/certs/www.corp.lab.crt /etc/ssl/certs/corp-lab-issuing-ca-1.crt > /etc/ssl/certs/www.corp.lab.crt');
    expect(lab.run('srv01', 'root', 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -subject').output).toBe('subject=C = US, O = Corp Lab, CN = Corp Lab Issuing CA 1');
  });
});

describe('MTU, path MTU discovery and MSS clamping', () => {
  it('ping -M do finds the path MTU; tracepath reports it', () => {
    const lab = new Lab();
    setMtu(lab, 'rtr01', 'eth2', 1492);
    expect(lab.run('ws01', 'alice', 'ping -c 1 -M do -s 1472 203.0.113.80').output).toMatch(/From 10\.0\.10\.1 icmp_seq=1 Frag needed and DF set \(mtu = 1492\)/);
    expect(lab.run('ws01', 'alice', 'ping -c 1 -M do -s 1472 203.0.113.80').output).toMatch(/ping: local error: message too long, mtu=1492/);
    expect(lab.run('ws01', 'alice', 'ip route get 203.0.113.80').output).toMatch(/mtu 1492/);
    expect(lab.run('ws01', 'alice', 'ping -c 1 -M do -s 1464 203.0.113.80').output).toMatch(/1472 bytes from 203\.0\.113\.80/);
    expect(lab.run('dev01', 'erin', 'tracepath -n 203.0.113.80').output).toMatch(/Resume: pmtu 1492/);
  });

  it('a one-sided MTU change drops large frames silently: HEAD works, downloads and TLS handshakes stall', () => {
    const lab = new Lab();
    setMtu(lab, 'rtr01', 'eth2', 1492);
    expect(lab.run('ws01', 'alice', 'curl -I http://203.0.113.80/downloads/tools-2.4.1.tar.gz').output).toMatch(/Content-Length: 4718592/);
    expect(lab.run('ws01', 'alice', 'curl -m 20 -o t.tgz http://203.0.113.80/downloads/tools-2.4.1.tar.gz').output).toBe('curl: (28) Operation timed out after 20000 milliseconds with 0 out of 4718592 bytes received');
    expect(lab.run('ws01', 'alice', 'curl -m 10 -I https://203.0.113.80/').output).toBe('curl: (28) SSL connection timeout');
    // MSS clamping on the router makes ext01 send segments that fit.
    lab.run('rtr01', 'root', 'nft add rule inet filter forward oifname "eth2" tcp flags syn tcp option maxseg size set rt mtu');
    expect(lab.run('rtr01', 'root', 'nft list chain inet filter forward').output).toMatch(/oifname "eth2" tcp flags syn tcp option maxseg size set rt mtu/);
    expect(lab.run('ws01', 'alice', 'curl -m 20 -o t.tgz http://203.0.113.80/downloads/tools-2.4.1.tar.gz').code).toBe(0);
    expect(lab.run('ws01', 'alice', 'ls -l t.tgz').output).toMatch(/ 4718592 /);
    expect(parseTcpdumpMss(lab.run('rtr01', 'root', 'tcpdump -n -i eth2 -c 400 tcp').output)).toContain(1452);
    expect(parseTcpdumpMss(lab.run('rtr01', 'root', 'tcpdump -n -i eth0 -c 400 tcp').output)).toContain(1460);
  });

  it('the uplink ticket rejects lowering the client MTU as a fix', () => {
    const s = findScenario('mtu-uplink-mismatch')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    lab.run('ws01', 'root', `sed -i 's#address 10.0.10.25/24#address 10.0.10.25/24\\n    mtu 1400#' /etc/network/interfaces`);
    lab.run('ws01', 'root', 'ifreload -a');
    const v = verifyScenario(lab.world, s);
    expect(v.constraints.find((c) => c.id === 'client-mtu')?.ok).toBe(false);
    expect(v.passed).toBe(false);
  });
});

describe('TLS tickets reject workarounds', () => {
  it('adding the intermediate to the client instead of fixing the server chain is rejected', () => {
    const s = findScenario('tls-missing-intermediate')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    lab.run('ws01', 'root', 'curl -s -o /usr/local/share/ca-certificates/issuing.crt http://www.corp.lab/pki/corp-lab-issuing-ca-1.crt');
    lab.run('ws01', 'root', 'update-ca-certificates');
    const v = verifyScenario(lab.world, s);
    expect(v.constraints.find((c) => c.id === 'trust-clean-ws01')?.ok).toBe(false);
    expect(v.passed).toBe(false);
  });

  it('a world-readable private key fails the expired-certificate ticket', () => {
    const s = findScenario('tls-expired')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    for (const c of s.solution[0].commands) lab.run('srv01', 'root', c);
    lab.run('srv01', 'root', 'chmod 644 /etc/ssl/private/www.corp.lab.key');
    const v = verifyScenario(lab.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'tls-key-protected')?.ok).toBe(false);
  });

  it('the key-mismatch ticket: the renewed file is on disk but the old certificate is served', () => {
    const s = findScenario('tls-key-mismatch')!;
    const world = buildSshLab();
    s.setup(world);
    const lab = new Lab(world);
    expect(lab.run('srv01', 'root', 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -enddate').output).toBe('notAfter=Jul  4 09:14:00 2027 GMT');
    expect(lab.run('ws01', 'alice', 'openssl s_client -connect www.corp.lab:443 </dev/null 2>/dev/null | openssl x509 -noout -enddate').output).toBe('notAfter=Oct 17 08:02:00 2026 GMT');
  });

  it('the expired ticket leaves the files nginx loads unchanged until a reload', () => {
    const s = findScenario('tls-expired')!;
    const world = buildSshLab();
    s.setup(world);
    const h = world.hosts.srv01;
    writeFile(h, '/etc/ssl/certs/www.corp.lab.crt', readFile(h, '/root/renewal/www.corp.lab-2026.crt')!, world.clock);
    writeFile(h, '/etc/ssl/private/www.corp.lab.key', readFile(h, '/root/renewal/www.corp.lab-2026.key')!, world.clock);
    const lab = new Lab(world);
    expect(lab.run('ws01', 'alice', 'curl -I https://www.corp.lab/').output).toMatch(/certificate has expired/);
    script(lab.world, 'srv01', ['systemctl reload nginx']);
    expect(lab.run('ws01', 'alice', 'curl -I https://www.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
  });
});

describe('TLS and MTU visual runs', () => {
  const expected: Record<string, RegExp> = {
    'https-ok': /SSL certificate verify ok\./, 'tls-expired': /certificate has expired/, 'tls-chain': /Verify return code: 21/, 'tls-name': /no alternative certificate subject name/,
    pmtud: /Frag needed and DF set \(mtu = 1492\)[\s\S]*message too long, mtu=1492/, mismatch: /0 out of 4718592 bytes received/, clamp: /200 OK/, tracepath: /Resume: pmtu 1492/,
  };
  it.each([...TLS_RUNS, ...MTU_RUNS].map((r) => r.id))('%s', (id) => {
    const run = [...TLS_RUNS, ...MTU_RUNS].find((r) => r.id === id)!;
    const v = runVisual(run);
    expect(v.output).toMatch(expected[id]);
    expect(v.trace.length).toBeGreaterThan(0);
  });
});
