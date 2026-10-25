import { describe, expect, it } from 'vitest';
import { writeFile } from '../src/engine/fs';
import { freshLab } from '../src/engine/lab/dependencies';
import { SRV01_NGINX_CONF } from '../src/engine/lab/pkiLab';
import { deployProxy, proxiedNginxConf } from '../src/engine/scenarios/proxyScenarios';
import { script } from '../src/engine/scenarios/engine';
import { Lab } from './helpers';

const proxied = (proxyPass?: string) => {
  const w = freshLab();
  deployProxy(w, proxyPass);
  return new Lab(w);
};
const get = (l: Lab, path = '/inventory/health') => l.run('ws01', 'alice', `curl -sS -i http://apps.corp.lab${path}`).output;

describe('nginx reverse proxy', () => {
  it('relays the upstream answer with its own Server header and logs the client', () => {
    const l = proxied();
    expect(get(l)).toMatch(/^HTTP\/1\.1 200 OK\nServer: nginx\/1\.22\.1\n[\s\S]*Connection: keep-alive\n\n\{"status":"ok","database":"ok"\}$/);
    expect(l.run('srv01', 'root', 'tail -n 1 /var/log/nginx/access.log').output).toMatch(/^10\.0\.10\.25 - - \[.*\] "GET \/inventory\/health HTTP\/1\.1" 200 32/);
  });

  it('replaces the location prefix only when proxy_pass has a URI part', () => {
    expect(get(proxied('http://dock01.corp.lab:8000'))).toMatch(/^HTTP\/1\.1 404 Not Found[\s\S]*\{"detail":"Not found\."\}$/);
    expect(get(proxied('http://dock01.corp.lab:8000/'), '/inventory/?x=1')).toMatch(/^HTTP\/1\.1 200 OK/);
  });

  it('502 for a refused upstream, with nginx\'s error.log line naming the upstream', () => {
    const l = proxied('http://dock01.corp.lab:8001/');
    expect(get(l)).toMatch(/^HTTP\/1\.1 502 Bad Gateway[\s\S]*<center>nginx\/1\.22\.1<\/center>/);
    expect(l.run('srv01', 'root', 'tail -n 1 /var/log/nginx/error.log').output).toMatch(/\[error\] \d+#\d+: \*1 connect\(\) failed \(111: Connection refused\) while connecting to upstream, client: 10\.0\.10\.25, server: apps\.corp\.lab, request: "GET \/inventory\/health HTTP\/1\.1", upstream: "http:\/\/10\.0\.20\.40:8001\/health", host: "apps\.corp\.lab"$/);
  });

  it('an upstream group falls through to the next server when one refuses', () => {
    const w = freshLab();
    deployProxy(w);
    const conf = proxiedNginxConf('http://inventory/').replace('http {\n', 'http {\n    upstream inventory {\n        server 10.0.20.40:8001;\n        server dock01.corp.lab:8000;\n    }\n');
    writeFile(w.hosts.srv01, '/etc/nginx/nginx.conf', conf, w.clock);
    script(w, 'srv01', ['systemctl reload nginx']);
    const l = new Lab(w);
    expect(get(l)).toMatch(/^HTTP\/1\.1 200 OK/);
  });

  it('resolves upstream names at load time: an unknown name fails nginx -t and the start, a failed reload keeps the old config', () => {
    const l = proxied();
    writeFile(l.world.hosts.srv01, '/etc/nginx/nginx.conf', proxiedNginxConf('http://nope.corp.lab:8000/'), l.world.clock);
    expect(l.run('srv01', 'root', 'nginx -t').output).toMatch(/^nginx: \[emerg\] host not found in upstream "nope\.corp\.lab:8000" in \/etc\/nginx\/nginx\.conf:\d+\nnginx: configuration file \/etc\/nginx\/nginx\.conf test failed$/);
    expect(l.run('srv01', 'root', 'systemctl reload nginx').code).not.toBe(0);
    expect(get(l)).toMatch(/^HTTP\/1\.1 200 OK/);
    l.run('srv01', 'root', 'systemctl restart nginx');
    expect(l.run('srv01', 'root', 'systemctl is-active nginx').output).toBe('failed');
    expect(l.run('ws01', 'alice', 'curl -sS https://www.corp.lab/').output).toMatch(/curl: \(7\) Failed to connect to www\.corp\.lab port 443/);
  });

  it('504 after proxy_connect_timeout when the backend drops the proxy; curl -m gives up first', () => {
    const w = freshLab();
    deployProxy(w);
    writeFile(w.hosts.srv01, '/etc/nginx/nginx.conf', SRV01_NGINX_CONF.replace(/}\n$/, '    server {\n        listen 80;\n        server_name apps.corp.lab;\n        location /inventory/ {\n            proxy_pass http://dock01.corp.lab:8000/;\n            proxy_connect_timeout 5s;\n        }\n    }\n}\n'), w.clock);
    script(w, 'srv01', ['systemctl reload nginx']);
    writeFile(w.hosts.dock01, '/etc/nftables.conf', 'flush ruleset\ntable inet filter {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established,related accept\n\t\tip saddr 10.0.10.0/24 tcp dport 8000 accept\n\t}\n}\n', w.clock);
    script(w, 'dock01', ['systemctl restart nftables', 'systemctl restart docker']);
    const l = new Lab(w);
    expect(l.run('ws01', 'alice', 'curl -sS -m 5 http://dock01.corp.lab:8000/health').output).toBe('{"status":"ok","database":"ok"}');
    expect(get(l)).toMatch(/^HTTP\/1\.1 504 Gateway Time-out/);
    expect(l.run('srv01', 'root', 'tail -n 1 /var/log/nginx/error.log').output).toMatch(/upstream timed out \(110: Connection timed out\) while connecting to upstream/);
    expect(l.run('ws01', 'alice', 'curl -sS -m 2 http://apps.corp.lab/inventory/health').output).toBe('curl: (28) Operation timed out after 2001 milliseconds with 0 bytes received');
  });
});
