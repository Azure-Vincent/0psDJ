import { describe, expect, it } from 'vitest';
import { buildDockerLab } from '../src/engine/lab/dockerLab';
import { rebootAll } from '../src/engine/scenarios/engine';
import { goJsonError } from '../src/engine/sim/docker';
import { goTemplate, humanDuration } from '../src/engine/shell/cmdDocker';
import { Lab } from './helpers';

const lab = () => new Lab(buildDockerLab());
const root = (l: Lab, c: string) => l.run('dock01', 'root', c);

describe('docker run, ps, logs and published ports', () => {
  it('publishes nginx through dockerd\'s DNAT rule and docker-proxy', () => {
    const l = lab();
    expect(root(l, 'docker run -d --name web -p 8080:80 nginx:1.25').output).toMatch(/^[0-9a-f]{64}$/);
    expect(root(l, 'docker ps').output).toMatch(/nginx:1\.25 +"\/docker-entrypoint\.…" .* Up .* 0\.0\.0\.0:8080->80\/tcp, :::8080->80\/tcp +web$/m);
    expect(root(l, "docker ps --format 'table {{.Names}}\\t{{.Status}}'").output.split('\n')[0]).toMatch(/^NAMES +STATUS$/);
    expect(root(l, 'ss -tlnp').output).toMatch(/0\.0\.0\.0:8080 .*docker-proxy/);
    expect(root(l, 'nft list table ip nat').output).toMatch(/iifname != "docker0" tcp dport 8080 dnat to 172\.17\.0\.2:80/);
    const page = l.run('ws01', 'alice', 'curl -sS -i http://dock01.corp.lab:8080/').output;
    expect(page).toMatch(/^HTTP\/1\.1 200 OK\nServer: nginx\/1\.25\.5/);
    expect(page).toMatch(/<title>Welcome to nginx!<\/title>/);
    expect(root(l, 'docker logs --tail 1 web').output).toMatch(/^10\.0\.10\.25 - - \[.*\] "GET \/ HTTP\/1\.1" 200 \d+ "-" "curl\/7\.88\.1"$/);
    expect(root(l, "docker inspect -f '{{.State.Status}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.HostConfig.RestartPolicy.Name}}' web").output).toBe('running 172.17.0.2 no');
    expect(root(l, 'docker port web').output).toBe('80/tcp -> 0.0.0.0:8080\n80/tcp -> [::]:8080');
  });

  it('reports the daemon\'s errors: name in use, port allocated, host port busy, unknown image', () => {
    const l = lab();
    root(l, 'docker run -d --name web -p 8080:80 nginx:1.25');
    expect(root(l, 'docker run -d --name web nginx:1.25').output).toMatch(/Conflict\. The container name "\/web" is already in use by container "[0-9a-f]{64}"/);
    const busy = root(l, 'docker run -d --name web2 -p 8080:80 nginx:1.25');
    expect(busy.code).toBe(125);
    expect(busy.output).toMatch(/Bind for 0\.0\.0\.0:8080 failed: port is already allocated\.$/);
    expect(root(l, 'docker run -d --name web3 -p 22:80 nginx:1.25').output).toMatch(/Error starting userland proxy: listen tcp4 0\.0\.0\.0:22: bind: address already in use/);
    expect(root(l, 'docker run -d nosuchimage').output).toMatch(/pull access denied for nosuchimage, repository does not exist/);
    expect(root(l, 'docker ps -a').output).toMatch(/Created +web2$/m);
  });

  it('a container whose process exits stops, with its output in docker logs', () => {
    const l = lab();
    root(l, 'docker run -d --name db postgres:16');
    expect(root(l, 'docker ps -a').output).toMatch(/Exited \(1\) .* db$/m);
    expect(root(l, 'docker logs db').output).toMatch(/^Error: Database is uninitialized and superuser password is not specified\./);
    const fg = root(l, 'docker run --name db2 postgres:16');
    expect(fg.code).toBe(1);
    expect(fg.output).toMatch(/You must specify POSTGRES_PASSWORD/);
  });
});

describe('networks, embedded DNS and the application', () => {
  it('the default bridge has no name resolution between containers; a user-defined network does', () => {
    const l = lab();
    root(l, 'docker run -d --name db -e POSTGRES_PASSWORD=s3cret postgres:16');
    root(l, 'docker run -d --name app --restart unless-stopped -e DB_PASSWORD=s3cret -p 8000:8000 corp/inventory:1.4');
    expect(root(l, 'docker ps').output).toMatch(/Restarting \(3\) .* app$/m);
    expect(root(l, 'docker logs app').output).toMatch(/psycopg2\.OperationalError: could not translate host name "db" to address/);
    expect(root(l, 'docker exec db cat /etc/resolv.conf').output).toMatch(/^nameserver 10\.0\.10\.53$/m);
    expect(root(l, 'docker exec app ls').output).toMatch(/is not running$/);

    root(l, 'docker network create appnet');
    root(l, 'docker rm -f app db');
    root(l, 'docker run -d --name db --network appnet -e POSTGRES_PASSWORD=s3cret postgres:16');
    root(l, 'docker run -d --name app --network appnet -e DB_PASSWORD=s3cret -p 8000:8000 corp/inventory:1.4');
    expect(root(l, 'docker exec app cat /etc/resolv.conf').output).toMatch(/^nameserver 127\.0\.0\.11$/m);
    expect(root(l, 'docker exec app getent hosts db').output).toMatch(/^172\.18\.0\.2\s+db$/);
    expect(root(l, 'ip -br addr').output).toMatch(/^br-[0-9a-f]{12}\s+UP\s+172\.18\.0\.1\/16/m);
    expect(l.run('ws01', 'alice', 'curl -sS http://inventory.corp.lab:8000/health').output).toBe('{"status":"ok","database":"ok"}');
    root(l, 'docker stop db');
    expect(l.run('ws01', 'alice', 'curl -sS -i http://inventory.corp.lab:8000/health').output).toMatch(/^HTTP\/1\.1 503 Service Unavailable/);
  });

  it('a wrong database password crashes the app with PostgreSQL\'s message', () => {
    const l = lab();
    root(l, 'docker network create appnet');
    root(l, 'docker run -d --name db --network appnet -e POSTGRES_PASSWORD=s3cret postgres:16');
    root(l, 'docker run -d --name app --network appnet -e DB_PASSWORD=wrong corp/inventory:1.4');
    expect(root(l, 'docker logs app').output).toMatch(/connection to server at "db" \(172\.18\.0\.2\), port 5432 failed: FATAL:  password authentication failed for user "postgres"/);
  });
});

describe('restart policies, the daemon and the host firewall', () => {
  it('reboot: always and unless-stopped return, a manual stop is remembered by unless-stopped', () => {
    let l = lab();
    root(l, 'docker run -d --name a --restart always nginx:1.25');
    root(l, 'docker run -d --name u --restart unless-stopped nginx:1.25');
    root(l, 'docker run -d --name s --restart unless-stopped nginx:1.25');
    root(l, 'docker run -d --name n nginx:1.25');
    root(l, 'docker stop s');
    l = new Lab(rebootAll(l.world));
    const ps = root(l, "docker ps -a --format '{{.Names}} {{.State}}'").output.split('\n').sort();
    expect(ps).toEqual(['a running', 'n exited', 's exited', 'u running']);
  });

  it('restarting nftables removes dockerd\'s tables; docker-proxy still answers on the host port', () => {
    const l = lab();
    root(l, 'docker run -d --name web -p 8080:80 nginx:1.25');
    root(l, 'systemctl restart nftables');
    expect(root(l, 'nft list tables').output).toBe('table inet filter');
    expect(l.run('ws01', 'alice', 'curl -sS -o /dev/null -w "%{http_code}" http://dock01.corp.lab:8080/').output).toBe('200');
    root(l, 'systemctl restart docker');
    expect(root(l, 'nft list tables').output).toBe('table inet filter\ntable ip nat\ntable ip filter');
  });

  it('a forward policy of drop in the admin\'s ruleset blocks published ports', () => {
    const l = lab();
    root(l, 'docker run -d --name web --restart always -p 8080:80 nginx:1.25');
    root(l, "printf 'flush ruleset\\ntable inet filter {\\n\\tchain input {\\n\\t\\ttype filter hook input priority filter; policy drop;\\n\\t\\tct state established,related accept\\n\\t\\tiif \"lo\" accept\\n\\t\\ttcp dport 22 accept\\n\\t}\\n\\tchain forward {\\n\\t\\ttype filter hook forward priority filter; policy drop;\\n\\t}\\n}\\n' > /etc/nftables.conf");
    root(l, 'systemctl restart nftables');
    root(l, 'systemctl restart docker');
    expect(l.run('ws01', 'alice', 'curl -sS -m 5 http://dock01.corp.lab:8080/').output).toMatch(/curl: \(28\) Failed to connect to dock01\.corp\.lab port 8080 after 5000 ms/);
  });

  it('daemon.json errors are reported like dockerd, and the socket needs root or the docker group', () => {
    const l = lab();
    root(l, `printf '{ "live-restore": true, }\\n' > /etc/docker/daemon.json`);
    expect(root(l, 'systemctl restart docker').code).not.toBe(0);
    expect(root(l, 'journalctl -u docker').output).toMatch(/unable to configure the Docker daemon with file \/etc\/docker\/daemon\.json: invalid character '\}' looking for beginning of object key string/);
    expect(root(l, 'docker ps').output).toBe('Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?');
    root(l, 'rm /etc/docker/daemon.json');
    root(l, 'systemctl start docker');
    expect(l.run('dock01', 'alice', 'docker ps').output).toMatch(/^permission denied while trying to connect to the Docker daemon socket at unix:\/\/\/var\/run\/docker\.sock/);
    root(l, 'usermod -aG docker alice');
    expect(l.run('dock01', 'alice', 'docker ps').code).toBe(0);
  });

  it('the API socket is root:docker 0660 and its permissions decide who may use the CLI', () => {
    const l = lab();
    expect(l.run('dock01', 'alice', 'ls -l /var/run/docker.sock').output).toMatch(/^srw-rw---- 1 root +docker +0 .* \/var\/run\/docker\.sock$/);
    expect(l.run('dock01', 'alice', 'stat /run/docker.sock').output).toContain('IO Block: 4096   socket');
    root(l, 'usermod -aG docker alice');
    expect(l.run('dock01', 'alice', 'docker ps').code).toBe(0);
    root(l, 'chmod 600 /var/run/docker.sock');
    expect(l.run('dock01', 'alice', 'docker ps').output).toMatch(/^permission denied while trying to connect/);
    root(l, 'systemctl stop docker');
    expect(root(l, 'ls /var/run/docker.sock').output).toBe('/var/run/docker.sock');
  });

  it('docker exec runs only programs the image has', () => {
    const l = lab();
    root(l, 'docker run -d --name web nginx:1.25');
    expect(root(l, 'docker exec web ping -c1 10.0.10.53').output).toBe('OCI runtime exec failed: exec failed: unable to start container process: exec: "ping": executable file not found in $PATH: unknown');
    expect(root(l, 'docker exec web printenv NGINX_VERSION').output).toBe('1.25.5');
    root(l, 'docker stop web');
    expect(root(l, 'docker exec web ls').output).toMatch(/^Error response from daemon: container [0-9a-f]{64} is not running$/);
  });
});

describe('helpers', () => {
  it('formats like the docker CLI and Go', () => {
    expect(humanDuration(500)).toBe('Less than a second');
    expect(humanDuration(65_000)).toBe('About a minute');
    expect(humanDuration(3 * 3600_000)).toBe('3 hours');
    expect(goTemplate('{{.A.B}} {{json .C}} {{range .D}}[{{.E}}]{{end}}', { A: { B: 1 }, C: ['x'], D: { k: { E: 2 }, l: { E: 3 } } })).toBe('1 ["x"] [2][3]');
    expect(goJsonError('{ bip: "1" }')).toBe("invalid character 'b' looking for beginning of object key string");
    expect(goJsonError('{ "a": 1')).toBe('unexpected end of JSON input');
  });
});
