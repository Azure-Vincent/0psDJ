// A competition scoring engine's SSH check, as CCDC-style scorers run it: a Go
// program (golang.org/x/crypto/ssh) dials the service, ignores the host key,
// logs in once with the team's published password and runs a command. Its
// result table shows Go's error text, which differs from OpenSSH's: this
// module produces the same messages from the simulated connection.

import { dnsQuery, resolve } from '../sim/dns';
import { handleRequest, httpBackend, httpHooks, iisLoaded, isTlsPort, selectServer } from '../sim/http';
import { sourceAddress } from '../sim/network';
import { allListeners, type NginxLoaded } from '../sim/services';
import { runSsh, type SshResult } from '../sim/ssh';
import { tcpConnect } from '../sim/tcp';
import type { World } from '../types';
import type { ScoredDnsGoal, ScoredSshGoal, ScoredWebGoal } from './types';

/** golang.org/x/crypto/ssh default key exchange algorithms (client offer). */
const GO_KEX = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1', 'ext-info-c', 'kex-strict-c-v00@openssh.com'];

const DIAL_FAILED = 'Unable to dial the remote host. Make sure the host is up, and credentials are correct';
/**
 * The engine gives each check a deadline (a few seconds). A SYN that gets no
 * answer at all (firewall drop, no route back, host down) makes Go's dial wait
 * far longer than that, so the engine's own deadline fires first and the
 * result carries the engine's message instead of Go's.
 */
const CHECK_TIMEOUT = { status: 'Encountered an unexpected error during the check.', error: 'check timed out. this is most likely due to services timing out' };

/**
 * Go's resolver error for a name that did not resolve: NXDOMAIN is "no such
 * host", SERVFAIL/REFUSED "server misbehaving", no answer "i/o timeout".
 */
function lookupError(world: World, fromHost: string, name: string): string {
  const client = world.hosts[fromHost];
  const ns = /^nameserver\s+(\S+)/m.exec(client.fs['/etc/resolv.conf']?.content ?? '')?.[1] ?? '127.0.0.53';
  const res = resolve(structuredClone(world), structuredClone(client), name, { family: 4 });
  const last = res.exchanges.at(-1)?.outcome;
  const why = res.ok || last === 'nxdomain' || last === 'nodata' || !last ? 'no such host'
    : last === 'timeout' ? `read udp ${sourceAddress(client, ns)}:53124->${ns}:53: i/o timeout` : 'server misbehaving';
  return `lookup ${name} on ${ns}:53: ${why}`;
}

/** Go's net.Dial / ssh.Dial error text for a simulated SSH attempt. */
export function goSshError(world: World, goal: ScoredSshGoal, r: SshResult): string {
  const port = goal.port ?? 22;
  const client = world.hosts[goal.fromHost];
  const res = resolve(world, client, goal.target, { family: 4 });
  const ip = res.ok ? res.ip : goal.target;
  switch (r.failure) {
    case 'resolve':
      return `dial tcp: ${lookupError(world, goal.fromHost, goal.target)}`;
    case 'connect':
      return r.errno === 'ECONNREFUSED' ? `dial tcp ${ip}:${port}: connect: connection refused`
        : r.errno === 'EHOSTUNREACH' ? `dial tcp ${ip}:${port}: connect: no route to host`
          : r.errno === 'ENETUNREACH' ? `dial tcp ${ip}:${port}: connect: network is unreachable`
            : `dial tcp ${ip}:${port}: i/o timeout`;
    case 'banner':
      return 'ssh: handshake failed: EOF';
    case 'kex':
      return `ssh: handshake failed: ssh: no common algorithm for key exchange; client offered: [${GO_KEX.join(' ')}], server offered: [${(r.serverOffer ?? []).join(' ')}]`;
    case 'auth':
      if (r.closedAfterAuth) return 'ssh: handshake failed: EOF';
      return `ssh: handshake failed: ssh: unable to authenticate, attempted methods [${(r.methodsTried ?? ['none']).join(' ')}], no supported methods remain`;
    default:
      return `ssh: handshake failed: ${r.lines.at(-1) ?? 'unknown error'}`;
  }
}

/** Run the scoring check; lines read like a row of the scoring engine's results table. */
export function scoredSshCheck(world: World, goal: ScoredSshGoal): { ok: boolean; lines: string[] } {
  const w = structuredClone(world);
  const r = runSsh(w, {
    clientHostId: goal.fromHost, localUser: goal.fromUser, target: goal.target, user: goal.user, port: goal.port,
    pubkeyAuthentication: false, gssapiAuthentication: false, passwordPrompts: 1, ignoreKnownHosts: true,
    answers: [goal.password], remoteCommand: goal.command ?? 'whoami', connectTimeoutS: 10,
  });
  const head = `Scoring engine: SSH check ${goal.user}@${goal.target}:${goal.port ?? 22} (password login, command "${goal.command ?? 'whoami'}")`;
  if (r.outcome === 'session') return { ok: true, lines: [head, 'Status: Success!'] };
  if (r.failure === 'shell') {
    return { ok: false, lines: [head, 'Status: Unable to run the check command', 'Error: Process exited with status 1', `Output: ${r.lines.find((l) => /not available/.test(l)) ?? ''}`] };
  }
  if (r.failure === 'connect' && (r.errno === 'ETIMEDOUT' || !r.errno)) {
    return { ok: false, lines: [head, `Status: ${CHECK_TIMEOUT.status}`, `Error: ${CHECK_TIMEOUT.error}`] };
  }
  return { ok: false, lines: [head, `Status: ${DIAL_FAILED}`, `Error: ${goSshError(w, goal, r)}`] };
}

const connectText: Record<string, string> = { ECONNREFUSED: 'connect: connection refused', EHOSTUNREACH: 'connect: no route to host', ENETUNREACH: 'connect: network is unreachable' };
const timedOut = (head: string) => ({ ok: false, lines: [head, `Status: ${CHECK_TIMEOUT.status}`, `Error: ${CHECK_TIMEOUT.error}`] });

/**
 * The web check: Go's net/http client GETs the URL once (no redirects, no
 * certificate verification, as scoring engines usually configure it), then
 * compares the status code and looks for the expected content in the page.
 * Engines usually skip certificate checks: a TLS problem only shows when the
 * handshake itself fails.
 */
export function scoredWebCheck(world: World, goal: ScoredWebGoal, live = false): { ok: boolean; lines: string[] } {
  // live: run against the world itself (earlier rounds, so they appear in the server's logs).
  const w = live ? world : structuredClone(world);
  const want = goal.status ?? 200;
  const head = `Scoring engine: web check GET ${goal.url} (expects ${want}${goal.content ? `, page containing "${goal.content}"` : ''})`;
  const fail = (status: string, error: string) => ({ ok: false, lines: [head, `Status: ${status}`, `Error: ${error}`] });
  const m = /^(https?):\/\/([^/:]+)(?::(\d+))?(\/[^#]*)?$/.exec(goal.url)!;
  const [scheme, hostname, portStr, path = '/'] = [m[1], m[2], m[3], m[4]];
  const port = Number(portStr ?? (scheme === 'https' ? 443 : 80));
  const get = `Get "${goal.url}"`;
  const client = w.hosts[goal.fromHost];
  const res = resolve(w, client, hostname, { family: 4 });
  if (!res.ok) {
    if (res.exchanges.at(-1)?.outcome === 'timeout') return timedOut(head);
    return fail('Web request failed', `${get}: dial tcp: ${lookupError(world, goal.fromHost, hostname)}`);
  }
  const c = tcpConnect(w, client, res.ip, port, { timeoutMs: 10_000 });
  if (!c.ok) {
    if (c.errno === 'ETIMEDOUT' || !connectText[c.errno]) return timedOut(head);
    return fail('Web request failed', `${get}: dial tcp ${res.ip}:${port}: ${connectText[c.errno]}`);
  }
  const conn = c.conn;
  const backend = httpBackend(w, conn.server, conn.sv.localPort, conn.sv.local);
  const server = backend.host;
  const listener = allListeners(server).find((l) => l.proto === 'tcp' && l.port === backend.port);
  const app = listener ? httpHooks.apps[listener.process] : undefined;
  const loaded = server.services.nginx?.state === 'active' ? (server.services.nginx.loaded as NginxLoaded) : iisLoaded(server);
  if (!app && listener?.process !== 'nginx' && listener?.service !== 'W3SVC') {
    conn.close('server');
    return fail('Web request failed', listener?.process === 'sshd' && scheme === 'http'
      ? `${get}: net/http: HTTP/1.x transport connection broken: malformed HTTP response "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"`
      : `${get}: EOF`);
  }
  const tlsSock = !!loaded?.servers?.some((s) => isTlsPort(s, backend.port));
  if (scheme === 'https' && !tlsSock) { conn.close('client'); return fail('Web request failed', `${get}: http: server gave HTTP response to HTTPS client`); }
  const req = { method: 'GET', path, hostHeader: portStr ? `${hostname}:${portStr}` : hostname, plainOnTls: scheme === 'http' && tlsSock, now: w.clock, client: { ip: backend.proxyFrom ?? conn.sv.peer, ua: 'Go-http-client/1.1' } };
  const r = app ? app(w, server, req) : handleRequest(server, selectServer(loaded, backend.local, backend.port, hostname)!, req);
  conn.send('c2s', 90 + path.length, { protocol: 'DATA', info: `GET ${path} HTTP/1.1`, fields: [] });
  conn.send('s2c', 200 + Math.min(r.size, 1200), { protocol: 'DATA', info: `HTTP/1.1 ${r.status} ${r.reason}`, fields: [] });
  conn.close('client');
  if (r.status !== want) return fail('Received an unexpected status code', `expected status code ${want}, got ${r.status} (${r.status} ${r.reason})`);
  if (goal.content && !new RegExp(goal.content).test(r.body)) {
    const title = /<title>([^<]*)<\/title>/i.exec(r.body)?.[1] ?? r.body.split('\n')[0].slice(0, 60);
    return fail('Page content did not match', `expected content "${goal.content}" not found in the page (page title: "${title}")`);
  }
  return { ok: true, lines: [head, 'Status: Success!'] };
}

/**
 * The DNS check: one UDP query (a Go DNS library, no retries over TCP) to the
 * team's server; the A records in the answer must include the expected address.
 */
export function scoredDnsCheck(world: World, goal: ScoredDnsGoal): { ok: boolean; lines: string[] } {
  const w = structuredClone(world);
  const head = `Scoring engine: DNS check ${goal.name} A @${goal.server} (expects ${goal.expect})`;
  const fail = (status: string, error: string) => ({ ok: false, lines: [head, `Status: ${status}`, `Error: ${error}`] });
  const client = w.hosts[goal.fromHost];
  const src = `${sourceAddress(client, goal.server)}:${40000 + (w.counter * 7919) % 20000}`;
  const ex = dnsQuery(w, client, goal.server, goal.name, 5, 'A');
  const q = `${goal.name.replace(/\.$/, '')}. A`;
  switch (ex.outcome) {
    case 'timeout': return timedOut(head);
    case 'port-unreachable': return fail('DNS query failed', `read udp ${src}->${goal.server}:53: read: connection refused`);
    case 'unreachable': return fail('DNS query failed', `read udp ${src}->${goal.server}:53: read: no route to host`);
    case 'nxdomain': return fail('Incorrect DNS answer', `${q}: server answered NXDOMAIN (no such name)`);
    case 'servfail': return fail('DNS query failed', `${q}: server answered SERVFAIL`);
    case 'refused': return fail('DNS query failed', `${q}: server answered REFUSED`);
    default: {
      const got = (ex.answer?.answers ?? []).filter((a) => a.type === 'A').map((a) => a.data);
      if (got.includes(goal.expect)) return { ok: true, lines: [head, 'Status: Success!'] };
      return fail('Incorrect DNS answer', `${q}: expected ${goal.expect}, got ${got.length ? got.join(', ') : 'no A records'}`);
    }
  }
}
