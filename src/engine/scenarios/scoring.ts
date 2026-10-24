// A competition scoring engine's SSH check, as CCDC-style scorers run it: a Go
// program (golang.org/x/crypto/ssh) dials the service, ignores the host key,
// logs in once with the team's published password and runs a command. Its
// result table shows Go's error text, which differs from OpenSSH's: this
// module produces the same messages from the simulated connection.

import { resolve } from '../sim/dns';
import { runSsh, type SshResult } from '../sim/ssh';
import type { World } from '../types';
import type { ScoredSshGoal } from './types';

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

/** Go's net.Dial / ssh.Dial error text for a simulated SSH attempt. */
export function goSshError(world: World, goal: ScoredSshGoal, r: SshResult): string {
  const port = goal.port ?? 22;
  const client = world.hosts[goal.fromHost];
  const res = resolve(world, client, goal.target, { family: 4 });
  const ip = res.ok ? res.ip : goal.target;
  switch (r.failure) {
    case 'resolve': {
      const ns = /^nameserver\s+(\S+)/m.exec(client.fs['/etc/resolv.conf']?.content ?? '')?.[1] ?? '127.0.0.53';
      return `dial tcp: lookup ${goal.target} on ${ns}:53: no such host`;
    }
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
