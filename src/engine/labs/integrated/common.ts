// Building blocks shared by the integrated labs: request-path hops and checks
// that run real commands on a copy of the lab.

import type { World } from '../../types';
import { NO, OK, probe } from '../engine';
import type { LabCheck, PathNode } from '../types';

/** The evidence a probe shows: the prompt, the command and (the end of) its output. */
export function evidence(host: string, user: string, command: string, output: string, code: number): string {
  const lines = output.split('\n').filter((l) => l.trim() !== '');
  const shown = lines.length > 12 ? [...lines.slice(0, 4), `… (${lines.length - 8} more lines)`, ...lines.slice(-4)] : lines;
  return [`${user}@${host}${user === 'root' || user === 'Administrator' ? '#' : '$'} ${command}`, ...shown, ...(code !== 0 ? [`(exit status ${code})`] : [])].join('\n');
}

/** A hop on a request path: OK when the command's output passes the test. */
export function hop(id: string, label: string, role: string, host: string, user: string, command: string, test: (out: string, code: number) => boolean): PathNode {
  return {
    id, label, role, host,
    probe(world: World) {
      const r = probe(world, host, user, command);
      return { ok: test(r.output, r.code), evidence: evidence(host, user, command, r.output, r.code) };
    },
  };
}

/** The host's default gateway (from its routing table) answers a ping: the hop users depend on, whatever the files say. */
export function gatewayHop(host: string, user: string): PathNode {
  return {
    id: 'gateway', label: 'Default gateway answers', role: 'The router named by the default route in the routing table (from DHCP or the configuration).', host,
    probe(world: World) {
      const r = probe(world, host, user, 'ip route');
      const gw = /^default via (\S+)/m.exec(r.output)?.[1];
      const ev = evidence(host, user, 'ip route', r.output, r.code);
      if (!gw) return { ok: false, evidence: `${ev}\n(no default route)` };
      const p = probe(world, host, user, `ping -c 1 -W 2 ${gw}`);
      return { ok: p.code === 0, evidence: `${ev}\n${evidence(host, user, `ping -c 1 -W 2 ${gw}`, p.output, p.code)}` };
    },
  };
}

/**
 * A check that runs one command: fail(out, code) returns the failure detail,
 * or null when the requirement holds; pass is the detail shown on success.
 */
export function cmdCheck(id: string, description: string, host: string, user: string, command: string, fail: (out: string, code: number) => string | null, pass: string): LabCheck {
  return {
    id, description,
    check(world: World) {
      const r = probe(world, host, user, command);
      const f = fail(r.output, r.code);
      return f ? NO(`${f}\n${evidence(host, user, command, r.output, r.code)}`) : OK(pass);
    },
  };
}

/** The last line of a command's output (for short failure messages). */
export const lastLine = (s: string) => s.trim().split('\n').pop() ?? '';
