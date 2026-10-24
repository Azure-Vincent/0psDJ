// Account state that PAM checks during a login, beyond the password itself:
// account expiry (chage -E, the 8th field of /etc/shadow) and pam_faillock,
// which locks an account after repeated failures. pam_faillock is active when
// /etc/pam.d/common-auth calls it; its settings come from
// /etc/security/faillock.conf and its tally lives in /var/run/faillock/<user>
// (a tmpfs: cleared at every boot).

import { mkdir, readFile, writeFile } from '../fs';
import type { Host, UserAccount, World } from '../types';

export const FAILLOCK_DIR = '/var/run/faillock';
export const FAILLOCK_CONF = '/etc/security/faillock.conf';
const DAY = 86_400_000;

/** Day number (days since 1970-01-01), as stored in /etc/shadow. */
export const dayOf = (ms: number): number => Math.floor(ms / DAY);

/** An account with an expiry date is expired from that day on (chage -E YYYY-MM-DD). */
export function accountExpired(u: UserAccount, now: number): boolean {
  return u.expires !== undefined && u.expires !== null && u.expires >= 0 && dayOf(now) >= u.expires;
}

/** Locked with passwd -l / usermod -L: the hash starts with "!" (or there is no password at all). */
export function passwordLocked(u: UserAccount): boolean {
  return u.password === null || u.password.startsWith('!');
}

export interface FaillockConf {
  deny: number;
  /** Seconds; 0 = locked until an administrator resets the tally. */
  unlockTime: number;
  /** Seconds within which failures count. */
  failInterval: number;
  evenDenyRoot: boolean;
}

/** pam_faillock settings, or null when the PAM stack does not use pam_faillock. */
export function faillockConf(host: Host): FaillockConf | null {
  const auth = readFile(host, '/etc/pam.d/common-auth') ?? '';
  if (!auth.split('\n').some((l) => !l.trim().startsWith('#') && /pam_faillock\.so\s+preauth/.test(l))) return null;
  const c: FaillockConf = { deny: 3, unlockTime: 600, failInterval: 900, evenDenyRoot: false };
  for (const raw of (readFile(host, FAILLOCK_CONF) ?? '').split('\n')) {
    const l = raw.replace(/#.*/, '').trim();
    const m = /^(\w+)\s*(?:=\s*(\S+))?$/.exec(l);
    if (!m) continue;
    const n = Number(m[2]);
    if (m[1] === 'deny' && Number.isFinite(n)) c.deny = n;
    else if (m[1] === 'unlock_time' && Number.isFinite(n)) c.unlockTime = n;
    else if (m[1] === 'fail_interval' && Number.isFinite(n)) c.failInterval = n;
    else if (m[1] === 'even_deny_root') c.evenDenyRoot = true;
  }
  return c;
}

export interface FaillockRecord { time: number; source: string }

export function faillockRecords(host: Host, user: string): FaillockRecord[] {
  const text = readFile(host, `${FAILLOCK_DIR}/${user}`) ?? '';
  return text.split('\n').filter(Boolean).map((l) => {
    const [t, src] = l.split(' ');
    return { time: Number(t), source: src ?? '' };
  });
}

/** True when pam_faillock currently denies the account (preauth). */
export function faillockLocked(host: Host, user: string, now: number, c: FaillockConf): boolean {
  if (c.deny <= 0 || (user === 'root' && !c.evenDenyRoot)) return false;
  const recent = faillockRecords(host, user).filter((r) => now - r.time <= c.failInterval * 1000);
  if (recent.length < c.deny) return false;
  const last = Math.max(...recent.map((r) => r.time));
  return c.unlockTime === 0 || now - last < c.unlockTime * 1000;
}

export function faillockRecordFailure(world: World, host: Host, user: string, source: string): void {
  const path = `${FAILLOCK_DIR}/${user}`;
  const prev = readFile(host, path) ?? '';
  ensureDir(world, host);
  writeFile(host, path, `${prev}${world.clock} ${source}\n`, world.clock, host.fs[path] ? undefined : { mode: 0o600 });
}

export function faillockReset(host: Host, user: string): void {
  delete host.fs[`${FAILLOCK_DIR}/${user}`];
}

/** /var/run is a tmpfs: tallies do not survive a reboot. */
export function faillockClearAll(host: Host): void {
  for (const p of Object.keys(host.fs)) if (p.startsWith(`${FAILLOCK_DIR}/`)) delete host.fs[p];
}

function ensureDir(world: World, host: Host): void {
  for (const d of ['/var', '/var/run', FAILLOCK_DIR]) if (!host.fs[d]) mkdir(host, d, world.clock);
}
