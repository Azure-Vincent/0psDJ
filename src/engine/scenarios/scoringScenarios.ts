// Scored services: tickets as a CCDC-style competition presents them. The
// white team's scoring engine logs in to srv01 over SSH every few minutes with
// the passwords the team published, and its results table shows Go's error
// text ("ssh: handshake failed: ssh: unable to authenticate, attempted methods
// [none password], no supported methods remain"). Very different causes give
// that same message, so each ticket is solved on the server: the sshd log, the
// account's state and the PAM stack.

import { effectiveConfig } from '../config/sshdConfig';
import { writeFile } from '../fs';
import { addUser } from '../lab/builder';
import { faillockConf } from '../sim/accounts';
import type { SshdLoaded } from '../sim/services';
import { runSsh } from '../sim/ssh';
import { Shell } from '../shell/shell';
import type { World } from '../types';
import { checkGoal, script, sshdPolicy } from './engine';
import type { Constraint, Goal, Scenario, ScoredSshGoal } from './types';

export const SCORE_USER = 'joe';
export const SCORE_PASSWORD = 'Joe-Score-2026';
export const SCORE_ROOT_PASSWORD = 'Root-Score-2026';
/** The scoring engine's checks come from ws01's address in this lab. */
export const SCORER_IP = '10.0.10.25';
const ATTACKER_IP = '10.0.30.25';

const SCORING_CONF = `# Competition rules, section 4 (scored services): the scoring engine logs in
# with the passwords published in the team packet. Password logins are allowed
# for the scored accounts only; everyone else keeps key-only logins (CHG-1042).
Match Group scored
    PasswordAuthentication yes
Match User root Address ${SCORER_IP}
    PasswordAuthentication yes
    PermitRootLogin yes
`;

const JOE_CHECK: ScoredSshGoal = {
  kind: 'scored-ssh', fromHost: 'ws01', fromUser: 'alice', target: 'srv01.corp.lab', user: SCORE_USER, password: SCORE_PASSWORD,
  description: `The scoring engine's SSH check passes again: it logs in to srv01.corp.lab as ${SCORE_USER} with the published password (${SCORE_PASSWORD}) and runs whoami.`,
};
const ROOT_CHECK: ScoredSshGoal = {
  ...JOE_CHECK, user: 'root', password: SCORE_ROOT_PASSWORD,
  description: `The scoring engine's root SSH check passes again: it logs in to srv01.corp.lab as root with the published password (${SCORE_ROOT_PASSWORD}) from ${SCORER_IP} and runs whoami.`,
};

const TERMINALS = [
  { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01 console (hypervisor), logged in as root. Scored service: SSH. Try: journalctl -u ssh -n 20, faillock --user joe, passwd -S joe, chage -l joe, sshd -T -C user=joe,host=ws01,addr=10.0.10.25.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01 (${SCORER_IP}): the scoring engine's checks come from this address. Reproduce a check with: ssh -o PubkeyAuthentication=no ${SCORE_USER}@srv01.corp.lab (password ${SCORE_PASSWORD}).` },
];

const BRIEFING = [
  'Competition: the white team\'s scoring engine checks your services every few minutes. A check that fails costs points; its results table shows the raw error of its Go SSH client.',
  `Scored service: SSH on srv01.corp.lab (10.0.20.10). The engine logs in from ${SCORER_IP} as ${SCORE_USER} (password ${SCORE_PASSWORD}) and, for some checks, as root (${SCORE_ROOT_PASSWORD}), then runs whoami. It ignores host keys and tries the password once.`,
  'srv01 policy (CHG-1042): key-only SSH logins and no root logins, except the password logins the competition rules require: the scored group, and root from the scoring engine only (/etc/ssh/sshd_config.d/50-scoring.conf).',
  'Fixes must survive a restart of every machine. Do not weaken the policy for everyone to make the check pass.',
];

const CANDIDATES = ['score-password-changed', 'pam-faillock-lockout', 'root-login-prohibited', 'account-expired', 'account-locked', 'user-not-allowed', 'auth-method-disabled', 'firewall-drop', 'sshd-not-running'];

/** The competition baseline on srv01: the scored account, root's published password, password logins for the scorer only. */
export function scoringBaseline(world: World): void {
  const srv = world.hosts.srv01;
  addUser(srv, { name: SCORE_USER, uid: 1101, gid: 1101, primaryGroup: SCORE_USER, groups: ['scored'], home: `/home/${SCORE_USER}`, shell: '/bin/bash', gecos: 'Joe (scored account)', password: SCORE_PASSWORD }, world.clock);
  srv.users.root.password = SCORE_ROOT_PASSWORD;
  writeFile(srv, '/etc/ssh/sshd_config.d/50-scoring.conf', SCORING_CONF, world.clock);
  script(world, 'srv01', ['systemctl reload ssh'], 60_000);
}

/** One SSH password attempt, as an attacker's tool makes them. */
function attempt(world: World, fromHost: string, fromUser: string, target: string, user: string, password: string): void {
  world.clock += 7_000;
  runSsh(world, { clientHostId: fromHost, localUser: fromUser, target, user, answers: [password], passwordPrompts: 1, pubkeyAuthentication: false, gssapiAuthentication: false, ignoreKnownHosts: true, connectTimeoutS: 5 });
}

function loadedSshd(world: World): SshdLoaded | null {
  return (world.hosts.srv01.services.ssh?.loaded as SshdLoaded | null) ?? null;
}

function aliceKeysStillWork(): Constraint {
  const goal: Goal = { description: '', localUser: 'alice', user: 'alice', target: 'srv01.corp.lab', method: 'publickey' };
  return {
    id: 'alice-key-login', required: true,
    description: 'alice still logs in to srv01 with her key, and only with her key.',
    check(world) {
      const r = checkGoal(world, goal);
      const l = loadedSshd(world);
      const pw = l ? effectiveConfig(l.parsed, { user: 'alice', groups: ['alice', ...(world.hosts.srv01.users.alice?.groups ?? [])], address: SCORER_IP }).passwordAuthentication : false;
      const ok = r.ok && !pw;
      return { id: this.id, ok, required: true, message: !r.ok ? `alice's key login broke: ${r.lines.at(-1) ?? ''}` : pw ? 'alice may now log in with a password: password logins were opened beyond the scored accounts.' : 'alice: key login works, passwords refused.' };
    },
  };
}

function rootOnlyFromScorer(): Constraint {
  return {
    id: 'root-only-from-scorer', required: true,
    description: `Root password logins stay limited to the scoring engine (${SCORER_IP}); from anywhere else root cannot log in with a password.`,
    check(world) {
      const l = loadedSshd(world);
      if (!l) return { id: this.id, ok: true, required: true, message: 'sshd is not running.' };
      const e = effectiveConfig(l.parsed, { user: 'root', groups: ['root'], address: ATTACKER_IP });
      const open = e.permitRootLogin === 'yes' && e.passwordAuthentication;
      return { id: this.id, ok: !open, required: true, message: open ? `root may log in with a password from ${ATTACKER_IP} (sshd -T -C user=root,addr=${ATTACKER_IP}): the root exception is no longer limited to the scoring engine.` : `From other addresses root password logins are still refused (PermitRootLogin ${e.permitRootLogin}).` };
    },
  };
}

function faillockKept(): Constraint {
  return {
    id: 'faillock-kept', required: true,
    description: 'pam_faillock stays enabled (deny at most 5): it is what stops password guessing.',
    check(world) {
      const c = faillockConf(world.hosts.srv01);
      const ok = !!c && c.deny > 0 && c.deny <= 5;
      return { id: this.id, ok, required: true, message: ok ? `pam_faillock active: deny = ${c!.deny}, unlock_time = ${c!.unlockTime}.` : 'pam_faillock was removed or weakened: brute force against the scored account is no longer limited.' };
    },
  };
}

function attackerBlocked(): Constraint {
  return {
    id: 'attacker-blocked', required: true,
    description: `The brute-force source ${ATTACKER_IP} can no longer reach SSH on srv01 (otherwise it locks the account again).`,
    check(world) {
      let w = structuredClone(world);
      const sh = new Shell(() => w, (n) => (w = n), { hostId: 'dev01', user: 'erin', cwd: '/home/erin' });
      const r = sh.execute('nc -zv -w 2 10.0.20.10 22');
      const ok = r.code !== 0;
      return { id: this.id, ok, required: true, message: ok ? `${ATTACKER_IP} cannot connect to srv01:22.` : `${ATTACKER_IP} still reaches srv01:22: the next round of guesses locks ${SCORE_USER} again.` };
    },
  };
}

function allowGroupsKept(): Constraint {
  return {
    id: 'allowgroups-kept', required: true,
    description: 'SSH stays limited to the allowed groups (sshadmins and the scored accounts), not opened to every account.',
    check(world) {
      const l = loadedSshd(world);
      if (!l) return { id: this.id, ok: true, required: true, message: 'sshd is not running.' };
      const g = l.effective.allowGroups;
      const ok = g.includes('sshadmins') && !g.some((x) => x === '*' || x === 'users');
      return { id: this.id, ok, required: true, message: ok ? `AllowGroups ${g.join(' ')}.` : `AllowGroups is now "${g.join(' ') || '(not set)'}": the restriction from the audit was removed or opened to everyone.` };
    },
  };
}

const AUTH_ERROR = /attempted methods \[none password\], no supported methods remain/;
export { AUTH_ERROR as SCORING_AUTH_ERROR };

export const SCORING_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'score-password-changed',
    title: 'The red team\'s souvenir',
    difficulty: 'beginner',
    ticket: `Scoring engine, SSH (srv01): failing since 02:14. "Unable to dial the remote host. Make sure the host is up, and credentials are correct - ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain". Teammate: "Nobody on our team touched ${SCORE_USER}."`,
    briefing: BRIEFING,
    goals: [JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      // The red team got in with a reused password and changed joe's.
      world.clock += 3 * 3600_000;
      script(world, 'srv01', [`echo '${SCORE_USER}:R3d-T3am-0wns-U' | chpasswd`], 60_000);
    },
    rootCauses: ['score-password-changed'],
    candidates: CANDIDATES,
    feedback: {
      'pam-faillock-lockout': `faillock --user ${SCORE_USER} shows no failures, and the log has no pam_faillock line.`,
      'root-login-prohibited': `The failing check logs in as ${SCORE_USER}, not root.`,
      'account-expired': `chage -l ${SCORE_USER}: "Account expires: never". An expired account gives "handshake failed: EOF", not "unable to authenticate".`,
      'account-locked': `passwd -S ${SCORE_USER} shows P (usable password), not L (locked).`,
      'user-not-allowed': 'The log says "Failed password", not "not allowed because ...": the account passes the AllowUsers/AllowGroups checks.',
      'auth-method-disabled': '"attempted methods [none password]" means password was offered by the server and tried: password logins are enabled for this account.',
      'firewall-drop': 'A firewall problem fails at "dial tcp ... i/o timeout", before any SSH handshake. Here authentication was reached.',
      'sshd-not-running': 'sshd answered and offered password authentication: it is running.',
    },
    hints: [
      'Translate the error: the TCP connection and the SSH handshake worked, the server offered password authentication, and the password the engine sent was rejected. The question is why the server rejected it.',
      `On srv01: journalctl -u ssh -n 20. "Failed password for ${SCORE_USER} from ${SCORER_IP}" with a pam_unix authentication failure means the password itself no longer matches. Then look for who changed it: journalctl -t chpasswd, journalctl -t passwd.`,
      `Set the published password back: echo '${SCORE_USER}:${SCORE_PASSWORD}' | chpasswd (or passwd ${SCORE_USER}). Then look for how the red team got in.`,
    ],
    explanation: {
      rootCause: `Someone changed ${SCORE_USER}'s password at night (chpasswd in the journal). The scoring engine still uses the published password, so pam_unix rejects every check.`,
      manifestation: 'Go\'s SSH client reports "unable to authenticate, attempted methods [none password]": the server offered password authentication and refused the password. OpenSSH would say "Permission denied (publickey,password)".',
      evidence: `srv01: "Failed password for ${SCORE_USER} from ${SCORER_IP}" and "pam_unix(sshd:auth): authentication failure ... user=${SCORE_USER}"; "chpasswd: pam_unix(chpasswd:chauthtok): password changed for ${SCORE_USER}" at the time the checks started failing; faillock and chage show nothing unusual.`,
      prevention: 'Watch password changes on scored accounts (journal, auth.log), change all default and reused passwords at the start of a competition, and reset scored passwords to the published value (or submit the change to the white team) as soon as a check fails.',
    },
    solution: [{ host: 'srv01', commands: [`echo '${SCORE_USER}:${SCORE_PASSWORD}' | chpasswd`] }],
    constraints: [sshdPolicy(), aliceKeysStillWork()],
    concepts: ['ssh.userauth', 'logs.journal'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-faillock',
    title: 'Locked out by the attacker',
    difficulty: 'intermediate',
    ticket: `Scoring engine, SSH (srv01): failing for 20 minutes with "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain". Teammate: "I checked, ${SCORE_USER}'s password is still the published one. I also turned on account lockout this morning, like the hardening guide says."`,
    briefing: [...BRIEFING, `Hardening this morning: pam_faillock enabled on srv01 (/etc/pam.d/common-auth, /etc/security/faillock.conf).`],
    goals: [JOE_CHECK],
    terminals: [...TERMINALS, { hostId: 'dev01', user: 'erin', label: 'dev01 (erin)', banner: `dev01 (${ATTACKER_IP}), a developer workstation on VLAN 30.` }],
    setup(world) {
      scoringBaseline(world);
      writeFile(world.hosts.srv01, '/etc/pam.d/common-auth', COMMON_AUTH_FAILLOCK, world.clock);
      writeFile(world.hosts.srv01, '/etc/security/faillock.conf', FAILLOCK_CONF_HARDENED, world.clock);
      world.clock += 2 * 3600_000;
      // A compromised workstation guesses joe's password.
      for (const p of ['joe', 'joe123', 'Password1', 'Welcome1!', 'Summer2026']) attempt(world, 'dev01', 'erin', '10.0.20.10', SCORE_USER, p);
      world.clock += 5 * 60_000;
    },
    rootCauses: ['pam-faillock-lockout'],
    acceptable: { 'firewall-drop': 'Not the cause of the failure, but part of the fix: the source of the guesses must be blocked or the account locks again.' },
    candidates: CANDIDATES,
    feedback: {
      'score-password-changed': `The password was not changed: no chpasswd/passwd entry in the journal, and the log shows pam_faillock refusing the attempt before the password is even checked.`,
      'root-login-prohibited': `The failing check logs in as ${SCORE_USER}.`,
      'account-expired': `chage -l ${SCORE_USER}: the account never expires (and expiry gives "handshake failed: EOF").`,
      'account-locked': `passwd -S ${SCORE_USER} shows P: the password itself is not locked. The lock is pam_faillock's tally (faillock --user ${SCORE_USER}).`,
      'user-not-allowed': 'No "not allowed because" line: the account passes sshd\'s access lists.',
      'auth-method-disabled': 'The engine tried a password ("[none password]"), so password logins are enabled for the account.',
      'sshd-not-running': 'sshd answers and offers password authentication.',
    },
    hints: [
      'The password is right and the error says authentication failed. What else can refuse a correct password? Read the server log: journalctl -u ssh -n 30.',
      `"pam_faillock(sshd:auth): Consecutive login failures for user ${SCORE_USER} account temporarily locked". faillock --user ${SCORE_USER} lists the failures and their source address; cat /etc/security/faillock.conf shows deny and unlock_time (0 = never unlocks by itself).`,
      `Block the source first (otherwise it locks the account again): add "ip saddr ${ATTACKER_IP} tcp dport 22 drop" above the SSH accept rule in /etc/nftables.conf and reload nftables. Then faillock --user ${SCORE_USER} --reset. Keep pam_faillock on.`,
    ],
    explanation: {
      rootCause: `pam_faillock (deny = 3, unlock_time = 0) locked ${SCORE_USER} after a compromised workstation (${ATTACKER_IP}) guessed passwords. While locked, PAM refuses even the correct password, and with unlock_time = 0 the lock never expires by itself.`,
      manifestation: 'Exactly the same Go error as a wrong password ("attempted methods [none password]"). With a non-zero unlock_time the check flips between failing and passing as the lock expires and the attacker locks it again: the intermittent pattern often seen in scoring tables.',
      evidence: `srv01: pam_faillock(sshd:auth) "Consecutive login failures ... temporarily locked"; faillock --user ${SCORE_USER} lists the failures from ${ATTACKER_IP}; passwd -S shows P; the password still works after a reset.`,
      prevention: 'Lockout protects passwords but lets an attacker deny service: block guessing sources early, use a non-zero unlock_time on scored accounts, and watch faillock / the journal for bursts of failures.',
    },
    solution: [{ host: 'srv01', commands: [
      `sed -i 's/^\\(\\s*\\)tcp dport 22 accept$/\\1ip saddr ${ATTACKER_IP} tcp dport 22 drop\\n\\1tcp dport 22 accept/' /etc/nftables.conf`,
      'nft -c -f /etc/nftables.conf && systemctl reload nftables',
      `faillock --user ${SCORE_USER} --reset`,
    ] }],
    constraints: [sshdPolicy(), faillockKept(), attackerBlocked(), aliceKeysStillWork()],
    concepts: ['ssh.userauth', 'logs.journal', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-root-prohibit',
    title: 'Root, but only with keys',
    difficulty: 'intermediate',
    ticket: 'Scoring engine, SSH root check (srv01): failing since the last round with "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain". The joe check still passes. Teammate: "I tightened 50-scoring.conf: root should only use keys, per the hardening guide."',
    briefing: BRIEFING,
    goals: [ROOT_CHECK, JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      script(world, 'srv01', ["sed -i 's/^    PermitRootLogin yes$/    PermitRootLogin prohibit-password/' /etc/ssh/sshd_config.d/50-scoring.conf", 'systemctl reload ssh'], 60_000);
    },
    rootCauses: ['root-login-prohibited'],
    candidates: CANDIDATES,
    feedback: {
      'score-password-changed': 'root\'s password is still the published one (try it on the console); the log has no pam_unix authentication failure for root.',
      'pam-faillock-lockout': 'pam_faillock is not configured, and it ignores root unless even_deny_root is set.',
      'account-expired': 'chage -l root: never expires (and that would give "handshake failed: EOF").',
      'account-locked': 'passwd -S root shows P.',
      'user-not-allowed': 'No "not allowed because" line: root passes the access lists.',
      'auth-method-disabled': 'The engine tried a password ("[none password]"): password authentication is offered to root from the scorer. It is PermitRootLogin that refuses it.',
      'firewall-drop': 'The handshake completed and the joe check passes.',
      'sshd-not-running': 'sshd answers.',
    },
    hints: [
      'Only the root check fails, with the same message as a wrong password. On srv01: journalctl -u ssh -n 20. "Failed password for root" without any pam_unix line means sshd refused root before asking PAM.',
      `Which settings apply to the scoring engine's root logins? sshd -T -C user=root,host=ws01,addr=${SCORER_IP} | grep -i -e permitrootlogin -e passwordauthentication.`,
      `PermitRootLogin prohibit-password allows root only with keys. Put PermitRootLogin yes back in the "Match User root Address ${SCORER_IP}" block of 50-scoring.conf (not globally), sshd -t, systemctl reload ssh.`,
    ],
    explanation: {
      rootCause: `The "Match User root Address ${SCORER_IP}" block was changed to PermitRootLogin prohibit-password. That still offers password authentication (the client tries it) but refuses every password for root, so the scorer's root check fails.`,
      manifestation: 'Go: "unable to authenticate, attempted methods [none password]", identical to a wrong password. OpenSSH: "Permission denied (publickey,password)". The joe check is unaffected.',
      evidence: `srv01: "Failed password for root from ${SCORER_IP}" with no pam_unix line; sshd -T -C user=root,host=ws01,addr=${SCORER_IP} prints permitrootlogin prohibit-password; the change in 50-scoring.conf.`,
      prevention: 'Test changes to sshd with sshd -T -C for each scored account and source, and keep exceptions required by the rules in one documented Match block.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/^    PermitRootLogin prohibit-password$/    PermitRootLogin yes/' /etc/ssh/sshd_config.d/50-scoring.conf", 'sshd -t && systemctl reload ssh'] }],
    constraints: [sshdPolicy(), rootOnlyFromScorer(), aliceKeysStillWork()],
    concepts: ['ssh.config', 'ssh.authz'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-account-expired',
    title: 'Account hygiene',
    difficulty: 'intermediate',
    ticket: `Scoring engine, SSH (srv01): failing since the account clean-up with "ssh: handshake failed: EOF". Teammate: "I ran the inactive-accounts script from the hardening checklist: it expires accounts nobody logged in to interactively for 90 days."`,
    briefing: BRIEFING,
    goals: [JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      script(world, 'srv01', [`chage -E 2026-10-01 ${SCORE_USER}`], 60_000);
    },
    rootCauses: ['account-expired'],
    candidates: CANDIDATES,
    feedback: {
      'score-password-changed': `A wrong password gives "unable to authenticate", not EOF; here the log shows the password was accepted by pam_unix and the account check failed.`,
      'pam-faillock-lockout': 'pam_faillock is not configured on srv01, and a lockout gives "unable to authenticate".',
      'root-login-prohibited': `The check logs in as ${SCORE_USER}.`,
      'account-locked': `passwd -S ${SCORE_USER} shows P: the password is not locked.`,
      'user-not-allowed': 'No "not allowed because" line in the log.',
      'auth-method-disabled': 'Authentication itself succeeded; the server closed the connection afterwards.',
      'firewall-drop': 'The handshake and authentication were reached: the network path works.',
      'sshd-not-running': 'sshd answered and authenticated the password.',
    },
    hints: [
      '"handshake failed: EOF" is not "unable to authenticate": the server closed the connection during login instead of refusing the password. Read why: journalctl -u ssh -n 20.',
      `"pam_unix(sshd:account): account ${SCORE_USER} has expired" and "fatal: Access denied for user ${SCORE_USER} by PAM account configuration". Check the account: chage -l ${SCORE_USER}, or the 8th field of grep ${SCORE_USER} /etc/shadow.`,
      `Remove the expiry from the scored account: chage -E -1 ${SCORE_USER} (or usermod -e '' ${SCORE_USER}). Exclude scored accounts from the clean-up script.`,
    ],
    explanation: {
      rootCause: `The inactive-accounts script set an expiry date in the past on ${SCORE_USER} (chage -E 2026-10-01). The scoring engine authenticates correctly, then PAM's account phase (pam_unix) refuses the expired account and sshd drops the connection.`,
      manifestation: 'Go: "ssh: handshake failed: EOF" (the server closed the connection during authentication). OpenSSH: "Your account has expired; please contact your system administrator" then "Connection closed".',
      evidence: `srv01: "pam_unix(sshd:account): account ${SCORE_USER} has expired (account expired)", "fatal: Access denied for user ${SCORE_USER} by PAM account configuration [preauth]"; chage -l ${SCORE_USER} → Account expires: Oct 01, 2026; /etc/shadow field 8 = 20727.`,
      prevention: 'Service and scored accounts never log in interactively: exclude them from inactivity clean-ups, and test every scored service after hygiene scripts run.',
    },
    solution: [{ host: 'srv01', commands: [`chage -E -1 ${SCORE_USER}`] }],
    constraints: [sshdPolicy(), aliceKeysStillWork()],
    concepts: ['ssh.userauth', 'linux.permissions'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-allowgroups',
    title: 'Only admins may SSH',
    difficulty: 'beginner',
    ticket: 'Scoring engine, SSH (srv01): both checks failing after the audit fix, "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain". Teammate: "Audit finding: restrict SSH to the admin group. Done: AllowGroups sshadmins. My key login still works."',
    briefing: BRIEFING,
    goals: [JOE_CHECK, ROOT_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      script(world, 'srv01', ['usermod -aG sshadmins alice', "printf 'AllowGroups sshadmins\\n' >> /etc/ssh/sshd_config.d/10-hardening.conf", 'systemctl reload ssh'], 60_000);
    },
    rootCauses: ['user-not-allowed'],
    candidates: CANDIDATES,
    feedback: {
      'score-password-changed': 'The log says "not allowed because none of user\'s groups are listed in AllowGroups": sshd refused the account before checking the password.',
      'pam-faillock-lockout': 'pam_faillock is not configured on srv01.',
      'root-login-prohibited': 'Both checks fail, joe\'s too. The log names AllowGroups for both.',
      'account-expired': 'An expired account gives "handshake failed: EOF".',
      'account-locked': 'passwd -S shows P for both accounts.',
      'auth-method-disabled': 'The engine tried a password, so it was offered: sshd still lists the methods for accounts it will refuse anyway, to avoid revealing which accounts exist.',
      'firewall-drop': 'The handshake completed.',
      'sshd-not-running': 'sshd answers.',
    },
    hints: [
      'Both scored accounts fail with the same message, and alice\'s key login works. What is different about alice? journalctl -u ssh -n 20 on srv01.',
      `"User ${SCORE_USER} from ${SCORER_IP} not allowed because none of user's groups are listed in AllowGroups". sshd refuses the account whatever the password, yet still asks for it so it does not reveal which accounts exist. sshd -T | grep -i allowgroups.`,
      `Allow the scored accounts too: AllowGroups sshadmins scored root (in 10-hardening.conf), sshd -t, systemctl reload ssh. Do not remove the restriction.`,
    ],
    explanation: {
      rootCause: `The audit fix added "AllowGroups sshadmins". ${SCORE_USER} (group scored) and root are not in it, so sshd treats them as not allowed and every authentication fails, even with the right password.`,
      manifestation: 'Go: "unable to authenticate, attempted methods [none password]": sshd still offers password authentication to refused accounts (so attackers cannot tell which accounts exist) and then fails every attempt.',
      evidence: `srv01: "User ${SCORE_USER} from ${SCORER_IP} not allowed because none of user's groups are listed in AllowGroups" (and the same for root); sshd -T shows allowgroups sshadmins; alice (in sshadmins) is unaffected.`,
      prevention: 'Before restricting access, list every account that must keep it, scored and service accounts first, and test each scored check after the change.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/^AllowGroups sshadmins$/AllowGroups sshadmins scored root/' /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t && systemctl reload ssh'] }],
    constraints: [sshdPolicy(), allowGroupsKept(), rootOnlyFromScorer(), aliceKeysStillWork()],
    concepts: ['ssh.authz', 'ssh.config'],
  },
];

const COMMON_AUTH_FAILLOCK = `#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# here are the per-package modules (the "Primary" block)
# pam_faillock: lock accounts after repeated failures (hardening checklist item 7)
auth	required			pam_faillock.so preauth
auth	[success=1 default=ignore]	pam_unix.so nullok
auth	[default=die]			pam_faillock.so authfail
# here's the fallback if no module succeeds
auth	requisite			pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth	required			pam_permit.so
auth	sufficient			pam_faillock.so authsucc
# end of pam-auth-update config
`;

const FAILLOCK_CONF_HARDENED = `# Configuration for locking the user after multiple failed
# authentication attempts.
#
# Hardening checklist item 7: lock after 3 failures, unlock by an administrator only.
deny = 3
unlock_time = 0
fail_interval = 900
`;
