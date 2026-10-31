// The simulated bash. Every command line runs against a copy of the world and
// is committed only when it completes, so interactive prompts (ssh host-key
// confirmation, passwords, sudo) can be answered by replaying the line with the
// collected answers. Because the engine is deterministic, the replay produces
// exactly the same intermediate state.

import { RESTIC_COMMANDS } from './cmdRestic';
import { MON_COMMANDS } from './cmdMon';
import { LDAP_COMMANDS } from './cmdLdap';
import { RADIUS_COMMANDS } from './cmdRadius';
import { BACKUP_COMMANDS } from './cmdBackup';
import { runDueTimers, setUnitRunner } from '../sim/timers';
import { maintainLeases } from '../sim/dhcp';
import { syslogFlush } from '../sim/syslog';
import { nfsSync } from '../sim/nfs';
import { canAccess, listDir, mergeWorld, normalizePath } from '../fs';
import { endSession } from '../sim/ssh';
import type { Host, UserAccount, World } from '../types';
import { bootHost } from '../sim/services';
import { isWindows } from '../win/model';
import { newSession, renderOutput, runLine, type PsCtx } from '../win/ps';
import { FILE_COMMANDS, getFile, resolvePath, writeChecked } from './cmdFiles';
import { NET_COMMANDS } from './cmdNet';
import { HTTP_COMMANDS } from './cmdHttp';
import { SYSTEM_COMMANDS } from './cmdSystem';
import { KRB_COMMANDS } from './cmdKrb';
import { RDP_COMMANDS } from './cmdRdp';
import { DOCKER_COMMANDS } from './cmdDocker';
import { NTP_COMMANDS } from './cmdNtp';
import { LOG_COMMANDS } from './cmdLog';
import { NFS_COMMANDS } from './cmdNfs';
import { SMB_COMMANDS } from './cmdSmb';
import { MAIL_COMMANDS } from './cmdMail';
import { PG_COMMANDS, psqlLine, psqlPrompt } from './cmdPg';
import { LINUX_ONLY, PF_COMMANDS, PF_VERSION } from './cmdPf';
import { expandParams, GLOB, parseCommandLine, type Segment } from './tokenize';
import { type CmdCtx, type CmdResult, type CommandDef, type EditorRequest, NeedInput, type SessionFrame } from './types';

export const COMMANDS: Record<string, CommandDef> = Object.fromEntries(
  [...FILE_COMMANDS, ...NET_COMMANDS, ...HTTP_COMMANDS, ...SYSTEM_COMMANDS, ...KRB_COMMANDS, ...RDP_COMMANDS, ...DOCKER_COMMANDS, ...NTP_COMMANDS, ...LOG_COMMANDS, ...NFS_COMMANDS, ...SMB_COMMANDS, ...MAIL_COMMANDS, ...PG_COMMANDS, ...BACKUP_COMMANDS, ...RESTIC_COMMANDS, ...MON_COMMANDS, ...LDAP_COMMANDS, ...RADIUS_COMMANDS].map((c) => [c.name, c]),
);

export interface ExecResult {
  output: string;
  code: number;
  needInput?: { text: string; secret: boolean; partial: string };
  editor?: EditorRequest;
  clear?: boolean;
  /** The command line that was executed, with commands recognised (for evidence logging). */
  commands: string[];
  /** Per-line styling when it differs by line (PowerShell error records and warnings). */
  lineKinds?: ('out' | 'err' | 'warn')[];
}

export interface CommandLogEntry {
  time: number;
  host: string;
  user: string;
  line: string;
  code: number;
}

export class Shell {
  frames: SessionFrame[];
  readonly log: CommandLogEntry[] = [];
  /** Exit status of the last command line ($?). */
  private status = 0;

  constructor(
    private getWorld: () => World,
    private commit: (w: World) => void,
    initial: SessionFrame,
    private onCommand?: (e: CommandLogEntry) => void,
  ) {
    this.frames = [initial];
  }

  get frame(): SessionFrame {
    return this.frames[this.frames.length - 1];
  }

  prompt(): string {
    const w = this.getWorld();
    const f = this.frame;
    const host = w.hosts[f.hostId];
    if (isWindows(host)) return `PS ${f.ps?.cwd ?? host.users[f.user]?.home ?? 'C:\\'}> `;
    if (host.kind === 'pfsense') return `[${PF_VERSION}][${f.user}@${host.hostname}.${host.domain}]${f.cwd}: `;
    if (f.psql) return psqlPrompt(w, f.psql);
    const u = host.users[f.user];
    const cwd = u && (f.cwd === u.home || f.cwd.startsWith(u.home + '/')) ? '~' + f.cwd.slice(u.home.length) : f.cwd;
    return `${f.user}@${host.hostname}:${cwd}${f.user === 'root' ? '#' : '$'} `;
  }

  /** Execute a line. `answers` are replies to prompts raised by earlier attempts of the same line. */
  execute(line: string, answers: string[] = []): ExecResult {
    if (isWindows(this.getWorld().hosts[this.frame.hostId])) return this.executePs(line, answers);
    const world = structuredClone(this.getWorld());
    // DHCP clients renew, rebind or lose their leases as simulated time passes.
    maintainLeases(world);
    // rsyslog forwards in the background: what earlier commands logged reaches the log server now.
    syslogFlush(world);
    nfsSync(world, 'before');
    // systemd timers whose time has come start their services (backups at night, after a reboot …).
    runDueTimers(world);
    const frames: SessionFrame[] = structuredClone(this.frames);
    const queue = [...answers];
    const executed: string[] = [];
    let editor: EditorRequest | undefined;
    let clear = false;
    // sshpass: password prompts are answered from its -p/-f/-e value instead of the terminal.
    let sshpass: { password: string; prompts: string[] } | null = null;
    const ask = (text: string, secret: boolean, partial = '') => {
      if (sshpass && secret && /password: ?$/i.test(text)) { sshpass.prompts.push(text); return sshpass.password; }
      if (queue.length === 0) throw new NeedInput(text, secret, partial);
      return queue.shift()!;
    };

    const runIn = (frame: SessionFrame, cmdLine: string, stdin?: string, lastStatus = 0): CmdResult => {
      let list;
      try {
        list = parseCommandLine(cmdLine);
      } catch (e) {
        return { out: `-bash: ${(e as Error).message}`, code: 2 };
      }
      const outputs: string[] = [];
      let code = lastStatus;
      let skip = false;
      for (const item of list) {
        if (!skip) {
          let input = stdin;
          let segOut = '';
          const status = code;
          for (const raw of item.pipeline) {
            const seg = expandSegment(frame, raw, status);
            if (seg.stdinFile) {
              const h = world.hosts[frame.hostId];
              const f = getFile(makeCtx(frame, undefined), normalizePath(seg.stdinFile, frame.cwd, h.users[frame.user].home));
              if (f.error) { segOut = `-bash: ${seg.stdinFile}: ${f.error}`; code = 1; break; }
              input = f.content;
            }
            // Like bash, open (and truncate) the redirect target before the command runs:
            // "cat a b > a" reads an already empty a.
            let redirectPath: string | undefined;
            if (seg.redirect) {
              const host = world.hosts[frame.hostId];
              redirectPath = normalizePath(seg.redirect.file, frame.cwd, host.users[frame.user].home);
              const e = writeChecked(makeCtx(frame, undefined), redirectPath, '', true);
              const trunc = e ?? (seg.redirect.append ? null : writeChecked(makeCtx(frame, undefined), redirectPath, ''));
              if (trunc) { segOut = `-bash: ${seg.redirect.file}: ${trunc}`; code = 1; input = ''; continue; }
            }
            const r = runArgv(frame, seg.argv, input);
            if (seg.redirect && redirectPath) {
              const e = writeChecked(makeCtx(frame, undefined), redirectPath, r.out ? r.out + '\n' : '', true);
              segOut = e ? `-bash: ${seg.redirect.file}: ${e}` : '';
              code = e ? 1 : r.code;
            } else {
              segOut = r.out;
              code = r.code;
            }
            input = r.out;
            if (r.editor) editor = r.editor;
            if (r.clear) clear = true;
          }
          if (segOut) outputs.push(segOut);
        }
        if (item.op === '&&') skip = code !== 0;
        else if (item.op === '||') skip = code === 0;
        else skip = false;
      }
      return { out: outputs.join('\n'), code };
    };

    // Like bash: an unquoted expansion that is empty disappears from the argument list.
    const expandSegment = (frame: SessionFrame, seg: Segment, status: number): Segment => {
      const host = world.hosts[frame.hostId];
      const user = host.users[frame.user];
      const lookup = (n: string): string => {
        switch (n) {
          case '?': return String(status);
          case '#': return String(frame.args?.length ?? 0);
          case '@': case '*': return (frame.args ?? []).join(' ');
          case 'HOME': return user?.home ?? '/';
          case 'USER': case 'LOGNAME': return frame.user;
          case 'HOSTNAME': return host.hostname;
          case 'PWD': return frame.cwd;
          case 'SHELL': return user?.shell ?? '/bin/bash';
          case 'UID': return String(user?.uid ?? 0);
          case 'PATH': return user?.uid === 0 ? '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' : '/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games';
          default: return /^[0-9]+$/.test(n) ? (n === '0' ? frame.argv0 ?? '-bash' : frame.args?.[Number(n) - 1] ?? '') : frame.vars?.[n] ?? frame.env?.[n] ?? '';
        }
      };
      const argv = seg.argv.flatMap((a) => {
        const v = expandParams(a, lookup);
        if (v === '' && a !== '' && /^(\u0001[^\u0002]*\u0002)+$/.test(a)) return [];
        return v.includes(GLOB) ? expandGlob(host, user, frame.cwd, v) : [v];
      });
      return {
        argv: argv.length ? argv : [''],
        redirect: seg.redirect && { ...seg.redirect, file: expandParams(seg.redirect.file, lookup).split(GLOB).join('') },
        stdinFile: seg.stdinFile && expandParams(seg.stdinFile, lookup).split(GLOB).join(''),
      };
    };

    const makeCtx = (frame: SessionFrame, stdin: string | undefined): CmdCtx => {
      const host = world.hosts[frame.hostId];
      return {
        world,
        host,
        user: host.users[frame.user],
        frame,
        stdin,
        ask,
        env: { ...(frame.env ?? {}) },
        run: (l, asUser, s, opts) => {
          if (!asUser) return runIn(frame, l, s);
          const [hostId, user] = asUser.split(':');
          const h = world.hosts[hostId];
          const home = h.users[user].home;
          const env = { ...(opts?.env ?? {}) };
          return runIn({ hostId, user, cwd: opts?.cwd ?? (h.fs[home] ? home : '/'), env, vars: { ...env } }, l, s);
        },
      };
    };

    /** A script or `bash -c` runs in a child shell: it inherits the exported variables, and its cd and assignments do not leak back. */
    const childFrame = (frame: SessionFrame): SessionFrame => ({ hostId: frame.hostId, user: frame.user, cwd: frame.cwd, sudoOk: frame.sudoOk, env: { ...(frame.env ?? {}) }, vars: { ...(frame.env ?? {}) } });

    /** KEY=VALUE lines of an environment file (systemd EnvironmentFile=, or a sourced file): "export " and quotes are accepted. */
    const ASSIGN = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;

    let scriptDepth = 0;
    /** Run a shell script line by line (set -e stops at the first failing line; exit N ends it). */
    const runScriptFile = (frame: SessionFrame, path: string, stdin: string | undefined, needExec: boolean, source = false, scriptArgs: string[] = []): CmdResult => {
      const host = world.hosts[frame.hostId];
      const p = normalizePath(path, frame.cwd, host.users[frame.user].home);
      const node = host.fs[p];
      const shown = path;
      if (!node) return { out: `-bash: ${shown}: No such file or directory`, code: 127 };
      if (node.type === 'dir') return { out: `-bash: ${shown}: Is a directory`, code: 126 };
      const ctx = makeCtx(frame, undefined);
      const f = getFile(ctx, p);
      if (f.error) return { out: `-bash: ${shown}: ${f.error}`, code: 126 };
      if (needExec && !canAccess(node, host.users[frame.user], 'x')) return { out: `-bash: ${shown}: Permission denied`, code: 126 };
      if (scriptDepth > 8) return { out: `-bash: ${shown}: too many nested scripts`, code: 1 };
      scriptDepth++;
      const out: string[] = [];
      let code = 0;
      let errexit = false;
      // `source FILE` runs in this shell; an executed script runs in a child shell.
      const sub = source ? frame : childFrame(frame);
      const savedArgs = sub.args;
      if (!source || scriptArgs.length) sub.args = scriptArgs;
      if (!source) sub.argv0 = path;
      try {
        for (const raw of f.content!.split('\n')) {
          const line = raw.trim();
          if (!line || line.startsWith('#')) continue;
          // errexit is the runner's job; the rest of the line (allexport …) goes to the set builtin.
          if (/^set\s+(-[a-z]*e[a-z]*|-o\s+errexit)(\s|$)/.test(line)) errexit = true;
          const ex = /^exit(?:\s+(\d+))?$/.exec(line);
          if (ex) { code = Number(ex[1] ?? code); break; }
          const r = runIn(sub, line, stdin);
          if (r.out) out.push(r.out);
          code = r.code;
          if (errexit && code !== 0) break;
        }
      } finally {
        scriptDepth--;
        if (source) sub.args = savedArgs;
      }
      return { out: out.join('\n'), code };
    };

    const runArgv = (frame: SessionFrame, argv: string[], stdin: string | undefined): CmdResult => {
      // VAR=value [VAR2=value] [command ...]: alone they set shell variables; before a command they are its environment only.
      let nAssign = 0;
      while (nAssign < argv.length && ASSIGN.test(argv[nAssign])) nAssign++;
      if (nAssign > 0) {
        const pairs = argv.slice(0, nAssign).map((a) => { const m = ASSIGN.exec(a)!; return [m[1], m[2]] as [string, string]; });
        if (nAssign === argv.length) {
          executed.push(argv.join(' '));
          for (const [n, v] of pairs) {
            (frame.vars ??= {})[n] = v;
            if ((frame.env && n in frame.env) || frame.allexport) (frame.env ??= {})[n] = v;
          }
          return { out: '', code: 0 };
        }
        const withEnv: SessionFrame = { ...frame, env: { ...(frame.env ?? {}), ...Object.fromEntries(pairs) } };
        const r = runArgv(withEnv, argv.slice(nAssign), stdin);
        frame.cwd = withEnv.cwd;
        return r;
      }
      const [name, ...args] = argv;
      executed.push(argv.join(' '));
      world.clock += 400; // typing/processing time between commands
      const host = world.hosts[frame.hostId];
      const baseEnv = (): Record<string, string> => {
        const u = host.users[frame.user];
        return { HOME: u?.home ?? '/', LOGNAME: frame.user, USER: frame.user, SHELL: u?.shell ?? '/bin/bash', PWD: frame.cwd, LANG: 'C.UTF-8', PATH: u?.uid === 0 ? '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' : '/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games' };
      };
      switch (name) {
        case 'export': {
          if (args.length === 0 || args[0] === '-p') {
            const env = frame.env ?? {};
            return { out: Object.keys(env).sort().map((k) => `declare -x ${k}="${env[k].replace(/(["\\$`])/g, '\\$1')}"`).join('\n'), code: 0 };
          }
          const bad: string[] = [];
          for (const a of args) {
            const m = ASSIGN.exec(a);
            if (m) { (frame.vars ??= {})[m[1]] = m[2]; (frame.env ??= {})[m[1]] = m[2]; }
            else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(a)) (frame.env ??= {})[a] = frame.vars?.[a] ?? '';
            else bad.push(`-bash: export: \`${a}': not a valid identifier`);
          }
          return { out: bad.join('\n'), code: bad.length ? 1 : 0 };
        }
        case 'set': {
          if (!args.length) {
            const vars = { ...baseEnv(), ...(frame.env ?? {}), ...(frame.vars ?? {}) };
            return { out: Object.keys(vars).sort().map((k) => `${k}=${/^[\w./:@%+,=-]*$/.test(vars[k]) ? vars[k] : `'${vars[k]}'`}`).join('\n'), code: 0 };
          }
          const OPTIONS = new Set(['allexport', 'errexit', 'nounset', 'pipefail', 'xtrace', 'noclobber', 'noglob', 'verbose', 'errtrace', 'functrace', 'noexec', 'posix']);
          for (let i = 0; i < args.length; i++) {
            const a = args[i];
            if (a === '--' || a === '-') break;
            if (a === '-o' || a === '+o') {
              const opt = args[++i];
              if (opt === undefined) return { out: '', code: 0 };
              if (!OPTIONS.has(opt)) return { out: `-bash: set: ${opt}: invalid option name`, code: 1 };
              if (opt === 'allexport') frame.allexport = a === '-o';
            } else if (/^[-+][abefhkmnoptuvxBCEHPT]+$/.test(a)) {
              if (a.includes('a')) frame.allexport = a.startsWith('-');
              if (a.endsWith('o') && args[i + 1] !== undefined) {
                const opt = args[++i];
                if (!OPTIONS.has(opt)) return { out: `-bash: set: ${opt}: invalid option name`, code: 1 };
                if (opt === 'allexport') frame.allexport = a.startsWith('-');
              }
            } else return { out: `-bash: set: ${a}: invalid option\nset: usage: set [-abefhkmnptuvxBCEHPT] [-o option-name] [--] [-] [arg ...]`, code: 2 };
          }
          return { out: '', code: 0 };
        }
        case 'unset':
          for (const a of args.filter((x) => !x.startsWith('-'))) { delete frame.vars?.[a]; delete frame.env?.[a]; }
          return { out: '', code: 0 };
        case 'env':
        case 'printenv': {
          if (name === 'env' && args.length) {
            const k = args.findIndex((a) => !ASSIGN.test(a));
            if (k >= 0) return runArgv({ ...frame, env: { ...(frame.env ?? {}), ...Object.fromEntries(args.slice(0, k).map((a) => { const m = ASSIGN.exec(a)!; return [m[1], m[2]]; })) } }, args.slice(k), stdin);
          }
          const env = { ...baseEnv(), ...(frame.env ?? {}) };
          if (name === 'printenv' && args.length) {
            const vals = args.filter((a) => a in env).map((a) => env[a]);
            return { out: vals.join('\n'), code: vals.length === args.length ? 0 : 1 };
          }
          return { out: Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n'), code: 0 };
        }
        case 'source':
        case '.':
          if (!args[0]) return { out: `-bash: ${name}: filename argument required\n${name}: usage: ${name} filename [arguments]`, code: 2 };
          return runScriptFile(frame, args[0], stdin, false, true, args.slice(1));
        case 'exit':
        case 'logout': {
          const top = frames[frames.length - 1];
          if (frame === top && top.su && frames.length > 1) {
            frames.pop();
            return { out: 'logout', code: Number(args[0] ?? 0) || 0 };
          }
          if (frame !== top || !top.ssh) {
            return { out: `${name}: this is the ${host.hostname} ${frames.length === 1 ? 'console' : 'shell'}; close the terminal tab instead`, code: 1 };
          }
          frames.pop();
          endSession(world, top.ssh);
          world.sessions = (world.sessions ?? []).filter((s) => !(s.serverHostId === top.ssh!.hostId && s.clientPort === top.ssh!.fromPort));
          return { out: `logout\nConnection to ${top.ssh.target} closed.`, code: 0 };
        }
        case 'clear':
          return { out: '', code: 0, clear: true };
        case 'true':
          return { out: '', code: 0 };
        case 'false':
          return { out: '', code: 1 };
        case 'help':
          return { out: helpText(), code: 0 };
        case 'which':
        case 'type': {
          const c = args[0];
          return COMMANDS[c] ? { out: `/usr/bin/${c}`, code: 0 } : { out: '', code: 1 };
        }
        case 'sudo': {
          const user = host.users[frame.user];
          let rest = args;
          let target = 'root';
          let login = false;
          while (rest[0]?.startsWith('-')) {
            const f = rest[0];
            rest = rest.slice(1);
            if (f === '--') break;
            if (f.startsWith('--')) {
              const [name, val] = f.split(/=(.*)/s);
              if (name === '--user') { target = val ?? rest[0] ?? ''; if (val === undefined) rest = rest.slice(1); }
              else if (name === '--login') login = true;
              continue;
            }
            for (let k = 1; k < f.length; k++) {
              if (f[k] === 'u') { target = f.slice(k + 1) || rest[0] || ''; if (!f.slice(k + 1)) rest = rest.slice(1); break; }
              if (f[k] === 'i') login = true;
            }
          }
          if (!host.users[target]) return { out: `sudo: unknown user ${target}`, code: 1 };
          if (rest.length === 0 && !login) return { out: 'usage: sudo -h | -K | -k | -V\nusage: sudo [-u user] command', code: 1 };
          if (user.uid !== 0) {
            if (!user.groups.includes('sudo')) return { out: `${user.name} is not in the sudoers file.`, code: 1 };
            if (!frame.sudoOk) {
              let okPw = false;
              for (let i = 0; i < 3 && !okPw; i++) {
                const pw = ask(`[sudo] password for ${user.name}: `, true);
                okPw = pw === user.password;
                if (!okPw && i < 2) executed.push('# sudo: Sorry, try again.');
              }
              if (!okPw) return { out: `sudo: 3 incorrect password attempts`, code: 1 };
              frame.sudoOk = true;
            }
          }
          const tu = host.users[target];
          if (rest.length === 0) {
            // sudo -i [-u USER]: a login shell as that user; exit returns here.
            frames.push({ hostId: frame.hostId, user: target, cwd: host.fs[tu.home] ? tu.home : '/', su: true });
            return { out: '', code: 0 };
          }
          // Debian's sudoers has env_reset: the command does not see the caller's exported variables (sudo VAR=value cmd sets them).
          const rootFrame: SessionFrame = { ...frame, user: target, cwd: login && host.fs[tu.home] ? tu.home : frame.cwd, env: {}, vars: {} };
          const r = runArgv(rootFrame, rest, stdin);
          if (target === 'root') frame.cwd = rootFrame.cwd;
          return r;
        }
        case 'su': {
          // su [-] [USER] [-c COMMAND]
          let rest = args;
          let command: string | undefined;
          let login = false;
          const names: string[] = [];
          for (let k = 0; k < rest.length; k++) {
            const a = rest[k];
            if (a === '-' || a === '-l' || a === '--login') login = true;
            else if (a === '-c' || a === '--command') command = rest[++k];
            else names.push(a);
          }
          rest = [];
          const target = names[0] ?? 'root';
          const tu = host.users[target];
          if (!tu) return { out: `su: user ${target} does not exist or the user entry does not contain all the required fields`, code: 1 };
          if (host.users[frame.user].uid !== 0) {
            const pw = ask('Password: ', true);
            if (!tu.password || pw !== tu.password) return { out: 'su: Authentication failure', code: 1 };
          }
          if (/nologin|false$/.test(tu.shell)) return { out: 'This account is currently not available.', code: 1 };
          const cwd = login && host.fs[tu.home] ? tu.home : frame.cwd;
          if (command !== undefined) return runIn({ hostId: frame.hostId, user: target, cwd }, command, stdin);
          frames.push({ hostId: frame.hostId, user: target, cwd, su: true });
          return { out: '', code: 0 };
        }
        case 'sshpass': {
          // sshpass -p PASS | -f FILE | -e (SSHPASS) command …: answers the password prompt; a second prompt means a wrong password (exit 5).
          let password: string | undefined;
          let i = 0;
          for (; i < args.length && args[i].startsWith('-'); i++) {
            const a = args[i];
            if (a === '-p' || a.startsWith('-p') ) { password = a.length > 2 ? a.slice(2) : args[++i]; continue; }
            if (a === '-e') { password = frame.env?.SSHPASS ?? frame.vars?.SSHPASS; if (password === undefined) return { out: 'sshpass: -e option given but SSHPASS environment variable not set', code: 3 }; continue; }
            if (a === '-f' || a.startsWith('-f')) {
              const file = a.length > 2 ? a.slice(2) : args[++i] ?? '';
              const f = getFile(makeCtx(frame, undefined), normalizePath(file, frame.cwd, host.users[frame.user].home));
              if (f.error) return { out: `sshpass: Failed to open password file "${file}": ${f.error}`, code: 3 };
              password = (f.content ?? '').split('\n')[0];
              continue;
            }
            if (a === '-v') continue;
            return { out: `sshpass: invalid option -- '${a.replace(/^-/, '')}'\nUsage: sshpass [-f|-d|-p|-e[env_var]] [-hV] command parameters`, code: 2 };
          }
          if (!args[i]) return { out: 'Usage: sshpass [-f|-d|-p|-e[env_var]] [-hV] command parameters', code: 2 };
          const prev = sshpass;
          sshpass = { password: password ?? '', prompts: [] };
          const used = sshpass;
          try {
            // sshpass gives up when it sees a second password prompt (exit 5): ssh gets one try.
            const argv = args.slice(i);
            const cmd = argv[0] === 'ssh' ? ['ssh', '-o', 'NumberOfPasswordPrompts=1', ...argv.slice(1)] : argv;
            const r = runArgv(frame, cmd, stdin);
            const refused = used.prompts.length > 0 && r.code === 255 && /Permission denied \(/.test(r.out);
            if (refused) return { out: '', code: 5 };
            // sshpass hides the prompts it answered (and only those).
            const lines = r.out.split('\n');
            for (const p of used.prompts) {
              const k = lines.indexOf(p);
              if (k >= 0) lines.splice(k, 1);
            }
            return { out: lines.join('\n'), code: r.code };
          } finally {
            sshpass = prev;
          }
        }
        case 'sh':
        case 'bash': {
          if (!args[0] || args[0] === '-c') return args[0] === '-c' ? runIn(childFrame(frame), args[1] ?? '', stdin) : { out: '', code: 0 };
          return runScriptFile(frame, args[0], stdin, false, false, args.slice(1));
        }
        default: {
          // pfSense: FreeBSD tools and pfSense scripts first; Linux tools do not exist (tcsh wording).
          const pf = host.kind === 'pfsense';
          if (pf && (LINUX_ONLY.has(name) || (!PF_COMMANDS[name] && !COMMANDS[name]))) return { out: `${name}: Command not found.`, code: 1 };
          const def = (pf ? PF_COMMANDS[name] : undefined) ?? COMMANDS[name];
          if (!def) {
            // A program given by path (./backup.sh), or a script installed in a PATH directory.
            if (!pf && name.includes('/')) return runScriptFile(frame, name, stdin, true, false, args);
            const u = host.users[frame.user];
            const dirs = u?.uid === 0 ? ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin'] : ['/usr/local/bin', '/usr/bin'];
            const found = !pf && dirs.map((d) => `${d}/${name}`).find((p) => host.fs[p]?.type === 'file');
            if (found) return runScriptFile(frame, found, stdin, true, false, args);
            return { out: `-bash: ${name}: command not found`, code: 127 };
          }
          const r = def.run(args, makeCtx(frame, stdin));
          if (r.enterSession) {
            frames.push(r.enterSession);
            const s = r.enterSession.ssh;
            if (s) {
              const server = world.hosts[s.hostId];
              world.sessions = [...(world.sessions ?? []), {
                clientHostId: s.clientHostId, serverHostId: s.hostId, clientIp: s.fromIp, clientPort: s.fromPort,
                serverIp: server.ifaces.find((i) => i.address && i.name !== 'lo')?.address ?? '', serverPort: 22, user: s.user, pid: s.pid,
              }];
            }
          }
          if (name === 'reboot' || (name === 'systemctl' && args[0] === 'reboot')) {
            // Any ssh session into the rebooted host is torn down.
            const idx = frames.findIndex((f, i) => i > 0 && f.hostId === frame.hostId && f.ssh);
            if (idx > 0) {
              const target = frames[idx].ssh!.target;
              frames.splice(idx);
              return { out: `${r.out}\nConnection to ${target} closed by remote host.\nConnection to ${target} closed.`, code: 255 };
            }
          }
          return r;
        }
      }
    };

    let result: CmdResult;
    try {
      const top = frames[frames.length - 1];
      if (top.psql) {
        executed.push(line);
        world.clock += 400;
        const r = psqlLine(makeCtx(top, undefined), top.psql, line);
        if (r.quit) frames.pop();
        result = { out: r.out, code: r.code };
      } else result = runIn(top, line, undefined, this.status);
    } catch (e) {
      if (e instanceof NeedInput) {
        return { output: '', code: -1, needInput: { text: e.text, secret: e.secret, partial: e.partial }, commands: executed };
      }
      throw e;
    }
    this.frames = frames;
    this.status = result.code;
    // NFS clients write their changes through to the server.
    nfsSync(world, 'after');
    this.commit(world);
    const entry: CommandLogEntry = { time: world.clock, host: frames[frames.length - 1].hostId, user: this.frame.user, line, code: result.code };
    this.log.push(entry);
    this.onCommand?.(entry);
    return { output: result.out, code: result.code, editor, clear, commands: executed };
  }

  /** A Windows host's console runs Windows PowerShell 5.1 instead of bash. */
  private executePs(line: string, answers: string[]): ExecResult {
    const world = structuredClone(this.getWorld());
    maintainLeases(world);
    // rsyslog forwards in the background: what earlier commands logged reaches the log server now.
    syslogFlush(world);
    const frames: SessionFrame[] = structuredClone(this.frames);
    const frame = frames[frames.length - 1];
    const host = world.hosts[frame.hostId];
    const user = host.users[frame.user];
    const session = (frame.ps ??= newSession(frame.cwd.startsWith('/') ? user.home : frame.cwd));
    const queue = [...answers];
    const ctx: PsCtx = {
      world, host, user, session, line, out: [],
      ask: (text, secret) => {
        if (queue.length === 0) throw new NeedInput(text, secret, renderOutput(ctx));
        return queue.shift()!;
      },
    };
    world.clock += 400;
    try {
      if (line.trim()) runLine(ctx, line);
    } catch (e) {
      if (e instanceof NeedInput) return { output: '', code: -1, needInput: { text: e.text, secret: e.secret, partial: e.partial }, commands: [line] };
      throw e;
    }
    let output = renderOutput(ctx);
    if (line.trim()) session.history.push(line);
    if (ctx.exit) output = [output, `exit: this is the ${host.hostname.toUpperCase()} console; close the terminal tab instead`].filter(Boolean).join('\n');
    if (ctx.reboot) {
      bootHost(world, host);
      frame.ps = newSession(user.home);
      output = [output, `[Cyber Owl Lab: ${host.hostname.toUpperCase()} restarted; you are signed in at the console again.]`].filter(Boolean).join('\n');
    }
    frame.cwd = frame.ps.cwd;
    const code = session.lastOk ? 0 : 1;
    this.frames = frames;
    this.status = code;
    this.commit(world);
    const entry: CommandLogEntry = { time: world.clock, host: frame.hostId, user: frame.user, line, code };
    this.log.push(entry);
    this.onCommand?.(entry);
    return { output, code, clear: ctx.clear, commands: line.trim() ? [line] : [], lineKinds: psLineKinds(output) };
  }

  /** Save the in-app editor buffer back into the simulated filesystem. */
  saveFile(req: EditorRequest, content: string): string | null {
    const world = structuredClone(this.getWorld());
    const frame = this.frames.find((f) => f.hostId === req.hostId) ?? this.frame;
    const host = world.hosts[req.hostId];
    const ctx: CmdCtx = {
      world, host, user: host.users[req.user] ?? host.users[frame.user], frame,
      ask: () => '',
      run: () => ({ out: '', code: 0 }),
      env: {},
    };
    const e = writeChecked(ctx, req.path, content);
    if (e) return e;
    this.commit(world);
    return null;
  }
}

/** Error records (from "<cmd> : message" or "At line:" to the closing " " line) are red, warnings yellow. */
function psLineKinds(output: string): ('out' | 'err' | 'warn')[] {
  const lines = output.split('\n');
  const kinds: ('out' | 'err' | 'warn')[] = [];
  let inErr = false;
  lines.forEach((l, i) => {
    if (!inErr && (/^At line:\d+ char:\d+$/.test(l) || (/ : /.test(l) && /^At line:\d+ char:\d+$/.test(lines[i + 1] ?? '')))) inErr = true;
    if (inErr) {
      kinds.push('err');
      if (l === ' ') inErr = false;
    } else kinds.push(/^WARNING: /.test(l) ? 'warn' : 'out');
  });
  return kinds;
}

function helpText(): string {
  const names = Object.keys(COMMANDS).sort();
  return [
    'Cyber Owl Lab simulated shell (GNU bash-compatible subset).',
    'Pipes (|), redirection (> and >>), && / || / ; and sudo are supported.',
    'Commands available in this simulation:',
    '',
    ...names.map((n) => `  ${n.padEnd(16)} ${COMMANDS[n].summary}`),
    '  sudo             run a command as root (asks for your password)',
    '  exit / logout    close an ssh session',
    '',
    'Use "<command> --help"-style usage lines from the Command Reference panel.',
  ].join('\n');
}

export { resolvePath };

/**
 * Pathname expansion of one word (bash): unquoted * ? [...] match directory entries segment by
 * segment; hidden names only when the pattern segment starts with "."; no match leaves the word as typed.
 */
function expandGlob(host: Host, user: UserAccount | undefined, cwd: string, word: string): string[] {
  const literal = word.split(GLOB).join('');
  if (!user) return [literal];
  const abs = literal.startsWith('/');
  const parts = word.split('/');
  let results: string[] = [abs ? '' : '.'];
  for (let i = abs ? 1 : 0; i < parts.length; i++) {
    const seg = parts[i];
    if (seg === '') continue;
    const next: string[] = [];
    for (const base of results) {
      const dirPath = base === '.' ? cwd : base === '' ? '/' : normalizePath(base, cwd, user.home);
      if (!seg.includes(GLOB)) { next.push(base === '.' ? seg : `${base}/${seg}`); continue; }
      const dir = host.fs[dirPath];
      if (!dir || dir.type !== 'dir' || !canAccess(dir, user, 'r')) continue;
      const pat = seg.split(GLOB).join('');
      let re: RegExp;
      try {
        re = new RegExp('^' + seg.replace(/[.+^${}()|\\]/g, '\\$&').replace(new RegExp(`${GLOB}\\*`, 'g'), '.*').replace(new RegExp(`${GLOB}\\?`, 'g'), '.').replace(new RegExp(`${GLOB}\\[!`, 'g'), '[^').replace(new RegExp(GLOB, 'g'), '') + '$');
      } catch { return [literal]; }
      for (const name of listDir(host, dirPath).map((p) => p.split('/').pop()!).sort()) {
        if (name.startsWith('.') && !pat.startsWith('.')) continue;
        if (re.test(name)) next.push(base === '.' ? name : `${base}/${name}`);
      }
    }
    results = next;
    if (!results.length) return [literal];
  }
  const out = results.filter((r) => host.fs[normalizePath(r, cwd, user.home)]);
  return out.length ? out : [literal];
}

// systemd units run their Exec lines through this shell, as User= in a fresh session with the unit's environment.
const SYSTEM_PATH = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'];
setUnitRunner({
  run(world, hostId, user, line, env, cwd) {
    let w = world;
    const sh = new Shell(() => w, (n) => (w = n), { hostId, user, cwd, env: { ...env }, vars: { ...env } });
    const r = sh.execute(line);
    // Merge back in place: callers hold references to the World's host objects.
    mergeWorld(world, w);
    if (r.needInput) return { out: `${r.output ? r.output + '\n' : ''}${r.needInput.text.trim()} (no terminal: cannot read a password)`, code: 1 };
    return { out: r.output, code: r.code };
  },
  resolve(host, program) {
    if (program.includes('/')) {
      const node = host.fs[program];
      if (node?.type === 'file') return (node.mode & 0o111) ? { path: program } : { error: 'Permission denied' };
      if (COMMANDS[program.split('/').pop()!] && SYSTEM_PATH.some((d) => program === `${d}/${program.split('/').pop()}`)) return { path: program };
      return { error: 'No such file or directory' };
    }
    const found = SYSTEM_PATH.map((d) => `${d}/${program}`).find((p) => host.fs[p]?.type === 'file');
    if (found) return { path: found };
    if (COMMANDS[program]) return { path: `/usr/bin/${program}` };
    return { error: 'No such file or directory' };
  },
});
