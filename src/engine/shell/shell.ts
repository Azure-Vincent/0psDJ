// The simulated bash. Every command line runs against a copy of the world and
// is committed only when it completes, so interactive prompts (ssh host-key
// confirmation, passwords, sudo) can be answered by replaying the line with the
// collected answers. Because the engine is deterministic, the replay produces
// exactly the same intermediate state.

import { maintainLeases } from '../sim/dhcp';
import { syslogFlush } from '../sim/syslog';
import { nfsSync } from '../sim/nfs';
import { canAccess, normalizePath } from '../fs';
import { endSession } from '../sim/ssh';
import type { World } from '../types';
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
import { expandParams, parseCommandLine, type Segment } from './tokenize';
import { type CmdCtx, type CmdResult, type CommandDef, type EditorRequest, NeedInput, type SessionFrame } from './types';

export const COMMANDS: Record<string, CommandDef> = Object.fromEntries(
  [...FILE_COMMANDS, ...NET_COMMANDS, ...HTTP_COMMANDS, ...SYSTEM_COMMANDS, ...KRB_COMMANDS, ...RDP_COMMANDS, ...DOCKER_COMMANDS, ...NTP_COMMANDS, ...LOG_COMMANDS, ...NFS_COMMANDS, ...SMB_COMMANDS, ...MAIL_COMMANDS, ...PG_COMMANDS].map((c) => [c.name, c]),
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
    const frames: SessionFrame[] = structuredClone(this.frames);
    const queue = [...answers];
    const executed: string[] = [];
    let editor: EditorRequest | undefined;
    let clear = false;
    const ask = (text: string, secret: boolean, partial = '') => {
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
          case 'HOME': return user?.home ?? '/';
          case 'USER': case 'LOGNAME': return frame.user;
          case 'HOSTNAME': return host.hostname;
          case 'PWD': return frame.cwd;
          case 'SHELL': return user?.shell ?? '/bin/bash';
          case 'UID': return String(user?.uid ?? 0);
          case 'PATH': return user?.uid === 0 ? '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' : '/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games';
          default: return '';
        }
      };
      const argv = seg.argv.flatMap((a) => {
        const v = expandParams(a, lookup);
        return v === '' && a !== '' && /^(\u0001[^\u0002]*\u0002)+$/.test(a) ? [] : [v];
      });
      return {
        argv: argv.length ? argv : [''],
        redirect: seg.redirect && { ...seg.redirect, file: expandParams(seg.redirect.file, lookup) },
        stdinFile: seg.stdinFile && expandParams(seg.stdinFile, lookup),
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
        run: (l, asUser, s) => {
          if (!asUser) return runIn(frame, l, s);
          const [hostId, user] = asUser.split(':');
          const h = world.hosts[hostId];
          const home = h.users[user].home;
          return runIn({ hostId, user, cwd: h.fs[home] ? home : '/' }, l, s);
        },
      };
    };

    let scriptDepth = 0;
    /** Run a shell script line by line (set -e stops at the first failing line; exit N ends it). */
    const runScriptFile = (frame: SessionFrame, path: string, stdin: string | undefined, needExec: boolean): CmdResult => {
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
      try {
        for (const raw of f.content!.split('\n')) {
          const line = raw.trim();
          if (!line || line.startsWith('#')) continue;
          if (/^set\s+-[a-z]*e/.test(line)) { errexit = true; continue; }
          const ex = /^exit(?:\s+(\d+))?$/.exec(line);
          if (ex) { code = Number(ex[1] ?? code); break; }
          const r = runIn(frame, line, stdin);
          if (r.out) out.push(r.out);
          code = r.code;
          if (errexit && code !== 0) break;
        }
      } finally {
        scriptDepth--;
      }
      return { out: out.join('\n'), code };
    };

    const runArgv = (frame: SessionFrame, argv: string[], stdin: string | undefined): CmdResult => {
      const [name, ...args] = argv;
      executed.push(argv.join(' '));
      world.clock += 400; // typing/processing time between commands
      const host = world.hosts[frame.hostId];
      switch (name) {
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
          const rootFrame: SessionFrame = { ...frame, user: target, cwd: login && host.fs[tu.home] ? tu.home : frame.cwd };
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
        case 'sh':
        case 'bash': {
          if (!args[0] || args[0] === '-c') return args[0] === '-c' ? runIn(frame, args[1] ?? '', stdin) : { out: '', code: 0 };
          return runScriptFile(frame, args[0], stdin, false);
        }
        default: {
          // pfSense: FreeBSD tools and pfSense scripts first; Linux tools do not exist (tcsh wording).
          const pf = host.kind === 'pfsense';
          if (pf && (LINUX_ONLY.has(name) || (!PF_COMMANDS[name] && !COMMANDS[name]))) return { out: `${name}: Command not found.`, code: 1 };
          const def = (pf ? PF_COMMANDS[name] : undefined) ?? COMMANDS[name];
          if (!def) {
            // A program given by path (./backup.sh), or a script installed in a PATH directory.
            if (!pf && name.includes('/')) return runScriptFile(frame, name, stdin, true);
            const u = host.users[frame.user];
            const dirs = u?.uid === 0 ? ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin'] : ['/usr/local/bin', '/usr/bin'];
            const found = !pf && dirs.map((d) => `${d}/${name}`).find((p) => host.fs[p]?.type === 'file');
            if (found) return runScriptFile(frame, found, stdin, true);
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
