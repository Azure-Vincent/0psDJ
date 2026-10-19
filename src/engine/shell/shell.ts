// The simulated bash. Every command line runs against a copy of the world and
// is committed only when it completes, so interactive prompts (ssh host-key
// confirmation, passwords, sudo) can be answered by replaying the line with the
// collected answers. Because the engine is deterministic, the replay produces
// exactly the same intermediate state.

import { normalizePath } from '../fs';
import { endSession } from '../sim/ssh';
import type { World } from '../types';
import { FILE_COMMANDS, resolvePath, writeChecked } from './cmdFiles';
import { NET_COMMANDS } from './cmdNet';
import { SYSTEM_COMMANDS } from './cmdSystem';
import { parseCommandLine } from './tokenize';
import { type CmdCtx, type CmdResult, type CommandDef, type EditorRequest, NeedInput, type SessionFrame } from './types';

export const COMMANDS: Record<string, CommandDef> = Object.fromEntries(
  [...FILE_COMMANDS, ...NET_COMMANDS, ...SYSTEM_COMMANDS].map((c) => [c.name, c]),
);

export interface ExecResult {
  output: string;
  code: number;
  needInput?: { text: string; secret: boolean; partial: string };
  editor?: EditorRequest;
  clear?: boolean;
  /** The command line that was executed, with commands recognised (for evidence logging). */
  commands: string[];
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
    const u = host.users[f.user];
    const cwd = u && (f.cwd === u.home || f.cwd.startsWith(u.home + '/')) ? '~' + f.cwd.slice(u.home.length) : f.cwd;
    return `${f.user}@${host.hostname}:${cwd}${f.user === 'root' ? '#' : '$'} `;
  }

  /** Execute a line. `answers` are replies to prompts raised by earlier attempts of the same line. */
  execute(line: string, answers: string[] = []): ExecResult {
    const world = structuredClone(this.getWorld());
    const frames: SessionFrame[] = structuredClone(this.frames);
    const queue = [...answers];
    const executed: string[] = [];
    let editor: EditorRequest | undefined;
    let clear = false;
    const ask = (text: string, secret: boolean, partial = '') => {
      if (queue.length === 0) throw new NeedInput(text, secret, partial);
      return queue.shift()!;
    };

    const runIn = (frame: SessionFrame, cmdLine: string, stdin?: string): CmdResult => {
      let list;
      try {
        list = parseCommandLine(cmdLine);
      } catch (e) {
        return { out: `-bash: ${(e as Error).message}`, code: 2 };
      }
      const outputs: string[] = [];
      let code = 0;
      let skip = false;
      for (const item of list) {
        if (!skip) {
          let input = stdin;
          let segOut = '';
          for (const seg of item.pipeline) {
            const r = runArgv(frame, seg.argv, input);
            if (seg.redirect) {
              const host = world.hosts[frame.hostId];
              const ctxUser = host.users[frame.user];
              const path = normalizePath(seg.redirect.file, frame.cwd, ctxUser.home);
              const e = writeChecked(makeCtx(frame, undefined), path, r.out ? r.out + '\n' : '', seg.redirect.append);
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

    const runArgv = (frame: SessionFrame, argv: string[], stdin: string | undefined): CmdResult => {
      const [name, ...args] = argv;
      executed.push(argv.join(' '));
      world.clock += 400; // typing/processing time between commands
      const host = world.hosts[frame.hostId];
      switch (name) {
        case 'exit':
        case 'logout': {
          const top = frames[frames.length - 1];
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
          while (rest[0]?.startsWith('-')) rest = rest.slice(1);
          if (rest.length === 0) return { out: 'usage: sudo -h | -K | -k | -V\nusage: sudo [-u user] command', code: 1 };
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
          const rootFrame: SessionFrame = { ...frame, user: 'root' };
          const r = runArgv(rootFrame, rest, stdin);
          frame.cwd = rootFrame.cwd;
          return r;
        }
        default: {
          const def = COMMANDS[name];
          if (!def) return { out: `-bash: ${name}: command not found`, code: 127 };
          const r = def.run(args, makeCtx(frame, stdin));
          if (r.enterSession) {
            frames.push(r.enterSession);
            const s = r.enterSession.ssh!;
            const server = world.hosts[s.hostId];
            world.sessions = [...(world.sessions ?? []), {
              clientHostId: s.clientHostId, serverHostId: s.hostId, clientIp: s.fromIp, clientPort: s.fromPort,
              serverIp: server.ifaces.find((i) => i.address && i.name !== 'lo')?.address ?? '', serverPort: 22, user: s.user, pid: s.pid,
            }];
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
      result = runIn(frames[frames.length - 1], line);
    } catch (e) {
      if (e instanceof NeedInput) {
        return { output: '', code: -1, needInput: { text: e.text, secret: e.secret, partial: e.partial }, commands: executed };
      }
      throw e;
    }
    this.frames = frames;
    this.commit(world);
    const entry: CommandLogEntry = { time: world.clock, host: frames[frames.length - 1].hostId, user: this.frame.user, line, code: result.code };
    this.log.push(entry);
    this.onCommand?.(entry);
    return { output: result.out, code: result.code, editor, clear, commands: executed };
  }

  /** Save the in-app editor buffer back into the simulated filesystem. */
  saveFile(req: EditorRequest, content: string): string | null {
    const world = structuredClone(this.getWorld());
    const frame = this.frames.find((f) => f.hostId === req.hostId) ?? this.frame;
    const host = world.hosts[req.hostId];
    const ctx: CmdCtx = {
      world, host, user: host.users[frame.user], frame,
      ask: () => '',
      run: () => ({ out: '', code: 0 }),
    };
    const e = writeChecked(ctx, req.path, content);
    if (e) return e;
    this.commit(world);
    return null;
  }
}

function helpText(): string {
  const names = Object.keys(COMMANDS).sort();
  return [
    'Infrastructure Lab simulated shell (GNU bash-compatible subset).',
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
