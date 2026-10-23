import type { Host, UserAccount, World } from '../types';
import type { PsSession } from '../win/ps/runtime';

export class NeedInput {
  /** `partial` is output produced before the question (shown above the prompt). */
  constructor(public text: string, public secret: boolean, public partial = '') {}
}

export interface SessionFrame {
  hostId: string;
  user: string;
  cwd: string;
  /** Present when this frame was entered via ssh (so `exit` closes the session). */
  ssh?: { hostId: string; user: string; fromIp: string; fromPort: number; pid: number; clientHostId: string; target: string };
  sudoOk?: boolean;
  /** PowerShell session state (variables, location, history) on a Windows host. */
  ps?: PsSession;
}

export interface EditorRequest {
  hostId: string;
  /** User whose permissions apply when saving (root when opened through sudo). */
  user: string;
  path: string;
  content: string;
  readOnly: boolean;
  isNew: boolean;
}

export interface CmdResult {
  out: string;
  code: number;
  editor?: EditorRequest;
  enterSession?: SessionFrame;
  exitSession?: boolean;
  clear?: boolean;
}

export interface CmdCtx {
  world: World;
  host: Host;
  user: UserAccount;
  frame: SessionFrame;
  /** Ask the learner for input. Throws NeedInput when no answer is queued yet. */
  ask(text: string, secret: boolean, partial?: string): string;
  /** Run a command line as `hostId:user` (used by ssh remote commands). */
  run(line: string, asUser?: string, stdin?: string): CmdResult;
  stdin?: string;
}

export interface CommandDef {
  name: string;
  summary: string;
  usage: string;
  run(args: string[], ctx: CmdCtx): CmdResult;
}

export const ok = (out: string, code = 0): CmdResult => ({ out, code });
export const err = (out: string, code = 1): CmdResult => ({ out, code });

/** Minimal getopt: splits flags (clustered short flags allowed) from positional args. */
export function parseFlags(args: string[], withValue: string[] = []): { flags: Map<string, string | true>; rest: string[] } {
  const flags = new Map<string, string | true>();
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { rest.push(...args.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=');
      if (v !== undefined) flags.set('--' + k, v);
      else if (withValue.includes('--' + k)) flags.set('--' + k, args[++i] ?? '');
      else flags.set('--' + k, true);
    } else if (a.startsWith('-') && a.length > 1 && (!/^-\d+$/.test(a) || a === '-4' || a === '-6')) {
      const chars = a.slice(1);
      for (let j = 0; j < chars.length; j++) {
        const f = '-' + chars[j];
        if (withValue.includes(f)) {
          const v = chars.slice(j + 1) || args[++i] || '';
          flags.set(f, v);
          break;
        }
        flags.set(f, true);
      }
    } else rest.push(a);
  }
  return { flags, rest };
}
