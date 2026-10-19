// File and user commands: ls, cat, head, tail, grep, echo, touch, mkdir, rm,
// chmod, chown, stat, cd, pwd, id, whoami, editors, passwd, usermod.

import { basename, canAccess, canTraverse, dirname, listDir, mkdir, modeString, normalizePath, writeFile } from '../fs';
import { formatSyslogTime } from '../sim/journal';
import type { FileNode, Host } from '../types';
import { type CmdCtx, type CommandDef, err, ok, parseFlags } from './types';

export function resolvePath(ctx: CmdCtx, p: string): string {
  return normalizePath(p, ctx.frame.cwd, ctx.user.home);
}

/** Virtual files generated from structured state. */
export function virtualFile(host: Host, path: string): string | undefined {
  if (path === '/etc/passwd') {
    return Object.values(host.users)
      .sort((a, b) => a.uid - b.uid)
      .map((u) => `${u.name}:x:${u.uid}:${u.gid}:${u.gecos}:${u.home}:${u.shell}`)
      .join('\n') + '\n';
  }
  if (path === '/etc/group') {
    const groups = new Map<string, Set<string>>();
    for (const u of Object.values(host.users)) {
      if (!groups.has(u.primaryGroup)) groups.set(u.primaryGroup, new Set());
      for (const g of u.groups) {
        if (!groups.has(g)) groups.set(g, new Set());
        groups.get(g)!.add(u.name);
      }
    }
    return [...groups.entries()].map(([g, m], i) => `${g}:x:${g === 'root' ? 0 : 1000 + i}:${[...m].join(',')}`).join('\n') + '\n';
  }
  if (path === '/etc/shadow') {
    return Object.values(host.users)
      .map((u) => `${u.name}:${u.password === null ? '!' : '$y$j9T$simulated$hash'}:20015:0:99999:7:::`)
      .join('\n') + '\n';
  }
  if (path === '/proc/sys/net/ipv4/ip_forward') return host.ipForward ? '1\n' : '0\n';
  return undefined;
}

const VIRTUAL_META: Record<string, Partial<FileNode>> = {
  '/etc/passwd': { mode: 0o644 },
  '/etc/group': { mode: 0o644 },
  '/etc/shadow': { mode: 0o640, group: 'shadow' },
  '/proc/sys/net/ipv4/ip_forward': { mode: 0o644 },
};

export function getFile(ctx: CmdCtx, path: string): { node: FileNode | null; content?: string; error?: string } {
  const v = virtualFile(ctx.host, path);
  if (v !== undefined) {
    const node: FileNode = { type: 'file', mode: 0o644, owner: 'root', group: 'root', content: v, mtime: ctx.host.bootTime, ...VIRTUAL_META[path] };
    if (!canAccess(node, ctx.user, 'r')) return { node, error: 'Permission denied' };
    return { node, content: v };
  }
  const node = ctx.host.fs[path];
  if (!node) return { node: null, error: 'No such file or directory' };
  if (!canTraverse(ctx.host, path, ctx.user)) return { node, error: 'Permission denied' };
  if (node.type === 'dir') return { node, error: 'Is a directory' };
  if (!canAccess(node, ctx.user, 'r')) return { node, error: 'Permission denied' };
  return { node, content: node.content };
}

/** Write a file honouring Unix permissions. Returns an error string on failure. */
export function writeChecked(ctx: CmdCtx, path: string, content: string, append = false): string | null {
  const existing = ctx.host.fs[path];
  if (existing?.type === 'dir') return 'Is a directory';
  const parent = ctx.host.fs[dirname(path)];
  if (!parent) return 'No such file or directory';
  if (!canTraverse(ctx.host, path, ctx.user)) return 'Permission denied';
  if (existing) {
    if (!canAccess(existing, ctx.user, 'w')) return 'Permission denied';
  } else if (!canAccess(parent, ctx.user, 'w')) return 'Permission denied';
  const meta = existing ? undefined : { mode: 0o644, owner: ctx.user.name, group: ctx.user.primaryGroup };
  ctx.world.clock += 50;
  writeFile(ctx.host, path, append && existing ? existing.content + content : content, ctx.world.clock, meta);
  return null;
}

function lsLine(name: string, n: FileNode, numeric: boolean, host: Host): string {
  const size = n.type === 'dir' ? 4096 : n.content.length;
  const owner = numeric ? String(host.users[n.owner]?.uid ?? 0) : n.owner;
  const group = numeric ? String(host.users[n.group]?.gid ?? 0) : n.group;
  let mode = modeString(n);
  if (n.mode & 0o1000) mode = mode.slice(0, 9) + (mode[9] === 'x' ? 't' : 'T');
  if (n.mode & 0o2000) mode = mode.slice(0, 6) + (mode[6] === 'x' ? 's' : 'S') + mode.slice(7);
  const time = formatSyslogTime(n.mtime).slice(0, 12);
  return `${mode} ${n.type === 'dir' ? 2 : 1} ${owner.padEnd(6)} ${group.padEnd(6)} ${String(size).padStart(5)} ${time} ${name}`;
}

const ls: CommandDef = {
  name: 'ls',
  summary: 'list directory contents',
  usage: 'ls [-l] [-a] [-d] [-n] [path...]',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const long = flags.has('-l') || flags.has('-n');
    const all = flags.has('-a');
    const targets = rest.length ? rest : ['.'];
    const out: string[] = [];
    let code = 0;
    for (const t of targets) {
      const path = resolvePath(ctx, t);
      const n = ctx.host.fs[path] ?? (virtualFile(ctx.host, path) !== undefined ? { type: 'file' as const, mode: 0o644, owner: 'root', group: 'root', content: virtualFile(ctx.host, path)!, mtime: ctx.host.bootTime } : undefined);
      if (!n) {
        out.push(`ls: cannot access '${t}': No such file or directory`);
        code = 2;
        continue;
      }
      if (n.type === 'file' || flags.has('-d')) {
        out.push(long ? lsLine(t, n, flags.has('-n'), ctx.host) : t);
        continue;
      }
      if (!canAccess(n, ctx.user, 'r') || !canTraverse(ctx.host, path + '/x', ctx.user)) {
        out.push(`ls: cannot open directory '${t}': Permission denied`);
        code = 2;
        continue;
      }
      if (targets.length > 1) out.push(`${t}:`);
      let names = listDir(ctx.host, path);
      if (!all) names = names.filter((x) => !x.startsWith('.'));
      if (long) {
        out.push(`total ${names.length * 4}`);
        if (all) {
          out.push(lsLine('.', n, flags.has('-n'), ctx.host));
          const parent = ctx.host.fs[dirname(path)];
          if (parent) out.push(lsLine('..', parent, flags.has('-n'), ctx.host));
        }
        for (const name of names) out.push(lsLine(name, ctx.host.fs[`${path === '/' ? '' : path}/${name}`], flags.has('-n'), ctx.host));
      } else out.push((all ? ['.', '..', ...names] : names).join('  '));
    }
    return { out: out.join('\n'), code };
  },
};

const cat: CommandDef = {
  name: 'cat',
  summary: 'print file contents',
  usage: 'cat FILE...',
  run(args, ctx) {
    if (args.length === 0) return ok(ctx.stdin ?? '');
    const out: string[] = [];
    let code = 0;
    for (const a of args.filter((x) => !x.startsWith('-'))) {
      const f = getFile(ctx, resolvePath(ctx, a));
      if (f.error) {
        out.push(`cat: ${a}: ${f.error}`);
        code = 1;
      } else out.push(f.content!.replace(/\n$/, ''));
    }
    return { out: out.join('\n'), code };
  },
};

function headTail(which: 'head' | 'tail'): CommandDef {
  return {
    name: which,
    summary: `print the ${which === 'head' ? 'first' : 'last'} lines of input`,
    usage: `${which} [-n N] [FILE]`,
    run(args, ctx) {
      const { flags, rest } = parseFlags(args.map((a) => (/^-\d+$/.test(a) ? `-n${a.slice(1)}` : a)), ['-n']);
      const n = Number(flags.get('-n') ?? 10);
      let text = ctx.stdin ?? '';
      if (rest[0]) {
        const f = getFile(ctx, resolvePath(ctx, rest[0]));
        if (f.error) return err(`${which}: cannot open '${rest[0]}' for reading: ${f.error}`);
        text = f.content!;
      }
      const lines = text.replace(/\n$/, '').split('\n');
      return ok((which === 'head' ? lines.slice(0, n) : lines.slice(-n)).join('\n'));
    },
  };
}

const grep: CommandDef = {
  name: 'grep',
  summary: 'print lines matching a pattern',
  usage: 'grep [-i] [-v] [-n] [-E] [-c] PATTERN [FILE...]',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-e']);
    const pattern = (flags.get('-e') as string | undefined) ?? rest.shift();
    if (pattern === undefined) return err('Usage: grep [OPTION]... PATTERNS [FILE]...', 2);
    let re: RegExp;
    try {
      // Basic regular expressions: \| is alternation, + ? ( ) { } | are literals.
      const src = flags.has('-E')
        ? pattern
        : pattern.replace(/\\\|/g, '\u0001').replace(/[+?(){}|]/g, (m) => '\\' + m).replace(/\u0001/g, '|');
      re = new RegExp(flags.has('-F') ? pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : src, flags.has('-i') ? 'i' : '');
    } catch {
      return err('grep: Invalid regular expression', 2);
    }
    const sources: { name: string; text: string }[] = [];
    if (rest.length === 0) sources.push({ name: '(standard input)', text: ctx.stdin ?? '' });
    for (const f of rest) {
      const r = getFile(ctx, resolvePath(ctx, f));
      if (r.error) return err(`grep: ${f}: ${r.error}`, 2);
      sources.push({ name: f, text: r.content! });
    }
    const out: string[] = [];
    let count = 0;
    for (const s of sources) {
      s.text.replace(/\n$/, '').split('\n').forEach((line, i) => {
        if (re.test(line) !== flags.has('-v')) {
          count++;
          out.push(`${sources.length > 1 ? s.name + ':' : ''}${flags.has('-n') ? `${i + 1}:` : ''}${line}`);
        }
      });
    }
    if (flags.has('-c')) return { out: String(count), code: count ? 0 : 1 };
    return { out: out.join('\n'), code: count ? 0 : 1 };
  },
};

const wc: CommandDef = {
  name: 'wc',
  summary: 'count lines',
  usage: 'wc -l [FILE]',
  run(args, ctx) {
    const { rest } = parseFlags(args);
    let text = ctx.stdin ?? '';
    if (rest[0]) {
      const f = getFile(ctx, resolvePath(ctx, rest[0]));
      if (f.error) return err(`wc: ${rest[0]}: ${f.error}`);
      text = f.content!;
    }
    const lines = text === '' ? 0 : text.replace(/\n$/, '').split('\n').length;
    return ok(rest[0] ? `${lines} ${rest[0]}` : String(lines));
  },
};

const echo: CommandDef = {
  name: 'echo',
  summary: 'print arguments',
  usage: 'echo [-n] TEXT...',
  run(args) {
    const n = args[0] === '-n';
    return ok((n ? args.slice(1) : args).join(' '));
  },
};

const touch: CommandDef = {
  name: 'touch',
  summary: 'create an empty file or update its timestamp',
  usage: 'touch FILE',
  run(args, ctx) {
    for (const a of args) {
      const p = resolvePath(ctx, a);
      const n = ctx.host.fs[p];
      if (n) {
        if (!canAccess(n, ctx.user, 'w')) return err(`touch: cannot touch '${a}': Permission denied`);
        n.mtime = ctx.world.clock;
      } else {
        const e = writeChecked(ctx, p, '');
        if (e) return err(`touch: cannot touch '${a}': ${e}`);
      }
    }
    return ok('');
  },
};

const mkdirCmd: CommandDef = {
  name: 'mkdir',
  summary: 'create directories',
  usage: 'mkdir [-p] [-m MODE] DIR',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-m']);
    for (const a of rest) {
      const p = resolvePath(ctx, a);
      if (ctx.host.fs[p]) {
        if (flags.has('-p')) continue;
        return err(`mkdir: cannot create directory '${a}': File exists`);
      }
      const parent = ctx.host.fs[dirname(p)];
      if (!parent) return err(`mkdir: cannot create directory '${a}': No such file or directory`);
      if (!canAccess(parent, ctx.user, 'w')) return err(`mkdir: cannot create directory '${a}': Permission denied`);
      const mode = flags.get('-m') ? parseInt(flags.get('-m') as string, 8) : 0o755;
      mkdir(ctx.host, p, ctx.world.clock, { mode, owner: ctx.user.name, group: ctx.user.primaryGroup });
    }
    return ok('');
  },
};

const rm: CommandDef = {
  name: 'rm',
  summary: 'remove files',
  usage: 'rm [-f] FILE',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    for (const a of rest) {
      const p = resolvePath(ctx, a);
      const n = ctx.host.fs[p];
      if (!n) {
        if (flags.has('-f')) continue;
        return err(`rm: cannot remove '${a}': No such file or directory`);
      }
      if (n.type === 'dir' && !flags.has('-r')) return err(`rm: cannot remove '${a}': Is a directory`);
      const parent = ctx.host.fs[dirname(p)];
      if (parent && !canAccess(parent, ctx.user, 'w')) return err(`rm: cannot remove '${a}': Permission denied`);
      for (const k of Object.keys(ctx.host.fs)) if (k === p || k.startsWith(p + '/')) delete ctx.host.fs[k];
    }
    return ok('');
  },
};

function applySymbolic(mode: number, spec: string): number | null {
  let m = mode;
  for (const part of spec.split(',')) {
    const r = /^([ugoa]*)([+\-=])([rwxt]*)$/.exec(part);
    if (!r) return null;
    const who = r[1] || 'a';
    let bits = 0;
    for (const w of who === 'a' ? 'ugo' : who) {
      const shift = w === 'u' ? 6 : w === 'g' ? 3 : 0;
      for (const p of r[3]) if (p !== 't') bits |= (p === 'r' ? 4 : p === 'w' ? 2 : 1) << shift;
    }
    if (r[2] === '+') m |= bits;
    else if (r[2] === '-') m &= ~bits;
    else {
      let mask = 0;
      for (const w of who === 'a' ? 'ugo' : who) mask |= 7 << (w === 'u' ? 6 : w === 'g' ? 3 : 0);
      m = (m & ~mask) | bits;
    }
  }
  return m;
}

const chmod: CommandDef = {
  name: 'chmod',
  summary: 'change file mode bits',
  usage: 'chmod [-R] MODE FILE...',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const [spec, ...files] = rest;
    if (!spec || files.length === 0) return err("chmod: missing operand\nTry 'chmod --help' for more information.");
    for (const f of files) {
      const p = resolvePath(ctx, f);
      const targets = flags.has('-R') ? Object.keys(ctx.host.fs).filter((k) => k === p || k.startsWith(p + '/')) : [p];
      if (!ctx.host.fs[p]) return err(`chmod: cannot access '${f}': No such file or directory`);
      for (const t of targets) {
        const n = ctx.host.fs[t];
        if (ctx.user.uid !== 0 && n.owner !== ctx.user.name) return err(`chmod: changing permissions of '${f}': Operation not permitted`);
        const next = /^[0-7]{3,4}$/.test(spec) ? parseInt(spec, 8) : applySymbolic(n.mode, spec);
        if (next === null) return err(`chmod: invalid mode: '${spec}'`);
        n.mode = next;
      }
    }
    return ok('');
  },
};

const chown: CommandDef = {
  name: 'chown',
  summary: 'change file owner and group',
  usage: 'chown [-R] USER[:GROUP] FILE...',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const [spec, ...files] = rest;
    if (!spec || !files.length) return err('chown: missing operand');
    if (ctx.user.uid !== 0) return err(`chown: changing ownership of '${files[0]}': Operation not permitted`);
    const [u, g] = spec.split(':');
    if (u && !ctx.host.users[u]) return err(`chown: invalid user: '${spec}'`);
    for (const f of files) {
      const p = resolvePath(ctx, f);
      if (!ctx.host.fs[p]) return err(`chown: cannot access '${f}': No such file or directory`);
      const targets = flags.has('-R') ? Object.keys(ctx.host.fs).filter((k) => k === p || k.startsWith(p + '/')) : [p];
      for (const t of targets) {
        if (u) ctx.host.fs[t].owner = u;
        if (g !== undefined) ctx.host.fs[t].group = g || ctx.host.users[u]?.primaryGroup || ctx.host.fs[t].group;
      }
    }
    return ok('');
  },
};

const stat: CommandDef = {
  name: 'stat',
  summary: 'display file status',
  usage: 'stat FILE',
  run(args, ctx) {
    const out: string[] = [];
    for (const a of args) {
      const p = resolvePath(ctx, a);
      const n = ctx.host.fs[p];
      if (!n) return err(`stat: cannot statx '${a}': No such file or directory`);
      const uid = ctx.host.users[n.owner]?.uid ?? 0;
      out.push(
        `  File: ${a}`,
        `  Size: ${n.type === 'dir' ? 4096 : n.content.length}\tBlocks: 8          IO Block: 4096   ${n.type === 'dir' ? 'directory' : 'regular file'}`,
        `Access: (${(n.mode & 0o7777).toString(8).padStart(4, '0')}/${modeString(n)})  Uid: (${String(uid).padStart(5)}/${n.owner.padStart(8)})   Gid: (${String(ctx.host.users[n.group]?.gid ?? 0).padStart(5)}/${n.group.padStart(8)})`,
        `Modify: ${new Date(Math.floor(n.mtime)).toISOString().replace('T', ' ').replace('Z', ' +0000')}`,
      );
    }
    return ok(out.join('\n'));
  },
};

const cd: CommandDef = {
  name: 'cd',
  summary: 'change directory',
  usage: 'cd [DIR]',
  run(args, ctx) {
    const target = resolvePath(ctx, args[0] ?? '~');
    const n = ctx.host.fs[target];
    if (!n) return err(`bash: cd: ${args[0]}: No such file or directory`);
    if (n.type !== 'dir') return err(`bash: cd: ${args[0]}: Not a directory`);
    if (!canAccess(n, ctx.user, 'x')) return err(`bash: cd: ${args[0]}: Permission denied`);
    ctx.frame.cwd = target;
    return ok('');
  },
};

const pwd: CommandDef = { name: 'pwd', summary: 'print working directory', usage: 'pwd', run: (_a, ctx) => ok(ctx.frame.cwd) };
const whoami: CommandDef = { name: 'whoami', summary: 'print effective user name', usage: 'whoami', run: (_a, ctx) => ok(ctx.user.name) };

const id: CommandDef = {
  name: 'id',
  summary: 'print user and group ids',
  usage: 'id [USER]',
  run(args, ctx) {
    const u = args[0] ? ctx.host.users[args[0]] : ctx.user;
    if (!u) return err(`id: '${args[0]}': no such user`);
    const gids = [u.primaryGroup, ...u.groups].map((g, i) => `${i === 0 ? u.gid : 27 + i}(${g})`);
    return ok(`uid=${u.uid}(${u.name}) gid=${u.gid}(${u.primaryGroup}) groups=${gids.join(',')}`);
  },
};

const editor: CommandDef = {
  name: 'nano',
  summary: 'edit a file (opens the in-app editor)',
  usage: 'nano FILE   (also: vi, vim, editor)',
  run(args, ctx) {
    const a = args.filter((x) => !x.startsWith('-'))[0];
    if (!a) return err('nano: a file name is required in this simulator');
    const p = resolvePath(ctx, a);
    const n = ctx.host.fs[p];
    if (n?.type === 'dir') return err(`nano: ${a} is a directory`);
    const readable = n ? canAccess(n, ctx.user, 'r') && canTraverse(ctx.host, p, ctx.user) : true;
    if (!readable) return err(`[ Error reading ${a}: Permission denied ]`);
    const parent = ctx.host.fs[dirname(p)];
    if (!n && !parent) return err(`[ Directory '${dirname(p)}' does not exist ]`);
    const writable = n ? canAccess(n, ctx.user, 'w') : canAccess(parent!, ctx.user, 'w');
    return {
      out: '',
      code: 0,
      editor: { hostId: ctx.host.id, path: p, content: n?.content ?? '', readOnly: !writable, isNew: !n },
    };
  },
};

const passwd: CommandDef = {
  name: 'passwd',
  summary: 'change a user password',
  usage: 'passwd [USER]',
  run(args, ctx) {
    const target = args[0] ?? ctx.user.name;
    const u = ctx.host.users[target];
    if (!u) return err(`passwd: user '${target}' does not exist`);
    if (ctx.user.uid !== 0 && target !== ctx.user.name) return err(`passwd: You may not view or modify password information for ${target}.`);
    if (ctx.user.uid !== 0) {
      const cur = ctx.ask(`Current password: `, true);
      if (cur !== u.password) return err('passwd: Authentication token manipulation error\npasswd: password unchanged');
    }
    const a = ctx.ask('New password: ', true);
    const b = ctx.ask('Retype new password: ', true);
    if (a !== b) return err('Sorry, passwords do not match.\npasswd: Authentication token manipulation error\npasswd: password unchanged', 10);
    if (!a) return err('No password has been supplied.\npasswd: Authentication token manipulation error\npasswd: password unchanged', 10);
    u.password = a;
    return ok('passwd: password updated successfully');
  },
};

const usermod: CommandDef = {
  name: 'usermod',
  summary: 'modify a user account (-aG GROUP, -s SHELL, -L/-U)',
  usage: 'usermod [-aG GROUP] [-s SHELL] [-L|-U] USER',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('usermod: Permission denied.\nusermod: cannot lock /etc/passwd; try again later.');
    const { flags, rest } = parseFlags(args, ['-G', '-s']);
    const u = ctx.host.users[rest[0]];
    if (!u) return err(`usermod: user '${rest[0]}' does not exist`, 6);
    if (flags.has('-G')) {
      const gs = String(flags.get('-G')).split(',');
      u.groups = flags.has('-a') ? [...new Set([...u.groups, ...gs])] : gs;
    }
    if (flags.has('-s')) u.shell = String(flags.get('-s'));
    if (flags.has('-L') && u.password && !u.password.startsWith('!')) u.password = '!' + u.password;
    if (flags.has('-U') && u.password?.startsWith('!')) u.password = u.password.slice(1);
    return ok('');
  },
};

/** Split a sed script on unescaped ';' (outside s/// arguments is good enough for the supported subset). */
function sedCommands(script: string): string[] {
  const out: string[] = [];
  let cur = '';
  let i = 0;
  while (i < script.length) {
    const c = script[i];
    if (c === 's' && cur.trim() === '') {
      // s<d>pat<d>rep<d>flags
      const d = script[i + 1];
      let j = i + 2;
      let parts = 0;
      while (j < script.length && parts < 2) {
        if (script[j] === '\\') j += 2;
        else { if (script[j] === d) parts++; j++; }
      }
      while (j < script.length && /[gI0-9]/.test(script[j])) j++;
      out.push(script.slice(i, j));
      i = j;
      cur = '';
      continue;
    }
    if (c === ';') { if (cur.trim()) out.push(cur.trim()); cur = ''; i++; continue; }
    cur += c;
    i++;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function sedRegex(src: string, flags: string): RegExp {
  // GNU basic regex subset -> JS: \( \) \{ \} \| \+ \? are operators, bare ones are literals.
  let out = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\' && i + 1 < src.length) {
      const n = src[++i];
      if ('(){}|+?'.includes(n)) out += n;
      else if (n === 't') out += '\t';
      else if (n === 'n') out += '\n';
      else out += '\\' + n;
    } else if ('(){}|+?'.includes(c)) out += '\\' + c;
    else out += c;
  }
  return new RegExp(out, flags);
}

function applySed(text: string, script: string): string | { error: string } {
  const cmds = sedCommands(script);
  const lines = text.replace(/\n$/, '').split('\n');
  const result: string[] = [];
  for (let line of lines) {
    let deleted = false;
    for (const cmd of cmds) {
      const del = /^\/(.*)\/d$/.exec(cmd);
      if (del) {
        if (sedRegex(del[1], '').test(line)) { deleted = true; break; }
        continue;
      }
      if (cmd[0] === 's') {
        const d = cmd[1];
        const parts: string[] = [];
        let cur = '';
        let i = 2;
        for (; i < cmd.length && parts.length < 2; i++) {
          if (cmd[i] === '\\' && cmd[i + 1] === d) { cur += d; i++; continue; }
          if (cmd[i] === d) { parts.push(cur); cur = ''; continue; }
          cur += cmd[i];
        }
        const flags = cmd.slice(i);
        if (parts.length < 2) return { error: `sed: -e expression #1, char ${cmd.length}: unterminated \`s' command` };
        const re = sedRegex(parts[0], flags.includes('g') ? 'g' : '');
        const rep = parts[1].replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\(\d)/g, '$$$1').replace(/&/g, '$$&');
        line = line.replace(re, rep);
        continue;
      }
      return { error: `sed: -e expression #1, char 1: unknown command: \`${cmd[0]}'` };
    }
    if (!deleted) result.push(line);
  }
  return result.join('\n') + '\n';
}

const sed: CommandDef = {
  name: 'sed',
  summary: 'stream editor (s/// substitution and /re/d deletion; -i edits in place)',
  usage: "sed [-i] 's/OLD/NEW/[g]' FILE | sed [-i] '/PATTERN/d' FILE",
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-e']);
    const scripts: string[] = [];
    if (flags.has('-e')) scripts.push(String(flags.get('-e')));
    else if (rest.length) scripts.push(rest.shift()!);
    if (!scripts.length) return err('Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...', 1);
    const files = rest;
    if (files.length === 0) {
      const r = applySed(ctx.stdin ?? '', scripts[0]);
      return typeof r === 'string' ? ok(r.replace(/\n$/, '')) : err(r.error, 1);
    }
    const outputs: string[] = [];
    for (const f of files) {
      const path = resolvePath(ctx, f);
      const file = getFile(ctx, path);
      if (file.error) return err(`sed: can't read ${f}: ${file.error}`, 2);
      const r = applySed(file.content!, scripts[0]);
      if (typeof r !== 'string') return err(r.error, 1);
      if (flags.has('-i')) {
        const e = writeChecked(ctx, path, r);
        if (e) return err(`sed: couldn't open temporary file ${dirname(path)}/sedXYZ: ${e}`, 4);
      } else outputs.push(r.replace(/\n$/, ''));
    }
    return ok(outputs.join('\n'));
  },
};

export const FILE_COMMANDS: CommandDef[] = [sed, 
  ls, cat, headTail('head'), headTail('tail'), grep, wc, echo, touch, mkdirCmd, rm, chmod, chown, stat, cd, pwd,
  whoami, id, editor, { ...editor, name: 'vi' }, { ...editor, name: 'vim' }, { ...editor, name: 'editor' }, passwd, usermod,
];

export { basename };
