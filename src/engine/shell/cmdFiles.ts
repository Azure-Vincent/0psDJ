// File and user commands: ls, cat, head, tail, grep, echo, touch, mkdir, rm,
// chmod, chown, stat, cd, pwd, id, whoami, editors, passwd, usermod.

import { basename, canAccess, canTraverse, dirname, listDir, mkdir, modeString, normalizePath, writeFile } from '../fs';
import { formatSyslogTime, isoTime } from '../sim/journal';
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
  if (path === '/dev/null') return '';
  const sys = /^\/sys\/class\/net\/([^/]+)\/([a-z_]+)$/.exec(path);
  if (sys) {
    const i = host.ifaces.find((x) => x.name === sys[1]);
    if (!i) return undefined;
    const lo = i.name === 'lo';
    const carrier = lo || (i.up && (i.segment !== null || !!host.bridge?.ports[i.name]));
    const files: Record<string, string> = {
      operstate: lo ? 'unknown' : !i.up ? 'down' : carrier ? 'up' : i.vlan ? 'lowerlayerdown' : 'down',
      carrier: carrier ? '1' : '0',
      address: i.mac,
      mtu: String(i.mtu ?? (lo ? 65536 : 1500)),
      speed: lo ? '-1' : carrier ? '1000' : '-1',
      duplex: lo ? 'unknown' : carrier ? 'full' : 'unknown',
      type: lo ? '772' : '1',
      ifindex: String(host.ifaces.indexOf(i) + 1),
    };
    return files[sys[2]] !== undefined ? files[sys[2]] + '\n' : undefined;
  }
  return undefined;
}

const VIRTUAL_META: Record<string, Partial<FileNode>> = {
  '/etc/passwd': { mode: 0o644 },
  '/etc/group': { mode: 0o644 },
  '/etc/shadow': { mode: 0o640, group: 'shadow' },
  '/proc/sys/net/ipv4/ip_forward': { mode: 0o644 },
  '/dev/null': { mode: 0o666 },
};

export function getFile(ctx: CmdCtx, path: string): { node: FileNode | null; content?: string; error?: string } {
  const v = virtualFile(ctx.host, path);
  // The kernel refuses carrier/speed/duplex of an interface that is administratively down.
  const down = /^\/sys\/class\/net\/([^/]+)\/(carrier|speed|duplex)$/.exec(path);
  if (v !== undefined && down && ctx.host.ifaces.some((i) => i.name === down[1] && i.name !== 'lo' && !i.up)) {
    return { node: { type: 'file', mode: 0o444, owner: 'root', group: 'root', content: '', mtime: ctx.host.bootTime }, error: 'Invalid argument' };
  }
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
  if (path === '/dev/null') return null;
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
  const size = n.type === 'dir' ? 4096 : n.size ?? n.content.length;
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
      // sysfs: one directory per network interface, a few attribute files each.
      const sysIf = /^\/sys\/class\/net(?:\/([^/]+))?$/.exec(path);
      if (sysIf && (!sysIf[1] || ctx.host.ifaces.some((i) => i.name === sysIf[1]))) {
        out.push((sysIf[1] ? ['address', 'carrier', 'duplex', 'ifindex', 'mtu', 'operstate', 'speed', 'type'] : ctx.host.ifaces.map((i) => i.name).concat(ctx.host.bridge ? [ctx.host.bridge.name] : []).sort()).join('  '));
        continue;
      }
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
        `  Size: ${n.type === 'dir' ? 4096 : n.size ?? n.content.length}\tBlocks: 8          IO Block: 4096   ${n.type === 'dir' ? 'directory' : 'regular file'}`,
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
      editor: { hostId: ctx.host.id, user: ctx.user.name, path: p, content: n?.content ?? '', readOnly: !writable, isNew: !n },
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
/** Length of a leading sed address ("/re/", "N", "$", optionally ",ADDR2") in `s`, or 0. */
function sedAddressLength(s: string): number {
  const one = (i: number): number => {
    if (s[i] === '/') {
      let j = i + 1;
      while (j < s.length && s[j] !== '/') j += s[j] === '\\' ? 2 : 1;
      return j < s.length ? j + 1 : i;
    }
    let j = i;
    while (j < s.length && /[0-9$]/.test(s[j])) j++;
    return j;
  };
  let i = one(0);
  if (i > 0 && s[i] === ',') {
    const j = one(i + 1);
    if (j > i + 1) i = j;
  }
  return i;
}

function sedCommands(script: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < script.length) {
    while (i < script.length && /[\s;]/.test(script[i])) i++;
    if (i >= script.length) break;
    const start = i;
    i += sedAddressLength(script.slice(i));
    if (script[i] === 's') {
      // s<d>pat<d>rep<d>flags
      const d = script[i + 1];
      let j = i + 2;
      let parts = 0;
      while (j < script.length && parts < 2) {
        if (script[j] === '\\') j += 2;
        else { if (script[j] === d) parts++; j++; }
      }
      while (j < script.length && /[gI0-9]/.test(script[j])) j++;
      i = j;
    } else {
      while (i < script.length && script[i] !== ';') i++;
    }
    out.push(script.slice(start, i).trim());
  }
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

type SedAddr = { re: RegExp } | { line: number } | { last: true };

interface SedCmd { a1?: SedAddr; a2?: SedAddr; op: string; arg: string; inRange: boolean }

function parseSedAddr(src: string): SedAddr {
  if (src.startsWith('/')) return { re: sedRegex(src.slice(1, -1), '') };
  if (src === '$') return { last: true };
  return { line: Number(src) };
}

function addrMatches(a: SedAddr, line: string, n: number, last: boolean): boolean {
  if ('re' in a) return a.re.test(line);
  if ('last' in a) return last;
  return n === a.line;
}

function applySed(text: string, script: string): string | { error: string } {
  const cmds: SedCmd[] = [];
  for (const raw of sedCommands(script)) {
    const len = sedAddressLength(raw);
    const addr = raw.slice(0, len);
    const rest = raw.slice(len).trim();
    const comma = addr.startsWith('/') ? addr.indexOf(',', addr.indexOf('/', 1)) : addr.indexOf(',');
    const [s1, s2] = comma > 0 ? [addr.slice(0, comma), addr.slice(comma + 1)] : [addr, ''];
    if (!rest || !'ds'.includes(rest[0])) return { error: `sed: -e expression #1, char ${raw.length}: unknown command: \`${rest[0] ?? ''}'` };
    cmds.push({ a1: s1 ? parseSedAddr(s1) : undefined, a2: s2 ? parseSedAddr(s2) : undefined, op: rest[0], arg: rest, inRange: false });
  }
  const lines = text.replace(/\n$/, '').split('\n');
  const result: string[] = [];
  lines.forEach((orig, idx) => {
    let line = orig;
    const n = idx + 1;
    const last = idx === lines.length - 1;
    let deleted = false;
    for (const c of cmds) {
      // Address selection, including ranges: a range starts on a1 and ends on the first a2 match after it.
      let selected = true;
      if (c.a1 && !c.a2) selected = addrMatches(c.a1, line, n, last);
      else if (c.a1 && c.a2) {
        if (c.inRange) {
          selected = true;
          if (addrMatches(c.a2, line, n, last) || ('line' in c.a2 && n >= c.a2.line)) c.inRange = false;
        } else if (addrMatches(c.a1, line, n, last)) {
          selected = true;
          c.inRange = !('line' in c.a2 && c.a2.line <= n);
        } else selected = false;
      }
      if (!selected) continue;
      if (c.op === 'd') { deleted = true; break; }
      const cmd = c.arg;
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
      if (parts.length < 2) return void (deleted = true, result.push('\u0000ERR' + cmd.length));
      const re = sedRegex(parts[0], flags.includes('g') ? 'g' : '');
      const rep = parts[1].replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\(\d)/g, '$$$1').replace(/&/g, '$$&');
      line = line.replace(re, rep);
    }
    if (!deleted) result.push(line);
  });
  const bad = result.find((l) => l.startsWith('\u0000ERR'));
  if (bad) return { error: `sed: -e expression #1, char ${bad.slice(4)}: unterminated \`s' command` };
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

const tee: CommandDef = {
  name: 'tee',
  summary: 'copy standard input to files and to standard output',
  usage: 'tee [-a] FILE...',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const text = ctx.stdin ?? '';
    const errors: string[] = [];
    for (const f of rest) {
      const e = writeChecked(ctx, resolvePath(ctx, f), text.endsWith('\n') || !text ? text : text + '\n', flags.has('-a'));
      if (e) errors.push(`tee: ${f}: ${e}`);
    }
    return { out: [text.replace(/\n$/, ''), ...errors].filter(Boolean).join('\n'), code: errors.length ? 1 : 0 };
  },
};

// cp / mv / diff: the backup-validate-rollback workflow (cp -a file file.bak, diff -u) needs them.
function copyOrMove(name: 'cp' | 'mv'): CommandDef {
  return {
    name,
    summary: name === 'cp' ? 'copy a file (-a/-p keep mode, owner and timestamps)' : 'move or rename a file',
    usage: `${name}${name === 'cp' ? ' [-a|-p]' : ''} SOURCE DEST`,
    run(args, ctx) {
      const { flags, rest } = parseFlags(args);
      if (rest.length < 2) return err(`${name}: missing destination file operand after '${rest[0] ?? ''}'\nTry '${name} --help' for more information.`);
      const [srcArg, dstArg] = rest;
      const src = resolvePath(ctx, srcArg);
      const n = ctx.host.fs[src];
      if (!n) return err(`${name}: cannot stat '${srcArg}': No such file or directory`);
      if (n.type === 'dir') return err(name === 'cp' ? `cp: -r not specified; omitting directory '${srcArg}'` : `mv: moving directories is not supported in the simulator`);
      if (!canTraverse(ctx.host, src, ctx.user) || !canAccess(n, ctx.user, 'r')) return err(`${name}: cannot open '${srcArg}' for reading: Permission denied`);
      let dst = resolvePath(ctx, dstArg);
      if (ctx.host.fs[dst]?.type === 'dir') dst = `${dst === '/' ? '' : dst}/${basename(src)}`;
      if (dst === src) return err(`${name}: '${srcArg}' and '${dstArg}' are the same file`);
      const e = writeChecked(ctx, dst, n.content ?? '');
      if (e) return err(`${name}: cannot create regular file '${dstArg}': ${e}`);
      const d = ctx.host.fs[dst];
      const keep = name === 'mv' || flags.has('-a') || flags.has('-p') || flags.has('--preserve');
      d.mode = n.mode;
      if (n.size !== undefined) d.size = n.size;
      if (keep && ctx.user.uid === 0) { d.owner = n.owner; d.group = n.group; }
      if (keep) d.mtime = n.mtime;
      if (name === 'mv') {
        const parent = ctx.host.fs[dirname(src)];
        if (parent && !canAccess(parent, ctx.user, 'w')) return err(`mv: cannot remove '${srcArg}': Permission denied`);
        delete ctx.host.fs[src];
      }
      return ok('');
    },
  };
}

/** Line diff (LCS) rendered like `diff -u` (3 lines of context) or classic `diff`. */
function lineDiff(a: string[], b: string[]): { op: ' ' | '-' | '+'; line: string; ai: number; bi: number }[] {
  const m = a.length;
  const n = b.length;
  const L: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) for (let j = n - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out: { op: ' ' | '-' | '+'; line: string; ai: number; bi: number }[] = [];
  let i = 0;
  let j = 0;
  while (i < m || j < n) {
    if (i < m && j < n && a[i] === b[j]) { out.push({ op: ' ', line: a[i], ai: i++, bi: j++ }); }
    else if (i < m && (j >= n || L[i + 1][j] >= L[i][j + 1])) out.push({ op: '-', line: a[i], ai: i++, bi: j });
    else out.push({ op: '+', line: b[j], ai: i, bi: j++ });
  }
  return out;
}

const diff: CommandDef = {
  name: 'diff',
  summary: 'compare two files line by line (-u for unified format)',
  usage: 'diff [-u] FILE1 FILE2',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    if (rest.length < 2) return err(`diff: missing operand after '${rest[0] ?? 'diff'}'\ndiff: Try 'diff --help' for more information.`, 2);
    const texts: string[][] = [];
    for (const f of rest.slice(0, 2)) {
      const p = resolvePath(ctx, f);
      const n = ctx.host.fs[p];
      if (!n) return err(`diff: ${f}: No such file or directory`, 2);
      if (!canAccess(n, ctx.user, 'r')) return err(`diff: ${f}: Permission denied`, 2);
      texts.push((n.content ?? '').replace(/\n$/, '').split('\n'));
    }
    const d = lineDiff(texts[0], texts[1]);
    if (d.every((x) => x.op === ' ')) return ok('');
    const out: string[] = [];
    if (flags.has('-u')) {
      const t = (f: string) => `${f}\t${isoTime(ctx.host.fs[resolvePath(ctx, f)].mtime).replace(' UTC', '.000000000 +0000')}`;
      out.push(`--- ${t(rest[0])}`, `+++ ${t(rest[1])}`);
      const changed = d.map((x, k) => (x.op !== ' ' ? k : -1)).filter((k) => k >= 0);
      let k = 0;
      while (k < changed.length) {
        let start = Math.max(0, changed[k] - 3);
        let end = Math.min(d.length - 1, changed[k] + 3);
        while (k + 1 < changed.length && changed[k + 1] - 3 <= end + 1) { k++; end = Math.min(d.length - 1, changed[k] + 3); }
        k++;
        const hunk = d.slice(start, end + 1);
        const aLines = hunk.filter((x) => x.op !== '+').length;
        const bLines = hunk.filter((x) => x.op !== '-').length;
        const aStart = (hunk.find((x) => x.op !== '+')?.ai ?? hunk[0].ai) + (aLines ? 1 : 0);
        const bStart = (hunk.find((x) => x.op !== '-')?.bi ?? hunk[0].bi) + (bLines ? 1 : 0);
        out.push(`@@ -${aStart},${aLines} +${bStart},${bLines} @@`, ...hunk.map((x) => x.op + x.line));
        start = end;
      }
    } else {
      for (let k = 0; k < d.length;) {
        if (d[k].op === ' ') { k++; continue; }
        const del: typeof d = [];
        const addl: typeof d = [];
        const a0 = d[k].ai;
        const b0 = d[k].bi;
        while (k < d.length && d[k].op !== ' ') { (d[k].op === '-' ? del : addl).push(d[k]); k++; }
        const r = (s: number, c: number) => (c <= 1 ? String(s + (c ? 1 : 0)) : `${s + 1},${s + c}`);
        const head = del.length && addl.length ? `${r(a0, del.length)}c${r(b0, addl.length)}` : del.length ? `${r(a0, del.length)}d${b0}` : `${a0}a${r(b0, addl.length)}`;
        out.push(head, ...del.map((x) => `< ${x.line}`), ...(del.length && addl.length ? ['---'] : []), ...addl.map((x) => `> ${x.line}`));
      }
    }
    return { out: out.join('\n'), code: 1 };
  },
};

export const FILE_COMMANDS: CommandDef[] = [tee, sed, copyOrMove('cp'), copyOrMove('mv'), diff,
  ls, cat, headTail('head'), headTail('tail'), grep, wc, echo, touch, mkdirCmd, rm, chmod, chown, stat, cd, pwd,
  whoami, id, editor, { ...editor, name: 'vi' }, { ...editor, name: 'vim' }, { ...editor, name: 'editor' }, passwd, usermod,
];

export { basename };
