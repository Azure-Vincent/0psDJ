// Samba tools: smbclient (the SMB client), and on the server smbpasswd,
// pdbedit, testparm and smbstatus.

import { canAccess, readFile } from '../fs';
import {
  boolValue, loadSmbConf, passdb, SAMBA_VERSION, shareList, smbConnect, smbDelete, smbList, smbMkdir, smbRead, smbWrite,
  SMB_CONF, type SmbError, type SmbSession,
} from '../sim/smb';
import { resolvePath, writeChecked } from './cmdFiles';
import { type CmdCtx, type CommandDef, err, ok } from './types';

const BLOCKS = '\n\t\t102687672 blocks of size 1024. 84862212 blocks available';
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** "Sat Oct 19 07:58:00 2024", as smbclient's ls prints times. */
function ctime(t: number): string {
  const d = new Date(Math.floor(t));
  const p = (n: number) => String(n).padStart(2, '0');
  return `${DAYS[d.getUTCDay()]} ${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} ${d.getUTCFullYear()}`;
}

function words(s: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

const connectError = (target: string, e: SmbError) => (e === 'NT_STATUS_CONNECTION_DISCONNECTED' ? `protocol negotiation failed: ${e}` : `do_connect: Connection to ${target} failed (Error ${e})`);

/** Run smbclient's -c commands in a connected share. */
function runCommands(ctx: CmdCtx, session: SmbSession, script: string): { out: string[]; code: number } {
  const out: string[] = [];
  let cwd = '';
  let code = 0;
  const rel = (p: string) => (p.startsWith('\\') || p.startsWith('/') ? p : `${cwd}\\${p}`).replace(/\//g, '\\').replace(/\\+/g, '\\');
  const show = (p: string) => (rel(p).startsWith('\\') ? rel(p) : '\\' + rel(p));
  for (const cmd of script.split(';').map((x) => x.trim()).filter(Boolean)) {
    const [name, ...args] = words(cmd);
    const op = name.toLowerCase();
    // IPC$ is the server's inter-process share: it has no files.
    if (session.ipc && !['pwd', 'exit', 'quit', 'q'].includes(op)) {
      out.push(op === 'ls' || op === 'dir' ? 'NT_STATUS_INVALID_INFO_CLASS listing \\*' : `NT_STATUS_ACCESS_DENIED ${op === 'get' || op === 'put' ? `opening remote file \\${args[op === 'put' ? 1 : 0] ?? args[0] ?? ''}` : `on \\${args[0] ?? ''}`}`);
      code = 1;
      continue;
    }
    if (op === 'ls' || op === 'dir') {
      const r = smbList(session, args[0] ? rel(args[0]) : cwd || '\\');
      if (r.status !== 'NT_STATUS_OK') { out.push(`${r.status} listing ${show(args[0] ?? '')}${args[0] ? '' : '*'}`); code = 1; continue; }
      for (const e of r.entries!) out.push(`  ${e.name.padEnd(30)}${(e.dir ? 'D' : 'N').padStart(7)} ${String(e.size).padStart(8)}  ${ctime(e.mtime)}`);
      out.push(BLOCKS);
    } else if (op === 'cd') {
      const target = args[0] ? rel(args[0]) : '\\';
      const r = smbList(session, target);
      if (r.status !== 'NT_STATUS_OK' || !r.entries?.some((e) => e.name === '.')) { out.push(`cd ${show(args[0] ?? '')}: NT_STATUS_OBJECT_NAME_NOT_FOUND`); code = 1; continue; }
      cwd = target === '\\' ? '' : target;
    } else if (op === 'pwd') {
      out.push(`Current directory is \\\\${session.server.hostname}\\${session.share?.name ?? 'IPC$'}${cwd || '\\'}${cwd ? '\\' : ''}`);
    } else if (op === 'get') {
      if (!args[0]) { out.push('get <filename> [localname]'); code = 1; continue; }
      const r = smbRead(session, rel(args[0]));
      if (r.status !== 'NT_STATUS_OK') { out.push(`${r.status} opening remote file ${show(args[0])}`); code = 1; continue; }
      const local = args[1] ?? args[0].split(/[\\/]/).pop()!;
      const e = writeChecked(ctx, resolvePath(ctx, local), r.content!);
      if (e) { out.push(`Error opening local file ${local}`); code = 1; continue; }
      out.push(`getting file ${show(args[0])} of size ${r.content!.length} as ${local} (78.1 KiloBytes/sec) (average 78.1 KiloBytes/sec)`);
    } else if (op === 'put') {
      if (!args[0]) { out.push('put <filename> [remotename]'); code = 1; continue; }
      const lp = resolvePath(ctx, args[0]);
      const node = ctx.host.fs[lp];
      if (!node || node.type !== 'file') { out.push(`${args[0]} does not exist`); code = 1; continue; }
      if (!canAccess(node, ctx.user, 'r')) { out.push(`Error opening local file ${args[0]}`); code = 1; continue; }
      const remote = args[1] ?? args[0].split('/').pop()!;
      const st = smbWrite(ctx.world, session, rel(remote), node.content);
      if (st !== 'NT_STATUS_OK') { out.push(`${st} opening remote file ${show(remote)}`); code = 1; continue; }
      out.push(`putting file ${args[0]} as ${show(remote)} (2.0 kb/s) (average 2.0 kb/s)`);
    } else if (op === 'mkdir' || op === 'md') {
      const st = smbMkdir(ctx.world, session, rel(args[0] ?? ''));
      if (st !== 'NT_STATUS_OK') { out.push(`${st} making remote directory ${show(args[0] ?? '')}`); code = 1; }
    } else if (op === 'rm' || op === 'del') {
      const st = smbDelete(session, rel(args[0] ?? ''), false);
      if (st !== 'NT_STATUS_OK') { out.push(`${st} deleting remote file ${show(args[0] ?? '')}`); code = 1; }
    } else if (op === 'rmdir' || op === 'rd') {
      const st = smbDelete(session, rel(args[0] ?? ''), true);
      if (st !== 'NT_STATUS_OK') { out.push(`${st} removing remote directory file ${show(args[0] ?? '')}`); code = 1; }
    } else if (op === 'exit' || op === 'quit' || op === 'q') {
      break;
    } else {
      out.push(`${name}: command not found`);
      code = 1;
    }
  }
  return { out, code };
}

const smbclient: CommandDef = {
  name: 'smbclient',
  summary: 'SMB client: list a server\'s shares (-L) or run commands in a share (-c "ls; get FILE; put FILE")',
  usage: 'smbclient -L SERVER [-U USER[%PASS] | -N] | smbclient //SERVER/SHARE [-U USER[%PASS] | -N] -c "COMMANDS"',
  run(args, ctx) {
    let user: string | null = ctx.user.name;
    let password: string | undefined;
    let anon = false;
    let listHost: string | undefined;
    let service: string | undefined;
    let script: string | undefined;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-U' || a === '--user') { const v = args[++i] ?? ''; const at = v.indexOf('%'); user = (at < 0 ? v : v.slice(0, at)).replace(/^.*[\\/]/, ''); if (at >= 0) password = v.slice(at + 1); }
      else if (/^-U./.test(a)) { const v = a.slice(2); const at = v.indexOf('%'); user = (at < 0 ? v : v.slice(0, at)).replace(/^.*[\\/]/, ''); if (at >= 0) password = v.slice(at + 1); }
      else if (a === '-N' || a === '--no-pass') anon = true;
      else if (a === '-L' || a === '--list') listHost = args[++i];
      else if (a === '-c' || a === '--command') script = args[++i];
      else if (['-W', '-m', '-d', '-p', '--workgroup', '--max-protocol', '--debuglevel', '--port'].includes(a)) i++;
      else if (a.startsWith('//') || a.startsWith('\\\\')) service = a;
      else if (a.startsWith('-')) continue;
      else if (!service) service = a;
    }
    if (!listHost && !service) return err('Usage: smbclient [OPTIONS] service <password>\n\nsmbclient -L SERVER | smbclient //SERVER/SHARE -c "COMMANDS"', 1);
    let server: string;
    let share: string | undefined;
    if (listHost) server = listHost.replace(/^[\\/]+/, '').split(/[\\/]/)[0];
    else {
      const m = /^[\\/]{2}([^\\/]+)[\\/]([^\\/]+)/.exec(service!);
      if (!m) return err(`${service}: Not enough '\\' characters in service`, 1);
      server = m[1];
      share = m[2];
    }
    // -N without -U: an anonymous session; -N with -U: that user with an empty password.
    if (anon && !args.some((a) => a.startsWith('-U') || a === '--user')) user = null;
    if (anon && password === undefined) password = '';
    if (password === undefined) password = ctx.ask(`Password for [WORKGROUP\\${user}]:`, true);
    const r = smbConnect(ctx.world, ctx.host, server, user, password, share);
    if (!r.ok) {
      if (r.stage === 'connect') return err(connectError(server, r.error), 1);
      if (r.stage === 'session') return err(`session setup failed: ${r.error}`, 1);
      return err(`tree connect failed: ${r.error}`, 1);
    }
    if (listHost) {
      const rows = shareList(r.session).map((s) => `\t${s.name.padEnd(15)} ${s.type.padEnd(9)} ${s.comment}`);
      return ok(['', '\tSharename       Type      Comment', '\t---------       ----      -------', ...rows, 'SMB1 disabled -- no workgroup available'].join('\n'));
    }
    if (!script) return err('Try "help" to get a list of possible commands.\nsmb: \\> (this simulator runs smbclient non-interactively: add -c "ls; get FILE; put FILE")', 1);
    const res = runCommands(ctx, r.session, script);
    return { out: res.out.join('\n'), code: res.code };
  },
};

function readSecret(ctx: CmdCtx, silent: boolean, prompts: string[]): string[] {
  if (silent) {
    const lines = (ctx.stdin ?? '').split('\n');
    return prompts.map((_, i) => lines[i] ?? '');
  }
  return prompts.map((p) => ctx.ask(p, true));
}

const smbpasswd: CommandDef = {
  name: 'smbpasswd',
  summary: 'set a user\'s Samba password (-a add, -x delete, -d disable, -e enable)',
  usage: 'smbpasswd [-a|-x|-d|-e] [-s] [USER]',
  run(args, ctx) {
    const flags = new Set(args.filter((a) => a.startsWith('-')).flatMap((a) => a.slice(1).split('')));
    const name = args.find((a) => !a.startsWith('-'));
    const db = passdb(ctx.host);
    const silent = flags.has('s');
    if (ctx.user.uid !== 0) {
      if (name && name !== ctx.user.name || flags.size && !(flags.size === 1 && silent)) return err('Only root can do that.', 1);
      const [old, a, b] = readSecret(ctx, silent, ['Old SMB password:', 'New SMB password:', 'Retype new SMB password:']);
      const e = db[ctx.user.name];
      if (!e || e.password !== old) return err(`Could not connect to machine 127.0.0.1: NT_STATUS_LOGON_FAILURE\nFailed to change password for ${ctx.user.name}`, 1);
      if (a !== b) return err('Mismatch - password unchanged.\nUnable to get new password.', 1);
      e.password = a;
      return ok(`Password changed for user ${ctx.user.name}`);
    }
    if (!name) return err('Usage: smbpasswd [options] [username]', 1);
    if (flags.has('x')) {
      if (!db[name]) return err(`Failed to find entry for user ${name}.\nFailed to delete entry for user ${name}.`, 1);
      delete db[name];
      return ok(`Deleted user ${name}.`);
    }
    if (flags.has('d') || flags.has('e')) {
      if (!db[name]) return err(`Failed to find entry for user ${name}.`, 1);
      db[name].disabled = flags.has('d');
      return ok(`${flags.has('d') ? 'Disabled' : 'Enabled'} user ${name}.`);
    }
    if (!flags.has('a') && !db[name]) return err(`Failed to find entry for user ${name}.\nFailed to modify password entry for user ${name}`, 1);
    const [a, b] = readSecret(ctx, silent, ['New SMB password:', 'Retype new SMB password:']);
    if (a !== b) return err('Mismatch - password unchanged.\nUnable to get new password.', 1);
    if (!ctx.host.users[name]) return err(`Failed to add entry for user ${name}.`, 1);
    const added = !db[name];
    db[name] = { name, password: a, disabled: db[name]?.disabled ?? false };
    return ok(added ? `Added user ${name}.` : '');
  },
};

const pdbedit: CommandDef = {
  name: 'pdbedit',
  summary: 'list Samba\'s user database (-L, -v for details)',
  usage: 'pdbedit -L [-v]',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('Username not found!\nFailed to open the passdb backend (permission denied on /var/lib/samba/private/passdb.tdb).', 1);
    if (!args.some((a) => /^-\w*L/.test(a) || a === '--list')) return err('pdbedit: this simulator supports -L (list) and -L -v', 1);
    const verbose = args.some((a) => /^-\w*v/.test(a) || a === '--verbose');
    const entries = Object.values(passdb(ctx.host)).sort((x, y) => x.name.localeCompare(y.name));
    if (!verbose) return ok(entries.map((e) => `${e.name}:${ctx.host.users[e.name]?.uid ?? -1}:${ctx.host.users[e.name]?.gecos ?? ''}`).join('\n'));
    return ok(entries.map((e) => ['---------------', `Unix username:        ${e.name}`, 'NT username:          ', `Account Flags:        [${e.disabled ? 'DU' : 'U '}         ]`, `Full Name:            ${ctx.host.users[e.name]?.gecos ?? ''}`, `Home Directory:       \\\\${ctx.host.hostname.toUpperCase()}\\${e.name}`].join('\n')).join('\n'));
  },
};

const BOOL_PARAMS = new Set(['read only', 'guest ok', 'browseable', 'available', 'inherit permissions', 'obey pam restrictions', 'unix password sync', 'pam password change', 'usershare allow guests', 'bind interfaces only', 'load printers', 'disable spoolss']);

const testparm: CommandDef = {
  name: 'testparm',
  summary: 'check /etc/samba/smb.conf and show the effective share definitions',
  usage: 'testparm [-s]',
  run(args, ctx) {
    const text = readFile(ctx.host, SMB_CONF);
    if (text === undefined) return err(`Load smb config files from ${SMB_CONF}\nError loading services.`, 1);
    const conf = loadSmbConf(ctx.host);
    // testparm -s lists only parameters that differ from the defaults.
    const DEFAULTS: Record<string, string> = { 'read only': 'Yes', browseable: 'Yes', 'guest ok': 'No', available: 'Yes' };
    const shown = (k: string, v: string) => !(BOOL_PARAMS.has(k) && DEFAULTS[k] === (boolValue(v) ? 'Yes' : 'No'));
    const show = (k: string, v: string) => `\t${k} = ${BOOL_PARAMS.has(k) ? (boolValue(v) ? 'Yes' : 'No') : v}`;
    const out = [`Load smb config files from ${SMB_CONF}`];
    for (const u of conf.unknown) out.push(`Unknown parameter encountered: "${u.name}"`, `Ignoring unknown parameter "${u.name}"`);
    out.push('Loaded services file OK.', 'Weak crypto is allowed by GnuTLS (e.g. NTLM as a compatibility fallback)', '', `Server role: ${(conf.global['server role'] ?? 'standalone server').toLowerCase().includes('standalone') ? 'ROLE_STANDALONE' : 'ROLE_' + (conf.global['server role'] ?? '').toUpperCase().replace(/\s+/g, '_')}`, '');
    if (!args.includes('-s') && !args.includes('--suppress-prompt')) out.push('Press enter to see a dump of your service definitions', '');
    out.push('# Global parameters', '[global]', ...Object.entries(conf.global).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => show(k, v)));
    for (const s of conf.shares) out.push('', '', `[${s.name}]`, ...Object.entries(s.params).filter(([k, v]) => shown(k, v)).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => show(k, v)));
    return ok(out.join('\n'));
  },
};

const smbstatus: CommandDef = {
  name: 'smbstatus',
  summary: 'show current Samba connections (mapped drives of Windows clients)',
  usage: 'smbstatus [-S]',
  run(_args, ctx) {
    if (ctx.user.uid !== 0) return err('smbstatus only works as root!', 1);
    if (ctx.host.services.smbd?.state !== 'active') return err('Samba version ' + SAMBA_VERSION + '\nsmbd not running', 1);
    const rows = Object.values(ctx.world.hosts).flatMap((h) => (h.win?.smbMappings ?? []).filter((m) => m.server === ctx.host.id).map((m) => ({ h, m })));
    const pidBase = ctx.host.services.smbd.pid ?? 900;
    const out = ['', `Samba version ${SAMBA_VERSION}`, 'PID     Username     Group        Machine                                   Protocol Version  Encryption           Signing              ', '-'.repeat(136)];
    rows.forEach(({ h, m }, i) => {
      const u = ctx.host.users[m.user];
      out.push(`${String(pidBase + 10 + i).padEnd(8)}${m.user.padEnd(13)}${(u?.primaryGroup ?? '').padEnd(13)}${`${h.win!.adapters[0]?.address ?? ''} (ipv4:${h.win!.adapters[0]?.address ?? ''}:${49700 + i})`.padEnd(42)}SMB3_11           -                    partial(AES-128-GMAC)`);
    });
    out.push('', 'Service      pid     Machine       Connected at                     Encryption   Signing     ', '-'.repeat(93));
    rows.forEach(({ h, m }, i) => out.push(`${m.share.padEnd(13)}${String(pidBase + 10 + i).padEnd(8)}${(h.win!.adapters[0]?.address ?? '').padEnd(14)}${new Date(Math.floor(ctx.world.clock)).toUTCString().padEnd(33)}-            -           `));
    out.push('', 'No locked files', '');
    return ok(out.join('\n'));
  },
};

export const SMB_COMMANDS: CommandDef[] = [smbclient, smbpasswd, pdbedit, testparm, smbstatus];
