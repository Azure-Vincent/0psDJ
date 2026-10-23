// sshd_config parser modelled on OpenSSH 9.2 (Debian 12) servconf.c semantics:
//  * keywords are case-insensitive, arguments are not;
//  * for most keywords the FIRST obtained value wins (later duplicates are ignored);
//  * Port, ListenAddress, HostKey, AllowUsers/DenyUsers/AllowGroups/DenyGroups,
//    AcceptEnv and Subsystem accumulate;
//  * `Include` is expanded in place (glob on the directory, lexical order);
//  * `Match` starts a conditional block that lasts until the next Match or EOF.
//    Supported criteria: User, Group, Address, All (others are accepted but never match).

import { inCidr, parseCidr } from '../net/ip';

export const SUPPORTED_KEX = [
  'sntrup761x25519-sha512@openssh.com',
  'curve25519-sha256',
  'curve25519-sha256@libssh.org',
  'ecdh-sha2-nistp256',
  'ecdh-sha2-nistp384',
  'ecdh-sha2-nistp521',
  'diffie-hellman-group-exchange-sha256',
  'diffie-hellman-group16-sha512',
  'diffie-hellman-group18-sha512',
  'diffie-hellman-group14-sha256',
  'diffie-hellman-group14-sha1',
  'diffie-hellman-group1-sha1',
  'diffie-hellman-group-exchange-sha1',
];
export const DEFAULT_KEX = SUPPORTED_KEX.slice(0, 10);

export const SUPPORTED_CIPHERS = [
  'chacha20-poly1305@openssh.com',
  'aes128-ctr',
  'aes192-ctr',
  'aes256-ctr',
  'aes128-gcm@openssh.com',
  'aes256-gcm@openssh.com',
  'aes128-cbc',
  'aes192-cbc',
  'aes256-cbc',
  '3des-cbc',
];
export const DEFAULT_CIPHERS = SUPPORTED_CIPHERS.slice(0, 6);

export const SUPPORTED_MACS = [
  'umac-64-etm@openssh.com',
  'umac-128-etm@openssh.com',
  'hmac-sha2-256-etm@openssh.com',
  'hmac-sha2-512-etm@openssh.com',
  'hmac-sha1-etm@openssh.com',
  'umac-64@openssh.com',
  'umac-128@openssh.com',
  'hmac-sha2-256',
  'hmac-sha2-512',
  'hmac-sha1',
];
export const DEFAULT_MACS = SUPPORTED_MACS;

const FLAG_KEYS = new Set([
  'strictmodes', 'pubkeyauthentication', 'passwordauthentication', 'permitemptypasswords',
  'kbdinteractiveauthentication', 'challengeresponseauthentication', 'usepam', 'x11forwarding',
  'printmotd', 'printlastlog', 'tcpkeepalive', 'usedns', 'hostbasedauthentication',
  'ignorerhosts', 'ignoreuserknownhosts', 'kerberosauthentication', 'gssapiauthentication',
  'gssapicleanupcredentials', 'gssapistrictacceptorcheck', 'permittty', 'allowagentforwarding', 'x11uselocalhost',
  'kerberosorlocalpasswd', 'kerberosticketcleanup', 'compression', 'permituserenvironment',
  'disableforwarding', 'exposeauthinfo',
]);

const LIST_KEYS = new Set([
  'port', 'listenaddress', 'hostkey', 'allowusers', 'denyusers', 'allowgroups', 'denygroups',
  'acceptenv', 'subsystem', 'authorizedkeysfile',
]);

const OTHER_KEYS = new Set([
  'include', 'addressfamily', 'rekeylimit', 'syslogfacility', 'loglevel', 'logingracetime',
  'permitrootlogin', 'maxauthtries', 'maxsessions', 'authorizedprincipalsfile',
  'authorizedkeyscommand', 'authorizedkeyscommanduser', 'allowtcpforwarding', 'allowstreamlocalforwarding',
  'gatewayports', 'x11displayoffset', 'clientaliveinterval', 'clientalivecountmax', 'pidfile',
  'maxstartups', 'permittunnel', 'chrootdirectory', 'versionaddendum', 'banner', 'match',
  'forcecommand', 'ciphers', 'macs', 'kexalgorithms', 'hostkeyalgorithms', 'pubkeyacceptedalgorithms',
  'pubkeyacceptedkeytypes', 'casignaturealgorithms', 'authenticationmethods', 'permitopen',
  'permitlisten', 'trustedusercakeys', 'revokedkeys', 'hostcertificate', 'ipqos', 'streamlocalbindmask',
  'streamlocalbindunlink', 'fingerprinthash', 'moduli', 'securitykeyprovider', 'setenv', 'logverbose',
  'requiredrsasize', 'channeltimeout', 'unusedconnectiontimeout', 'pubkeyauthoptions',
]);

export const LOG_LEVELS = ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3'];

export interface Directive {
  key: string; // lower-case keyword
  keyword: string; // as written
  args: string[];
  file: string;
  line: number;
}

export interface MatchBlock {
  criteria: { kind: string; values: string[] }[];
  directives: Directive[];
  file: string;
  line: number;
}

export interface ParseError {
  file: string;
  line: number;
  message: string;
}

export interface ParsedSshdConfig {
  global: Directive[];
  matches: MatchBlock[];
  errors: ParseError[];
}

export interface SshdEffective {
  ports: number[];
  listenAddresses: string[]; // "addr" or "addr:port"
  addressFamily: string;
  hostKeys: string[];
  logLevel: string;
  loginGraceTime: number;
  permitRootLogin: string;
  strictModes: boolean;
  maxAuthTries: number;
  pubkeyAuthentication: boolean;
  authorizedKeysFiles: string[];
  passwordAuthentication: boolean;
  permitEmptyPasswords: boolean;
  kbdInteractiveAuthentication: boolean;
  gssapiAuthentication: boolean;
  gssapiStrictAcceptorCheck: boolean;
  usePAM: boolean;
  allowUsers: string[];
  denyUsers: string[];
  allowGroups: string[];
  denyGroups: string[];
  kexAlgorithms: string[];
  ciphers: string[];
  macs: string[];
  x11Forwarding: boolean;
  printMotd: boolean;
  banner: string;
  useDNS: boolean;
  authenticationMethods: string;
  subsystems: string[];
  clientAliveInterval: number;
  allowTcpForwarding: string;
}

export const COMPILED_DEFAULTS: SshdEffective = {
  ports: [22],
  listenAddresses: [],
  addressFamily: 'any',
  hostKeys: [],
  logLevel: 'INFO',
  loginGraceTime: 120,
  permitRootLogin: 'prohibit-password',
  strictModes: true,
  maxAuthTries: 6,
  pubkeyAuthentication: true,
  authorizedKeysFiles: ['.ssh/authorized_keys', '.ssh/authorized_keys2'],
  passwordAuthentication: true,
  permitEmptyPasswords: false,
  kbdInteractiveAuthentication: true,
  gssapiAuthentication: false,
  gssapiStrictAcceptorCheck: true,
  usePAM: false,
  allowUsers: [],
  denyUsers: [],
  allowGroups: [],
  denyGroups: [],
  kexAlgorithms: DEFAULT_KEX,
  ciphers: DEFAULT_CIPHERS,
  macs: DEFAULT_MACS,
  x11Forwarding: false,
  printMotd: true,
  banner: 'none',
  useDNS: false,
  authenticationMethods: 'any',
  subsystems: [],
  clientAliveInterval: 0,
  allowTcpForwarding: 'yes',
};

/** Tokenise a config line, honouring double quotes. */
function tokenize(line: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2]);
  return out;
}

function globToRegExp(glob: string): RegExp {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]');
  return new RegExp('^' + esc + '$');
}

/**
 * Parse sshd_config. `readFile` resolves Include targets; `listFiles` lists
 * absolute file paths (used for glob expansion).
 */
export function parseSshdConfig(
  path: string,
  readFile: (p: string) => string | undefined,
  listFiles: () => string[],
): ParsedSshdConfig {
  const result: ParsedSshdConfig = { global: [], matches: [], errors: [] };
  let currentMatch: MatchBlock | null = null;

  const parseFile = (file: string, depth: number) => {
    const text = readFile(file);
    if (text === undefined) return;
    text.split('\n').forEach((raw, idx) => {
      const lineNo = idx + 1;
      const line = raw.replace(/\r$/, '');
      const trimmed = line.trim();
      if (trimmed === '' || trimmed.startsWith('#')) return;
      // Allow "Keyword=value"
      const eq = /^(\S+?)\s*=\s*(.*)$/.exec(trimmed);
      const tokens = eq && !/\s/.test(eq[1]) ? [eq[1], ...tokenize(eq[2])] : tokenize(trimmed);
      const keyword = tokens[0];
      const key = keyword.toLowerCase();
      const args = tokens.slice(1);
      const err = (message: string) => result.errors.push({ file, line: lineNo, message });

      if (!FLAG_KEYS.has(key) && !LIST_KEYS.has(key) && !OTHER_KEYS.has(key)) {
        err(`Bad configuration option: ${keyword}`);
        return;
      }
      if (key === 'include') {
        if (depth > 8) return err('Too many recursive configuration includes');
        for (const pattern of args) {
          const re = globToRegExp(pattern);
          const files = listFiles().filter((f) => re.test(f)).sort();
          for (const f of files) parseFile(f, depth + 1);
        }
        return;
      }
      if (key === 'match') {
        const criteria: MatchBlock['criteria'] = [];
        for (let i = 0; i < args.length; i++) {
          const kind = args[i].toLowerCase();
          if (kind === 'all') {
            criteria.push({ kind, values: [] });
            continue;
          }
          const v = args[i + 1];
          if (v === undefined) return err(`Missing Match criteria for ${args[i]}`);
          criteria.push({ kind, values: v.split(',') });
          i++;
        }
        currentMatch = { criteria, directives: [], file, line: lineNo };
        result.matches.push(currentMatch);
        return;
      }
      if (args.length === 0) return err(`${keyword}: missing argument.`);

      // Value validation (subset mirroring servconf.c error messages)
      if (FLAG_KEYS.has(key) && !['yes', 'no'].includes(args[0])) {
        return err(`unsupported option "${args[0]}".`);
      }
      if (key === 'port') {
        const n = Number(args[0]);
        if (!Number.isInteger(n) || n < 1 || n > 65535) return err('Badly formatted port number.');
      }
      if (key === 'loglevel' && !LOG_LEVELS.includes(args[0].toUpperCase())) {
        return err(`unsupported log level '${args[0]}'`);
      }
      if (key === 'permitrootlogin' && !['yes', 'no', 'prohibit-password', 'without-password', 'forced-commands-only'].includes(args[0])) {
        return err(`unsupported option "${args[0]}".`);
      }
      if (key === 'maxauthtries' && !/^\d+$/.test(args[0])) return err('Invalid number.');
      if (['kexalgorithms', 'ciphers', 'macs'].includes(key)) {
        const supported = key === 'kexalgorithms' ? SUPPORTED_KEX : key === 'ciphers' ? SUPPORTED_CIPHERS : SUPPORTED_MACS;
        const names = args[0].replace(/^[+\-^]/, '').split(',');
        const bad = names.find((n) => !n.includes('*') && !supported.includes(n));
        const label = key === 'kexalgorithms' ? 'KexAlgorithms' : key === 'ciphers' ? 'ciphers' : 'MACs';
        if (bad) return err(`Bad SSH2 ${label} '${args[0]}'.`);
      }

      const d: Directive = { key, keyword, args, file, line: lineNo };
      if (currentMatch) (currentMatch as MatchBlock).directives.push(d);
      else result.global.push(d);
    });
  };

  parseFile(path, 0);
  // A Match block opened in an included file ends at the end of that file in
  // real sshd; our blocks are tracked globally which is equivalent for the
  // configs used by the labs (Match blocks live at the end of the main file).
  return result;
}

function applyAlgList(current: string[], spec: string, supported: string[]): string[] {
  const names = spec.slice(/^[+\-^]/.test(spec) ? 1 : 0).split(',');
  const expand = (n: string) => (n.includes('*') ? supported.filter((s) => globToRegExp(n).test(s)) : [n]);
  const list = names.flatMap(expand);
  if (spec.startsWith('+')) return [...current, ...list.filter((n) => !current.includes(n))];
  if (spec.startsWith('-')) return current.filter((n) => !list.includes(n));
  if (spec.startsWith('^')) return [...list, ...current.filter((n) => !list.includes(n))];
  return list;
}

function applyDirectives(eff: SshdEffective, directives: Directive[], seen: Set<string>): void {
  const yes = (d: Directive) => d.args[0] === 'yes';
  for (const d of directives) {
    if (LIST_KEYS.has(d.key)) {
      switch (d.key) {
        case 'port':
          if (!seen.has('port')) eff.ports = [];
          eff.ports.push(Number(d.args[0]));
          break;
        case 'listenaddress':
          eff.listenAddresses.push(d.args[0]);
          break;
        case 'hostkey':
          eff.hostKeys.push(d.args[0]);
          break;
        case 'allowusers':
          eff.allowUsers.push(...d.args);
          break;
        case 'denyusers':
          eff.denyUsers.push(...d.args);
          break;
        case 'allowgroups':
          eff.allowGroups.push(...d.args);
          break;
        case 'denygroups':
          eff.denyGroups.push(...d.args);
          break;
        case 'subsystem':
          eff.subsystems.push(d.args.join(' '));
          break;
        case 'authorizedkeysfile':
          if (!seen.has('authorizedkeysfile')) eff.authorizedKeysFiles = d.args;
          break;
      }
      seen.add(d.key);
      continue;
    }
    if (seen.has(d.key)) continue; // first obtained value wins
    seen.add(d.key);
    switch (d.key) {
      case 'addressfamily': eff.addressFamily = d.args[0]; break;
      case 'loglevel': eff.logLevel = d.args[0].toUpperCase(); break;
      case 'logingracetime': eff.loginGraceTime = parseInt(d.args[0], 10); break;
      case 'permitrootlogin': eff.permitRootLogin = d.args[0] === 'without-password' ? 'prohibit-password' : d.args[0]; break;
      case 'strictmodes': eff.strictModes = yes(d); break;
      case 'maxauthtries': eff.maxAuthTries = Number(d.args[0]); break;
      case 'pubkeyauthentication': eff.pubkeyAuthentication = yes(d); break;
      case 'passwordauthentication': eff.passwordAuthentication = yes(d); break;
      case 'permitemptypasswords': eff.permitEmptyPasswords = yes(d); break;
      case 'kbdinteractiveauthentication':
      case 'challengeresponseauthentication':
        eff.kbdInteractiveAuthentication = yes(d);
        seen.add('kbdinteractiveauthentication');
        seen.add('challengeresponseauthentication');
        break;
      case 'usepam': eff.usePAM = yes(d); break;
      case 'gssapiauthentication': eff.gssapiAuthentication = yes(d); break;
      case 'gssapistrictacceptorcheck': eff.gssapiStrictAcceptorCheck = yes(d); break;
      case 'kexalgorithms': eff.kexAlgorithms = applyAlgList(DEFAULT_KEX, d.args[0], SUPPORTED_KEX); break;
      case 'ciphers': eff.ciphers = applyAlgList(DEFAULT_CIPHERS, d.args[0], SUPPORTED_CIPHERS); break;
      case 'macs': eff.macs = applyAlgList(DEFAULT_MACS, d.args[0], SUPPORTED_MACS); break;
      case 'x11forwarding': eff.x11Forwarding = yes(d); break;
      case 'printmotd': eff.printMotd = yes(d); break;
      case 'banner': eff.banner = d.args[0]; break;
      case 'usedns': eff.useDNS = yes(d); break;
      case 'authenticationmethods': eff.authenticationMethods = d.args.join(' '); break;
      case 'clientaliveinterval': eff.clientAliveInterval = parseInt(d.args[0], 10); break;
      case 'allowtcpforwarding': eff.allowTcpForwarding = d.args[0]; break;
    }
  }
}

function clone(e: SshdEffective): SshdEffective {
  return JSON.parse(JSON.stringify(e));
}

export interface MatchContext {
  user: string;
  groups: string[];
  address: string;
}

function matches(block: MatchBlock, ctx: MatchContext): boolean {
  return block.criteria.every((c) => {
    const anyGlob = (vals: string[], subject: string) =>
      vals.some((v) => (v.startsWith('!') ? false : globToRegExp(v).test(subject))) &&
      !vals.some((v) => v.startsWith('!') && globToRegExp(v.slice(1)).test(subject));
    switch (c.kind) {
      case 'all': return true;
      case 'user': return anyGlob(c.values, ctx.user);
      case 'group': return ctx.groups.some((g) => anyGlob(c.values, g));
      case 'address':
        return c.values.some((v) => {
          const cidr = parseCidr(v);
          return cidr ? inCidr(ctx.address, cidr) : globToRegExp(v).test(ctx.address);
        });
      default: return false;
    }
  });
}

/** Effective server-wide configuration (what `sshd -T` prints with no -C). */
export function effectiveConfig(parsed: ParsedSshdConfig, ctx?: MatchContext): SshdEffective {
  const eff = clone(COMPILED_DEFAULTS);
  const seen = new Set<string>();
  applyDirectives(eff, parsed.global, seen);
  if (eff.hostKeys.length === 0) {
    eff.hostKeys = ['/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_ecdsa_key', '/etc/ssh/ssh_host_ed25519_key'];
  }
  if (ctx) {
    const mseen = new Set<string>();
    for (const block of parsed.matches) {
      if (!matches(block, ctx)) continue;
      // Match directives override global values; within matches, first wins.
      const overlay = clone(eff);
      const listReset = new Set<string>();
      for (const d of block.directives) {
        if (mseen.has(d.key) && !LIST_KEYS.has(d.key)) continue;
        if (LIST_KEYS.has(d.key) && !listReset.has(d.key)) {
          listReset.add(d.key);
        }
        mseen.add(d.key);
        applyDirectives(overlay, [d], new Set());
      }
      Object.assign(eff, overlay);
    }
  }
  return eff;
}

/** Render effective config in `sshd -T` style (subset of keys used in lessons). */
export function renderSshdT(eff: SshdEffective): string {
  const yn = (b: boolean) => (b ? 'yes' : 'no');
  const lines: string[] = [];
  for (const p of eff.ports) lines.push(`port ${p}`);
  lines.push(`addressfamily ${eff.addressFamily}`);
  const la = eff.listenAddresses.length ? eff.listenAddresses : ['[::]', '0.0.0.0'];
  for (const a of la) for (const p of eff.ports) lines.push(`listenaddress ${a.includes(':') && !a.startsWith('[') ? a : `${a}:${p}`}`);
  lines.push(`loglevel ${eff.logLevel}`);
  lines.push(`logingracetime ${eff.loginGraceTime}`);
  lines.push(`permitrootlogin ${eff.permitRootLogin}`);
  lines.push(`strictmodes ${yn(eff.strictModes)}`);
  lines.push(`maxauthtries ${eff.maxAuthTries}`);
  lines.push(`pubkeyauthentication ${yn(eff.pubkeyAuthentication)}`);
  lines.push(`authorizedkeysfile ${eff.authorizedKeysFiles.join(' ')}`);
  lines.push(`passwordauthentication ${yn(eff.passwordAuthentication)}`);
  lines.push(`permitemptypasswords ${yn(eff.permitEmptyPasswords)}`);
  lines.push(`kbdinteractiveauthentication ${yn(eff.kbdInteractiveAuthentication)}`);
  lines.push(`gssapiauthentication ${yn(eff.gssapiAuthentication)}`);
  lines.push(`gssapistrictacceptorcheck ${yn(eff.gssapiStrictAcceptorCheck)}`);
  lines.push(`usepam ${yn(eff.usePAM)}`);
  lines.push(`x11forwarding ${yn(eff.x11Forwarding)}`);
  lines.push(`printmotd ${yn(eff.printMotd)}`);
  lines.push(`usedns ${yn(eff.useDNS)}`);
  lines.push(`clientaliveinterval ${eff.clientAliveInterval}`);
  lines.push(`allowtcpforwarding ${eff.allowTcpForwarding}`);
  lines.push(`banner ${eff.banner}`);
  lines.push(`authenticationmethods ${eff.authenticationMethods}`);
  for (const h of eff.hostKeys) lines.push(`hostkey ${h}`);
  if (eff.allowUsers.length) lines.push(`allowusers ${eff.allowUsers.join(' ')}`);
  if (eff.denyUsers.length) lines.push(`denyusers ${eff.denyUsers.join(' ')}`);
  if (eff.allowGroups.length) lines.push(`allowgroups ${eff.allowGroups.join(' ')}`);
  if (eff.denyGroups.length) lines.push(`denygroups ${eff.denyGroups.join(' ')}`);
  for (const s of eff.subsystems) lines.push(`subsystem ${s}`);
  lines.push(`kexalgorithms ${eff.kexAlgorithms.join(',')}`);
  lines.push(`ciphers ${eff.ciphers.join(',')}`);
  lines.push(`macs ${eff.macs.join(',')}`);
  return lines.join('\n');
}

export function formatErrors(errors: ParseError[]): string[] {
  const lines = errors.map((e) => `${e.file} line ${e.line}: ${e.message}`);
  if (errors.length) lines.push(`${errors[0].file}: terminating, ${errors.length} bad configuration options`);
  return lines;
}
