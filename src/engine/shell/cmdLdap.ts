// OpenLDAP 2.5 client tools as Debian 12 ships them (ldap-utils): ldapsearch
// and ldapwhoami, with /etc/ldap/ldap.conf (URI, BASE, TLS_CACERT,
// TLS_REQCERT), simple binds (-x), StartTLS (-ZZ), LDIF output and the error
// texts libldap prints.

import { type LdapClientConf, type LdapError, type LdapSession, clientConf, ldapBind, ldapConnect, ldapSearch, ldifLine, parseFilter, parseLdapUri, type Scope } from '../sim/ldap';
import { getFile, resolvePath } from './cmdFiles';
import { type CmdCtx, type CommandDef, err, ok } from './types';

interface Opts { flags: Map<string, string | true>; rest: string[]; bad?: string }

/** getopt as the OpenLDAP tools use it: single-letter options, values attached or separate, -LLL counted. */
function ldapOpts(args: string[], withValue: string): Opts {
  const flags = new Map<string, string | true>();
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('-') || a === '-') { rest.push(a); continue; }
    for (let j = 1; j < a.length; j++) {
      const c = a[j];
      if (withValue.includes(c)) {
        const v = a.slice(j + 1) || args[++i];
        if (v === undefined) return { flags, rest, bad: `${c}` };
        flags.set(c, v);
        break;
      }
      if (c === 'L' || c === 'Z') flags.set(c, String(Number(flags.get(c) ?? 0) + 1));
      else if ('xWvnNcMuTt'.includes(c)) flags.set(c, true);
      else return { flags, rest, bad: c };
    }
  }
  return { flags, rest };
}

/** "# Alice Martin, Users, ad.corp.lab": the RDN values, with the DC components joined by dots. */
function entryComment(dn: string): string {
  if (!dn) return '';
  const parts = dn.split(/,(?=[A-Za-z]+=)/);
  const dcs = parts.filter((p) => /^dc=/i.test(p)).map((p) => p.slice(3));
  return [...parts.filter((p) => !/^dc=/i.test(p)).map((p) => p.replace(/^[^=]+=/, '')), dcs.join('.')].filter(Boolean).join(', ');
}

const errText = (prefix: string, e: LdapError) => `${prefix}: ${e.name} (${e.code})${e.info ? `\n\tadditional info: ${e.info}` : ''}`;

/** Connect and bind as the tools do: -x simple bind, otherwise SASL (which needs Kerberos or EXTERNAL). */
type Opened = { session: LdapSession; conf: LdapClientConf; warn?: string } | { out: string; code: number };

function openAndBind(ctx: CmdCtx, o: Opts, prog: string): Opened {
  const conf = clientConf(ctx.host, ctx.user.home);
  const uriText = (o.flags.get('H') as string | undefined) ?? conf.uri;
  if (!uriText) return { out: `${prog}: ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)`.replace(`${prog}: `, ''), code: 255 };
  const uri = parseLdapUri(uriText);
  if (!uri) return { out: `Could not parse LDAP URI(s)=${uriText} (3)`, code: 1 };
  const startTls = Number(o.flags.get('Z') ?? 0);
  const c = ldapConnect(ctx.world, ctx.host, uri, conf, startTls > 0 && uri.scheme === 'ldap');
  if ('error' in c) {
    if (c.error.code === -11) {
      // -Z continues without TLS; -ZZ requires it.
      if (startTls === 1) {
        const plain = ldapConnect(ctx.world, ctx.host, uri, conf, false);
        if ('error' in plain) return { out: errText('ldap_sasl_bind(SIMPLE)', plain.error), code: 255 };
        return finishBind(ctx, o, prog, plain.session, conf, `${errText('ldap_start_tls', c.error)}`);
      }
      return { out: errText('ldap_start_tls', c.error), code: 1 };
    }
    return { out: errText('ldap_sasl_bind(SIMPLE)', c.error), code: 255 };
  }
  return finishBind(ctx, o, prog, c.session, conf);
}

function finishBind(ctx: CmdCtx, o: Opts, _prog: string, session: LdapSession, conf: LdapClientConf, warn?: string): Opened {
  if (!o.flags.has('x')) {
    return { out: `${warn ? warn + '\n' : ''}SASL/GSS-SPNEGO authentication started\nldap_sasl_interactive_bind: Local error (-2)\n\tadditional info: SASL(-1): generic failure: GSSAPI Error: Unspecified GSS failure.  Minor code may provide more information (No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_${ctx.user.uid}))`, code: 254 };
  }
  const dn = (o.flags.get('D') as string | undefined) ?? conf.binddn ?? '';
  let pw = (o.flags.get('w') as string | undefined) ?? '';
  if (o.flags.has('W')) pw = ctx.ask('Enter LDAP Password: ', true);
  const yfile = o.flags.get('y') as string | undefined;
  if (yfile) {
    const f = getFile(ctx, resolvePath(ctx, yfile));
    if (f.error) return { out: `Could not open password file ${yfile}: ${f.error}`, code: 1 };
    pw = f.content!.replace(/\n$/, '');
  }
  const e = ldapBind(ctx.world, session, ctx.host, dn, pw);
  if (e) return { out: `${warn ? warn + '\n' : ''}${errText('ldap_bind', e)}`, code: e.code };
  return { session, conf, ...(warn ? { warn } : {}) };
}

const ldapsearch: CommandDef = {
  name: 'ldapsearch',
  summary: 'LDAP search tool',
  usage: 'ldapsearch -x [-H URI] [-D binddn] [-w passwd | -W | -y file] [-ZZ] [-b base] [-s base|one|sub|children] [-LLL] [filter [attrs...]]',
  run(args, ctx) {
    const o = ldapOpts(args, 'HDwybsoazlhpePfE');
    if (o.bad) return err(`ldapsearch: invalid option -- '${o.bad}'\nldapsearch: unrecognized option -${o.bad}\nusage: ldapsearch [options] [filter [attributes...]]`, 1);
    const r = openAndBind(ctx, o, 'ldapsearch');
    if ('out' in r) return { out: r.out, code: r.code };
    const ldif = Number(o.flags.get('L') ?? 0);
    const base = (o.flags.get('b') as string | undefined) ?? r.conf.base ?? '';
    const scopeArg = ((o.flags.get('s') as string | undefined) ?? 'sub').toLowerCase();
    const scope: Scope | null = scopeArg === 'base' ? 'base' : scopeArg === 'one' || scopeArg === 'onelevel' ? 'one' : scopeArg === 'sub' || scopeArg === 'subtree' ? 'sub' : scopeArg === 'children' ? 'children' : null;
    if (!scope) return err(`scope should be base, one, sub or children`, 1);
    const filterText = o.rest[0] ?? '(objectclass=*)';
    const attrs = o.rest.slice(1);
    const filter = parseFilter(filterText);
    if (!filter) return err('ldapsearch: ldap_search_ext: Bad search filter (-7)', 255);
    const res = ldapSearch(r.session, base, scope, filter, attrs, /:3268$/.test(String(o.flags.get('H') ?? '')));
    const out: string[] = [];
    const warn = r.warn;
    if (warn) out.push(warn);
    if (ldif < 1) out.push('# extended LDIF', '#', '# LDAPv3', `# base <${base}>${r.conf.base && !o.flags.has('b') ? ' (default)' : ''} with scope ${scope === 'sub' ? 'subtree' : scope === 'one' ? 'oneLevel' : scope === 'base' ? 'baseObject' : 'children'}`, `# filter: ${filterText.startsWith('(') ? filterText : `(${filterText})`}`, `# requesting: ${attrs.length ? attrs.join(' ') + ' ' : 'ALL'}`, '#', '');
    if (ldif < 2 && ldif > 0) out.push('version: 1', '');
    if (res.error && ldif >= 1) {
      // With -L/-LL/-LLL the error goes to standard error in the tool's short form.
      // ldapsearch's print_result(): the result, then "Matched DN:" and "Additional information:".
      out.push(`${res.error.name} (${res.error.code})`);
      if (res.error.matched) out.push(`Matched DN: ${res.error.matched}`);
      if (res.error.info) out.push(`Additional information: ${res.error.info}`);
      return { out: out.join('\n').replace(/\n+$/, ''), code: res.error.code };
    }
    for (const e of res.entries) {
      if (ldif < 1) out.push(`# ${entryComment(e.dn)}`);
      out.push(e.dn === '' ? 'dn:' : ldifLine('dn', e.dn));
      for (const [k, vs] of Object.entries(e.attrs)) for (const v of vs) out.push(ldifLine(k, v));
      out.push('');
    }
    for (const ref of res.refs) {
      if (ldif < 1) out.push('# search reference', `ref: ${ref}`, '');
      else out.push(`# refldap://${ref.replace(/^ldap:\/\//, '')}`, '');
    }
    if (ldif < 1) {
      out.push('# search result', 'search: 2', `result: ${res.error ? `${res.error.code} ${res.error.name}` : '0 Success'}`);
      if (res.error?.matched) out.push(`matchedDN: ${res.error.matched}`);
      if (res.error?.info) out.push(`text: ${res.error.info}`);
      out.push('', `# numResponses: ${res.entries.length + res.refs.length + 1}`);
      if (res.entries.length) out.push(`# numEntries: ${res.entries.length}`);
      if (res.refs.length) out.push(`# numReferences: ${res.refs.length}`);
    }
    return { out: out.join('\n').replace(/\n+$/, ''), code: res.error ? res.error.code : 0 };
  },
};

const ldapwhoami: CommandDef = {
  name: 'ldapwhoami',
  summary: 'LDAP who am i? tool',
  usage: 'ldapwhoami -x [-H URI] [-D binddn] [-w passwd | -W | -y file] [-ZZ]',
  run(args, ctx) {
    const o = ldapOpts(args, 'HDwyoe');
    if (o.bad) return err(`ldapwhoami: invalid option -- '${o.bad}'`, 1);
    const r = openAndBind(ctx, o, 'ldapwhoami');
    if ('out' in r) return { out: r.out, code: r.code };
    const ad = r.session.dc.win!.ad!;
    return ok(r.session.bound ? `u:${ad.netbios}\\${r.session.bound}` : 'anonymous');
  },
};

export const LDAP_COMMANDS: CommandDef[] = [ldapsearch, ldapwhoami];
