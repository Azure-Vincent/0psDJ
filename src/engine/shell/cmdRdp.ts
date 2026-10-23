// xfreerdp (FreeRDP 2.10, Debian 12): the Remote Desktop client on the Linux
// machines. The simulator has no graphics, so a successful connection reports
// the session that Windows created and disconnects; every failure prints
// FreeRDP's own error names and exit codes.

import { mkdir, readFile, writeFile } from '../fs';
import { rdpConnect, rdpThumbprint, type RdpResult } from '../win/rdp';
import { resolvePath } from './cmdFiles';
import { type CommandDef, err, ok } from './types';

const ERR_CODES: Record<string, string> = {
  ERRCONNECT_DNS_NAME_NOT_FOUND: '0x00020005',
  ERRCONNECT_CONNECT_FAILED: '0x00020006',
  ERRCONNECT_CONNECT_TRANSPORT_FAILED: '0x0002000D',
  ERRCONNECT_LOGON_FAILURE: '0x00020014',
  ERRCONNECT_ACCOUNT_DISABLED: '0x00020012',
  ERRCONNECT_AUTHENTICATION_FAILED: '0x00020009',
  ERRCONNECT_ACCOUNT_LOCKED_OUT: '0x00020018',
};

// xfreerdp exit codes (client/X11/xfreerdp.h).
const EXIT: Record<string, number> = {
  ERRCONNECT_DNS_NAME_NOT_FOUND: 131, ERRCONNECT_CONNECT_FAILED: 131, ERRCONNECT_CONNECT_TRANSPORT_FAILED: 131,
  ERRCONNECT_LOGON_FAILURE: 132, ERRCONNECT_ACCOUNT_DISABLED: 132, ERRCONNECT_AUTHENTICATION_FAILED: 132, ERRCONNECT_ACCOUNT_LOCKED_OUT: 135, ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES: 9,
};

const USAGE = 'FreeRDP - A Free Remote Desktop Protocol Implementation\nSee www.freerdp.com for more information\n\nUsage: xfreerdp [file] [options] [/v:<server>[:port]]\n\nSyntax:\n    /flag (enables flag)\n    /option:<value> (specifies option with value)\n    +toggle -toggle (enables or disables toggle, where \'/\' is a synonym of \'+\')\n\n    /v:<server>[:port]    Server hostname\n    /u:[[<domain>\\]<user>|<user>[@<domain>]] Username\n    /p:<password>         Password\n    /d:<domain>           Domain\n    /cert:ignore          Ignore the certificate\n    +auth-only            Authenticate only';

const xfreerdp: CommandDef = {
  name: 'xfreerdp',
  summary: 'Remote Desktop (RDP) client: connect to a Windows host',
  usage: 'xfreerdp /v:HOST[:PORT] /u:USER [/p:PASSWORD] [/cert:ignore] [+auth-only]',
  run(args, ctx) {
    const opt = (n: string) => args.find((a) => a.toLowerCase().startsWith(`/${n}:`))?.slice(n.length + 2);
    const v = opt('v');
    if (!v) return args.length && !args.includes('--help') && !args.includes('/help') ? err(USAGE, 128) : ok(USAGE);
    const [target, portStr] = v.split(':');
    const port = Number(portStr ?? 3389);
    let user = opt('u') ?? ctx.user.name;
    const dom = opt('d');
    if (dom && !user.includes('\\')) user = `${dom}\\${user}`;
    const authOnly = args.some((a) => /^[+/]auth-only$/i.test(a));
    const ignoreCert = args.some((a) => /^\/cert[:-]ignore$/i.test(a) || a === '/cert-ignore');
    const t = () => {
      const d = new Date(ctx.world.clock);
      return `[${d.toISOString().slice(11, 19)}:${String(d.getUTCMilliseconds()).padStart(3, '0')}] [${ctx.world.counter % 30000 + 1200}:${ctx.world.counter % 30000 + 1201}]`;
    };
    const log = (level: string, tag: string, msg: string) => `${t()} [${level}][${tag}] - ${msg}`;
    const fail = (out: string[], r: RdpResult) => {
      const e = r.error!;
      if (e.startsWith('ERRINFO')) out.push(log('ERROR', 'com.freerdp.core', `${e} (0x00000009):The user cannot connect to the server due to insufficient access privileges.`));
      else out.push(log('ERROR', 'com.freerdp.core', `${r.stage === 'nla' ? 'nla_recv_pdu' : r.stage === 'dns' || r.stage === 'connect' ? 'freerdp_tcp_connect' : 'transport_connect_tls'}:freerdp_set_last_error_ex ${e} [${ERR_CODES[e]}]`));
      if (r.stage === 'nla') out.push(log('ERROR', 'com.freerdp.core.transport', 'BIO_read returned an error: 0'));
      out.push(log('ERROR', 'com.freerdp.client.x11', `Failed to connect, exit status ${EXIT[e] ?? 131}`).replace('Failed to connect, exit status 9', 'Disconnected, exit status 9'));
      return err(out.join('\n'), EXIT[e] ?? 131);
    };
    const password = opt('p') ?? ctx.ask('Password: ', true);
    const out: string[] = [];
    // The certificate prompt comes after the TLS handshake; replaying the line with the answer runs the same connection.
    const r = rdpConnect(ctx.world, ctx.host, target, port, user, password, { authOnly });
    if (r.stage === 'dns' || r.stage === 'connect' || r.stage === 'transport') return fail(out, r);
    const server = r.server!;
    const known = resolvePath(ctx, '~/.config/freerdp/known_hosts2');
    const print = rdpThumbprint(server);
    const entry = `${target} ${port} ${print}`;
    if (!ignoreCert && !(readFile(ctx.host, known) ?? '').split('\n').includes(entry)) {
      const cn = `${server.hostname.toUpperCase()}.corp.lab`;
      out.push(log('WARN', 'com.freerdp.crypto', `Certificate verification failure 'self-signed certificate (18)' at stack position 0`), log('WARN', 'com.freerdp.crypto', `CN = ${cn}`));
      const ans = ctx.ask([...out, `Certificate details for ${target}:${port} (RDP-Server):`, `\tCommon Name: ${cn}`, `\tSubject:     CN = ${cn}`, `\tIssuer:      CN = ${cn}`, `\tThumbprint:  ${print}`,
        'The above X.509 certificate could not be verified, possibly because you do not have', 'the CA certificate in your certificate store, or the certificate has expired.', 'Please look at the OpenSSL documentation on how to add a private CA to the store.', 'Do you trust the above certificate? (Y/T/N) '].join('\n'), false).trim().toLowerCase();
      if (ans !== 'y' && ans !== 't') {
        out.push(log('ERROR', 'com.freerdp.core', 'transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED [0x00020008]'), log('ERROR', 'com.freerdp.client.x11', 'Failed to connect, exit status 131'));
        return err(out.join('\n'), 131);
      }
      if (ans === 'y') {
        const dir = resolvePath(ctx, '~/.config/freerdp');
        for (const d of [resolvePath(ctx, '~/.config'), dir]) if (!ctx.host.fs[d]) mkdir(ctx.host, d, ctx.world.clock, { mode: 0o700, owner: ctx.user.name, group: ctx.user.primaryGroup });
        writeFile(ctx.host, known, (readFile(ctx.host, known) ?? '') + entry + '\n', ctx.world.clock, { owner: ctx.user.name, group: ctx.user.primaryGroup, mode: 0o600 });
      }
      out.length = 0;
    }
    if (r.stage !== 'ok') return fail(out, r);
    if (authOnly) {
      out.push(log('INFO', 'com.freerdp.client.x11', 'Authentication only, exit status 0'));
      return ok(out.join('\n'));
    }
    out.push(log('INFO', 'com.freerdp.gdi', 'Local framebuffer format  PIXEL_FORMAT_BGRX32'), log('INFO', 'com.freerdp.gdi', 'Remote framebuffer format PIXEL_FORMAT_BGRA32'),
      `[Infrastructure Lab: connected. ${server.hostname.toUpperCase()} logged ${r.account} on in a Remote Desktop session (no graphics in the simulator); the client disconnects now.]`,
      log('INFO', 'com.freerdp.core', 'freerdp_disconnect: ERRINFO_LOGOFF_BY_USER (0x0000000C):The disconnection was initiated by the user logging off their session on the server.'));
    return ok(out.join('\n'));
  },
};

export const RDP_COMMANDS: CommandDef[] = [xfreerdp];
