// FreeRADIUS tools: radtest (freeradius-utils, a wrapper around radclient) and
// the server binary's configuration check (freeradius -C / -XC).

import { resolve } from '../sim/dns';
import { confErrorText, radiusdCheck, radiusExchange, RADDB } from '../sim/radius';
import { sourceAddress } from '../sim/network';
import { type CommandDef, err, ok } from './types';

const radtest: CommandDef = {
  name: 'radtest',
  summary: 'Send an Access-Request to a RADIUS server (freeradius-utils)',
  usage: 'radtest [-t pap] [-4|-6] user password radius-server[:port] nas-port-number secret',
  run(args, ctx) {
    const pos: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-t') { const t = args[++i]; if (t !== 'pap') return err(`radtest: the simulator only supports -t pap (got ${t ?? ''})`, 1); continue; }
      if (a === '-4' || a === '-6' || a === '-x') continue;
      if (a === '-P') { i++; continue; }
      pos.push(a);
    }
    if (pos.length < 5) return err('Usage: radtest [OPTIONS] user passwd radius-server[:port] nas-port-number secret [ppphint] [nasname]\n        -d RADIUS_DIR       Set radius directory\n        -t <type>           Set authentication method\n                            type can be pap, chap, mschap, or eap-md5\n        -P protocol         Select udp (default) or tcp\n        -x                  Enable debug output\n        -4                  Use IPv4 for the NAS address (default)\n        -6                  Use IPv6 for the NAS address', 2);
    const [user, password, serverArg, nasPort, secret] = pos;
    const [name, portText] = serverArg.split(':');
    const port = portText ? Number(portText) : 1812;
    const r = resolve(ctx.world, ctx.host, name === 'localhost' ? '127.0.0.1' : name, { family: 4 });
    if (!r.ok) return err(`radclient: Failed to find IP address for host ${name}: Name or service not known`, 1);
    const src = r.ip.startsWith('127.') ? '127.0.0.1' : sourceAddress(ctx.host, r.ip);
    const res = radiusExchange(ctx.world, ctx.host, r.ip, port, { user, password, secret, messageAuthenticator: true, nasPort: Number(nasPort) || 0 });
    const out = [
      `Sent Access-Request Id ${res.id} from 0.0.0.0:${res.sport} to ${r.ip}:${port} length ${50 + user.length + 16}`,
      `\tUser-Name = "${user}"`,
      `\tUser-Password = "${password}"`,
      `\tNAS-IP-Address = ${src}`,
      `\tNAS-Port = ${Number(nasPort) || 0}`,
      '\tMessage-Authenticator = 0x00',
      `\tCleartext-Password = "${password}"`,
    ];
    if (res.kind === 'timeout') {
      // radclient retries (3 tries, 3 s apart) before it gives up.
      out.push(out[0], out[0]);
      out.push(`(0) No reply from server for ID ${res.id} socket 3`);
      return { out: out.join('\n'), code: 1 };
    }
    const code = res.kind === 'accept' ? 'Access-Accept' : 'Access-Reject';
    out.push(`Received ${code} Id ${res.id} from ${res.from}:${port} to ${src}:${res.sport} length ${20 + res.reply.reduce((s, x) => s + 2 + x.value.length, 0)}`);
    for (const x of res.reply) out.push(`\t${x.attr} = "${x.value}"`);
    if (res.kind === 'reject') {
      out.push('(0) -: Expected Access-Accept got Access-Reject');
      return { out: out.join('\n'), code: 1 };
    }
    return ok(out.join('\n'));
  },
};

const freeradius: CommandDef = {
  name: 'freeradius',
  summary: 'FreeRADIUS server (-C checks the configuration, -X runs in debug mode)',
  usage: 'freeradius -C | -XC | -X',
  run(args, ctx) {
    const flags = args.join('');
    if (!/^-[CXxfl]*/.test(flags) || !args.length) return err('freeradius: the simulator runs the server as a service: systemctl start freeradius. Use freeradius -C (or -XC) to check the configuration, freeradius -X for debug mode.', 1);
    if (ctx.user.uid !== 0) return err(`freeradius: Error: Failed to open ${RADDB}/radiusd.conf: Permission denied\nErrors reading or parsing ${RADDB}/radiusd.conf`, 1);
    const c = radiusdCheck(ctx.host);
    const head = /X/.test(flags) ? [
      'FreeRADIUS Version 3.2.1',
      'Copyright (C) 1999-2022 The FreeRADIUS server project and contributors',
      `Starting - reading configuration files ...`,
      `including configuration file ${RADDB}/radiusd.conf`,
      `including configuration file ${RADDB}/clients.conf`,
      `including files in directory ${RADDB}/mods-enabled/`,
      `including files in directory ${RADDB}/sites-enabled/`,
    ] : [];
    if ('msg' in c) return err([...head, confErrorText(c), `Errors reading or parsing ${RADDB}/radiusd.conf`].join('\n'), 1);
    if (/X/.test(flags)) {
      for (const cl of c.clients) head.push(`client ${cl.name} {`, `\tipaddr = ${cl.ipaddr}`, '\trequire_message_authenticator = no', `\tsecret = <<< secret >>>`, `\tshortname = "${cl.shortname}"`, '}');
      if (c.ldap) head.push('rlm_ldap: libldap vendor: OpenLDAP, version: 20513', `rlm_ldap (ldap): server = "${c.ldap.server}"`, `rlm_ldap (ldap): identity = "${c.ldap.identity}"`, `rlm_ldap (ldap): base_dn = "${c.ldap.baseDn}"`);
    }
    if (/C/.test(flags)) return ok([...head, 'Configuration appears to be OK'].join('\n'));
    // -X: debug mode in the foreground. While the service runs, the ports are taken.
    if (ctx.host.services.freeradius?.state === 'active') return err([...head, 'Failed binding to auth address * port 1812 bound to server default: Address already in use', `${RADDB}/sites-enabled/default[59]: Error binding to port for 0.0.0.0 port 1812`].join('\n'), 1);
    return err([...head, 'Listening on auth address * port 1812 bound to server default', 'Ready to process requests', '(the simulator does not keep a debug-mode server running: use systemctl start freeradius and read /var/log/freeradius/radius.log)'].join('\n'), 1);
  },
};

export const RADIUS_COMMANDS: CommandDef[] = [radtest, freeradius];
