// Remote Desktop: what happens when a client connects to a Windows host's RDP
// listener. The stages are the ones a real connection goes through, and each
// fails in its own way: name resolution, the TCP connection (firewall, listener),
// TLS, Network Level Authentication (CredSSP: the password and the account),
// and the logon itself, where the user right "Allow log on through Remote
// Desktop Services" (Administrators and Remote Desktop Users) is checked.

import { resolve } from '../sim/dns';
import { allListeners } from '../sim/services';
import { tcpConnect } from '../sim/tcp';
import type { Host, World } from '../types';
import { sha256Hex } from '../util/sha256';
import { isWindows, winEvent } from './model';
import { userDisabled } from './ps/cmdlets/system';

export type RdpStage = 'dns' | 'connect' | 'transport' | 'nla' | 'logon' | 'ok';

export interface RdpResult {
  stage: RdpStage;
  /** FreeRDP error name for the failure (ERRCONNECT_..., ERRINFO_...). */
  error?: string;
  server?: Host;
  serverIp?: string;
  /** Who logged on, as Windows names it (WIN01\alice). */
  account?: string;
  elapsedMs: number;
}

/** Certificate fingerprint of a host's self-signed "Remote Desktop" certificate. */
export function rdpThumbprint(host: Host): string {
  return sha256Hex(`rdp-cert:${host.id}`).slice(0, 64).match(/../g)!.join(':');
}

const RDP_RIGHTS = ['Administrators', 'Remote Desktop Users'];

export function rdpConnect(world: World, client: Host, target: string, port: number, user: string, password: string, opts: { authOnly?: boolean } = {}): RdpResult {
  const start = world.clock;
  const elapsed = () => Math.round(world.clock - start);
  const r = resolve(world, client, target, { family: 4 });
  if (!r.ok) return { stage: 'dns', error: 'ERRCONNECT_DNS_NAME_NOT_FOUND', elapsedMs: elapsed() };
  const c = tcpConnect(world, client, r.ip, port, { timeoutMs: 15_000 });
  if (!c.ok) return { stage: 'connect', error: c.errno === 'ECONNREFUSED' ? 'ERRCONNECT_CONNECT_FAILED' : 'ERRCONNECT_CONNECT_TRANSPORT_FAILED', serverIp: r.ip, elapsedMs: elapsed() };
  const conn = c.conn;
  const server = conn.server;
  const listener = allListeners(server).find((l) => l.proto === 'tcp' && l.port === conn.sv.localPort);
  conn.send('c2s', 47, { protocol: 'RDP', info: 'X.224 Connection Request (TLS, CredSSP)', fields: [] });
  if (!isWindows(server) || listener?.service !== 'TermService') {
    conn.close('server');
    return { stage: 'transport', error: 'ERRCONNECT_CONNECT_TRANSPORT_FAILED', server, serverIp: r.ip, elapsedMs: elapsed() };
  }
  conn.send('s2c', 19, { protocol: 'RDP', info: 'X.224 Connection Confirm (selected: CredSSP)', fields: [] });
  conn.send('c2s', 517, { protocol: 'TLS', info: 'Client Hello', fields: [] });
  conn.send('s2c', 1300, { protocol: 'TLS', info: 'Server Hello, Certificate (self-signed, Remote Desktop store)', fields: [] });
  // CredSSP / NLA: the server's LSA checks the credentials before any session exists.
  conn.send('c2s', 340, { protocol: 'TLS', info: 'CredSSP: NTLM NEGOTIATE / AUTHENTICATE', fields: [], encrypted: true });
  const name = user.replace(/^(\.|[^\\]*)\\/, '');
  const key = Object.keys(server.users).find((u) => u.toLowerCase() === name.toLowerCase());
  const host = server.hostname.toUpperCase();
  const fail = (stage: RdpStage, error: string, status: string, reason: string): RdpResult => {
    winEvent(world, server, 'Security', 4625, 'Microsoft-Windows-Security-Auditing', `An account failed to log on.\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\t${name}\n\tAccount Domain:\t\t${host}\n\nFailure Information:\n\tFailure Reason:\t\t${reason}\n\tStatus:\t\t\t${status}\n\nNetwork Information:\n\tSource Network Address:\t${conn.sv.peer}\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp\n\tAuthentication Package:\tNTLM`, 'Information');
    conn.close('server');
    return { stage, error, server, serverIp: r.ip, elapsedMs: elapsed() };
  };
  const account = key ? server.users[key] : undefined;
  if (!account || account.password === null || account.password !== password) return fail('nla', 'ERRCONNECT_LOGON_FAILURE', '0xC000006D', 'Unknown user name or bad password.');
  if (userDisabled(server, key!)) return fail('nla', 'ERRCONNECT_ACCOUNT_DISABLED', '0xC0000072', 'Account currently disabled.');
  const qualified = `${host}\\${key}`;
  winEvent(world, server, 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', 1149, 'Microsoft-Windows-TerminalServices-RemoteConnectionManager', `Remote Desktop Services: User authentication succeeded:\n\nUser: ${key}\nDomain: ${host}\nSource Network Address: ${conn.sv.peer}`);
  if (opts.authOnly) {
    conn.close('client');
    return { stage: 'ok', server, serverIp: r.ip, account: qualified, elapsedMs: elapsed() };
  }
  // Logon: SeRemoteInteractiveLogonRight (Administrators, Remote Desktop Users).
  if (!account.groups.some((g) => RDP_RIGHTS.includes(g))) {
    winEvent(world, server, 'Security', 4625, 'Microsoft-Windows-Security-Auditing', `An account failed to log on.\n\nLogon Type:\t\t\t10\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\t${key}\n\tAccount Domain:\t\t${host}\n\nFailure Information:\n\tFailure Reason:\t\tThe user has not been granted the requested logon type at this machine.\n\tStatus:\t\t\t0xC000015B\n\nNetwork Information:\n\tSource Network Address:\t${conn.sv.peer}`, 'Information');
    conn.send('s2c', 30, { protocol: 'TLS', info: 'Set Error Info PDU (ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES)', fields: [], encrypted: true });
    conn.close('server');
    return { stage: 'logon', error: 'ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES', server, serverIp: r.ip, elapsedMs: elapsed() };
  }
  winEvent(world, server, 'Security', 4624, 'Microsoft-Windows-Security-Auditing', `An account was successfully logged on.\n\nLogon Information:\n\tLogon Type:\t\t10\n\nNew Logon:\n\tAccount Name:\t\t${key}\n\tAccount Domain:\t\t${host}\n\nNetwork Information:\n\tSource Network Address:\t${conn.sv.peer}`);
  winEvent(world, server, 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 21, 'Microsoft-Windows-TerminalServices-LocalSessionManager', `Remote Desktop Services: Session logon succeeded:\n\nUser: ${qualified}\nSession ID: 2\nSource Network Address: ${conn.sv.peer}`);
  conn.send('s2c', 1200, { protocol: 'TLS', info: 'Desktop graphics updates', fields: [], encrypted: true });
  conn.close('client');
  return { stage: 'ok', server, serverIp: r.ip, account: qualified, elapsedMs: elapsed() };
}
