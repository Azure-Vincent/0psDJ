// TCP connection establishment, data segments and teardown on top of the
// network model. Implements the Linux client behaviour that matters for
// troubleshooting: SYN retransmission with exponential backoff
// (net.ipv4.tcp_syn_retries = 6, ~127 s total), RST -> ECONNREFUSED, and ICMP
// errors during SYN_SENT aborting the connect() with the mapped errno.

import type { AppLayer, Host, Packet, TcpFlag, World } from '../types';
import { seededInt } from '../util/sha256';
import { type Delivery, makeRst, nextId, sourceAddress, transmit } from './network';
import { findListener } from './services';
import { activeRecorder } from './trace';

export type ConnectErrno = 'ECONNREFUSED' | 'ETIMEDOUT' | 'EHOSTUNREACH' | 'ENETUNREACH' | 'EPERM';

export const ERRNO_TEXT: Record<ConnectErrno, string> = {
  ECONNREFUSED: 'Connection refused',
  ETIMEDOUT: 'Connection timed out',
  EHOSTUNREACH: 'No route to host',
  ENETUNREACH: 'Network is unreachable',
  EPERM: 'Operation not permitted',
};

/** The connection as the server sees it (differs from the client's view behind NAT). */
export interface ServerView {
  local: string;
  localPort: number;
  peer: string;
  peerPort: number;
}

export class TcpConn {
  clientSeq: number;
  serverSeq: number;
  sv: ServerView;
  constructor(
    public world: World,
    public client: Host,
    public server: Host,
    public clientIp: string,
    public serverIp: string,
    public clientPort: number,
    public serverPort: number,
    clientIsn: number,
    serverIsn: number,
    sv?: ServerView,
  ) {
    this.clientSeq = clientIsn;
    this.serverSeq = serverIsn;
    this.sv = sv ?? { local: serverIp, localPort: serverPort, peer: clientIp, peerPort: clientPort };
  }

  /** Send a data segment. Returns false if it did not reach the peer. */
  send(dir: 'c2s' | 's2c', len: number, app?: AppLayer, flags: TcpFlag[] = ['PSH', 'ACK']): { ok: boolean; packet: Packet; delivery: Delivery } {
    const c2s = dir === 'c2s';
    const p: Packet = {
      id: nextId(this.world),
      src: c2s ? this.clientIp : this.sv.local,
      dst: c2s ? this.serverIp : this.sv.peer,
      ttl: 64,
      proto: 'tcp',
      tcp: {
        sport: c2s ? this.clientPort : this.sv.localPort,
        dport: c2s ? this.serverPort : this.sv.peerPort,
        seq: c2s ? this.clientSeq : this.serverSeq,
        ack: c2s ? this.serverSeq : this.clientSeq,
        flags,
        window: c2s ? 502 : 509,
        len,
        options: 'NOP,NOP,TS',
      },
      app,
    };
    const advance = len + (flags.includes('FIN') ? 1 : 0);
    if (c2s) this.clientSeq = (this.clientSeq + advance) >>> 0;
    else this.serverSeq = (this.serverSeq + advance) >>> 0;
    this.world.clock += 0.3;
    const delivery = transmit(this.world, c2s ? this.client.id : this.server.id, p);
    return { ok: delivery.status === 'delivered', packet: p, delivery };
  }

  /** Orderly close initiated by `who` (FIN, FIN/ACK, ACK). */
  close(who: 'client' | 'server'): void {
    const first = who === 'client' ? 'c2s' : 's2c';
    const second = who === 'client' ? 's2c' : 'c2s';
    const rec = activeRecorder();
    if (rec) rec.phase = 'Teardown';
    const a = this.send(first, 0, undefined, ['FIN', 'ACK']);
    const b = this.send(second, 0, undefined, ['FIN', 'ACK']);
    const c = this.send(first, 0, undefined, ['ACK']);
    rec?.describe(a.packet.id, `TCP FIN (${who} closes)`, `The ${who} has no more data to send. FIN consumes one sequence number. Its socket moves to FIN_WAIT_1.`);
    rec?.describe(b.packet.id, 'TCP FIN, ACK', 'The peer acknowledges the FIN and, having nothing more to send either, sends its own FIN in the same segment.');
    rec?.describe(c.packet.id, 'TCP ACK (close complete)', `The final ACK. The ${who} side enters TIME_WAIT (2×MSL) so that delayed segments of this connection cannot be confused with a new one; conntrack entries on firewalls along the path move to closing states.`);
  }
}

export type ConnectResult =
  | { ok: true; conn: TcpConn; elapsedMs: number; attempts: number }
  | { ok: false; errno: ConnectErrno; elapsedMs: number; attempts: number; detail: string };

function ephemeralPort(world: World, host: Host): number {
  return seededInt(`${host.id}:${world.counter}`, 40000, 60999);
}

export interface ConnectOptions {
  /** Abort after this many ms (ssh -o ConnectTimeout, nc -w). */
  timeoutMs?: number;
  synRetries?: number;
}

/** Perform a TCP three-way handshake from `client` to dstIp:dport. */
export function tcpConnect(world: World, client: Host, dstIp: string, dport: number, opts: ConnectOptions = {}): ConnectResult {
  const start = world.clock;
  const sport = ephemeralPort(world, client);
  const isn = seededInt(`isn:${client.id}:${sport}:${world.counter}`, 1, 0x7fffffff);
  const synRetries = opts.synRetries ?? 6;
  const srcIp = sourceAddress(client, dstIp);
  const rec = activeRecorder();
  if (rec) rec.phase = 'TCP';

  let rto = 1000;
  for (let attempt = 0; attempt <= synRetries; attempt++) {
    const syn: Packet = {
      id: nextId(world), src: srcIp, dst: dstIp, ttl: 64, proto: 'tcp',
      tcp: { sport, dport, seq: isn, ack: 0, flags: ['SYN'], window: 64240, len: 0, options: 'MSS=1460,SACK_PERM,TS,WS=128' },
    };
    if (rec) rec.setState(client.id, { tcp: 'SYN_SENT' });
    const d = transmit(world, client.id, syn);
    rec?.describe(syn.id, attempt === 0 ? 'TCP SYN' : `TCP SYN (retransmission #${attempt})`, attempt === 0
      ? `Step 1 of the three-way handshake. The client picks a random Initial Sequence Number (ISN=${isn}) and advertises options: MSS 1460 (largest segment it accepts), SACK permitted, timestamps and window scaling. Socket state: SYN_SENT.`
      : `No SYN-ACK arrived within the retransmission timeout, so the kernel resends the identical SYN (same ISN and source port). Linux doubles the timeout each time (1, 2, 4, 8, 16, 32 s) and gives up after net.ipv4.tcp_syn_retries=6 retransmissions (~127 s). Repeated identical SYNs in a capture mean "nothing is answering".`);
    const fail = (errno: ConnectErrno, detail: string): ConnectResult => {
      if (rec) rec.setState(client.id, { tcp: 'CLOSED' });
      return { ok: false, errno, elapsedMs: world.clock - start, attempts: attempt + 1, detail };
    };

    if (d.status === 'local-error') return fail(d.errno, d.reason);
    if (d.status === 'delivered') {
      const server = world.hosts[d.host];
      const f = d.final; // as received: may differ from what the client sent if NAT was applied
      const sv = { local: f.dst, localPort: f.tcp!.dport, peer: f.src, peerPort: f.tcp!.sport };
      const listener = findListener(server, 'tcp', sv.local, sv.localPort);
      if (!listener) {
        const rst = makeRst(world, f);
        const r = transmit(world, server.id, rst);
        rec?.describe(rst.id, 'TCP RST (no listener)', `The SYN reached ${server.hostname}, but no socket is listening on ${sv.local}:${sv.localPort}. The kernel itself (not any application) answers with RST/ACK. The client's connect() fails immediately with ECONNREFUSED: "Connection refused". This proves routing and firewalls let the SYN through; the problem is on the server's service side.`);
        if (r.status === 'delivered') return fail('ECONNREFUSED', `no process listening on ${sv.local}:${sv.localPort}; kernel answered with RST`);
      } else {
        const sisn = seededInt(`isn:${server.id}:${dport}:${world.counter}`, 1, 0x7fffffff);
        if (rec) rec.setState(server.id, { tcp: 'SYN_RECV' });
        const synack: Packet = {
          id: nextId(world), src: sv.local, dst: sv.peer, ttl: 64, proto: 'tcp',
          tcp: { sport: sv.localPort, dport: sv.peerPort, seq: sisn, ack: (isn + 1) >>> 0, flags: ['SYN', 'ACK'], window: 65160, len: 0, options: 'MSS=1460,SACK_PERM,TS,WS=128' },
        };
        world.clock += 0.3;
        const r = transmit(world, server.id, synack);
        rec?.describe(synack.id, 'TCP SYN-ACK', `Step 2. ${listener.process} (pid ${listener.pid}) has a listening socket on ${listener.addr}:${listener.port}, so the kernel accepts the SYN, stores a half-open connection (SYN_RECV), picks its own ISN (${sisn}) and acknowledges the client's ISN+1 (Ack=${(isn + 1) >>> 0}). The application is not involved yet: the kernel completes the handshake and queues the connection for accept().`);
        if (r.status === 'delivered') {
          const conn = new TcpConn(world, client, server, srcIp, dstIp, sport, dport, (isn + 1) >>> 0, (sisn + 1) >>> 0, sv);
          if (rec) rec.setState(client.id, { tcp: 'ESTABLISHED' });
          const ack = conn.send('c2s', 0, undefined, ['ACK']);
          rec?.describe(ack.packet.id, 'TCP ACK (handshake complete)', `Step 3. The client acknowledges the server's ISN+1. Both sides are now ESTABLISHED and each knows the other's starting sequence number, so lost or reordered data can be detected. Firewalls with connection tracking now classify further packets of this flow as "established".`);
          if (rec) rec.setState(server.id, { tcp: 'ESTABLISHED' });
          return { ok: true, conn, elapsedMs: world.clock - start, attempts: attempt + 1 };
        }
        // SYN-ACK lost on the way back: the client keeps retransmitting SYNs.
      }
    } else if (d.status === 'rejected' && d.rst?.delivered) {
      return fail('ECONNREFUSED', `${d.reason}: TCP RST sent by firewall`);
    } else if (d.error?.delivered) {
      const code = d.error.packet.icmp!;
      if (code.type === 3 && code.code === 3) return fail('ECONNREFUSED', `ICMP port unreachable from ${d.error.packet.src}`);
      if (code.type === 3 && code.code === 0) return fail('ENETUNREACH', `ICMP network unreachable from ${d.error.packet.src}`);
      if (code.type === 3) return fail('EHOSTUNREACH', `ICMP ${code.description} from ${d.error.packet.src}`);
      // time exceeded during connect is a soft error: keep retrying
    }

    // No answer: wait for the retransmission timer.
    const elapsed = world.clock - start;
    if (opts.timeoutMs !== undefined && elapsed + rto >= opts.timeoutMs) {
      world.clock = start + opts.timeoutMs;
      return fail('ETIMEDOUT', `no reply within ConnectTimeout (${opts.timeoutMs / 1000}s)`);
    }
    world.clock += rto;
    if (attempt < synRetries) rto *= 2;
  }
  if (rec) rec.setState(client.id, { tcp: 'CLOSED' });
  return { ok: false, errno: 'ETIMEDOUT', elapsedMs: world.clock - start, attempts: synRetries + 1, detail: `no SYN-ACK after ${synRetries + 1} SYNs` };
}
