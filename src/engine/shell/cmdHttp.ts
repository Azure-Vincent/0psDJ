// HTTP(S) and PKI tools: curl, openssl (x509, verify, s_client, req, genrsa, rsa,
// pkey, md5/sha256) and update-ca-certificates. Output and error texts follow
// curl 7.88.1, OpenSSL 3.0 and ca-certificates 20230311 on Debian 12.

import { basename, dirname, listDir } from '../fs';
import { hostPort } from '../net/addr';
import { resolve } from '../sim/dns';
import { handleRequest, headerBytes, httpBackend, httpHooks, iisLoaded, pfWebLoaded, isTlsPort, selectServer, sendBulk, type HttpResponse } from '../sim/http';
import {
  asn1Time, CA_BUNDLE, type Cert, cn, type Csr, csrPem, dnCurl, dnOpenssl, fingerprint, keyIdFor, keyPem, makeCert, matchesHost, modulus,
  parseCerts, parseCsr, parseKey, parseSubj, type PrivKey, publicKeyPem, trustStore, VERIFY_TEXT, verifyChain, certPem,
} from '../sim/pki';
import { allListeners, type NginxLoaded } from '../sim/services';
import { ERRNO_TEXT, type TcpConn, tcpConnect } from '../sim/tcp';
import { activeRecorder } from '../sim/trace';
import { sha256, utf8 } from '../util/sha256';
import { getFile, resolvePath, writeChecked } from './cmdFiles';
import { curlImap, mailTlsChain } from './cmdMail';
import { type CmdCtx, type CommandDef, err, ok, parseFlags } from './types';

const ERRNO_NUM: Record<string, number> = { ECONNREFUSED: 111, ETIMEDOUT: 110, EHOSTUNREACH: 113, ENETUNREACH: 101, EPERM: 1, EMSGSIZE: 90 };

/** Size of a certificate in DER form on the wire (approximation). */
const derSize = (c: Cert) => 560 + c.bits / 8 + 256 + c.san.join(',').length;

/** Read a file the way a command running as the current user can. */
function load(ctx: CmdCtx, path: string): { text?: string; error?: string } {
  if (path === '-' || path === '/dev/stdin') return { text: ctx.stdin ?? '' };
  const f = getFile(ctx, resolvePath(ctx, path));
  return f.error ? { error: f.error } : { text: f.content! };
}

/** Write a file as the current user; private keys get mode 0600 as OpenSSL creates them. */
function save(ctx: CmdCtx, path: string, text: string, mode?: number): string | null {
  const p = resolvePath(ctx, path);
  const e = writeChecked(ctx, p, text);
  if (!e && mode !== undefined) ctx.host.fs[p].mode = mode;
  return e;
}

const CERT_HELP = 'More details here: https://curl.se/docs/sslcerts.html\n\ncurl failed to verify the legitimacy of the server and therefore could not\nestablish a secure connection to it. To learn more about this situation and\nhow to fix it, please visit the web page mentioned above.';

/** TLS alert a client sends for a verification error (RFC 8446 §6.2). */
function alertFor(code: number): string {
  if (code === 10) return 'certificate expired (557)';
  if (code === 9) return 'bad certificate (554)';
  return 'unknown CA (560)';
}

interface TlsResult {
  ok: boolean;
  chain: Cert[];
  /** First verification error (OpenSSL code) or 0. */
  code: number;
  errors: { depth: number; code: number; cert: Cert }[];
  stalled?: boolean;
  bytesRead: number;
}

/** TLS 1.3 handshake on an established connection to nginx. */
function tlsHandshake(conn: TcpConn, chain: Cert[], sni: string, trusted: Cert[]): TlsResult {
  const rec = activeRecorder();
  if (rec) rec.phase = 'TLS';
  const hello = conn.send('c2s', 517, { protocol: 'TLS', info: 'Client Hello', fields: [{ name: 'Server Name Indication', value: sni }, { name: 'Supported Version', value: 'TLS 1.3, TLS 1.2' }, { name: 'ALPN', value: 'h2, http/1.1' }] });
  rec?.describe(hello.packet.id, 'TLS ClientHello', `The client offers TLS versions and cipher suites, sends its X25519 key share and names the site it wants in the SNI extension (${sni || 'none: an IP address was used'}). SNI travels in clear text: it is how one IP address serves several certificates.`);
  const flight = 122 + 6 + chain.reduce((n, c) => n + derSize(c) + 5, 0) + 264 + 58;
  const first = conn.world.counter;
  const delivered = sendBulk(conn, 's2c', flight, 'Server Hello, Change Cipher Spec, Application Data', 'TLS');
  rec?.describe(first + 1, 'TLS ServerHello + encrypted Certificate flight', `The server answers with its key share; from here on the handshake is encrypted. The flight carries the Certificate message (${chain.map((c) => cn(c.subject)).join(' + ')}), CertificateVerify (a signature with the private key) and Finished: ${flight} bytes, so it fills full-size TCP segments. On a path with an MTU problem this is where HTTPS stalls.`);
  if (!delivered) return { ok: false, chain, code: 0, errors: [], stalled: true, bytesRead: 0 };
  const v = verifyChain(chain[0], chain.slice(1), trusted, conn.world.clock);
  return { ok: v.ok, chain, code: v.errors[0]?.code ?? 0, errors: v.errors, bytesRead: flight };
}

// ---------------------------------------------------------------------------
// curl
// ---------------------------------------------------------------------------

function progressMeter(size: number, ms: number): string {
  const speed = ms > 0 ? Math.round((size / ms) * 1000) : size;
  const human = (n: number) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)}M` : n >= 1024 ? `${Math.round(n / 1024)}k` : String(n));
  const t = (s: number) => { const x = Math.round(s); return `${String(Math.floor(x / 3600)).padStart(1, '0')}:${String(Math.floor((x % 3600) / 60)).padStart(2, '0')}:${String(x % 60).padStart(2, '0')}`; };
  return `  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100 ${human(size).padStart(5)}  100 ${human(size).padStart(5)}    0     0  ${human(speed).padStart(5)}      0  ${t(ms / 1000)}  ${t(ms / 1000)} --:--:-- ${human(speed).padStart(5)}`;
}

const curl: CommandDef = {
  name: 'curl',
  summary: 'transfer a URL over HTTP or HTTPS',
  usage: 'curl [-4|-6] [-I|-i] [-v] [-s] [-k] [-L] [--cacert FILE] [--resolve HOST:PORT:ADDR] [-m SECONDS] [-o FILE|-O] [-w FORMAT] URL',
  run(argv, ctx) {
    if (argv.some((a) => /^imaps?:\/\//i.test(a))) return curlImap(argv, ctx);
    // Request body / query options (repeatable): -d, --data-urlencode, -G, -X.
    const data: string[] = [];
    let getMode = false;
    let methodOpt: string | undefined;
    const args: string[] = [];
    for (let i = 0; i < argv.length; i++) {
      const a = argv[i];
      const val = () => argv[++i] ?? '';
      if (a === '-d' || a === '--data' || a === '--data-raw' || a === '--data-binary') data.push(val());
      else if (a === '--data-urlencode') {
        const v = val();
        const eq = v.indexOf('=');
        data.push(eq < 0 ? encodeURIComponent(v) : `${v.slice(0, eq)}=${encodeURIComponent(v.slice(eq + 1))}`);
      } else if (a === '-G' || a === '--get') getMode = true;
      else if (a === '-X' || a === '--request') methodOpt = val().toUpperCase();
      else if (/^-X./.test(a)) methodOpt = a.slice(2).toUpperCase();
      else args.push(a);
    }
    const { flags, rest } = parseFlags(args, ['-m', '--max-time', '--connect-timeout', '-o', '--output', '--cacert', '--resolve', '-w', '--write-out']);
    if (rest.some((a) => /^imaps?:\/\//i.test(a))) return curlImap(args, ctx);
    const url = rest[0];
    const m = url ? /^(?:(https?):\/\/)?(\[[0-9a-fA-F:.]+\]|[^/:?#]+)(?::(\d+))?([^#]*)/.exec(url) : null;
    if (!m) return err('curl: no URL specified!\ncurl: try \'curl --help\' or \'curl --manual\' for more information', 2);
    if (url && /^[a-z]+:\/\//i.test(url) && !/^https?:/i.test(url)) return err(`curl: (1) Protocol "${url.split(':')[0]}" not supported or disabled in libcurl`, 1);
    const silent = flags.has('-s') || flags.has('--silent');
    const showErr = !silent || flags.has('-S') || flags.has('--show-error');
    const verbose = flags.has('-v') || flags.has('--verbose');
    const head = flags.has('-I') || flags.has('--head');
    const include = flags.has('-i') || flags.has('--include');
    const insecure = flags.has('-k') || flags.has('--insecure');
    const follow = flags.has('-L') || flags.has('--location');
    const max = flags.get('-m') ?? flags.get('--max-time');
    const connectMax = flags.get('--connect-timeout');
    const outFile = (flags.get('-o') ?? flags.get('--output')) as string | undefined;
    const remoteName = flags.has('-O') || flags.has('--remote-name');
    const writeOut = (flags.get('-w') ?? flags.get('--write-out')) as string | undefined;
    const fail = (code: number, msg: string, log: string[] = []) => err([verbose ? log.join('\n') : '', showErr ? `curl: (${code}) ${msg}` : ''].filter(Boolean).join('\n'), code);

    // --cacert replaces the trust store (CURLOPT_CAINFO).
    let trusted: Cert[];
    const caFile = flags.get('--cacert') as string | undefined;
    if (caFile) {
      const f = load(ctx, caFile);
      trusted = f.text ? parseCerts(f.text).filter((c): c is Cert => !!c) : [];
      if (f.error || trusted.length === 0) return fail(77, `error setting certificate file: ${caFile}`);
    } else trusted = trustStore(ctx.host);
    const pins = new Map<string, string>();
    const rs = flags.get('--resolve');
    if (typeof rs === 'string') {
      const [h, p, a] = rs.split(':');
      if (h && p && a) pins.set(`${h.toLowerCase()}:${p}`, rs.split(':').slice(2).join(':').replace(/^\[|\]$/g, ''));
    }

    const start = ctx.world.clock;
    const vlog: string[] = [];
    let scheme = (m[1] ?? 'http').toLowerCase();
    let hostname = m[2];
    let portStr = m[3];
    let path = m[4] || '/';
    if (getMode && data.length) path += (path.includes('?') ? '&' : '?') + data.join('&');
    const method = methodOpt ?? (head ? 'HEAD' : data.length && !getMode ? 'POST' : 'GET');
    // A form body (POST): the APIs read it like query parameters.
    const appPath = (p: string) => (method === 'POST' && data.length && !getMode ? p + (p.includes('?') ? '&' : '?') + data.join('&') : p);
    let redirects = 0;
    let output = '';
    for (;;) {
      const port = Number(portStr ?? (scheme === 'https' ? 443 : 80));
      const bare = hostname.replace(/^\[|\]$/g, '');
      const hostHeader = `${hostname}${portStr ? ':' + portStr : ''}`;
      let addrs: string[];
      const pinned = pins.get(`${bare.toLowerCase()}:${port}`);
      if (pinned) {
        addrs = [pinned];
        vlog.push(`* Added ${bare}:${port}:${pinned} to DNS cache`);
      } else {
        const r = resolve(ctx.world, ctx.host, hostname, { family: flags.has('-6') ? 6 : flags.has('-4') ? 4 : 0 });
        if (!r.ok) return fail(6, `Could not resolve host: ${bare}`);
        addrs = r.addrs;
      }
      // Happy Eyeballs (RFC 8305, curl's default 200 ms): try the first address;
      // if it has not connected within 200 ms and an address of the other family
      // exists, race that one. Errors that come back immediately fall through.
      const limit = connectMax ?? max;
      let c: ReturnType<typeof tcpConnect> | null = null;
      for (let k = 0; k < addrs.length; k++) {
        const addr = addrs[k];
        const otherFamilyLeft = addrs.slice(k + 1).some((a) => a.includes(':') !== addr.includes(':'));
        const left = limit ? Number(limit) * 1000 - (ctx.world.clock - start) : undefined;
        const budget = otherFamilyLeft ? Math.min(200, left ?? 200) : left;
        vlog.push(`*   Trying ${hostPort(addr, port)}...`);
        c = tcpConnect(ctx.world, ctx.host, addr, port, { timeoutMs: budget });
        if (c.ok) break;
        if (k < addrs.length - 1) vlog.push(`* connect to ${addr} port ${port} failed: ${ERRNO_TEXT[c.errno]}`);
      }
      if (!c || !c.ok) {
        const elapsed = Math.round(ctx.world.clock - start);
        const last = c && !c.ok ? c.errno : 'ETIMEDOUT';
        const text = last === 'ECONNREFUSED' ? `Failed to connect to ${bare} port ${port} after ${Math.max(1, elapsed)} ms: Couldn't connect to server`
          : last === 'ETIMEDOUT' ? `Failed to connect to ${bare} port ${port} after ${elapsed} ms: Couldn't connect to server`
          : `Failed to connect to ${bare} port ${port} after ${Math.max(3, elapsed)} ms: ${ERRNO_TEXT[last]}`;
        return fail(last === 'ETIMEDOUT' && limit ? 28 : 7, text, vlog);
      }
      const conn = c.conn;
      if (max) conn.deadline = start + Number(max) * 1000;
      vlog.push(`* Connected to ${bare} (${conn.serverIp}) port ${port} (#0)`);
      // A published container port: docker-proxy hands the connection to the container.
      const backend = httpBackend(ctx.world, conn.server, conn.sv.localPort, conn.sv.local);
      const server = backend.host;
      const listener = allListeners(server).find((l) => l.port === backend.port && l.proto === 'tcp');
      const app = listener ? httpHooks.apps[listener.process] : undefined;
      const loaded = server.services.nginx?.state === 'active' ? (server.services.nginx.loaded as NginxLoaded) : iisLoaded(server) ?? pfWebLoaded(server);
      const sockTls = !!loaded?.servers?.some((s) => isTlsPort(s, backend.port));
      const reqInfo = `${method} ${path} HTTP/1.1`;

      if (!app && listener?.process !== 'nginx' && listener?.service !== 'W3SVC') {
        conn.send('c2s', 78, { protocol: 'DATA', info: `${reqInfo} Host: ${hostname}`, fields: [] });
        conn.close('server');
        if (listener?.process === 'sshd' && scheme === 'http') return fail(1, 'Received HTTP/0.9 when not allowed', vlog);
        return fail(35, 'OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection', vlog);
      }

      let sni = bare;
      if (scheme === 'https') {
        vlog.push('* ALPN: offers h2,http/1.1', '* TLSv1.3 (OUT), TLS handshake, Client hello (1):');
        if (!insecure) vlog.push(`*  CAfile: ${caFile ?? CA_BUNDLE}`, '*  CApath: /etc/ssl/certs');
        if (!sockTls) {
          conn.send('c2s', 517, { protocol: 'TLS', info: 'Client Hello', fields: [{ name: 'Server Name Indication', value: sni }] });
          conn.send('s2c', 157, { protocol: 'DATA', info: 'HTTP/1.1 400 Bad Request', fields: [] });
          conn.close('server');
          return fail(35, 'OpenSSL/3.0.11: error:0A00010B:SSL routines::wrong version number', vlog);
        }
        const srv = selectServer(loaded, backend.local, backend.port, /^[\d.]+$|:/.test(sni) ? undefined : sni)!;
        const tls = tlsHandshake(conn, srv.tls!.chain, sni, trusted);
        if (tls.stalled) {
          if (conn.lastError === 'deadline') return fail(28, 'SSL connection timeout', vlog);
          return fail(35, `OpenSSL SSL_connect: Connection timed out in connection to ${bare}:${port}`, vlog);
        }
        vlog.push('* TLSv1.3 (IN), TLS handshake, Server hello (2):', '* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):', '* TLSv1.3 (IN), TLS handshake, Certificate (11):');
        if (!tls.ok && !insecure) {
          const alert = conn.send('c2s', 7, { protocol: 'TLS', info: `Alert (Level: Fatal, Description: ${alertFor(tls.code).replace(/ \(\d+\)$/, '')})`, fields: [] });
          activeRecorder()?.describe(alert.packet.id, 'TLS alert: certificate rejected', `curl verified the chain against its trust store and failed with OpenSSL error ${tls.code} (${VERIFY_TEXT[tls.code]}). It aborts the handshake with a fatal alert; no HTTP request is sent. The network did its job: this is a certificate problem.`);
          conn.close('client');
          vlog.push(`* TLSv1.3 (OUT), TLS alert, ${alertFor(tls.code)}:`, `* SSL certificate problem: ${VERIFY_TEXT[tls.code]}`, '* Closing connection 0');
          return fail(60, `SSL certificate problem: ${VERIFY_TEXT[tls.code]}\n${CERT_HELP}`, vlog);
        }
        vlog.push('* TLSv1.3 (IN), TLS handshake, CERT verify (15):', '* TLSv1.3 (IN), TLS handshake, Finished (20):', '* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):', '* TLSv1.3 (OUT), TLS handshake, Finished (20):');
        const fin = conn.send('c2s', 80, { protocol: 'TLS', info: 'Change Cipher Spec, Application Data', fields: [] });
        activeRecorder()?.describe(fin.packet.id, 'TLS client Finished', insecure && !tls.ok ? `Verification failed (${VERIFY_TEXT[tls.code]}) but -k tells curl to continue anyway: the connection is encrypted but the server is not authenticated.` : 'The chain verified up to a trusted root and every certificate is within its validity period. The client completes the handshake; next it checks the host name against the subjectAltName.');
        const leaf = tls.chain[0];
        const matched = matchesHost(leaf, bare);
        vlog.push('* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384', '* ALPN: server accepted http/1.1', '* Server certificate:',
          `*  subject: ${dnCurl(leaf.subject)}`, `*  start date: ${asn1Time(leaf.notBefore)}`, `*  expire date: ${asn1Time(leaf.notAfter)}`);
        if (!matched && !insecure) {
          vlog.push(`*  subjectAltName does not match ${bare}`, `* SSL: no alternative certificate subject name matches target host name '${bare}'`, '* Closing connection 0');
          conn.send('c2s', 24, { protocol: 'TLS', info: 'Alert (Level: Fatal, Description: Close Notify)', fields: [] });
          conn.close('client');
          return fail(60, `SSL: no alternative certificate subject name matches target host name '${bare}'\n${CERT_HELP}`, vlog);
        }
        vlog.push(matched ? `*  subjectAltName: host "${bare}" matched cert's "${matched}"` : `*  subjectAltName does not match ${bare}`, `*  issuer: ${dnCurl(leaf.issuer)}`,
          tls.ok ? '*  SSL certificate verify ok.' : `*  SSL certificate verify result: ${VERIFY_TEXT[tls.code]} (${tls.code}), continuing anyway.`);
      } else sni = '';

      // HTTP request and response.
      const srv = selectServer(loaded, backend.local, backend.port, scheme === 'https' && !/^[\d.]+$|:/.test(bare) ? bare : hostHeader)!;
      const proto = scheme === 'https' ? 'TLS' : 'DATA';
      const recorder = activeRecorder();
      if (recorder) recorder.phase = 'HTTP';
      vlog.push(`> ${method} ${path} HTTP/1.1`, `> Host: ${hostHeader}`, '> User-Agent: curl/7.88.1', '> Accept: */*', ...(method === 'POST' && data.length ? ['> Content-Type: application/x-www-form-urlencoded'] : []), '>');
      conn.send('c2s', 78 + path.length + hostHeader.length + (proto === 'TLS' ? 22 : 0), { protocol: proto, info: proto === 'TLS' ? 'Application Data' : `${reqInfo} Host: ${hostHeader}`, fields: [], encrypted: proto === 'TLS' });
      const res: HttpResponse = app ? app(ctx.world, server, { method, path: appPath(path), hostHeader, plainOnTls: false, now: ctx.world.clock, client: { ip: backend.proxyFrom ?? conn.sv.peer, ua: 'curl/7.88.1' } }) : handleRequest(server, srv, { method: head ? 'HEAD' : 'GET', path, hostHeader, plainOnTls: scheme === 'http' && sockTls, now: ctx.world.clock, client: { ip: backend.proxyFrom ?? conn.sv.peer, ua: 'curl/7.88.1' } }, ctx.world);
      // A slow server (a reverse proxy waiting for its upstream): curl -m gives up first.
      if (max && ctx.world.clock - start > Number(max) * 1000) {
        conn.close('client');
        return fail(28, `Operation timed out after ${Number(max) * 1000 + 1} milliseconds with 0 bytes received`, vlog);
      }
      const statusLine = `HTTP/1.1 ${res.status} ${res.reason}`;
      const hdrs = [statusLine, ...res.headers.map(([k, v]) => `${k}: ${v}`)];
      const hb = headerBytes(res);
      const bodyLen = head ? 0 : res.size;
      const smallBody = bodyLen <= 1200;
      const okHdr = sendBulk(conn, 's2c', hb + (smallBody ? bodyLen : 0), proto === 'TLS' ? 'Application Data' : statusLine, proto);
      const elapsedNow = () => Math.round(ctx.world.clock - start);
      const stalled = (got: number) => {
        if (conn.lastError === 'deadline') return fail(28, `Operation timed out after ${elapsedNow()} milliseconds with ${got} out of ${got === 0 && !okHdr ? -1 : bodyLen} bytes received`.replace(' out of -1', ''), vlog);
        return err([verbose ? vlog.join('\n') : '', '^C', `[Cyber Owl Lab: no data arrived for ${Math.round(elapsedNow() / 60000)} minutes; the server's kernel gave up retransmitting, but curl without -m waits forever, so the simulator interrupted it. Use -m SECONDS to set a time limit.]`].filter(Boolean).join('\n'), 130);
      };
      if (!okHdr) return stalled(0);
      vlog.push(...hdrs.map((h) => `< ${h}`), '<');
      if (!smallBody && !sendBulk(conn, 's2c', bodyLen, proto === 'TLS' ? 'Application Data' : 'Continuation', proto)) return stalled(0);
      if (res.status === 400 && scheme === 'http' && sockTls) conn.close('server');
      else conn.close('client');
      vlog.push(`* Connection #0 to host ${bare} left intact`);
      const loc = res.headers.find(([k]) => k === 'Location')?.[1];
      if (follow && loc && res.status >= 300 && res.status < 400 && redirects < 5) {
        redirects++;
        vlog.push(`* Issue another request to this URL: '${loc}'`);
        if (head) output += hdrs.join('\n') + '\n\n';
        const n = /^(https?):\/\/(\[[0-9a-fA-F:.]+\]|[^/:?#]+)(?::(\d+))?([^#]*)/.exec(loc);
        if (n) { scheme = n[1]; hostname = n[2]; portStr = n[3]; path = n[4] || '/'; }
        else path = loc;
        continue;
      }
      const elapsed = Math.max(1, ctx.world.clock - start);
      const wo = writeOut ? writeOut.replace(/%\{http_code\}/g, String(res.status)).replace(/%\{size_download\}/g, String(bodyLen)).replace(/%\{ssl_verify_result\}/g, '0').replace(/\\n/g, '\n') : '';
      if (outFile || remoteName) {
        const target = outFile ?? (basename(path.split('?')[0]) || 'index.html');
        const p = resolvePath(ctx, target);
        const e = writeChecked(ctx, p, head ? hdrs.join('\n') + '\n' : res.body);
        if (e) return err(`${silent ? '' : progressMeter(0, elapsed) + '\n'}Warning: Failed to open the file ${target}: ${e}\ncurl: (23) Failure writing output to destination`, 23);
        if (!head && res.binary && ctx.host.fs[p]) ctx.host.fs[p].size = res.size;
        const meter = silent ? '' : progressMeter(bodyLen, elapsed);
        return ok([verbose ? vlog.join('\n') : '', meter, wo].filter(Boolean).join('\n'));
      }
      if (head) return ok([verbose ? vlog.join('\n') : output + hdrs.join('\n'), wo].filter(Boolean).join('\n'));
      if (res.binary) {
        return err([verbose ? vlog.join('\n') : '', 'Warning: Binary output can mess up your terminal. Use "--output -" to tell \nWarning: curl to output it to your console anyway, or consider "--output \nWarning: <FILE>" to save to a file.'].filter(Boolean).join('\n'), 23);
      }
      return ok([verbose ? vlog.join('\n') : '', include && !verbose ? `${hdrs.join('\n')}\n` : '', res.body.replace(/\n$/, ''), wo].filter(Boolean).join('\n'));
    }
  },
};

// ---------------------------------------------------------------------------
// openssl
// ---------------------------------------------------------------------------

/** OpenSSL-style option parsing: single-dash long options, some taking a value. */
function oparse(args: string[], withValue: string[]): { opts: Map<string, string | true>; rest: string[]; bad?: string } {
  const opts = new Map<string, string | true>();
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('-') && a.length > 1) {
      const name = a.replace(/^--?/, '');
      if (withValue.includes(name)) {
        if (i + 1 >= args.length) return { opts, rest, bad: name };
        opts.set(name, args[++i]);
      } else opts.set(name, true);
    } else rest.push(a);
  }
  return { opts, rest };
}

const ERR_PREFIX = '40F7A1C2B67F0000:error:';

function hexColons(hex: string, perLine: number, indent: string): string {
  const pairs = hex.toLowerCase().match(/../g)!;
  const lines: string[] = [];
  for (let i = 0; i < pairs.length; i += perLine) lines.push(indent + pairs.slice(i, i + perLine).join(':') + (i + perLine < pairs.length ? ':' : ''));
  return lines.join('\n');
}

function certText(c: Cert): string {
  const pub = '00' + modulus(c.keyId, c.bits);
  const ski = hexColons(c.keyId + c.keyId.slice(0, 24), 20, '').toUpperCase();
  const aki = hexColons(c.signer + c.signer.slice(0, 24), 20, '').toUpperCase();
  const ext = c.ca
    ? [`            X509v3 Basic Constraints: critical\n                CA:TRUE${c.pathlen !== undefined ? `, pathlen:${c.pathlen}` : ''}`, '            X509v3 Key Usage: critical\n                Certificate Sign, CRL Sign']
    : ['            X509v3 Basic Constraints: critical\n                CA:FALSE', '            X509v3 Key Usage: critical\n                Digital Signature, Key Encipherment', '            X509v3 Extended Key Usage: \n                TLS Web Server Authentication'];
  if (c.san.length) ext.push(`            X509v3 Subject Alternative Name: \n                ${c.san.join(', ')}`);
  ext.push(`            X509v3 Subject Key Identifier: \n                ${ski}`);
  if (c.signer !== c.keyId) ext.push(`            X509v3 Authority Key Identifier: \n                ${aki}`);
  return [
    'Certificate:', '    Data:', '        Version: 3 (0x2)', '        Serial Number:', hexColons(c.serial, 20, '            '),
    '        Signature Algorithm: sha256WithRSAEncryption', `        Issuer: ${dnOpenssl(c.issuer)}`, '        Validity',
    `            Not Before: ${asn1Time(c.notBefore)}`, `            Not After : ${asn1Time(c.notAfter)}`, `        Subject: ${dnOpenssl(c.subject)}`,
    '        Subject Public Key Info:', '            Public Key Algorithm: rsaEncryption', `                Public-Key: (${c.bits} bit)`, '                Modulus:',
    hexColons(pub, 15, '                    '), '                Exponent: 65537 (0x10001)', '        X509v3 extensions:', ...ext,
    '    Signature Algorithm: sha256WithRSAEncryption', '    Signature Value:', hexColons(c.sig + c.sig, 18, '        '),
  ].join('\n');
}

function readCertArg(ctx: CmdCtx, file: string | true | undefined): { cert?: Cert; out?: string } {
  const name = typeof file === 'string' ? file : '<stdin>';
  const f = load(ctx, typeof file === 'string' ? file : '-');
  if (f.error) return { out: `Could not open file or uri for loading certificate from ${name}\n${ERR_PREFIX}80000002:system library:file_open:${f.error === 'Permission denied' ? 'Permission denied' : 'No such file or directory'}:../providers/implementations/storemgmt/file_store.c:267:calling stat(${name})\nUnable to load certificate` };
  const c = parseCerts(f.text!)[0];
  if (!c) return { out: `Could not read certificate from ${name}\nUnable to load certificate` };
  return { cert: c };
}

function readKeyArg(ctx: CmdCtx, file: string | true | undefined): { key?: PrivKey; out?: string } {
  const name = typeof file === 'string' ? file : '<stdin>';
  const f = load(ctx, typeof file === 'string' ? file : '-');
  if (f.error) return { out: `Could not open file or uri for loading private key from ${name}\n${ERR_PREFIX}80000002:system library:file_open:${f.error}:../providers/implementations/storemgmt/file_store.c:267:calling stat(${name})` };
  const k = parseKey(f.text!);
  if (!k) return { out: `Could not read private key from ${name}` };
  return { key: k };
}

/** Parse "subjectAltName = DNS:a, DNS:b" (from -addext or an -extfile). */
function sanFrom(text: string): string[] {
  const m = /subjectAltName\s*=\s*([^\n]+)/.exec(text);
  return m ? m[1].split(',').map((s) => s.trim()).filter((s) => /^(DNS|IP):/.test(s)) : [];
}

function x509(args: string[], ctx: CmdCtx) {
  const { opts, bad } = oparse(args, ['in', 'out', 'CA', 'CAkey', 'days', 'checkend', 'ext', 'extfile', 'extensions', 'signkey', 'nameopt', 'set_serial', 'copy_extensions', 'inform', 'outform']);
  if (bad) return err(`x509: Option -${bad} needs a value\nx509: Use -help for summary.`, 1);
  if (opts.has('req')) {
    // Sign a CSR: openssl x509 -req -in r.csr -CA ca.crt -CAkey ca.key [-CAcreateserial] -out c.crt -days N [-extfile f | -copy_extensions copy]
    const f = load(ctx, (opts.get('in') as string) ?? '-');
    if (f.error) return err(`Could not open file or uri for loading certificate request from ${opts.get('in')}`, 1);
    const csr = parseCsr(f.text!);
    if (!csr) return err(`Could not read certificate request from ${opts.get('in') ?? '<stdin>'}\nUnable to load certificate request input`, 1);
    let issuer: { dn: Cert['subject']; keyId: string };
    if (opts.has('CA')) {
      const ca = readCertArg(ctx, opts.get('CA'));
      if (!ca.cert) return err(ca.out!, 1);
      const k = readKeyArg(ctx, opts.get('CAkey') ?? opts.get('CA'));
      if (!k.key) return err(k.out!, 1);
      if (k.key.keyId !== ca.cert.keyId) return err(`CA certificate and CA private key do not match\n${ERR_PREFIX}05800074:x509 certificate routines:X509_check_private_key:key values mismatch:../crypto/x509/x509_cmp.c:405:`, 1);
      issuer = { dn: ca.cert.subject, keyId: k.key.keyId };
    } else if (opts.has('signkey')) {
      const k = readKeyArg(ctx, opts.get('signkey'));
      if (!k.key) return err(k.out!, 1);
      issuer = { dn: csr.subject, keyId: k.key.keyId };
    } else return err('We need a private key to sign with, use -signkey or -CAkey or -CA with private key', 1);
    let san: string[] = [];
    if (opts.get('copy_extensions') === 'copy' || opts.get('copy_extensions') === 'copyall') san = csr.san;
    if (typeof opts.get('extfile') === 'string') {
      const e = load(ctx, opts.get('extfile') as string);
      if (e.error) return err(`Error opening extfile ${opts.get('extfile')}`, 1);
      san = sanFrom(e.text!);
    }
    const days = Number(opts.get('days') ?? 30);
    const cert = makeCert({ subject: csr.subject, issuer: issuer.dn, notBefore: ctx.world.clock, notAfter: ctx.world.clock + days * 86_400_000, san, ca: false, keyId: csr.keyId, signer: issuer.keyId, bits: csr.bits });
    const pemText = certPem(cert);
    if (opts.has('out')) {
      const e = save(ctx, opts.get('out') as string, pemText);
      if (e) return err(`Could not open file or uri for writing ${opts.get('out')}: ${e}`, 1);
    }
    if (opts.has('CAcreateserial') && typeof opts.get('CA') === 'string') save(ctx, (opts.get('CA') as string).replace(/\.[^./]+$/, '') + '.srl', cert.serial + '\n');
    return ok(`Certificate request self-signature ok\nsubject=${dnOpenssl(cert.subject)}${opts.has('out') ? '' : '\n' + pemText.trimEnd()}`);
  }
  const r = readCertArg(ctx, opts.get('in'));
  if (!r.cert) return err(r.out!, 1);
  const c = r.cert;
  const out: string[] = [];
  let code = 0;
  if (opts.has('text')) out.push(certText(c));
  if (opts.has('serial')) out.push(`serial=${c.serial}`);
  if (opts.has('subject')) out.push(`subject=${dnOpenssl(c.subject)}`);
  if (opts.has('issuer')) out.push(`issuer=${dnOpenssl(c.issuer)}`);
  if (opts.has('dates') || opts.has('startdate')) out.push(`notBefore=${asn1Time(c.notBefore)}`);
  if (opts.has('dates') || opts.has('enddate')) out.push(`notAfter=${asn1Time(c.notAfter)}`);
  if (opts.has('fingerprint')) out.push(opts.has('sha1') ? `sha1 Fingerprint=${fingerprint(c, 'sha1')}` : `sha256 Fingerprint=${fingerprint(c, 'sha256')}`);
  if (opts.has('modulus')) out.push(`Modulus=${modulus(c.keyId, c.bits)}`);
  if (opts.has('pubkey')) out.push(publicKeyPem(c.keyId, c.bits));
  if (typeof opts.get('ext') === 'string') {
    for (const e of (opts.get('ext') as string).split(',')) {
      if (e === 'subjectAltName' && c.san.length) out.push(`X509v3 Subject Alternative Name: \n    ${c.san.join(', ')}`);
      if (e === 'basicConstraints') out.push(`X509v3 Basic Constraints: critical\n    CA:${c.ca ? 'TRUE' : 'FALSE'}${c.pathlen !== undefined ? `, pathlen:${c.pathlen}` : ''}`);
    }
  }
  if (opts.has('checkend')) {
    const secs = Number(opts.get('checkend'));
    const expires = ctx.world.clock + secs * 1000 > c.notAfter;
    out.push(expires ? 'Certificate will expire' : 'Certificate will not expire');
    code = expires ? 1 : 0;
  }
  if (!opts.has('noout')) {
    const pemText = certPem(c).trimEnd();
    if (opts.has('out')) {
      const e = save(ctx, opts.get('out') as string, pemText + '\n');
      if (e) return err(`Could not open file or uri for writing ${opts.get('out')}: ${e}`, 1);
    } else out.push(pemText);
  }
  return { out: out.join('\n'), code };
}

function verifyCmd(args: string[], ctx: CmdCtx) {
  const { opts, rest, bad } = oparse(args, ['CAfile', 'untrusted', 'CApath', 'purpose', 'attime']);
  if (bad) return err(`verify: Option -${bad} needs a value`, 1);
  let trusted = trustStore(ctx.host);
  if (typeof opts.get('CAfile') === 'string') {
    const f = load(ctx, opts.get('CAfile') as string);
    if (f.error) return err(`Error loading file ${opts.get('CAfile')}`, 1);
    trusted = parseCerts(f.text!).filter((c): c is Cert => !!c);
  }
  let untrusted: Cert[] = [];
  if (typeof opts.get('untrusted') === 'string') {
    const f = load(ctx, opts.get('untrusted') as string);
    if (f.error) return err(`Error loading file ${opts.get('untrusted')}`, 1);
    untrusted = parseCerts(f.text!).filter((c): c is Cert => !!c);
  }
  const now = typeof opts.get('attime') === 'string' ? Number(opts.get('attime')) * 1000 : ctx.world.clock;
  const files = rest.length ? rest : ['stdin'];
  const out: string[] = [];
  let code = 0;
  for (const file of files) {
    const r = readCertArg(ctx, file === 'stdin' ? undefined : file);
    if (!r.cert) { out.push(r.out!); code = 2; continue; }
    const v = verifyChain(r.cert, untrusted, trusted, now);
    if (v.ok) { out.push(`${file}: OK`); continue; }
    const e = v.errors[0];
    out.push(dnOpenssl(e.cert.subject), `error ${e.code} at ${e.depth} depth lookup: ${VERIFY_TEXT[e.code]}`, `error ${file}: verification failed`);
    code = 2;
  }
  return { out: out.join('\n'), code };
}

function sClient(args: string[], ctx: CmdCtx) {
  const { opts, bad } = oparse(args, ['connect', 'servername', 'CAfile', 'verify_return_error', 'starttls']);
  if (bad) return err(`s_client: Option -${bad} needs a value`, 1);
  const target = (opts.get('connect') as string) ?? 'localhost:4433';
  const mm = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(target);
  if (!mm) return err(`s_client: -connect argument or target parameter malformed or ambiguous`, 1);
  const host = mm[1].replace(/^\[|\]$/g, '');
  const port = Number(mm[2]);
  const r = resolve(ctx.world, ctx.host, host, {});
  if (!r.ok) return err(`${ERR_PREFIX}10080002:BIO routines:BIO_lookup_ex:system lib:../crypto/bio/bio_addr.c:738:Name or service not known\nconnect:errno=0`, 1);
  const c = tcpConnect(ctx.world, ctx.host, r.addrs[0], port, {});
  if (!c.ok) {
    return err(`${ERR_PREFIX}8000006F:system library:BIO_connect:${ERRNO_TEXT[c.errno]}:../crypto/bio/bio_sock2.c:114:calling connect()\n${ERR_PREFIX}10000067:BIO routines:BIO_connect:connect error:../crypto/bio/bio_sock2.c:116:\nconnect:errno=${ERRNO_NUM[c.errno] ?? 110}`, 1);
  }
  const conn = c.conn;
  conn.deadline = ctx.world.clock + 60_000;
  const loaded = conn.server.services.nginx?.state === 'active' ? (conn.server.services.nginx.loaded as NginxLoaded) : null;
  const sni = typeof opts.get('servername') === 'string' ? (opts.get('servername') as string) : /^[\d.]+$|:/.test(host) ? undefined : host;
  const srv = selectServer(loaded, conn.sv.local, conn.sv.localPort, sni);
  // Postfix and Dovecot: TLS on connect (465, 993) or after STARTTLS (-starttls smtp|imap).
  const starttls = opts.get('starttls');
  const mail = mailTlsChain(ctx.world, conn, typeof starttls === 'string' ? starttls.toLowerCase() : undefined);
  if (mail?.error === 'handshake') {
    conn.close('server');
    return err(`CONNECTED(00000003)\n${ERR_PREFIX}0A000126:SSL routines::unexpected eof while reading:../ssl/record/rec_layer_s3.c:308:\n---\nno peer certificate available\n---\nNo client certificate CA names sent\n---\nSSL handshake has read 0 bytes and written 299 bytes\nVerification: OK\n---\nNew, (NONE), Cipher is (NONE)\nSecure Renegotiation IS NOT supported\nCompression: NONE\nExpansion: NONE\nNo ALPN negotiated\nEarly data was not sent\nVerify return code: 0 (ok)\n---`, 1);
  }
  if (mail ? !!mail.error : !srv || !isTlsPort(srv, conn.sv.localPort)) {
    conn.send('c2s', 299, { protocol: 'TLS', info: 'Client Hello', fields: [] });
    conn.close('server');
    return err(`CONNECTED(00000003)\n${mail?.error === 'no-starttls' ? "Didn't find STARTTLS in server response, trying anyway...\n" : ''}${ERR_PREFIX}0A00010B:SSL routines:ssl3_get_record:wrong version number:../ssl/record/ssl3_record.c:354:\n---\nno peer certificate available\n---\nNo client certificate CA names sent\n---\nSSL handshake has read 5 bytes and written 299 bytes\nVerification: OK\n---\nNew, (NONE), Cipher is (NONE)\nSecure Renegotiation IS NOT supported\nCompression: NONE\nExpansion: NONE\nNo ALPN negotiated\nEarly data was not sent\nVerify return code: 0 (ok)\n---`, 1);
  }
  let trusted = trustStore(ctx.host);
  if (typeof opts.get('CAfile') === 'string') {
    const f = load(ctx, opts.get('CAfile') as string);
    trusted = f.text ? parseCerts(f.text).filter((x): x is Cert => !!x) : [];
  }
  const tls = tlsHandshake(conn, mail?.chain ?? srv!.tls!.chain, sni ?? '', trusted);
  if (tls.stalled) return err(`CONNECTED(00000003)\n[Cyber Owl Lab: the server's certificate flight never arrived; s_client waited until you pressed Ctrl-C]\n^C`, 130);
  const chain = tls.chain;
  const v = verifyChain(chain[0], chain.slice(1), trusted, ctx.world.clock);
  // verify callback output, from the top of the built chain down to the leaf
  const lines: string[] = ['CONNECTED(00000003)'];
  for (let depth = v.chain.length - 1; depth >= 0; depth--) {
    const cert = v.chain[depth];
    for (const e of v.errors.filter((x) => x.depth === depth)) {
      lines.push(`depth=${depth} ${dnOpenssl(cert.subject)}`, `verify error:num=${e.code}:${VERIFY_TEXT[e.code]}`);
      if (e.code === 10) lines.push(`notAfter=${asn1Time(cert.notAfter)}`);
      lines.push('verify return:1');
    }
    if (!v.errors.some((x) => x.depth === depth)) lines.push(`depth=${depth} ${dnOpenssl(cert.subject)}`, 'verify return:1');
  }
  const last = v.errors[v.errors.length - 1];
  if (last && opts.has('verify_return_error')) {
    conn.close('client');
    return err([...lines, `${ERR_PREFIX}0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:../ssl/statem/statem_clnt.c:1889:`].join('\n'), 1);
  }
  lines.push('---', 'Certificate chain');
  chain.forEach((cert, i) => {
    lines.push(` ${i} s:${dnOpenssl(cert.subject)}`, `   i:${dnOpenssl(cert.issuer)}`, `   a:PKEY: rsaEncryption, ${cert.bits} (bit); sigalg: RSA-SHA256`, `   v:NotBefore: ${asn1Time(cert.notBefore)}; NotAfter: ${asn1Time(cert.notAfter)}`);
    if (opts.has('showcerts')) lines.push(certPem(cert).trimEnd());
  });
  lines.push('---');
  if (!opts.has('showcerts')) lines.push('Server certificate', certPem(chain[0]).trimEnd());
  lines.push(`subject=${dnOpenssl(chain[0].subject)}`, `issuer=${dnOpenssl(chain[0].issuer)}`, '---', 'No client certificate CA names sent', 'Peer signing digest: SHA256', 'Peer signature type: RSA-PSS', 'Server Temp Key: X25519, 253 bits', '---',
    `SSL handshake has read ${tls.bytesRead} bytes and written 373 bytes`, `Verification${last ? ` error: ${VERIFY_TEXT[last.code]}` : ': OK'}`, '---',
    'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', `Server public key is ${chain[0].bits} bit`, 'Secure Renegotiation IS NOT supported', 'Compression: NONE', 'Expansion: NONE', 'No ALPN negotiated', 'Early data was not sent',
    `Verify return code: ${last ? `${last.code} (${VERIFY_TEXT[last.code]})` : '0 (ok)'}`, '---', 'DONE');
  conn.send('c2s', 80, { protocol: 'TLS', info: 'Change Cipher Spec, Application Data', fields: [] });
  conn.close('client');
  return ok(lines.join('\n'));
}

function newKey(ctx: CmdCtx, spec: string | true | undefined, path: string): PrivKey {
  const bits = typeof spec === 'string' && /rsa:(\d+)/.test(spec) ? Number(/rsa:(\d+)/.exec(spec)![1]) : 2048;
  return { keyId: keyIdFor(`${ctx.host.id}:${path}:${ctx.world.clock}:${ctx.world.counter++}`), bits };
}

const KEYGEN_NOISE = '.+...+.....+......+++++++++++++++++++++++++++++++++++++++*..+.......+++++\n-----';

function req(args: string[], ctx: CmdCtx) {
  const { opts, bad } = oparse(args, ['in', 'out', 'key', 'keyout', 'newkey', 'subj', 'days', 'addext', 'config', 'extensions']);
  if (bad) return err(`req: Option -${bad} needs a value`, 1);
  if (!opts.has('new') && !opts.has('x509') && !opts.has('newkey')) {
    const f = load(ctx, (opts.get('in') as string) ?? '-');
    const csr = f.text ? parseCsr(f.text) : undefined;
    if (!csr) return err(`Could not read certificate request from ${opts.get('in') ?? '<stdin>'}\nUnable to load X509 request`, 1);
    const out: string[] = [];
    if (opts.has('verify')) out.push('Certificate request self-signature verify OK');
    if (opts.has('subject')) out.push(`subject=${dnOpenssl(csr.subject)}`);
    if (opts.has('text')) out.push('Certificate Request:', '    Data:', '        Version: 1 (0x0)', `        Subject: ${dnOpenssl(csr.subject)}`, '        Subject Public Key Info:', '            Public Key Algorithm: rsaEncryption', `                Public-Key: (${csr.bits} bit)`, '        Attributes:', '            Requested Extensions:', ...(csr.san.length ? ['                X509v3 Subject Alternative Name: ', `                    ${csr.san.join(', ')}`] : []), '    Signature Algorithm: sha256WithRSAEncryption');
    if (!opts.has('noout')) out.push(csrPem(csr).trimEnd());
    return ok(out.join('\n'));
  }
  if (typeof opts.get('subj') !== 'string') return err('[Cyber Owl Lab: interactive Distinguished Name prompts are not simulated; pass the subject with -subj "/CN=www.corp.lab"]', 1);
  const subject = parseSubj(opts.get('subj') as string);
  if (!subject) return err(`req: Error parsing -subj argument ${opts.get('subj')}: subject name is expected to be in the format /type0=value0/type1=value1/type2=...`, 1);
  let key: PrivKey;
  const noise: string[] = [];
  if (opts.has('newkey')) {
    const keyout = (opts.get('keyout') as string) ?? 'privkey.pem';
    key = newKey(ctx, opts.get('newkey'), keyout);
    if (!opts.has('nodes') && !opts.has('noenc')) return err('[Cyber Owl Lab: passphrase-protected keys are not simulated; add -nodes (or -noenc) so nginx can read the key at boot]', 1);
    const e = save(ctx, keyout, keyPem(key), 0o600);
    if (e) return err(`req: Can't open "${keyout}" for writing, ${e}`, 1);
    noise.push(KEYGEN_NOISE);
  } else if (opts.has('key')) {
    const k = readKeyArg(ctx, opts.get('key'));
    if (!k.key) return err(k.out!, 1);
    key = k.key;
  } else return err('req: Missing -key or -newkey', 1);
  const san = typeof opts.get('addext') === 'string' ? sanFrom(opts.get('addext') as string) : [];
  let text: string;
  if (opts.has('x509')) {
    const days = Number(opts.get('days') ?? 30);
    text = certPem(makeCert({ subject, issuer: subject, notBefore: ctx.world.clock, notAfter: ctx.world.clock + days * 86_400_000, san, ca: true, keyId: key.keyId, signer: key.keyId, bits: key.bits }));
  } else text = csrPem({ subject, san, keyId: key.keyId, bits: key.bits } satisfies Csr);
  if (opts.has('out')) {
    const e = save(ctx, opts.get('out') as string, text);
    if (e) return err(`req: Can't open "${opts.get('out')}" for writing, ${e}`, 1);
  } else noise.push(text.trimEnd());
  return ok(noise.join('\n'));
}

function genrsa(args: string[], ctx: CmdCtx) {
  const { opts, rest } = oparse(args, ['out', 'algorithm', 'pkeyopt']);
  const out = (opts.get('out') as string) ?? undefined;
  const bits = Number(rest[0] ?? /rsa_keygen_bits:(\d+)/.exec(String(opts.get('pkeyopt') ?? ''))?.[1] ?? 2048);
  const key = newKey(ctx, `rsa:${bits}`, out ?? '-');
  if (!out) return ok(keyPem(key).trimEnd());
  const e = save(ctx, out, keyPem(key), 0o600);
  if (e) return err(`Can't open "${out}" for writing, ${e}`, 1);
  return ok(KEYGEN_NOISE.replace(/\n-----$/, ''));
}

function rsaPkey(cmd: string, args: string[], ctx: CmdCtx) {
  const { opts } = oparse(args, ['in', 'out']);
  const k = readKeyArg(ctx, opts.get('in'));
  if (!k.key) return err(k.out!, 1);
  const out: string[] = [];
  if (opts.has('check')) out.push(cmd === 'rsa' ? 'RSA key ok' : 'Key is valid');
  if (opts.has('modulus')) out.push(`Modulus=${modulus(k.key.keyId, k.key.bits)}`);
  if (opts.has('text')) out.push(`Private-Key: (${k.key.bits} bit, 2 primes)`, 'modulus:', hexColons('00' + modulus(k.key.keyId, k.key.bits), 15, '    '), 'publicExponent: 65537 (0x10001)', '[Cyber Owl Lab: private exponent and primes omitted]');
  if (opts.has('pubout')) out.push(publicKeyPem(k.key.keyId, k.key.bits));
  else if (!opts.has('noout')) out.push(keyPem(k.key).trimEnd());
  return ok(out.join('\n'));
}

function digest(alg: string, args: string[], ctx: CmdCtx) {
  const files = args.filter((a) => !a.startsWith('-'));
  const h = (s: string) => {
    const full = [...sha256(utf8(s))].map((b) => b.toString(16).padStart(2, '0')).join('');
    return alg === 'md5' ? full.slice(0, 32) : alg === 'sha1' ? full.slice(0, 40) : full;
  };
  const label = ({ md5: 'MD5', sha1: 'SHA1', sha256: 'SHA2-256' } as Record<string, string>)[alg] ?? alg.toUpperCase();
  if (!files.length) return ok(`${label}(stdin)= ${h(ctx.stdin ?? '')}`);
  return ok(files.map((f) => { const r = load(ctx, f); return r.error ? `${f}: ${r.error}` : `${label}(${f})= ${h(r.text!)}`; }).join('\n'));
}

const openssl: CommandDef = {
  name: 'openssl',
  summary: 'OpenSSL: x509, verify, s_client, req, genrsa, rsa, pkey, md5/sha256',
  usage: 'openssl x509|verify|s_client|req|genrsa|genpkey|rsa|pkey|md5|sha256|version [options]',
  run(args, ctx) {
    const [sub, ...rest] = args;
    switch (sub) {
      case 'x509': return x509(rest, ctx);
      case 'verify': return verifyCmd(rest, ctx);
      case 's_client': return sClient(rest, ctx);
      case 'req': return req(rest, ctx);
      case 'genrsa': case 'genpkey': return genrsa(rest, ctx);
      case 'rsa': case 'pkey': return rsaPkey(sub, rest, ctx);
      case 'md5': case 'sha1': case 'sha256': case 'dgst': return digest(sub === 'dgst' ? (rest.find((a) => /^-(md5|sha1|sha256)$/.test(a))?.slice(1) ?? 'sha256') : sub, rest.filter((a) => !/^-(md5|sha1|sha256)$/.test(a)), ctx);
      case 'version': return ok('OpenSSL 3.0.11 19 Sep 2023 (Library: OpenSSL 3.0.11 19 Sep 2023)');
      case undefined: return err('[Cyber Owl Lab: interactive openssl prompt not simulated]\nusage: openssl x509|verify|s_client|req|genrsa|rsa|pkey|md5|sha256|version', 1);
      default: return err(`Invalid command '${sub}'; type "help" for a list.`, 1);
    }
  },
};

// ---------------------------------------------------------------------------
// update-ca-certificates
// ---------------------------------------------------------------------------

function filesUnder(ctx: CmdCtx, dir: string): string[] {
  const out: string[] = [];
  for (const name of listDir(ctx.host, dir)) {
    const p = `${dir}/${name}`;
    const n = ctx.host.fs[p];
    if (n?.type === 'dir') out.push(...filesUnder(ctx, p));
    else if (n) out.push(p);
  }
  return out;
}

const updateCaCertificates: CommandDef = {
  name: 'update-ca-certificates',
  summary: 'rebuild /etc/ssl/certs/ca-certificates.crt from the trusted CA files',
  usage: 'update-ca-certificates [--fresh]',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('/usr/sbin/update-ca-certificates: 104: cannot create /etc/ca-certificates.conf.new: Permission denied', 2);
    const conf = ctx.host.fs['/etc/ca-certificates.conf']?.content ?? '';
    const selected = conf.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && !l.startsWith('!'));
    const sources = [
      ...selected.map((f) => `/usr/share/ca-certificates/${f}`).filter((p) => ctx.host.fs[p]),
      ...filesUnder(ctx, '/usr/local/share/ca-certificates').filter((p) => p.endsWith('.crt')),
    ];
    const warnings: string[] = [];
    const certs: Cert[] = [];
    for (const p of sources) {
      const c = parseCerts(ctx.host.fs[p].content).filter((x): x is Cert => !!x);
      if (c.length === 0) warnings.push(`WARNING: ${basename(p)} does not contain a certificate or CRL: skipping`);
      else certs.push(c[0]);
    }
    const before = trustStore(ctx.host);
    const fresh = args.includes('--fresh') || args.includes('-f');
    const key = (c: Cert) => c.keyId + dnOpenssl(c.subject);
    const added = certs.filter((c) => !before.some((b) => key(b) === key(c))).length;
    const removed = before.filter((b) => !certs.some((c) => key(b) === key(c))).length;
    ctx.world.clock += 900;
    const dir = dirname(CA_BUNDLE);
    if (!ctx.host.fs[dir]) return err(`/usr/sbin/update-ca-certificates: 1: cannot create ${CA_BUNDLE}: Directory nonexistent`, 2);
    ctx.host.fs[CA_BUNDLE] = { type: 'file', mode: 0o644, owner: 'root', group: 'root', content: certs.map((c) => certPem(c)).join(''), mtime: ctx.world.clock };
    return ok([
      ...(fresh ? ['Clearing symlinks in /etc/ssl/certs...', 'done.'] : []),
      'Updating certificates in /etc/ssl/certs...', ...warnings,
      `${fresh ? certs.length : added} added, ${fresh ? 0 : removed} removed; done.`, 'Running hooks in /etc/ca-certificates/update.d...', 'done.',
    ].join('\n'));
  },
};

export const HTTP_COMMANDS: CommandDef[] = [curl, openssl, updateCaCertificates];
