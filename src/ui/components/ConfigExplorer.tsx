import { useMemo, useState } from 'react';
import { effectiveConfig, formatErrors, parseSshdConfig, renderSshdT } from '../../engine/config/sshdConfig';

const MAIN = `Include /etc/ssh/sshd_config.d/*.conf
#Port 22
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

Match Address 10.0.30.0/24
    PasswordAuthentication yes
`;
const DROPIN = `PermitRootLogin no
PasswordAuthentication no
AllowUsers alice bob
`;

export function ConfigExplorer() {
  const [main, setMain] = useState(MAIN);
  const [dropin, setDropin] = useState(DROPIN);
  const [user, setUser] = useState('alice');
  const [addr, setAddr] = useState('10.0.10.25');
  const [useCtx, setUseCtx] = useState(false);
  const result = useMemo(() => {
    const files: Record<string, string> = { '/etc/ssh/sshd_config': main, '/etc/ssh/sshd_config.d/10-local.conf': dropin };
    const parsed = parseSshdConfig('/etc/ssh/sshd_config', (p) => files[p], () => Object.keys(files));
    if (parsed.errors.length) return { errors: formatErrors(parsed.errors), text: '' };
    return { errors: [], text: renderSshdT(effectiveConfig(parsed, useCtx ? { user, groups: [], address: addr } : undefined)) };
  }, [main, dropin, user, addr, useCtx]);
  const highlight = /^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|kbdinteractiveauthentication|strictmodes|kexalgorithms|loglevel)\b/;
  return (
    <div className="grid2">
      <div>
        <div className="small muted">/etc/ssh/sshd_config</div>
        <textarea rows={12} value={main} onChange={(e) => setMain(e.target.value)} spellCheck={false} />
        <div className="small muted" style={{ marginTop: 6 }}>/etc/ssh/sshd_config.d/10-local.conf (included by the first line)</div>
        <textarea rows={5} value={dropin} onChange={(e) => setDropin(e.target.value)} spellCheck={false} />
        <label className="row small" style={{ marginTop: 6 }}>
          <input type="checkbox" checked={useCtx} onChange={(e) => setUseCtx(e.target.checked)} /> Evaluate for a connection (sshd -T -C):
          user <input style={{ width: 80 }} value={user} onChange={(e) => setUser(e.target.value)} disabled={!useCtx} />
          addr <input style={{ width: 110 }} value={addr} onChange={(e) => setAddr(e.target.value)} disabled={!useCtx} />
        </label>
      </div>
      <div>
        <div className="small muted">{result.errors.length ? 'sshd -t' : `sshd -T${useCtx ? ` -C user=${user},addr=${addr}` : ''}`} (simulator parser)</div>
        {result.errors.length ? (
          <pre style={{ color: 'var(--err)' }}>{result.errors.join('\n')}</pre>
        ) : (
          <pre style={{ maxHeight: 420 }}>
            {result.text.split('\n').map((l, i) => <div key={i} style={highlight.test(l) ? { fontWeight: 700, color: 'var(--accent)' } : undefined}>{l}</div>)}
          </pre>
        )}
        <div className="small muted">Try: move "PasswordAuthentication yes" above the Include, add a typo, or enable the connection context with addr 10.0.30.7.</div>
      </div>
    </div>
  );
}
