import { useRef, useState } from 'react';
import { emptyProgress, type Progress, type Theme } from '../../learning/progress';
import { useProgress } from '../state';

const THEMES: [Theme, string][] = [
  ['system', 'Follow system (Paper / Ember)'],
  ['light', 'Paper (soft light)'],
  ['dark', 'Ember (soft dark)'],
  ['contrast-light', 'High-contrast light'],
  ['contrast-dark', 'High-contrast dark'],
];

export function Settings() {
  const { progress, update, reset, replace } = useProgress();
  const fileRef = useRef<HTMLInputElement>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const exportProgress = () => {
    const blob = new Blob([JSON.stringify(progress, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `infralab-progress-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  const importProgress = async (file: File) => {
    try {
      const p = JSON.parse(await file.text()) as Progress;
      if (p.version !== 1 || !Array.isArray(p.attempts)) throw new Error('not an Infrastructure Lab progress file');
      replace({ ...emptyProgress(), ...p });
      setMsg('Progress imported.');
    } catch (e) {
      setMsg(`Import failed: ${(e as Error).message}`);
    }
  };
  return (
    <div className="page">
      <h1>Settings</h1>
      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Theme</h3>
        <p className="small muted">The default themes use tinted backgrounds, softer text contrast and coloured headings, code and diagrams, which is easier on the eyes over long sessions. The high-contrast themes keep the original black-on-white / white-on-black look.</p>
        <div className="row">
          {THEMES.map(([t, label]) => (
            <label key={t} className="row"><input type="radio" checked={progress.settings.theme === t} onChange={() => update((p) => ({ ...p, settings: { ...p.settings, theme: t } }))} />{label}</label>
          ))}
        </div>
      </div>
      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Progress data</h3>
        <p className="small muted">Progress is stored locally on this computer (browser storage; in the desktop app, inside its user-data folder). Nothing is sent anywhere.</p>
        <div className="row">
          <button onClick={exportProgress}>Export progress (.json)</button>
          <button onClick={() => fileRef.current?.click()}>Import progress…</button>
          <input ref={fileRef} type="file" accept="application/json,.json" style={{ display: 'none' }} onChange={(e) => e.target.files?.[0] && importProgress(e.target.files[0])} />
          <button className="danger" onClick={() => { if (confirm('Delete all progress, answers and troubleshooting history?')) { reset(); setMsg('Progress reset.'); } }}>Reset all progress</button>
        </div>
        {msg && <div className="small" style={{ marginTop: 6 }}>{msg}</div>}
      </div>
      <div className="card">
        <h3>About the simulation</h3>
        <p className="small">
          Infrastructure Lab simulates hosts, routing, ARP, nftables, DNS, systemd services and OpenSSH in a deterministic engine written in TypeScript.
          It does not run real operating systems, virtual machines or containers. Simulated behaviour follows the cited RFCs and the behaviour of Debian 12
          (OpenSSH 9.2p1, BIND 9.18, nftables 1.0.6, systemd 252); simplifications are noted where they appear. Use the Deployment guides to build the same
          environment on real virtual machines.
        </p>
      </div>
    </div>
  );
}
