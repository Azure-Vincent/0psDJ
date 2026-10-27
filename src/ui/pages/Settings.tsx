import { useRef, useState } from 'react';
import { emptyProgress, type Progress, type Theme } from '../../learning/progress';
import { useProgress } from '../state';
import { updater, useUpdateStatus, type UpdateStatus } from '../updater';

const THEMES: [Theme, string][] = [
  ['system', 'Follow system (Paper / Ember)'],
  ['light', 'Paper (soft light)'],
  ['dark', 'Ember (soft dark)'],
  ['contrast-light', 'High-contrast light'],
  ['contrast-dark', 'High-contrast dark'],
];

const RELEASES = 'https://github.com/Azure-Vincent/0psDJ/releases';

const mb = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;

function describe(s: UpdateStatus): string {
  switch (s.state) {
    case 'unsupported': return 'Updates work in the installed desktop app (not when running from source).';
    case 'not-configured': return 'This build has no update signing key, so it cannot verify updates and never installs one.';
    case 'checking': return 'Checking GitHub for a newer release…';
    case 'current': return `You have the latest version${s.latest ? ` (latest release: ${s.latest})` : ''}.`;
    case 'unsigned': return `The latest release${s.tag ? ` (${s.tag})` : ''} has no signed update manifest, so it is not offered here. You can still download it from the releases page.`;
    case 'no-build': return `Version ${s.latest} has no build for this computer (${s.platform}) in the format you installed; check the releases page.`;
    case 'available': return `Version ${s.latest} is available${s.size ? ` (${mb(s.size)})` : ''}. Its release manifest is signed by the project; the download will be checked against it.`;
    case 'downloading': return `Downloading version ${s.latest}: ${mb(s.received ?? 0)} of ${mb(s.total ?? 0)}…`;
    case 'ready': return s.mode === 'nsis' ? `Version ${s.latest} is downloaded and verified; it installs when you quit the app.` : `Version ${s.latest} is installed; it starts the next time you open the app.`;
    case 'restarting': return `Installing version ${s.latest} and restarting…`;
    case 'downloaded': return `Version ${s.latest} was verified and saved to your Downloads folder${s.file ? ` (${s.file})` : ''}. Install it from there.`;
    case 'error': return `Update failed: ${s.error}. Nothing was installed.`;
    default: return '';
  }
}

function UpdatesCard() {
  const [status, setStatus] = useUpdateStatus();
  if (!updater) {
    return (
      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Updates</h3>
        <p className="small muted">You are using the web version, which is always the version it was built from. The desktop app can update itself; new versions are published on the <a href={RELEASES} target="_blank" rel="noreferrer">releases page</a>.</p>
      </div>
    );
  }
  if (!status) return null;
  const busy = ['checking', 'downloading', 'restarting'].includes(status.state);
  const canUse = status.supported && status.configured;
  const setPrefs = (p: Partial<{ autoCheck: boolean; autoInstall: boolean }>) =>
    updater!.setPrefs({ autoCheck: p.autoCheck ?? status.autoCheck, autoInstall: p.autoInstall ?? status.autoInstall }).then(setStatus);
  const installLabel = status.mode === 'download' ? 'Download verified installer' : 'Update and restart';
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3>Updates</h3>
      <p className="small muted">
        Installed version: <strong>{status.current}</strong>. The app checks the project's GitHub releases and installs an update only if it is signed with
        the project's key and every downloaded file matches its signed checksum; anything else is refused. The check sends no data about you or your progress.
      </p>
      <div className="small" role="status" aria-live="polite" style={{ marginBottom: 8 }}>
        {describe(status)}
        {status.lastCheck && !busy && <span className="muted"> Last checked {new Date(status.lastCheck).toLocaleString()}.</span>}
      </div>
      <div className="row" style={{ marginBottom: 8 }}>
        <button disabled={!canUse || busy} onClick={() => updater!.check().then(setStatus)}>Check for updates</button>
        {status.state === 'available' && (
          <button onClick={() => { if (status.mode === 'download' || confirm(`Install version ${status.latest} now? The app will close and restart.`)) updater!.install().then(setStatus); }}>{installLabel}</button>
        )}
        {status.releaseUrl && <a className="small" href={status.releaseUrl} target="_blank" rel="noreferrer">Release notes</a>}
      </div>
      <div className="row">
        <label className="row"><input type="checkbox" disabled={!canUse} checked={status.autoCheck} onChange={(e) => setPrefs({ autoCheck: e.target.checked })} />Check for updates automatically</label>
        <label className="row"><input type="checkbox" disabled={!canUse || !status.autoCheck} checked={status.autoInstall} onChange={(e) => setPrefs({ autoInstall: e.target.checked })} />Install verified updates automatically (applied when you quit, never during a session)</label>
      </div>
      {status.mode === 'download' && <p className="small muted" style={{ marginTop: 6 }}>This copy (portable, zip, .deb, .tar.gz or macOS) cannot replace itself: the verified file is saved to your Downloads folder for you to install.</p>}
    </div>
  );
}

export function Settings() {
  const { progress, update, reset, replace } = useProgress();
  const fileRef = useRef<HTMLInputElement>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const exportProgress = () => {
    const blob = new Blob([JSON.stringify(progress, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cyber-owl-lab-progress-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  const importProgress = async (file: File) => {
    try {
      const p = JSON.parse(await file.text()) as Progress;
      if (p.version !== 1 || !Array.isArray(p.attempts)) throw new Error('not a Cyber Owl Lab progress file');
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
      <UpdatesCard />
      <div className="card">
        <h3>About the simulation</h3>
        <p className="small">
          Cyber Owl Lab simulates hosts, routing, ARP, nftables, DNS, systemd services and OpenSSH in a deterministic engine written in TypeScript.
          It does not run real operating systems, virtual machines or containers. Simulated behaviour follows the cited RFCs and the behaviour of Debian 12
          (OpenSSH 9.2p1, BIND 9.18, nftables 1.0.6, systemd 252); simplifications are noted where they appear. Use the Deployment guides to build the same
          environment on real virtual machines.
        </p>
      </div>
    </div>
  );
}
