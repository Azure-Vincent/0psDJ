// The updater inside the running app: preferences, automatic checks, the IPC
// the Settings page uses, and installing a verified update. The verification
// itself is in updater.cjs.
//
// How an update is applied depends on how the app was installed:
//  - Windows installer (NSIS): the verified installer runs silently, either at
//    once ("Update and restart") or when the app quits (automatic updates);
//  - Linux AppImage: the verified AppImage replaces the running file (the old
//    one stays mounted until exit), so the next start is the new version;
//  - anything else: the verified file is saved to Downloads and shown.

'use strict';

const { app, ipcMain, net, shell, BrowserWindow } = require('electron');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const U = require('./updater.cjs');
const PUBLIC_KEYS = require('./update-public-keys.cjs');

const CHECK_INTERVAL = 6 * 60 * 60 * 1000;

let prefs = { autoCheck: true, autoInstall: true, lastCheck: 0 };
let status = { state: 'idle' };
/** The last verified check result: what install() may act on. Never comes from the renderer. */
let verified = null;
/** A verified Windows installer waiting to run when the app quits. */
let stagedInstaller = null;
let busy = false;
let allowedUrl = () => false;

const prefsFile = () => path.join(app.getPath('userData'), 'updater.json');
const updatesDir = () => path.join(app.getPath('userData'), 'updates');

function loadPrefs() {
  try {
    const p = JSON.parse(fs.readFileSync(prefsFile(), 'utf8'));
    prefs = { autoCheck: p.autoCheck !== false, autoInstall: p.autoInstall !== false, lastCheck: Number(p.lastCheck) || 0 };
  } catch { /* first start or unreadable: defaults */ }
}

function savePrefs() {
  try { fs.writeFileSync(prefsFile(), JSON.stringify(prefs), { mode: 0o600 }); } catch { /* not fatal */ }
}

function env() {
  return {
    platform: process.platform,
    arch: process.arch,
    appImage: process.env.APPIMAGE,
    portableDir: process.env.PORTABLE_EXECUTABLE_DIR,
    execPath: process.execPath,
    hasUninstaller: process.platform === 'win32' && fs.existsSync(path.join(path.dirname(process.execPath), `Uninstall ${app.getName()}.exe`)),
  };
}

function publicStatus() {
  return {
    ...status,
    current: app.getVersion(),
    supported: app.isPackaged,
    configured: PUBLIC_KEYS.length > 0,
    autoCheck: prefs.autoCheck,
    autoInstall: prefs.autoInstall,
    lastCheck: prefs.lastCheck || null,
  };
}

function setStatus(s) {
  status = s;
  for (const w of BrowserWindow.getAllWindows()) if (!w.isDestroyed()) w.webContents.send('updater:changed', publicStatus());
}

const fetchFn = (url, init) => net.fetch(url, init);

async function check(auto = false) {
  if (!app.isPackaged) return setStatus({ state: 'unsupported' });
  if (busy) return;
  busy = true;
  setStatus({ state: 'checking' });
  try {
    const r = await U.checkForUpdate({ fetchFn, currentVersion: app.getVersion(), publicKeys: PUBLIC_KEYS, env: env() });
    prefs.lastCheck = Date.now();
    savePrefs();
    verified = r.state === 'available' ? r : null;
    if (r.state === 'available') setStatus({ state: 'available', latest: r.version, mode: r.mode, releaseUrl: r.releaseUrl, size: r.file.size });
    else setStatus({ state: r.state, latest: r.latest, tag: r.tag });
  } catch (e) {
    verified = null;
    setStatus({ state: 'error', error: e instanceof U.UpdateError ? e.message : 'could not reach GitHub' });
  } finally {
    busy = false;
  }
  // Automatic updates never interrupt a session: the installer runs at quit, the AppImage is used at the next start.
  if (auto && prefs.autoInstall && verified && verified.mode !== 'download') await install(false);
}

async function download(dest) {
  const v = verified;
  return U.downloadVerified({
    fetchFn, url: v.url, dest, size: v.file.size, sha256: v.file.sha256,
    onProgress: (received, total) => {
      if (received === total || received % (4 * 1024 * 1024) < 65536) setStatus({ state: 'downloading', latest: v.version, received, total });
    },
  });
}

/** Re-hash a staged file right before it is executed. */
function sameHash(file, sha256) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') === sha256;
}

/** Install what the last check verified. `now`: restart into it at once (otherwise at quit / next start). */
async function install(now = true) {
  if (busy || !verified) return publicStatus();
  busy = true;
  const v = verified;
  try {
    if (v.mode === 'nsis') {
      fs.mkdirSync(updatesDir(), { recursive: true, mode: 0o700 });
      const dir = fs.mkdtempSync(path.join(updatesDir(), 'dl-'));
      const file = await download(path.join(dir, v.file.name));
      stagedInstaller = { file, sha256: v.file.sha256 };
      if (now) {
        runInstaller(true);
        setStatus({ state: 'restarting', latest: v.version });
        setTimeout(() => app.quit(), 300);
      } else setStatus({ state: 'ready', latest: v.version, mode: v.mode });
    } else if (v.mode === 'appimage') {
      const target = process.env.APPIMAGE;
      if (!target || !path.isAbsolute(target) || !fs.statSync(target).isFile()) throw new U.UpdateError('cannot locate the running AppImage');
      const tmp = `${target}.update-${crypto.randomBytes(6).toString('hex')}`;
      await download(tmp);
      fs.chmodSync(tmp, 0o755);
      fs.renameSync(tmp, target);
      if (now) {
        setStatus({ state: 'restarting', latest: v.version });
        app.relaunch({ execPath: target, args: process.argv.slice(1) });
        setTimeout(() => app.quit(), 300);
      } else setStatus({ state: 'ready', latest: v.version, mode: v.mode });
    } else {
      const file = await download(U.freePath(app.getPath('downloads'), v.file.name));
      shell.showItemInFolder(file);
      setStatus({ state: 'downloaded', latest: v.version, file: path.basename(file) });
    }
    verified = null;
  } catch (e) {
    setStatus({ state: 'error', error: e instanceof U.UpdateError ? e.message : `update failed: ${e.code || 'download error'}` });
  } finally {
    busy = false;
  }
  return publicStatus();
}

/** Start the staged Windows installer (silently; `relaunch` starts the app afterwards). */
function runInstaller(relaunch) {
  const s = stagedInstaller;
  stagedInstaller = null;
  if (!s || !fs.existsSync(s.file) || !sameHash(s.file, s.sha256)) return;
  spawn(s.file, relaunch ? ['/S', '--force-run'] : ['/S'], { detached: true, stdio: 'ignore' }).unref();
}

function init(distDir, devUrl) {
  const distUrl = pathToFileURL(distDir).href;
  allowedUrl = (u) => typeof u === 'string' && (u.startsWith(`${distUrl}/`) || (!!devUrl && u.startsWith(devUrl)));
  loadPrefs();
  // Leftovers of an earlier session (an installer that already ran, an aborted download).
  try { fs.rmSync(updatesDir(), { recursive: true, force: true }); } catch { /* ignore */ }

  // Only our own pages may use the updater.
  const guard = (fn) => (event, ...args) => {
    if (!allowedUrl(event.senderFrame?.url)) throw new Error('not allowed');
    return fn(...args);
  };
  ipcMain.handle('updater:status', guard(() => publicStatus()));
  ipcMain.handle('updater:check', guard(async () => { await check(false); return publicStatus(); }));
  ipcMain.handle('updater:install', guard(() => install(true)));
  ipcMain.handle('updater:set-prefs', guard((p) => {
    prefs.autoCheck = p?.autoCheck === true;
    prefs.autoInstall = p?.autoInstall === true;
    savePrefs();
    return publicStatus();
  }));

  app.on('before-quit', () => { if (stagedInstaller) runInstaller(false); });

  if (!app.isPackaged) { status = { state: 'unsupported' }; return; }
  if (!PUBLIC_KEYS.length) { status = { state: 'not-configured' }; return; }
  const tick = () => { if (prefs.autoCheck && Date.now() - prefs.lastCheck > CHECK_INTERVAL) check(true); };
  setTimeout(tick, 15_000);
  setInterval(tick, 60 * 60 * 1000).unref();
}

module.exports = { init };
