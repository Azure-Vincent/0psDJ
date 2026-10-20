// Starts Electron from node_modules for `npm run desktop` / `desktop:dev`.
//
// Same rule as the launcher installed in packaged Linux builds
// (build/afterPack.cjs): keep Chromium's sandbox when it can work, and add
// --no-sandbox only when the system restricts unprivileged user namespaces
// (e.g. Ubuntu 23.10+/24.04 AppArmor) and chrome-sandbox is not setuid root,
// or when running as root.

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const electron = require('electron'); // path to the Electron binary when required from Node
const args = process.argv.slice(2);

function read(p) {
  try {
    return fs.readFileSync(p, 'utf8').trim();
  } catch {
    return null;
  }
}

function sandboxAvailable() {
  const helper = path.join(path.dirname(electron), 'chrome-sandbox');
  try {
    const st = fs.statSync(helper);
    if (st.uid === 0 && (st.mode & 0o4000) !== 0) return true; // setuid-root helper
  } catch {
    /* no helper: rely on user namespaces */
  }
  if (read('/proc/sys/kernel/unprivileged_userns_clone') === '0') return false;
  if (read('/proc/sys/kernel/apparmor_restrict_unprivileged_userns') === '1') return false;
  if (read('/proc/sys/user/max_user_namespaces') === '0') return false;
  return true;
}

if (process.platform === 'linux' && !args.includes('--no-sandbox')) {
  if (process.getuid && process.getuid() === 0) args.unshift('--no-sandbox');
  else if (!sandboxAvailable()) {
    console.error('Infrastructure Lab: this system restricts unprivileged user namespaces and chrome-sandbox is not setuid root; starting with --no-sandbox.');
    args.unshift('--no-sandbox');
  }
}

const child = spawn(electron, args, { stdio: 'inherit' });
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 0);
});
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => child.kill(s));
