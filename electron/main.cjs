// Electron shell for Cyber Owl Lab.
// The renderer is a fully offline static build (dist/). All simulations run
// locally in the renderer process; the only network access is the optional
// update check (update-service.cjs), made by the main process to GitHub.
const { app, BrowserWindow, nativeTheme, shell } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const updates = require('./update-service.cjs');

// --dev (load the Vite dev server) only when running from source: a packaged app always loads its own files.
const isDev = process.argv.includes('--dev') && !app.isPackaged;
const DIST = path.join(__dirname, '..', 'dist');
const DEV_URL = 'http://localhost:5173/';

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 680,
    title: 'Cyber Owl Lab',
    // Matches the default soft themes (Ember / Paper) so the window does not flash white while loading.
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#262321' : '#f3ead7',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  // Open external reference links (RFCs, vendor docs) in the system browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  // The page never navigates away from the app (links to other sites open in the browser).
  win.webContents.on('will-navigate', (e, url) => {
    if (!url.startsWith(isDev ? DEV_URL : `${pathToFileURL(DIST).href}/`)) e.preventDefault();
  });

  if (isDev) {
    win.loadURL(DEV_URL);
  } else {
    win.loadFile(path.join(DIST, 'index.html'));
  }
}

app.whenReady().then(() => {
  updates.init(DIST, isDev ? DEV_URL : null);
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
