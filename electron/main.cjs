// Electron shell for Infrastructure Lab.
// The renderer is a fully offline static build (dist/). No network access is
// required; all simulations run locally in the renderer process.
const { app, BrowserWindow, nativeTheme, shell } = require('electron');
const path = require('node:path');

const isDev = process.argv.includes('--dev');

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 680,
    title: 'Infrastructure Lab',
    // Matches the default soft themes (Ember / Paper) so the window does not flash white while loading.
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#262321' : '#f3ead7',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  // Open external reference links (RFCs, vendor docs) in the system browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  if (isDev) {
    win.loadURL('http://localhost:5173');
  } else {
    win.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
