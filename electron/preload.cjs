// Preload (sandboxed): exposes only the updater's fixed requests to the page.
// The page can ask for the status, a check, the install of what the last check
// verified, and the automatic-update preferences; it can pass no URL or path.
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('labUpdater', {
  status: () => ipcRenderer.invoke('updater:status'),
  check: () => ipcRenderer.invoke('updater:check'),
  install: () => ipcRenderer.invoke('updater:install'),
  setPrefs: (prefs) => ipcRenderer.invoke('updater:set-prefs', { autoCheck: prefs?.autoCheck === true, autoInstall: prefs?.autoInstall === true }),
  onChange: (cb) => {
    const listener = (_e, status) => cb(status);
    ipcRenderer.on('updater:changed', listener);
    return () => ipcRenderer.removeListener('updater:changed', listener);
  },
});
