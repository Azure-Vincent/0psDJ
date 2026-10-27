// The desktop app's updater, as the page sees it (electron/preload.cjs). The
// page can only ask for the status, a check, the install of the update the
// last check verified, and the automatic-update preferences. In a browser
// there is no updater.

import { useEffect, useState } from 'react';

export type UpdateState =
  | 'idle' | 'unsupported' | 'not-configured' | 'checking' | 'current' | 'unsigned' | 'no-build' | 'available'
  | 'downloading' | 'ready' | 'restarting' | 'downloaded' | 'error';

export interface UpdateStatus {
  state: UpdateState;
  current: string;
  supported: boolean;
  configured: boolean;
  autoCheck: boolean;
  autoInstall: boolean;
  lastCheck: number | null;
  latest?: string;
  mode?: 'nsis' | 'appimage' | 'download';
  releaseUrl?: string;
  size?: number;
  received?: number;
  total?: number;
  file?: string;
  tag?: string;
  platform?: string;
  error?: string;
}

interface LabUpdater {
  status(): Promise<UpdateStatus>;
  check(): Promise<UpdateStatus>;
  install(): Promise<UpdateStatus>;
  setPrefs(p: { autoCheck: boolean; autoInstall: boolean }): Promise<UpdateStatus>;
  onChange(cb: (s: UpdateStatus) => void): () => void;
}

export const updater: LabUpdater | undefined = (globalThis as { labUpdater?: LabUpdater }).labUpdater;

/** The updater's status, kept current; null in a browser or before the first answer. */
export function useUpdateStatus(): [UpdateStatus | null, (s: UpdateStatus) => void] {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  useEffect(() => {
    if (!updater) return;
    let live = true;
    updater.status().then((s) => live && setStatus(s)).catch(() => {});
    const off = updater.onChange((s) => live && setStatus(s));
    return () => { live = false; off(); };
  }, []);
  return [status, setStatus];
}
