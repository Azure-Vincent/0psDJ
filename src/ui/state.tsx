import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { emptyProgress, loadProgress, saveProgress, type Progress } from '../learning/progress';

function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

interface ProgressCtx {
  progress: Progress;
  update(fn: (p: Progress) => Progress): void;
  reset(): void;
  replace(p: Progress): void;
}

const Ctx = createContext<ProgressCtx | null>(null);

export function ProgressProvider({ children }: { children: ReactNode }) {
  const [progress, setProgress] = useState<Progress>(() => loadProgress(storage()));
  useEffect(() => saveProgress(storage(), progress), [progress]);
  const update = useCallback((fn: (p: Progress) => Progress) => setProgress((p) => fn(p)), []);
  const value = useMemo(
    () => ({ progress, update, reset: () => setProgress(emptyProgress()), replace: (p: Progress) => setProgress(p) }),
    [progress, update],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useProgress(): ProgressCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('ProgressProvider missing');
  return c;
}

// --- Hash router ---------------------------------------------------------------

export function useRoute(): string[] {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const on = () => setHash(window.location.hash);
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  const path = hash.replace(/^#\/?/, '').split('?')[0];
  return path ? path.split('/').map(decodeURIComponent) : ['dashboard'];
}

export function routeQuery(): URLSearchParams {
  return new URLSearchParams(window.location.hash.split('?')[1] ?? '');
}

export function go(path: string): void {
  window.location.hash = '#/' + path;
}

export function now(): number {
  return Date.now();
}
