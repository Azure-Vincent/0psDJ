// Local progress store: concept-level mastery, assessment answers, troubleshooting
// attempt history and predictions. Persisted to localStorage (inside Electron
// this lives in the app's userData directory). No network, no accounts.

import type { ConceptId } from '../engine/scenarios/types';

export interface ConceptStat {
  correct: number;
  incorrect: number;
  lastSeen: number;
  /** Misconception keys (e.g. cause ids or question option ids) the learner showed. */
  misconceptions: string[];
}

export interface TroubleshootingAttempt {
  id: string;
  scenarioId: string;
  startedAt: number;
  endedAt?: number;
  status: 'in-progress' | 'resolved' | 'revealed' | 'abandoned';
  hintsUsed: number;
  diagnoses: { time: number; selected: string[]; correct: boolean }[];
  verifications: { time: number; passed: boolean; summary: string }[];
  commands: { time: number; host: string; user: string; line: string; code: number }[];
  notes: { symptoms: string; evidence: string; hypothesis: string };
}

/** system / light / dark use the soft palettes; contrast-* the original high-contrast ones. */
export type Theme = 'system' | 'light' | 'dark' | 'contrast-light' | 'contrast-dark';

export interface Progress {
  version: 1;
  lessons: Record<string, { visited: string[]; lastSection?: string }>;
  concepts: Partial<Record<ConceptId, ConceptStat>>;
  questions: Record<string, { attempts: number; correct: boolean; firstTryCorrect: boolean }>;
  exercises: Record<string, { attempts: number; correct: boolean }>;
  predictions: Record<string, { attempts: number; correct: boolean }>;
  attempts: TroubleshootingAttempt[];
  /** Guided labs: completed step ids (in order of completion), steps done with "do it for me", timestamps. */
  labs: Record<string, LabProgress>;
  settings: { theme: Theme };
}

export interface LabProgress {
  completed: string[];
  assisted: string[];
  startedAt: number;
  finishedAt?: number;
  // Integrated labs (all optional: older saved progress stays valid).
  mode?: 'guided' | 'assisted' | 'independent';
  /** Modes in which the whole lab (including troubleshooting and review) was finished. */
  modesCompleted?: ('guided' | 'assisted' | 'independent')[];
  hints?: number;
  commands?: number;
  /** Diagnostic tools used (first words: ping, ss, dig, journalctl …). */
  tools?: string[];
  /** Service restarts and reboots typed by the learner (during troubleshooting: before the diagnosis). */
  restarts?: number;
  fault?: { injectedAt: number; restartsBefore?: number; solutionShown?: boolean; diagnosis?: { selected: string[]; correct: boolean; attempts: number }; repairedAt?: number; hints?: number; commandsBefore?: number };
  /** Review answers: question id → chosen index (first answer counts). */
  review?: Record<string, number>;
  notes?: string;
  /** Assisted mode: steps whose detailed tasks were revealed (each counted once as a hint). */
  tasksShown?: string[];
}

export const STORAGE_KEY = 'infralab.progress.v1';

export function emptyProgress(): Progress {
  return { version: 1, lessons: {}, concepts: {}, questions: {}, exercises: {}, predictions: {}, attempts: [], labs: {}, settings: { theme: 'system' } };
}

export function loadProgress(storage: Pick<Storage, 'getItem'> | null): Progress {
  try {
    const raw = storage?.getItem(STORAGE_KEY);
    if (!raw) return emptyProgress();
    const p = JSON.parse(raw);
    if (p?.version !== 1) return emptyProgress();
    return { ...emptyProgress(), ...p, settings: { ...emptyProgress().settings, ...p.settings } };
  } catch {
    return emptyProgress();
  }
}

export function saveProgress(storage: Pick<Storage, 'setItem'> | null, p: Progress): void {
  try {
    storage?.setItem(STORAGE_KEY, JSON.stringify(p));
  } catch {
    /* storage full or unavailable: progress stays in memory for this session */
  }
}

export function recordConcepts(p: Progress, concepts: ConceptId[], correct: boolean, time: number, misconception?: string): Progress {
  const next = { ...p, concepts: { ...p.concepts } };
  for (const c of concepts) {
    const s: ConceptStat = { correct: 0, incorrect: 0, lastSeen: 0, misconceptions: [], ...next.concepts[c] };
    next.concepts[c] = {
      correct: s.correct + (correct ? 1 : 0),
      incorrect: s.incorrect + (correct ? 0 : 1),
      lastSeen: time,
      misconceptions: misconception && !correct ? [...s.misconceptions.filter((m) => m !== misconception), misconception].slice(-8) : s.misconceptions,
    };
  }
  return next;
}

export type MasteryLevel = 'not started' | 'learning' | 'struggling' | 'proficient';

/** Laplace-smoothed accuracy plus evidence count. */
export function mastery(s: ConceptStat | undefined): { score: number; level: MasteryLevel } {
  if (!s || s.correct + s.incorrect === 0) return { score: 0, level: 'not started' };
  const score = (s.correct + 1) / (s.correct + s.incorrect + 2);
  if (s.incorrect >= 2 && score < 0.5) return { score, level: 'struggling' };
  if (score >= 0.75 && s.correct >= 3) return { score, level: 'proficient' };
  return { score, level: 'learning' };
}
