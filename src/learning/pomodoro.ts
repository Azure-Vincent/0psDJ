/**
 * Pomodoro study timer: focused study blocks separated by short breaks, with a longer
 * break after every few blocks. Pure state machine (no timers, no DOM) so the UI can
 * persist it, survive reloads and route changes, and so it can be tested with a fake clock.
 *
 * Time is anchored on wall-clock deadlines (`endsAt`), not on counting ticks: a tab in the
 * background or a sleeping laptop still ends a phase on time.
 */

export interface PomodoroConfig {
  /** Length of a study block, minutes. */
  studyMin: number;
  /** Length of a short break, minutes. */
  breakMin: number;
  /** Length of the long break, minutes. */
  longBreakMin: number;
  /** A long break replaces the short one after this many study blocks. */
  longEvery: number;
  /** Play a short chime when a phase ends. */
  sound: boolean;
}

export const DEFAULT_POMODORO: PomodoroConfig = { studyMin: 25, breakMin: 5, longBreakMin: 15, longEvery: 4, sound: true };

/** Allowed ranges for the settings form (inclusive). */
export const POMODORO_LIMITS = {
  studyMin: [5, 120],
  breakMin: [1, 30],
  longBreakMin: [5, 60],
  longEvery: [2, 8],
} as const satisfies Record<string, readonly [number, number]>;

/** A complete, valid configuration from possibly partial or out-of-range stored values. */
export function pomodoroConfig(stored?: Partial<PomodoroConfig> | null): PomodoroConfig {
  const c = { ...DEFAULT_POMODORO, ...(stored ?? {}) };
  const clamp = (k: keyof typeof POMODORO_LIMITS) => {
    const [lo, hi] = POMODORO_LIMITS[k];
    const v = Math.round(Number(c[k]));
    return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : DEFAULT_POMODORO[k];
  };
  return { studyMin: clamp('studyMin'), breakMin: clamp('breakMin'), longBreakMin: clamp('longBreakMin'), longEvery: clamp('longEvery'), sound: c.sound !== false };
}

/** idle: not running. breakOver: the break ended and the next study block waits for the student. */
export type PomodoroPhase = 'idle' | 'study' | 'break' | 'longBreak' | 'breakOver';

export interface PomodoroState {
  phase: PomodoroPhase;
  /** When the running phase ends (ms since epoch). Absent when idle, paused or breakOver. */
  endsAt?: number;
  /** Time left when paused (ms). */
  remainingMs?: number;
  /** Total length of the current phase (ms), for progress bars. */
  totalMs?: number;
  /** Study blocks finished in the current cycle (resets after a long break). */
  completed: number;
}

export type PomodoroEvent = 'studyDone' | 'breakDone';

export const IDLE: PomodoroState = { phase: 'idle', completed: 0 };

const MIN = 60_000;
/** A break that ended more than this long ago is forgotten: the timer goes back to idle. */
export const STALE_MS = 60 * MIN;

export function phaseLengthMs(phase: PomodoroPhase, cfg: PomodoroConfig): number {
  switch (phase) {
    case 'study': return cfg.studyMin * MIN;
    case 'break': return cfg.breakMin * MIN;
    case 'longBreak': return cfg.longBreakMin * MIN;
    default: return 0;
  }
}

export const isBreak = (s: PomodoroState) => s.phase === 'break' || s.phase === 'longBreak';
export const isPaused = (s: PomodoroState) => s.remainingMs !== undefined && s.endsAt === undefined;

export function startStudy(s: PomodoroState, cfg: PomodoroConfig, now: number): PomodoroState {
  const totalMs = phaseLengthMs('study', cfg);
  return { phase: 'study', endsAt: now + totalMs, totalMs, completed: s.phase === 'idle' ? 0 : s.completed };
}

/** Start the break that follows a study block (also used to take a break early). */
function startBreak(completed: number, cfg: PomodoroConfig, from: number): PomodoroState {
  const phase = completed > 0 && completed % cfg.longEvery === 0 ? 'longBreak' : 'break';
  const totalMs = phaseLengthMs(phase, cfg);
  return { phase, endsAt: from + totalMs, totalMs, completed };
}

export function pause(s: PomodoroState, now: number): PomodoroState {
  if (s.endsAt === undefined) return s;
  return { ...s, endsAt: undefined, remainingMs: Math.max(0, s.endsAt - now) };
}

export function resume(s: PomodoroState, now: number): PomodoroState {
  if (!isPaused(s)) return s;
  return { ...s, endsAt: now + s.remainingMs!, remainingMs: undefined };
}

/** End the break now and go straight back to studying. */
export function skipBreak(s: PomodoroState, cfg: PomodoroConfig, now: number): PomodoroState {
  if (!isBreak(s) && s.phase !== 'breakOver') return s;
  return startStudy(s, cfg, now);
}

export function stop(): PomodoroState {
  return IDLE;
}

export function remainingMs(s: PomodoroState, now: number): number {
  if (s.endsAt !== undefined) return Math.max(0, s.endsAt - now);
  return s.remainingMs ?? 0;
}

/**
 * Advance the timer to `now`. A study block that ended starts its break (anchored on the
 * block's scheduled end, so time away from the app counts); a break that ended waits in
 * `breakOver` for the student to start the next block. Returns the events that happened,
 * oldest first (both when the app was closed through a whole break).
 */
export function tick(s: PomodoroState, cfg: PomodoroConfig, now: number): { state: PomodoroState; events: PomodoroEvent[] } {
  const events: PomodoroEvent[] = [];
  let cur = s;
  if (cur.phase === 'study' && cur.endsAt !== undefined && now >= cur.endsAt) {
    cur = startBreak(cur.completed + 1, cfg, cur.endsAt);
    events.push('studyDone');
  }
  if (isBreak(cur) && cur.endsAt !== undefined && now >= cur.endsAt) {
    // Back long after the break ended (app closed overnight): start fresh, without a pop-up for a stale session.
    if (now - cur.endsAt > STALE_MS) return { state: IDLE, events: [] };
    cur = { phase: 'breakOver', completed: cur.phase === 'longBreak' ? 0 : cur.completed };
    events.push('breakDone');
  }
  return { state: cur, events };
}

/** mm:ss (or h:mm:ss) for a duration, rounding up so 0:00 shows only at the end. */
export function formatClock(ms: number): string {
  const total = Math.ceil(Math.max(0, ms) / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = String(total % 60).padStart(2, '0');
  return h ? `${h}:${String(m).padStart(2, '0')}:${sec}` : `${m}:${sec}`;
}

/** Restore a stored state, dropping anything malformed. */
export function parseState(raw: string | null): PomodoroState {
  try {
    const s = raw ? JSON.parse(raw) : null;
    if (!s || !['idle', 'study', 'break', 'longBreak', 'breakOver'].includes(s.phase)) return IDLE;
    const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
    return { phase: s.phase, endsAt: num(s.endsAt), remainingMs: num(s.remainingMs), totalMs: num(s.totalMs), completed: num(s.completed) ?? 0 };
  } catch {
    return IDLE;
  }
}
