import { useEffect, useRef, useSyncExternalStore } from 'react';
import {
  IDLE, formatClock, isBreak, isPaused, parseState, pause, pomodoroConfig, remainingMs, resume, skipBreak, startStudy, stop, tick,
  type PomodoroConfig, type PomodoroEvent, type PomodoroState,
} from '../learning/pomodoro';
import { useProgress } from './state';

// The timer state lives outside React so it survives page changes, and in localStorage so it
// survives a reload or restart of the app (a running block keeps its wall-clock deadline).
const KEY = 'infralab.pomodoro';

function load(): PomodoroState {
  try {
    return parseState(localStorage.getItem(KEY));
  } catch {
    return IDLE;
  }
}

let state: PomodoroState = load();
let now = Date.now();
const listeners = new Set<() => void>();
let snapshot = { state, now };

function emit() {
  snapshot = { state, now };
  for (const l of listeners) l();
}

function set(next: PomodoroState) {
  state = next;
  now = Date.now();
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    // Storage unavailable: the timer still runs for this session.
  }
  emit();
}

// Another window of the app changed the timer: adopt its state instead of overwriting it.
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (e) => {
    if (e.key !== KEY) return;
    state = parseState(e.newValue);
    now = Date.now();
    emit();
  });
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function usePomodoro(): { state: PomodoroState; now: number; cfg: PomodoroConfig; act: Actions } {
  const snap = useSyncExternalStore(subscribe, () => snapshot);
  const { progress } = useProgress();
  const cfg = pomodoroConfig(progress.settings.pomodoro);
  const t = () => Date.now();
  const act: Actions = {
    start: () => set(startStudy(state, cfg, t())),
    pause: () => set(pause(state, t())),
    resume: () => set(resume(state, t())),
    skipBreak: () => set(skipBreak(state, cfg, t())),
    stop: () => set(stop()),
  };
  return { ...snap, cfg, act };
}

interface Actions {
  start(): void;
  pause(): void;
  resume(): void;
  skipBreak(): void;
  stop(): void;
}

/** A short two-note chime (Web Audio, no sound files). */
function chime(kind: PomodoroEvent) {
  try {
    const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctx) return;
    const ctx = new Ctx();
    // A context created outside a click can start suspended (autoplay policy): ask to resume it.
    void ctx.resume().catch(() => undefined);
    const notes = kind === 'studyDone' ? [660, 880] : [880, 660];
    notes.forEach((f, i) => {
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.type = 'sine';
      o.frequency.value = f;
      const t0 = ctx.currentTime + i * 0.25;
      g.gain.setValueAtTime(0.0001, t0);
      g.gain.exponentialRampToValueAtTime(0.2, t0 + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.22);
      o.connect(g).connect(ctx.destination);
      o.start(t0);
      o.stop(t0 + 0.25);
    });
    setTimeout(() => ctx.close(), 1000);
  } catch {
    // No audio device: the pop-up is enough.
  }
}

const LABEL: Record<PomodoroState['phase'], string> = {
  idle: 'Pomodoro',
  study: 'Study',
  break: 'Break',
  longBreak: 'Long break',
  breakOver: 'Break over',
};

/** Keep Tab inside the dialog. */
function trapFocus(e: React.KeyboardEvent<HTMLDivElement>) {
  if (e.key !== 'Tab') return;
  const items = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('button'));
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (e.shiftKey && (document.activeElement === first || document.activeElement === e.currentTarget)) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

/**
 * Runs the clock (once per second while a phase is running), plays the chime, shows the
 * remaining time in the window title, and renders the break pop-up. Mount once.
 */
export function PomodoroHost() {
  const { state: s, now: n, cfg, act } = usePomodoro();
  const baseTitle = useRef(document.title);
  const dialogRef = useRef<HTMLDivElement>(null);
  const open = isBreak(s) || s.phase === 'breakOver';
  // Take focus when the pop-up opens, so typing in a terminal behind it stops.
  useEffect(() => {
    if (open) dialogRef.current?.focus();
  }, [open, s.phase]);

  const running = s.endsAt !== undefined;
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => {
      now = Date.now();
      const r = tick(state, cfg, now);
      if (r.state !== state) set(r.state);
      else if (state.endsAt !== undefined) emit();
      if (cfg.sound && r.events.length) chime(r.events[r.events.length - 1]);
    }, 1000);
    return () => clearInterval(id);
  }, [running, cfg.studyMin, cfg.breakMin, cfg.longBreakMin, cfg.longEvery, cfg.sound]);

  useEffect(() => {
    const running = s.phase === 'study' || isBreak(s);
    document.title = running ? `${formatClock(remainingMs(s, n))} ${LABEL[s.phase]}${isPaused(s) ? ' (paused)' : ''} · ${baseTitle.current}` : baseTitle.current;
  }, [s, n]);

  if (!isBreak(s) && s.phase !== 'breakOver') return null;
  const left = remainingMs(s, n);
  const total = s.totalMs ?? 1;
  const nextLong = s.phase === 'breakOver' && s.completed > 0 && (s.completed + 1) % cfg.longEvery === 0;
  return (
    <div className="modal-bg" role="presentation">
      <div className="modal pomo-modal" role="dialog" aria-modal="true" aria-labelledby="pomo-title" tabIndex={-1} ref={dialogRef} onKeyDown={trapFocus}>
        {s.phase === 'breakOver' ? (
          <>
            <h2 id="pomo-title">Break over</h2>
            <p>Ready for the next {cfg.studyMin}-minute study block?{nextLong ? ` After it you get a ${cfg.longBreakMin}-minute long break.` : ''}</p>
            <div className="row">
              <button className="primary" onClick={act.start}>Start studying</button>
              <button onClick={act.stop}>Stop the timer</button>
            </div>
          </>
        ) : (
          <>
            <h2 id="pomo-title">{s.phase === 'longBreak' ? 'Long break' : 'Time for a break'}</h2>
            <p className="muted">
              {s.phase === 'longBreak'
                ? `You finished ${cfg.longEvery} study blocks. Take a proper rest: walk around, get a drink, rest your eyes.`
                : 'Step away from the screen: stand up, stretch, look at something far away.'}
            </p>
            <div className="pomo-big" aria-live="off">{formatClock(left)}</div>
            <span className="meter ok" aria-hidden><span style={{ width: `${Math.round((1 - left / total) * 100)}%` }} /></span>
            <div className="row">
              {isPaused(s) ? <button onClick={act.resume}>Resume break</button> : <button onClick={act.pause}>Pause</button>}
              <button onClick={act.skipBreak}>Skip break and study</button>
              <button onClick={act.stop}>Stop the timer</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/** The timer in the sidebar: phase, time left, completed blocks and controls. */
export function PomodoroWidget() {
  const { state: s, now: n, cfg, act } = usePomodoro();
  const running = s.phase === 'study' || isBreak(s);
  const left = running ? remainingMs(s, n) : s.phase === 'idle' ? cfg.studyMin * 60_000 : 0;
  const done = s.completed % cfg.longEvery;
  return (
    <div className={`pomo pomo-${s.phase}`} aria-label="Pomodoro timer">
      <div className="pomo-head">
        <span aria-hidden>🍅</span>
        <span className="pomo-label">{LABEL[s.phase]}{isPaused(s) ? ' (paused)' : ''}</span>
        <span className="pomo-time" role="timer">{s.phase === 'breakOver' ? '' : formatClock(left)}</span>
      </div>
      {running && <span className={`meter${isBreak(s) ? ' ok' : ''}`} aria-hidden><span style={{ width: `${Math.round((1 - left / (s.totalMs ?? 1)) * 100)}%` }} /></span>}
      <div className="pomo-dots" title={`${done} of ${cfg.longEvery} study blocks before the long break`}>
        {Array.from({ length: cfg.longEvery }, (_, i) => <span key={i} className={i < done ? 'on' : ''} />)}
      </div>
      <div className="pomo-actions">
        {s.phase === 'idle' && <button onClick={act.start}>Start studying</button>}
        {s.phase === 'breakOver' && <button onClick={act.start}>Next block</button>}
        {running && (isPaused(s) ? <button onClick={act.resume}>Resume</button> : <button onClick={act.pause}>Pause</button>)}
        {s.phase !== 'idle' && <button onClick={act.stop} title="Stop and reset the timer">Stop</button>}
      </div>
    </div>
  );
}

/** Compact time shown in the collapsed sidebar rail. */
export function PomodoroRail() {
  const { state: s, now: n } = usePomodoro();
  if (s.phase !== 'study' && !isBreak(s)) return null;
  return (
    <div className={`pomo-rail pomo-${s.phase}`} title={`${LABEL[s.phase]}: ${formatClock(remainingMs(s, n))} left`}>
      🍅<br />{Math.ceil(remainingMs(s, n) / 60_000)}m
    </div>
  );
}
