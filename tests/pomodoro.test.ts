import { describe, expect, it } from 'vitest';
import {
  DEFAULT_POMODORO, IDLE, formatClock, parseState, pause, pomodoroConfig, remainingMs, resume, skipBreak, startStudy, tick,
} from '../src/learning/pomodoro';
import { emptyProgress, loadProgress } from '../src/learning/progress';

const MIN = 60_000;
const cfg = { ...DEFAULT_POMODORO, studyMin: 25, breakMin: 5, longBreakMin: 15, longEvery: 2 };

describe('pomodoro timer', () => {
  it('runs study → break → break over, and counts the block', () => {
    let s = startStudy(IDLE, cfg, 0);
    expect(s.phase).toBe('study');
    expect(remainingMs(s, 10 * MIN)).toBe(15 * MIN);
    expect(tick(s, cfg, 24 * MIN).events).toEqual([]);
    let r = tick(s, cfg, 25 * MIN);
    expect(r.events).toEqual(['studyDone']);
    s = r.state;
    expect(s).toMatchObject({ phase: 'break', completed: 1, endsAt: 30 * MIN });
    r = tick(s, cfg, 30 * MIN);
    expect(r.events).toEqual(['breakDone']);
    expect(r.state).toMatchObject({ phase: 'breakOver', completed: 1 });
  });

  it('gives the long break after the configured number of blocks, then starts a new cycle', () => {
    let s = startStudy(IDLE, cfg, 0);
    s = tick(s, cfg, 25 * MIN).state; // block 1 → short break
    s = tick(s, cfg, 30 * MIN).state;
    s = startStudy(s, cfg, 31 * MIN);
    s = tick(s, cfg, 56 * MIN).state; // block 2 → long break
    expect(s).toMatchObject({ phase: 'longBreak', completed: 2, endsAt: 71 * MIN });
    s = tick(s, cfg, 71 * MIN).state;
    expect(s).toMatchObject({ phase: 'breakOver', completed: 0 });
  });

  it('keeps wall-clock time: a block that ended while the app was closed still starts its break on time', () => {
    const s = startStudy(IDLE, cfg, 0);
    const r = tick(s, cfg, 32 * MIN); // closed through the whole block and the break
    expect(r.events).toEqual(['studyDone', 'breakDone']);
    expect(r.state.phase).toBe('breakOver');
    const mid = tick(s, cfg, 27 * MIN).state; // back during the break: 3 minutes of it remain
    expect(remainingMs(mid, 27 * MIN)).toBe(3 * MIN);
  });

  it('forgets a session whose break ended long ago (app reopened the next day), with no pop-up', () => {
    const r = tick(startStudy(IDLE, cfg, 0), cfg, 24 * 60 * MIN);
    expect(r).toEqual({ state: IDLE, events: [] });
  });

  it('pauses and resumes without losing time', () => {
    let s = startStudy(IDLE, cfg, 0);
    s = pause(s, 10 * MIN);
    expect(tick(s, cfg, 60 * MIN).events).toEqual([]);
    expect(remainingMs(s, 60 * MIN)).toBe(15 * MIN);
    s = resume(s, 60 * MIN);
    expect(s.endsAt).toBe(75 * MIN);
  });

  it('skipping a break starts the next study block at once', () => {
    let s = tick(startStudy(IDLE, cfg, 0), cfg, 25 * MIN).state;
    s = skipBreak(s, cfg, 26 * MIN);
    expect(s).toMatchObject({ phase: 'study', completed: 1, endsAt: 51 * MIN });
  });

  it('clamps settings and fills in defaults', () => {
    expect(pomodoroConfig(undefined)).toEqual(DEFAULT_POMODORO);
    expect(pomodoroConfig({ studyMin: 1, breakMin: 99, longBreakMin: Number.NaN, longEvery: 3.6 })).toMatchObject({ studyMin: 5, breakMin: 30, longBreakMin: 15, longEvery: 4 });
  });

  it('formats the clock and restores stored state safely', () => {
    expect(formatClock(25 * MIN)).toBe('25:00');
    expect(formatClock(61_500)).toBe('1:02');
    expect(formatClock(0)).toBe('0:00');
    expect(parseState('{"phase":"study","endsAt":5,"completed":2}')).toMatchObject({ phase: 'study', endsAt: 5, completed: 2 });
    expect(parseState('{"phase":"party"}')).toEqual(IDLE);
    expect(parseState('not json')).toEqual(IDLE);
  });

  it('old progress files without timer settings still load', () => {
    const old = JSON.stringify({ ...emptyProgress(), settings: { theme: 'dark' } });
    const p = loadProgress({ getItem: () => old });
    expect(pomodoroConfig(p.settings.pomodoro)).toEqual(DEFAULT_POMODORO);
  });
});
