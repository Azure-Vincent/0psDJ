// A strip on lesson and lab pages that places the page on the study roadmap
// and leads to the previous and next step.

import { ROADMAP, ROADMAP_STEPS } from '../../content/roadmap';
import { roadmapIndexOf, viewStep } from '../roadmapProgress';
import { go, useProgress } from '../state';

export function RoadmapBar({ kind, id, emphasiseNext = false }: { kind: 'lesson' | 'lab'; id: string; emphasiseNext?: boolean }) {
  const { progress } = useProgress();
  const i = roadmapIndexOf(kind, id);
  if (i < 0) return null;
  const { phase } = ROADMAP_STEPS[i];
  const prev = ROADMAP_STEPS[i - 1];
  const next = ROADMAP_STEPS[i + 1];
  const pv = prev && viewStep(progress, prev.step);
  const nv = next && viewStep(progress, next.step);
  const done = viewStep(progress, ROADMAP_STEPS[i].step).status === 'done';
  // Practice steps (open-ended, no completion) are not counted.
  const tracked = ROADMAP_STEPS.filter(({ step }) => step.kind !== 'practice');
  const n = tracked.findIndex((x) => x.index === i) + 1;
  return (
    <nav className="roadmap-bar small" aria-label="Roadmap">
      <a href="#/start" className="roadmap-where">
        Roadmap · Phase {ROADMAP.indexOf(phase) + 1}: {phase.title} · step {n} of {tracked.length}
      </a>
      <span className="roadmap-nav">
        {pv && <button type="button" className="link" onClick={() => go(pv.link)} title={pv.title}>← {pv.title.split(':')[0]}</button>}
        {nv && (
          <button type="button" className={done || emphasiseNext ? 'primary' : ''} onClick={() => go(nv.link)} title={`${nv.kindLabel}: ${nv.title}`}>
            Next: {nv.title.split(':')[0]} →
          </button>
        )}
      </span>
    </nav>
  );
}
