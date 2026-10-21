// Certification objective map (#/certification): where each published exam
// objective is covered in the application, and where the gaps are.

import { useState } from 'react';
import { CERT_DISCLAIMER, CERT_EXAMS } from '../../content/certification';
import { Inline } from '../components/Markdown';
import { routeQuery } from '../state';

const COVERAGE: Record<string, [string, string]> = { covered: ['ok', 'covered'], partial: ['warn', 'partial'], gap: ['err', 'gap'] };

function linkLabel(l: string): string {
  const [head, a, b] = l.split(/[/?]/);
  if (head === 'lesson') return `Lesson: ${a}${b ? ` › ${b}` : ''}`;
  if (head === 'troubleshoot') return `Ticket: ${a}`;
  if (head === 'cases') return `Case study: ${a}`;
  if (head === 'reference') return `Reference: ${decodeURIComponent(l.split('id=')[1] ?? '')}`;
  return l;
}

export function Certification() {
  const focus = routeQuery().get('o');
  const [examId, setExamId] = useState(() => CERT_EXAMS.find((e) => focus?.startsWith(e.code + ':'))?.id ?? CERT_EXAMS[0]?.id);
  const [onlyGaps, setOnlyGaps] = useState(false);
  const exam = CERT_EXAMS.find((e) => e.id === examId);
  return (
    <div className="page">
      <h1>Certification map</h1>
      <div className="callout warn small">{CERT_DISCLAIMER}</div>
      <div className="row" style={{ margin: '10px 0' }}>
        {CERT_EXAMS.map((e) => <button key={e.id} className={e.id === examId ? 'primary' : ''} onClick={() => setExamId(e.id)}>{e.name} ({e.code})</button>)}
        <label className="row small"><input type="checkbox" checked={onlyGaps} onChange={(e) => setOnlyGaps(e.target.checked)} /> Show only partial coverage and gaps</label>
      </div>
      {exam && (
        <>
          <p className="small">
            Objectives version: <strong>{exam.version}</strong>. Official outline: <a href={exam.officialUrl} target="_blank" rel="noreferrer">{exam.officialUrl}</a>.
            {' '}Coverage: {(['covered', 'partial', 'gap'] as const).map((k) => `${exam.domains.flatMap((d) => d.objectives).filter((o) => o.coverage === k).length} ${k}`).join(' · ')}.
          </p>
          {exam.domains.map((d) => {
            const objs = d.objectives.filter((o) => !onlyGaps || o.coverage !== 'covered');
            if (objs.length === 0) return null;
            return (
              <div key={d.id}>
                <h2>{d.id} {d.title} <span className="muted small">({d.weight})</span></h2>
                <table>
                  <thead><tr><th style={{ width: 70 }}>Objective</th><th>Title</th><th style={{ width: 90 }}>Coverage</th><th>Where in the app</th></tr></thead>
                  <tbody>
                    {objs.map((o) => (
                      <tr key={o.id} id={`obj-${o.id}`} style={focus === o.id ? { outline: '2px solid var(--accent)' } : undefined}>
                        <td className="mono small">{o.id.split(':')[1]}</td>
                        <td className="small">{o.title}{o.note && <div className="muted"><Inline text={o.note} /></div>}</td>
                        <td><span className={`badge ${COVERAGE[o.coverage][0]}`}>{COVERAGE[o.coverage][1]}</span></td>
                        <td className="small">{o.links.length ? o.links.map((l) => <div key={l}><a href={`#/${l}`}>{linkLabel(l)}</a></div>) : <span className="muted">not covered</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}
