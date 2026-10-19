import { COMMAND_REFS } from '../../content/commands';
import { GLOSSARY } from '../../content/glossary';
import { ASSESSMENTS, LESSONS } from '../../content/lessons';
import { ALL_SCENARIOS } from '../../engine/scenarios';
import { CURRICULUM } from '../../content/curriculum';
import { go, routeQuery } from '../state';

interface Hit { kind: string; title: string; snippet: string; link: string }

function snippet(text: string, q: string): string {
  const i = text.toLowerCase().indexOf(q);
  if (i < 0) return text.slice(0, 140);
  return (i > 50 ? '…' : '') + text.slice(Math.max(0, i - 50), i + 90).replace(/\s+/g, ' ') + '…';
}

export function searchAll(query: string): Hit[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  const hits: Hit[] = [];
  for (const L of LESSONS) {
    const sections: [string, string, string][] = [
      ['what', 'What is it?', L.what], ['internals', 'How it works', L.internals], ['config', 'Configuration', L.configIntro + L.directives.map((d) => `${d.name} ${d.explanation} ${d.security}`).join(' ')],
      ['troubleshoot', 'Troubleshooting', L.troubleshootingIntro + L.errorMap.map((e) => `${e.message} ${e.meaning}`).join(' ')],
      ['deploy', 'Deploy', L.deployment.flatMap((d) => d.steps.map((s) => `${s.title} ${s.command ?? ''} ${s.what} ${s.why}`)).join(' ')],
    ];
    for (const [id, title, text] of sections) if (text.toLowerCase().includes(q)) hits.push({ kind: 'Lesson', title: `${L.title} › ${title}`, snippet: snippet(text, q), link: `lesson/${L.id}/${id}` });
  }
  for (const c of COMMAND_REFS) {
    const text = `${c.name} ${c.purpose} ${c.syntax} ${c.interpretation} ${c.limitations}`;
    if (text.toLowerCase().includes(q)) hits.push({ kind: `Command (${c.platform})`, title: c.name, snippet: snippet(c.purpose, q), link: `commands?id=${c.id}&q=${encodeURIComponent(c.name)}` });
  }
  for (const g of GLOSSARY) if (`${g.term} ${g.definition}`.toLowerCase().includes(q)) hits.push({ kind: 'Glossary', title: g.term, snippet: snippet(g.definition, q), link: `glossary?q=${encodeURIComponent(g.term)}` });
  for (const s of ALL_SCENARIOS) if (`${s.title} ${s.ticket}`.toLowerCase().includes(q)) hits.push({ kind: 'Troubleshooting ticket', title: s.title, snippet: snippet(s.ticket, q), link: `troubleshoot/${s.id}` });
  for (const a of Object.values(ASSESSMENTS)) for (const qq of a.questions) if (qq.prompt.toLowerCase().includes(q)) hits.push({ kind: 'Assessment', title: qq.prompt.slice(0, 70), snippet: '', link: `lesson/${a.id}/assess` });
  for (const m of CURRICULUM) for (const t of m.topics) if (t.title.toLowerCase().includes(q)) hits.push({ kind: `Curriculum (${t.status})`, title: `${m.id}: ${t.title}`, snippet: t.note ?? '', link: t.link ?? 'curriculum' });
  return hits;
}

export function Search() {
  const q = routeQuery().get('q') ?? '';
  const hits = searchAll(q);
  return (
    <div className="page">
      <h1>Search: “{q}”</h1>
      {hits.length === 0 && <p className="muted">No results. Searches lessons, commands, glossary, tickets, assessment and curriculum.</p>}
      {hits.map((h, i) => (
        <div key={i} className="card" style={{ marginBottom: 8, cursor: 'pointer' }} onClick={() => go(h.link)}>
          <div className="small muted">{h.kind}</div>
          <strong>{h.title}</strong>
          {h.snippet && <div className="small">{h.snippet}</div>}
        </div>
      ))}
    </div>
  );
}
