import { useState } from 'react';
import { GLOSSARY } from '../../content/glossary';
import { Inline } from '../components/Markdown';
import { routeQuery } from '../state';

export function Glossary() {
  const [q, setQ] = useState(routeQuery().get('q') ?? '');
  const list = GLOSSARY.filter((g) => `${g.term} ${g.definition}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="page">
      <h1>Glossary</h1>
      <input placeholder="Filter terms…" value={q} onChange={(e) => setQ(e.target.value)} style={{ marginBottom: 12, width: 320 }} />
      <table>
        <tbody>
          {list.map((g) => (
            <tr key={g.term} id={`term-${g.term}`}>
              <th style={{ width: 220 }}>{g.term}</th>
              <td><Inline text={g.definition} />{g.related && <div className="small muted">Related: {g.related.join(', ')}</div>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
