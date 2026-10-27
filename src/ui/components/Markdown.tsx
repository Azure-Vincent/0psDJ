// Renderer for the content "markdown-lite" format (see content/types.ts).
// Builds React elements directly; no HTML injection.

import { Fragment, type ReactNode } from 'react';

function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = [];
  // [label](#/lesson/ipnet/internals): links to other pages of the app (in-app routes only).
  const re = /(`[^`]+`|\[[^\]]+\]\(#\/[^)\s]+\)|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith('`')) out.push(<code key={`${keyBase}-${i++}`}>{tok.slice(1, -1)}</code>);
    else if (tok.startsWith('[')) {
      const m2 = /^\[([^\]]+)\]\((#\/[^)]+)\)$/.exec(tok)!;
      out.push(<a key={`${keyBase}-${i++}`} href={m2[2]}>{inline(m2[1], `${keyBase}-l${i}`)}</a>);
    }
    else if (tok.startsWith('**')) out.push(<strong key={`${keyBase}-${i++}`}>{tok.slice(2, -2)}</strong>);
    else out.push(<em key={`${keyBase}-${i++}`}>{tok.slice(1, -1)}</em>);
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Inline({ text }: { text: string }) {
  return <>{inline(text, 'i')}</>;
}

export function Markdown({ text }: { text: string }) {
  const lines = text.replace(/^\n+|\n+$/g, '').split('\n');
  const blocks: ReactNode[] = [];
  let i = 0;
  let k = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === '') { i++; continue; }
    if (line.startsWith('```')) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) body.push(lines[i++]);
      i++;
      blocks.push(<pre key={k++}>{body.join('\n')}</pre>);
      continue;
    }
    if (line.trim() === ':::practice') {
      // Practice block: "Q:" and "A:" lines (a line without a prefix continues the one above), closed by ":::".
      const pairs: { q: string; a: string }[] = [];
      let cur: 'q' | 'a' = 'q';
      i++;
      while (i < lines.length && lines[i].trim() !== ':::') {
        const l = lines[i++].trim();
        if (l.startsWith('Q: ')) { pairs.push({ q: l.slice(3), a: '' }); cur = 'q'; }
        else if (l.startsWith('A: ') && pairs.length) { pairs[pairs.length - 1].a = l.slice(3); cur = 'a'; }
        else if (l && pairs.length) pairs[pairs.length - 1][cur] += ' ' + l;
      }
      i++;
      blocks.push(
        <div className="practice" key={k++}>
          <div className="practice-head">Practice</div>
          <ol>
            {pairs.map((pq, j) => (
              <li key={j}>
                {inline(pq.q, `pq${k}${j}`)}
                <details><summary>Show answer</summary><div>{inline(pq.a, `pa${k}${j}`)}</div></details>
              </li>
            ))}
          </ol>
        </div>,
      );
      continue;
    }
    if (line.startsWith('### ')) { blocks.push(<h3 key={k++}>{inline(line.slice(4), `h${k}`)}</h3>); i++; continue; }
    if (line.startsWith('> ')) {
      const body: string[] = [];
      while (i < lines.length && lines[i].startsWith('> ')) body.push(lines[i++].slice(2));
      blocks.push(<div className="callout" key={k++}>{inline(body.join(' '), `c${k}`)}</div>);
      continue;
    }
    if (line.startsWith('|')) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i].startsWith('|')) {
        // "\|" is a literal pipe inside a cell (e.g. a shell pipeline).
        const cells = lines[i].split(/(?<!\\)\|/).slice(1, -1).map((c) => c.trim().replace(/\\\|/g, '|'));
        if (!cells.every((c) => /^-+$/.test(c))) rows.push(cells);
        i++;
      }
      const [head, ...body] = rows;
      blocks.push(
        <div key={k++} className="table-scroll"><table>
          <thead><tr>{head.map((c, j) => <th key={j}>{inline(c, `th${j}`)}</th>)}</tr></thead>
          <tbody>{body.map((r, ri) => <tr key={ri}>{r.map((c, j) => <td key={j}>{inline(c, `td${ri}${j}`)}</td>)}</tr>)}</tbody>
        </table></div>,
      );
      continue;
    }
    if (/^(- |\d+\. )/.test(line)) {
      const ordered = /^\d+\. /.test(line);
      // In a numbered list, "- " lines belong to the step above them; a blank line followed by
      // the next number continues the same list, so steps keep their own numbers.
      const items: { text: string; sub: string[] }[] = [];
      const start = ordered ? Number(/^(\d+)\./.exec(line)![1]) : 1;
      while (i < lines.length) {
        const l = lines[i];
        if (ordered && /^- /.test(l) && items.length) { items[items.length - 1].sub.push(l.slice(2)); i++; continue; }
        // In either kind of list, an indented "  - " line is a sub-point of the item above it.
        if (/^ {2,}- /.test(l) && items.length) { items[items.length - 1].sub.push(l.trim().slice(2)); i++; continue; }
        if (ordered ? /^\d+\. /.test(l) : /^- /.test(l)) { items.push({ text: l.replace(/^(- |\d+\. )/, ''), sub: [] }); i++; continue; }
        if (ordered && l.trim() === '' && Number(/^(\d+)\. /.exec(lines[i + 1] ?? '')?.[1]) === start + items.length) { i++; continue; }
        break;
      }
      const Tag = ordered ? 'ol' : 'ul';
      blocks.push(
        <Tag key={k++} start={ordered && start !== 1 ? start : undefined}>
          {items.map((it, j) => (
            <li key={j}>{inline(it.text, `li${j}`)}{it.sub.length > 0 && <ul>{it.sub.map((x, n) => <li key={n}>{inline(x, `li${j}s${n}`)}</li>)}</ul>}</li>
          ))}
        </Tag>,
      );
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() !== '' && !/^(- |\d+\. |### |> |```|\||:::)/.test(lines[i])) para.push(lines[i++]);
    blocks.push(<p key={k++}>{inline(para.join(' '), `p${k}`)}</p>);
  }
  return <div className="md">{blocks.map((b, j) => <Fragment key={j}>{b}</Fragment>)}</div>;
}
