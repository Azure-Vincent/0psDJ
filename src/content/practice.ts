/**
 * Practice blocks in lesson text (RichText):
 *
 *   :::practice
 *   Q: question (a following line without a prefix continues it)
 *   A: answer, revealed on request
 *   :::
 *
 * One parser, shared by the Markdown renderer and the content tests.
 */
export interface PracticeBlock {
  pairs: { q: string; a: string }[];
  /** False when the block ran into a "### " heading or the end of the text before its ":::" line. */
  closed: boolean;
  /** Lines that belong to no question (text before the first "Q:", or an "A:" without a question). */
  stray: string[];
  /** Index of the first line after the block. */
  next: number;
}

export const isPracticeStart = (line: string) => line.trim() === ':::practice';

/** Parse the block whose ":::practice" line is lines[start]. */
export function readPractice(lines: string[], start: number): PracticeBlock {
  const pairs: { q: string; a: string }[] = [];
  const stray: string[] = [];
  let cur: 'q' | 'a' = 'q';
  let i = start + 1;
  while (i < lines.length && lines[i].trim() !== ':::' && !lines[i].startsWith('### ')) {
    const l = lines[i++].trim();
    const last = pairs[pairs.length - 1];
    if (l.startsWith('Q: ')) { pairs.push({ q: l.slice(3), a: '' }); cur = 'q'; }
    else if (l.startsWith('A: ') && last && !last.a) { last.a = l.slice(3); cur = 'a'; }
    else if (l && last) last[cur] += ' ' + l;
    else if (l) stray.push(l);
  }
  const closed = i < lines.length && lines[i].trim() === ':::';
  return { pairs, closed, stray, next: closed ? i + 1 : i };
}

/** Every practice block in a text, with the text that follows it up to the next "### " heading. */
export function practiceBlocks(text: string): (PracticeBlock & { after: string })[] {
  const lines = text.split('\n');
  const out: (PracticeBlock & { after: string })[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!isPracticeStart(lines[i])) continue;
    const b = readPractice(lines, i);
    let j = b.next;
    while (j < lines.length && !lines[j].startsWith('### ')) j++;
    out.push({ ...b, after: lines.slice(b.next, j).join('\n') });
    i = b.next - 1;
  }
  return out;
}

/** The text without its practice blocks (for search snippets, which must not reveal answers). */
export function stripPractice(text: string): string {
  const lines = text.split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isPracticeStart(lines[i])) { i = readPractice(lines, i).next - 1; continue; }
    out.push(lines[i]);
  }
  return out.join('\n');
}
