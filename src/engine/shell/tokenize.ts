// Shell-like tokenizer: quotes, escapes, pipes, redirection, && / || / ;

export type Segment = { argv: string[]; redirect?: { file: string; append: boolean } };
export type Pipeline = Segment[];
export type CommandList = { pipeline: Pipeline; op: ';' | '&&' | '||' | null }[];

export function tokenizeLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let has = false;
  let q: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === q) { q = null; continue; }
      if (c === '\\' && q === '"' && i + 1 < line.length && '"\\$'.includes(line[i + 1])) { cur += line[++i]; continue; }
      cur += c;
      continue;
    }
    if (c === '"' || c === "'") { q = c; has = true; continue; }
    if (c === '\\' && i + 1 < line.length) { cur += line[++i]; has = true; continue; }
    if (/\s/.test(c)) {
      if (cur || has) { out.push(cur); cur = ''; has = false; }
      continue;
    }
    const two = line.slice(i, i + 2);
    if (two === '&&' || two === '||' || two === '>>') {
      if (cur || has) { out.push(cur); cur = ''; has = false; }
      out.push('\u0000' + two);
      i++;
      continue;
    }
    if (c === '|' || c === ';' || c === '>') {
      if (cur || has) { out.push(cur); cur = ''; has = false; }
      out.push('\u0000' + c);
      continue;
    }
    if (c === '#' && !cur && !has) break;
    cur += c;
    has = true;
  }
  if (q) throw new Error('unexpected EOF while looking for matching `' + q + "'");
  if (cur || has) out.push(cur);
  return out;
}

export function parseCommandLine(line: string): CommandList {
  const toks = tokenizeLine(line);
  const list: CommandList = [];
  let pipeline: Pipeline = [];
  let seg: Segment = { argv: [] };
  const endSeg = () => {
    if (seg.argv.length === 0) throw new Error('syntax error near unexpected token');
    pipeline.push(seg);
    seg = { argv: [] };
  };
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.startsWith('\u0000')) {
      const op = t.slice(1);
      if (op === '|') { endSeg(); continue; }
      if (op === '>' || op === '>>') {
        const file = toks[++i];
        if (!file || file.startsWith('\u0000')) throw new Error('syntax error near unexpected token `newline\'');
        seg.redirect = { file, append: op === '>>' };
        continue;
      }
      endSeg();
      list.push({ pipeline, op: op as ';' | '&&' | '||' });
      pipeline = [];
      continue;
    }
    seg.argv.push(t);
  }
  if (seg.argv.length) pipeline.push(seg);
  if (pipeline.length) list.push({ pipeline, op: null });
  return list;
}
