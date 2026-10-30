// Shell-like tokenizer: quotes, escapes, pipes, redirection, && / || / ;

/** Parameter expansions ($?, $HOME, ${USER}) are kept as placeholders and resolved when the command runs. */
export const VAR_OPEN = '\u0001';
export const VAR_CLOSE = '\u0002';
/** Marks an unquoted * ? [ that pathname expansion may act on (quoted ones stay literal). */
export const GLOB = '\u0003';

/** Reads a parameter name after "$" at line[i]; returns the name and the index of its last character. */
function paramAt(line: string, i: number): { name: string; end: number } | null {
  const next = line[i + 1];
  if (next === '?') return { name: '?', end: i + 1 };
  if (next === '{') {
    const m = /^\{([A-Za-z_][A-Za-z0-9_]*|\?)\}/.exec(line.slice(i + 1));
    return m ? { name: m[1], end: i + m[0].length } : null;
  }
  const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(line.slice(i + 1));
  return m ? { name: m[0], end: i + m[0].length } : null;
}

export function expandParams(arg: string, lookup: (name: string) => string): string {
  return arg.includes(VAR_OPEN) ? arg.replace(/\u0001([^\u0002]*)\u0002/g, (_, n: string) => lookup(n)) : arg;
}

export type Segment = { argv: string[]; redirect?: { file: string; append: boolean }; stdinFile?: string };
export type Pipeline = Segment[];
export type CommandList = { pipeline: Pipeline; op: ';' | '&&' | '||' | null }[];

export function tokenizeLine(line: string, globs = false): string[] {
  const out: string[] = [];
  let cur = '';
  let has = false;
  let q: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === q) { q = null; continue; }
      if (c === '\\' && q === '"' && i + 1 < line.length && '"\\$'.includes(line[i + 1])) { cur += line[++i]; continue; }
      if (c === '$' && q === '"') {
        const p = paramAt(line, i);
        if (p) { cur += VAR_OPEN + p.name + VAR_CLOSE; i = p.end; continue; }
      }
      cur += c;
      continue;
    }
    if (c === '"' || c === "'") { q = c; has = true; continue; }
    if (c === '\\' && i + 1 < line.length) { cur += line[++i]; has = true; continue; }
    if (/\s/.test(c)) {
      if (cur || has) { out.push(cur); cur = ''; has = false; }
      continue;
    }
    // stderr redirection (2>file, 2>>file, 2>&1): the simulator has one output stream, so it is parsed and ignored.
    if (c === '2' && !cur && !has && line[i + 1] === '>') {
      const op = line[i + 2] === '>' ? '2>>' : '2>';
      out.push('\u0000' + op);
      i += op.length - 1;
      continue;
    }
    const two = line.slice(i, i + 2);
    if (two === '&&' || two === '||' || two === '>>') {
      if (cur || has) { out.push(cur); cur = ''; has = false; }
      out.push('\u0000' + two);
      i++;
      continue;
    }
    if (c === '|' || c === ';' || c === '>' || c === '<') {
      if (cur || has) { out.push(cur); cur = ''; has = false; }
      out.push('\u0000' + c);
      continue;
    }
    if (c === '#' && !cur && !has) break;
    if (c === '$') {
      const p = paramAt(line, i);
      if (p) { cur += VAR_OPEN + p.name + VAR_CLOSE; i = p.end; has = true; continue; }
    }
    if (globs && (c === '*' || c === '?' || c === '[')) cur += GLOB;
    cur += c;
    has = true;
  }
  if (q) throw new Error('unexpected EOF while looking for matching `' + q + "'");
  if (cur || has) out.push(cur);
  return out;
}

export function parseCommandLine(line: string): CommandList {
  const toks = tokenizeLine(line, true);
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
      if (op === '2>' || op === '2>>' || op === '<') {
        const file = toks[++i];
        if (!file || file.startsWith('\u0000')) throw new Error('syntax error near unexpected token `newline\'');
        if (op === '<') seg.stdinFile = file;
        continue;
      }
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
