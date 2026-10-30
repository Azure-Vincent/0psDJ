// A YAML subset (block mappings and sequences, flow lists and maps, quoted
// scalars, | and > block scalars): what compose files and the Prometheus and
// Alertmanager configurations use. Errors read like go-yaml's.

// ---------------------------------------------------------------------------

export type Yaml = string | Yaml[] | { [k: string]: Yaml } | null;

export class YamlError extends Error {}

function scalar(raw: string): Yaml {
  const v = raw.trim();
  if (v === '' || v === '~' || v === 'null') return null;
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  if (v.startsWith('[') && v.endsWith(']')) return splitFlow(v.slice(1, -1)).map((x) => scalar(x) as string);
  if (v === '{}') return {};
  if (v.startsWith('{') && v.endsWith('}')) {
    // A flow mapping: {severity: page, team: ops}
    const out: Record<string, Yaml> = {};
    for (const part of splitFlow(v.slice(1, -1))) {
      const m = /^("[^"]*"|'[^']*'|[^:]+?):\s*(.*)$/.exec(part);
      if (!m) throw new YamlError(`yaml: did not find expected ',' or '}'`);
      out[scalar(m[1]) as string] = scalar(m[2]);
    }
    return out;
  }
  return v;
}

/** Split a flow collection's items on top-level commas (not inside quotes). */
function splitFlow(body: string): string[] {
  const out: string[] = [];
  let q: string | null = null;
  let cur = '';
  for (const c of body) {
    if (q) { if (c === q) q = null; cur += c; continue; }
    if (c === '"' || c === "'") q = c;
    if (c === ',') { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean);
}

/** Strip a comment (a # after whitespace, outside quotes). */
function uncomment(line: string): string {
  let q: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

export function parseYaml(text: string): Yaml {
  const lines: { n: number; indent: number; text: string }[] = [];
  const raws = text.split('\n');
  // Block scalars (key: | or key: >): their lines are text, kept apart from the structure.
  const blocks = new Map<number, string>();
  for (let i = 0; i < raws.length; i++) {
    const raw = raws[i];
    if (/^\s*\t/.test(raw) || /^\t/.test(raw)) throw new YamlError(`yaml: line ${i + 1}: found character that cannot start any token`);
    const t = uncomment(raw).replace(/\s+$/, '');
    if (!t.trim()) continue;
    const indent = t.length - t.trimStart().length;
    const bs = /^(.*:\s+)([|>])([+-]?)$/.exec(t.trim());
    if (bs) {
      const body: string[] = [];
      let j = i + 1;
      let inner = -1;
      for (; j < raws.length; j++) {
        const r = raws[j];
        if (!r.trim()) { body.push(''); continue; }
        const ind = r.length - r.trimStart().length;
        if (ind <= indent) break;
        if (inner < 0) inner = ind;
        body.push(r.slice(Math.min(inner, ind)));
      }
      while (body.length && body[body.length - 1] === '') body.pop();
      const textValue = bs[2] === '>' ? body.join(' ').replace(/\s+/g, ' ').trim() : body.join('\n') + (bs[3] === '-' ? '' : '\n');
      blocks.set(i + 1, textValue);
      lines.push({ n: i + 1, indent, text: `${bs[1]}\u0000${i + 1}` });
      i = j - 1;
      continue;
    }
    lines.push({ n: i + 1, indent, text: t.trim() });
  }
  const blockOr = (v: Yaml): Yaml => (typeof v === 'string' && v.startsWith('\u0000') ? blocks.get(Number(v.slice(1))) ?? '' : v);
  let pos = 0;
  const block = (indent: number): Yaml => {
    const first = lines[pos];
    if (!first) return null;
    if (first.text.startsWith('- ') || first.text === '-') {
      const out: Yaml[] = [];
      while (pos < lines.length && lines[pos].indent === indent && (lines[pos].text.startsWith('- ') || lines[pos].text === '-')) {
        const l = lines[pos];
        const rest = l.text.replace(/^-\s*/, '');
        pos++;
        const kv = /^([^:'"\s][^:]*?):(\s+(.*))?$/.exec(rest);
        if (kv && !/^\S+:\/\//.test(rest) && !/^[\d.]+:\d/.test(rest)) {
          // "- key: value" starts a mapping whose other keys are indented further.
          const obj: Record<string, Yaml> = {};
          obj[kv[1]] = kv[3] !== undefined ? blockOr(scalar(kv[3])) : pos < lines.length && lines[pos].indent > l.indent ? block(lines[pos].indent) : null;
          if (pos < lines.length && lines[pos].indent > l.indent && !(lines[pos].text.startsWith('- '))) Object.assign(obj, block(lines[pos].indent) as Record<string, Yaml>);
          out.push(obj);
        } else if (rest === '') {
          out.push(pos < lines.length && lines[pos].indent > indent ? block(lines[pos].indent) : null);
        } else out.push(scalar(rest));
      }
      if (pos < lines.length && lines[pos].indent > indent) throw new YamlError(`yaml: line ${lines[pos].n}: did not find expected '-' indicator`);
      return out;
    }
    const obj: Record<string, Yaml> = {};
    while (pos < lines.length && lines[pos].indent === indent) {
      const l = lines[pos];
      const m = /^("[^"]*"|'[^']*'|[^:]+?):(\s+(.*)|)$/.exec(l.text);
      if (!m) throw new YamlError(`yaml: line ${l.n}: could not find expected ':'`);
      const key = (scalar(m[1]) as string) ?? '';
      pos++;
      if (m[3] !== undefined && m[3] !== '') obj[key] = blockOr(scalar(m[3]));
      else if (pos < lines.length && lines[pos].indent > indent) obj[key] = block(lines[pos].indent);
      else if (pos < lines.length && lines[pos].indent === indent && lines[pos].text.startsWith('- ')) obj[key] = block(indent);
      else obj[key] = null;
    }
    if (pos < lines.length && lines[pos].indent > indent) throw new YamlError(`yaml: line ${lines[pos].n}: mapping values are not allowed in this context`);
    return obj;
  };
  const doc = block(lines[0]?.indent ?? 0);
  if (pos < lines.length) throw new YamlError(`yaml: line ${lines[pos].n}: did not find expected key`);
  return doc;
}

