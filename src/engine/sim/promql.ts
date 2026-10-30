// A PromQL subset (Prometheus 2.42): selectors with label matchers, range
// selectors, offset, arithmetic and comparison operators (bool, on/ignoring),
// and/or/unless, aggregations (sum, avg, min, max, count, topk, bottomk with
// by/without) and the functions administrators use in alert rules. Errors
// carry Prometheus' "line:col: parse error: …" text.

export type Labels = Record<string, string>;
export interface Series { labels: Labels; samples: [number, number][] }
/** Where the samples come from: every series whose name/labels might match. */
export interface DataSource { series(name: string | undefined): Series[] }

export interface InstantSample { labels: Labels; value: number; t: number }
export type Value =
  | { kind: 'vector'; samples: InstantSample[] }
  | { kind: 'matrix'; series: Series[] }
  | { kind: 'scalar'; value: number }
  | { kind: 'string'; value: string };

export class PromQLError extends Error {}

/** Default look-back for instant selectors (--query.lookback-delta). */
export const LOOKBACK_MS = 5 * 60_000;

const UNITS: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000, y: 31_536_000_000 };

/** "5m", "1h30m", "15s" → milliseconds (null when invalid). */
export function parseDuration(text: string): number | null {
  const t = text.trim();
  if (!t || !/^(\d+(ms|s|m|h|d|w|y))+$/.test(t)) return null;
  let ms = 0;
  for (const m of t.matchAll(/(\d+)(ms|s|m|h|d|w|y)/g)) ms += Number(m[1]) * UNITS[m[2]];
  return ms;
}

/** Prometheus' duration formatting: 5m0s style is not used; it prints 5m, 1h30m, 15s. */
export function formatDuration(ms: number): string {
  if (ms === 0) return '0s';
  let rest = ms;
  let out = '';
  for (const [u, n] of [['y', UNITS.y], ['w', UNITS.w], ['d', UNITS.d], ['h', UNITS.h], ['m', UNITS.m], ['s', UNITS.s], ['ms', 1]] as const) {
    if (rest >= n) { out += `${Math.floor(rest / n)}${u}`; rest %= n; }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type TokKind = 'num' | 'str' | 'ident' | 'dur' | 'op' | 'eof';
interface Tok { kind: TokKind; text: string; pos: number }

const OPS = ['==', '!=', '>=', '<=', '=~', '!~', '+', '-', '*', '/', '%', '^', '>', '<', '=', '(', ')', '{', '}', '[', ']', ',', ':'];

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    const start = i;
    if (c === '"' || c === "'" || c === '`') {
      let s = '';
      i++;
      while (i < src.length && src[i] !== c) {
        if (src[i] === '\\' && c !== '`' && i + 1 < src.length) { const n = src[i + 1]; s += n === 'n' ? '\n' : n === 't' ? '\t' : n; i += 2; continue; }
        s += src[i++];
      }
      if (i >= src.length) throw new PromQLError(`${pos(src, start)}: parse error: unterminated quoted string ${c}`);
      i++;
      out.push({ kind: 'str', text: s, pos: start });
      continue;
    }
    const dur = /^(\d+(ms|s|m|h|d|w|y))+/.exec(src.slice(i));
    if (dur && !/^[\w.]/.test(src.slice(i + dur[0].length, i + dur[0].length + 1) || ' ')) { out.push({ kind: 'dur', text: dur[0], pos: start }); i += dur[0].length; continue; }
    const num = /^(0x[0-9a-fA-F]+|\d*\.?\d+(?:[eE][+-]?\d+)?|Inf|NaN)/.exec(src.slice(i));
    if (num && /[\d.]/.test(c)) { out.push({ kind: 'num', text: num[0], pos: start }); i += num[0].length; continue; }
    const id = /^[a-zA-Z_:][a-zA-Z0-9_:]*/.exec(src.slice(i));
    if (id) { out.push({ kind: 'ident', text: id[0], pos: start }); i += id[0].length; continue; }
    const op = OPS.find((o) => src.startsWith(o, i));
    if (op) { out.push({ kind: 'op', text: op, pos: start }); i += op.length; continue; }
    throw new PromQLError(`${pos(src, start)}: parse error: unexpected character: '${c}'`);
  }
  out.push({ kind: 'eof', text: '', pos: src.length });
  return out;
}

function pos(src: string, at: number): string {
  const before = src.slice(0, at);
  const line = before.split('\n').length;
  const col = at - before.lastIndexOf('\n');
  return `${line}:${col}`;
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

export interface Matcher { name: string; op: '=' | '!=' | '=~' | '!~'; value: string }
export type Node =
  | { t: 'num'; v: number }
  | { t: 'str'; v: string }
  | { t: 'sel'; name?: string; matchers: Matcher[]; range?: number; offset: number }
  | { t: 'call'; fn: string; args: Node[] }
  | { t: 'agg'; op: string; by?: string[]; without?: string[]; param?: Node; expr: Node }
  | { t: 'bin'; op: string; lhs: Node; rhs: Node; bool: boolean; on?: string[]; ignoring?: string[] }
  | { t: 'neg'; expr: Node }
  | { t: 'paren'; expr: Node }
  | { t: 'subq'; expr: Node; range: number; step?: number };

const AGGS = new Set(['sum', 'avg', 'min', 'max', 'count', 'topk', 'bottomk', 'stddev', 'stdvar', 'group']);
/** Function name → [argument kinds]; 'm' range vector, 'v' instant vector, 's' scalar, '?' optional. */
const FUNCS: Record<string, string[]> = {
  rate: ['m'], irate: ['m'], increase: ['m'], delta: ['m'], idelta: ['m'], deriv: ['m'], changes: ['m'], resets: ['m'],
  avg_over_time: ['m'], min_over_time: ['m'], max_over_time: ['m'], sum_over_time: ['m'], count_over_time: ['m'], last_over_time: ['m'], present_over_time: ['m'],
  predict_linear: ['m', 's'], absent: ['v'], absent_over_time: ['m'], abs: ['v'], ceil: ['v'], floor: ['v'], round: ['v', 's?'], sqrt: ['v'], exp: ['v'], ln: ['v'],
  clamp: ['v', 's', 's'], clamp_min: ['v', 's'], clamp_max: ['v', 's'], scalar: ['v'], vector: ['s'], time: [], timestamp: ['v'], sort: ['v'], sort_desc: ['v'],
  label_replace: ['v', 'str', 'str', 'str', 'str'], day_of_week: [], hour: [],
};

const PREC: Record<string, number> = { or: 1, and: 2, unless: 2, '==': 3, '!=': 3, '<=': 3, '<': 3, '>=': 3, '>': 3, '+': 4, '-': 4, '*': 5, '/': 5, '%': 5, '^': 6 };
const COMPARE = new Set(['==', '!=', '<=', '<', '>=', '>']);

export function parsePromQL(src: string): Node {
  if (!src.trim()) throw new PromQLError('1:1: parse error: no expression found in input');
  const toks = lex(src);
  let p = 0;
  const peek = () => toks[p];
  const next = () => toks[p++];
  const fail = (t: Tok, msg: string): never => { throw new PromQLError(`${pos(src, t.pos)}: parse error: ${msg}`); };
  const describe = (t: Tok) => (t.kind === 'eof' ? 'end of input' : t.kind === 'num' ? `number "${t.text}"` : t.kind === 'str' ? `string "${t.text}"` : t.kind === 'dur' ? `duration "${t.text}"` : t.kind === 'ident' ? `identifier "${t.text}"` : `"${t.text}"`);
  const expect = (text: string, ctx: string) => { const t = next(); if (t.text !== text || (t.kind !== 'op' && t.kind !== 'ident')) fail(t, `unexpected ${describe(t)} ${ctx}`); };
  const isOp = (t: Tok, ...texts: string[]) => t.kind === 'op' && texts.includes(t.text);

  const labelList = (): string[] => {
    expect('(', 'in grouping opts, expected "("');
    const out: string[] = [];
    while (!isOp(peek(), ')')) {
      const t = next();
      if (t.kind !== 'ident') fail(t, `unexpected ${describe(t)} in grouping opts, expected label`);
      out.push(t.text);
      if (isOp(peek(), ',')) next();
    }
    next();
    return out;
  };

  const matchers = (): Matcher[] => {
    const out: Matcher[] = [];
    next(); // {
    while (!isOp(peek(), '}')) {
      const n = next();
      if (n.kind !== 'ident') fail(n, `unexpected ${describe(n)} in label matching, expected label`);
      const o = next();
      if (!isOp(o, '=', '!=', '=~', '!~')) fail(o, `unexpected ${describe(o)} in label matching, expected label matching operator`);
      const v = next();
      if (v.kind !== 'str') fail(v, `unexpected ${describe(v)} in label matching, expected string`);
      if (o.text === '=~' || o.text === '!~') { try { new RegExp(`^(?:${v.text})$`); } catch { fail(v, `error parsing regexp: invalid regular expression: \`${v.text}\``); } }
      out.push({ name: n.text, op: o.text as Matcher['op'], value: v.text });
      if (isOp(peek(), ',')) next();
      else if (!isOp(peek(), '}')) fail(peek(), `unexpected ${describe(peek())} in label matching, expected "," or "}"`);
    }
    next();
    return out;
  };

  const postfix = (node: Node): Node => {
    let n = node;
    for (;;) {
      if (isOp(peek(), '[')) {
        const open = next();
        const d = next();
        if (d.kind !== 'dur') fail(d, `unexpected ${describe(d)} in subquery or range selector, expected duration`);
        const range = parseDuration(d.text)!;
        if (isOp(peek(), ':')) {
          next();
          let step: number | undefined;
          if (peek().kind === 'dur') step = parseDuration(next().text)!;
          expect(']', 'in subquery, expected "]"');
          n = { t: 'subq', expr: n, range, step };
          continue;
        }
        expect(']', 'in range selector, expected "]"');
        if (n.t !== 'sel') fail(open, `ranges only allowed for vector selectors`);
        if (n.t === 'sel') n = { ...n, range };
        continue;
      }
      if (peek().kind === 'ident' && peek().text === 'offset') {
        next();
        const neg = isOp(peek(), '-') ? (next(), -1) : 1;
        const d = next();
        if (d.kind !== 'dur') fail(d, `unexpected ${describe(d)} in offset, expected duration`);
        if (n.t !== 'sel') fail(d, 'offset modifier must be preceded by an instant vector selector or range vector selector');
        if (n.t === 'sel') n = { ...n, offset: neg * parseDuration(d.text)! };
        continue;
      }
      return n;
    }
  };

  const primary = (): Node => {
    const t = peek();
    if (isOp(t, '-', '+')) { next(); const e = unaryOperand(); return t.text === '-' ? (e.t === 'num' ? { t: 'num', v: -e.v } : { t: 'neg', expr: e }) : e; }
    if (isOp(t, '(')) {
      next();
      const e = expr(0);
      expect(')', 'in parenthesized expression, expected ")"');
      return postfix({ t: 'paren', expr: e });
    }
    if (t.kind === 'num') { next(); return { t: 'num', v: t.text === 'Inf' ? Infinity : t.text === 'NaN' ? NaN : Number(t.text) }; }
    if (t.kind === 'str') { next(); return { t: 'str', v: t.text }; }
    if (isOp(t, '{')) return postfix({ t: 'sel', matchers: matchers(), offset: 0 });
    if (t.kind === 'ident') {
      next();
      if (AGGS.has(t.text) && (isOp(peek(), '(') || (peek().kind === 'ident' && (peek().text === 'by' || peek().text === 'without')))) {
        let by: string[] | undefined;
        let without: string[] | undefined;
        const mod = () => { if (peek().kind === 'ident' && peek().text === 'by') { next(); by = labelList(); } else if (peek().kind === 'ident' && peek().text === 'without') { next(); without = labelList(); } };
        mod();
        expect('(', `in aggregation, expected "("`);
        let param: Node | undefined;
        let e = expr(0);
        if (t.text === 'topk' || t.text === 'bottomk') { expect(',', 'in aggregation, expected ","'); param = e; e = expr(0); }
        expect(')', 'in aggregation, expected ")"');
        mod();
        return { t: 'agg', op: t.text, by, without, param, expr: e };
      }
      if (isOp(peek(), '(')) {
        const sig = FUNCS[t.text];
        if (!sig) fail(t, `unknown function with name "${t.text}"`);
        next();
        const args: Node[] = [];
        while (!isOp(peek(), ')')) {
          args.push(expr(0));
          if (isOp(peek(), ',')) next();
          else if (!isOp(peek(), ')')) fail(peek(), `unexpected ${describe(peek())} in function call, expected "," or ")"`);
        }
        next();
        const required = sig.filter((k) => !k.endsWith('?')).length;
        if (args.length < required || args.length > sig.length) fail(t, `expected ${required} argument(s) in call to "${t.text}", got ${args.length}`);
        args.forEach((a, i) => {
          const k = sig[i].replace('?', '');
          if (k === 'm' && !(a.t === 'sel' && a.range !== undefined) && a.t !== 'subq') fail(t, `expected type range vector in call to function "${t.text}", got instant vector`);
          if (k === 'v' && a.t === 'sel' && a.range !== undefined) fail(t, `expected type instant vector in call to function "${t.text}", got range vector`);
        });
        return postfix({ t: 'call', fn: t.text, args });
      }
      if (['by', 'without', 'on', 'ignoring', 'bool', 'offset', 'and', 'or', 'unless'].includes(t.text)) fail(t, `unexpected ${describe(t)}`);
      return postfix({ t: 'sel', name: t.text, matchers: isOp(peek(), '{') ? matchers() : [], offset: 0 });
    }
    return fail(t, `unexpected ${describe(t)}`);
  };
  const unaryOperand = (): Node => primary();

  const binOpAt = (): string | null => {
    const t = peek();
    if (t.kind === 'op' && PREC[t.text] !== undefined) return t.text;
    if (t.kind === 'ident' && (t.text === 'and' || t.text === 'or' || t.text === 'unless')) return t.text;
    return null;
  };

  const expr = (minPrec: number): Node => {
    let lhs = primary();
    for (;;) {
      const op = binOpAt();
      if (!op || PREC[op] < minPrec) break;
      next();
      let bool = false;
      let on: string[] | undefined;
      let ignoring: string[] | undefined;
      if (peek().kind === 'ident' && peek().text === 'bool') {
        if (!COMPARE.has(op)) fail(peek(), 'bool modifier can only be used on comparison operators');
        next();
        bool = true;
      }
      if (peek().kind === 'ident' && (peek().text === 'on' || peek().text === 'ignoring')) {
        const k = next().text;
        const l = labelList();
        if (k === 'on') on = l; else ignoring = l;
        if (peek().kind === 'ident' && (peek().text === 'group_left' || peek().text === 'group_right')) { next(); if (isOp(peek(), '(')) labelList(); }
      }
      // ^ is right-associative.
      const rhs = expr(op === '^' ? PREC[op] : PREC[op] + 1);
      if (COMPARE.has(op) && !bool && lhs.t === 'num' && rhs.t === 'num') fail(toks[p - 1], 'comparisons between scalars must use BOOL modifier');
      lhs = { t: 'bin', op, lhs, rhs, bool, on, ignoring };
    }
    return lhs;
  };

  const root = expr(0);
  if (peek().kind !== 'eof') fail(peek(), `unexpected ${describe(peek())}`);
  return root;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/** Is VALUE a valid (anchored) label regex? */
export function validLabelRegex(value: string): boolean {
  try { new RegExp(`^(?:${value})$`); return true; } catch { return false; }
}

/** Label matching (=, !=, =~, !~) as Prometheus and Alertmanager do it; an invalid regex matches nothing. */
export function matchLabel(labels: Labels, m: { name: string; op: string; value: string }): boolean {
  const v = labels[m.name] ?? '';
  if (m.op === '=') return v === m.value;
  if (m.op === '!=') return v !== m.value;
  if (!validLabelRegex(m.value)) return false;
  const ok = new RegExp(`^(?:${m.value})$`).test(v);
  return m.op === '=~' ? ok : !ok;
}
const matches = matchLabel;

export const dropName = (l: Labels): Labels => { const { __name__: _n, ...rest } = l; return rest; };
const sigOf = (l: Labels, on?: string[], ignoring?: string[]): string => {
  const keys = Object.keys(l).filter((k) => k !== '__name__' && (on ? on.includes(k) : !(ignoring ?? []).includes(k))).sort();
  return keys.map((k) => `${k}=${l[k]}`).join(',');
};

function selectSeries(ds: DataSource, n: Extract<Node, { t: 'sel' }>): Series[] {
  const ms = [...n.matchers];
  if (n.name) ms.push({ name: '__name__', op: '=', value: n.name });
  const nameM = ms.find((m) => m.name === '__name__' && m.op === '=');
  return ds.series(nameM?.value).filter((s) => ms.every((m) => matches(s.labels, m)));
}

function instant(ds: DataSource, n: Extract<Node, { t: 'sel' }>, at: number): InstantSample[] {
  const t = at - n.offset;
  const out: InstantSample[] = [];
  for (const s of selectSeries(ds, n)) {
    // The newest sample within the look-back window (a series that went stale has none).
    let last: [number, number] | undefined;
    for (const smp of s.samples) if (smp[0] <= t && smp[0] > t - LOOKBACK_MS) last = smp;
    if (last) out.push({ labels: s.labels, value: last[1], t: at });
  }
  return out;
}

function rangeSel(ds: DataSource, n: Extract<Node, { t: 'sel' }>, at: number): Series[] {
  const t = at - n.offset;
  const from = t - (n.range ?? 0);
  return selectSeries(ds, n).map((s) => ({ labels: s.labels, samples: s.samples.filter(([ts]) => ts > from && ts <= t) })).filter((s) => s.samples.length > 0);
}

/** Prometheus' extrapolated rate/increase/delta (functions.go: extrapolatedRate). */
function extrapolated(s: [number, number][], rangeStart: number, rangeEnd: number, isCounter: boolean, isRate: boolean): number | null {
  if (s.length < 2) return null;
  let delta = s[s.length - 1][1] - s[0][1];
  if (isCounter) for (let i = 1; i < s.length; i++) if (s[i][1] < s[i - 1][1]) delta += s[i - 1][1];
  const sampledInterval = (s[s.length - 1][0] - s[0][0]) / 1000;
  const avg = sampledInterval / (s.length - 1);
  let durToStart = (s[0][0] - rangeStart) / 1000;
  const durToEnd = (rangeEnd - s[s.length - 1][0]) / 1000;
  if (isCounter && delta > 0 && s[0][1] >= 0) {
    const durToZero = sampledInterval * (s[0][1] / delta);
    if (durToZero < durToStart) durToStart = durToZero;
  }
  const threshold = avg * 1.1;
  let extrap = sampledInterval;
  extrap += durToStart < threshold ? durToStart : avg / 2;
  extrap += durToEnd < threshold ? durToEnd : avg / 2;
  const r = delta * (extrap / sampledInterval);
  return isRate ? r / ((rangeEnd - rangeStart) / 1000) : r;
}

function linreg(s: [number, number][], at: number): { slope: number; intercept: number } {
  const n = s.length;
  let sx = 0, sy = 0, sxy = 0, sxx = 0;
  for (const [t, v] of s) { const x = (t - at) / 1000; sx += x; sy += v; sxy += x * v; sxx += x * x; }
  const cov = sxy - (sx * sy) / n;
  const varx = sxx - (sx * sx) / n;
  const slope = varx === 0 ? 0 : cov / varx;
  return { slope, intercept: sy / n - slope * (sx / n) };
}

function rangeInput(ds: DataSource, a: Node, at: number): { series: Series[]; range: number } {
  if (a.t === 'sel') return { series: rangeSel(ds, a, at), range: a.range ?? 0 };
  if (a.t === 'subq') {
    const step = a.step ?? 60_000;
    const map = new Map<string, Series>();
    for (let t = Math.ceil((at - a.range) / step) * step; t <= at; t += step) {
      if (t <= at - a.range) continue;
      const v = evaluate(ds, a.expr, t);
      const samples = v.kind === 'vector' ? v.samples : v.kind === 'scalar' ? [{ labels: {}, value: v.value, t }] : [];
      for (const s of samples) {
        const k = JSON.stringify(s.labels);
        if (!map.has(k)) map.set(k, { labels: s.labels, samples: [] });
        map.get(k)!.samples.push([t, s.value]);
      }
    }
    return { series: [...map.values()], range: a.range };
  }
  throw new PromQLError('expected range vector');
}

const asScalar = (v: Value): number => (v.kind === 'scalar' ? v.value : v.kind === 'vector' ? (v.samples.length === 1 ? v.samples[0].value : NaN) : NaN);

function callFn(ds: DataSource, n: Extract<Node, { t: 'call' }>, at: number): Value {
  const vec = (samples: InstantSample[]): Value => ({ kind: 'vector', samples });
  const overRange = (f: (s: [number, number][], from: number) => number | null, keepName = false): Value => {
    const { series, range } = rangeInput(ds, n.args[0], at);
    const off = n.args[0].t === 'sel' ? n.args[0].offset : 0;
    const out: InstantSample[] = [];
    for (const s of series) {
      const v = f(s.samples, at - off - range);
      if (v !== null && v !== undefined) out.push({ labels: keepName ? s.labels : dropName(s.labels), value: v, t: at });
    }
    return vec(out);
  };
  const mapVec = (f: (v: number) => number): Value => {
    const v = evaluate(ds, n.args[0], at);
    if (v.kind !== 'vector') return v;
    return vec(v.samples.map((s) => ({ labels: dropName(s.labels), value: f(s.value), t: at })));
  };
  const arg = (i: number) => asScalar(evaluate(ds, n.args[i], at));
  switch (n.fn) {
    case 'rate': case 'increase': case 'delta': {
      const off = n.args[0].t === 'sel' ? n.args[0].offset : 0;
      return overRange((s, from) => extrapolated(s, from, at - off, n.fn !== 'delta', n.fn === 'rate'));
    }
    case 'irate': case 'idelta': return overRange((s) => {
      if (s.length < 2) return null;
      const [a, b] = s.slice(-2);
      const d = n.fn === 'irate' && b[1] < a[1] ? b[1] : b[1] - a[1];
      return n.fn === 'irate' ? d / ((b[0] - a[0]) / 1000) : d;
    });
    case 'deriv': return overRange((s) => (s.length < 2 ? null : linreg(s, at).slope));
    case 'predict_linear': { const k = arg(1); return overRange((s) => { if (s.length < 2) return null; const r = linreg(s, at); return r.intercept + r.slope * k; }); }
    case 'changes': return overRange((s) => s.slice(1).filter((x, i) => x[1] !== s[i][1]).length);
    case 'resets': return overRange((s) => s.slice(1).filter((x, i) => x[1] < s[i][1]).length);
    case 'avg_over_time': return overRange((s) => s.reduce((a, x) => a + x[1], 0) / s.length);
    case 'min_over_time': return overRange((s) => Math.min(...s.map((x) => x[1])));
    case 'max_over_time': return overRange((s) => Math.max(...s.map((x) => x[1])));
    case 'sum_over_time': return overRange((s) => s.reduce((a, x) => a + x[1], 0));
    case 'count_over_time': return overRange((s) => s.length);
    case 'last_over_time': return overRange((s) => s[s.length - 1][1], true);
    case 'present_over_time': return overRange(() => 1);
    case 'absent': case 'absent_over_time': {
      const v = n.fn === 'absent' ? evaluate(ds, n.args[0], at) : { kind: 'vector' as const, samples: rangeInput(ds, n.args[0], at).series.map((s) => ({ labels: s.labels, value: 1, t: at })) };
      if (v.kind === 'vector' && v.samples.length) return vec([]);
      const a = n.args[0];
      const labels: Labels = {};
      if (a.t === 'sel') for (const m of a.matchers) if (m.op === '=' && m.name !== '__name__') labels[m.name] = m.value;
      return vec([{ labels, value: 1, t: at }]);
    }
    case 'abs': return mapVec(Math.abs);
    case 'ceil': return mapVec(Math.ceil);
    case 'floor': return mapVec(Math.floor);
    case 'sqrt': return mapVec(Math.sqrt);
    case 'exp': return mapVec(Math.exp);
    case 'ln': return mapVec(Math.log);
    case 'round': { const to = n.args[1] ? arg(1) : 1; return mapVec((v) => Math.floor(v / to + 0.5) * to); }
    case 'clamp': { const lo = arg(1), hi = arg(2); return mapVec((v) => Math.max(lo, Math.min(hi, v))); }
    case 'clamp_min': { const lo = arg(1); return mapVec((v) => Math.max(lo, v)); }
    case 'clamp_max': { const hi = arg(1); return mapVec((v) => Math.min(hi, v)); }
    case 'scalar': { const v = evaluate(ds, n.args[0], at); return { kind: 'scalar', value: v.kind === 'vector' && v.samples.length === 1 ? v.samples[0].value : NaN }; }
    case 'vector': return vec([{ labels: {}, value: arg(0), t: at }]);
    case 'time': return { kind: 'scalar', value: at / 1000 };
    case 'day_of_week': return { kind: 'scalar', value: new Date(at).getUTCDay() };
    case 'hour': return { kind: 'scalar', value: new Date(at).getUTCHours() };
    case 'timestamp': return mapVec(() => at / 1000);
    case 'sort': case 'sort_desc': {
      const v = evaluate(ds, n.args[0], at);
      if (v.kind !== 'vector') return v;
      return vec([...v.samples].sort((a, b) => (n.fn === 'sort' ? a.value - b.value : b.value - a.value)));
    }
    case 'label_replace': {
      const v = evaluate(ds, n.args[0], at);
      if (v.kind !== 'vector') return v;
      const [dst, repl, src, re] = n.args.slice(1).map((a) => (a.t === 'str' ? a.v : ''));
      const rx = new RegExp(`^(?:${re})$`);
      return vec(v.samples.map((s) => {
        const m = rx.exec(s.labels[src] ?? '');
        if (!m) return s;
        const val = repl.replace(/\$(\d+)|\$\{(\d+)\}/g, (_x, a, b) => m[Number(a ?? b)] ?? '');
        const labels = { ...s.labels };
        if (val) labels[dst] = val; else delete labels[dst];
        return { ...s, labels };
      }));
    }
  }
  throw new PromQLError(`unknown function with name "${n.fn}"`);
}

function aggregate(ds: DataSource, n: Extract<Node, { t: 'agg' }>, at: number): Value {
  const v = evaluate(ds, n.expr, at);
  if (v.kind !== 'vector') throw new PromQLError(`expected type instant vector in aggregation expression, got ${v.kind === 'matrix' ? 'range vector' : v.kind}`);
  const key = (l: Labels): Labels => {
    const out: Labels = {};
    if (n.by) { for (const k of n.by) if (l[k] !== undefined) out[k] = l[k]; return out; }
    if (n.without) { for (const [k, x] of Object.entries(l)) if (k !== '__name__' && !n.without.includes(k)) out[k] = x; return out; }
    return out;
  };
  if (n.op === 'topk' || n.op === 'bottomk') {
    const k = asScalar(evaluate(ds, n.param!, at));
    const groups = new Map<string, InstantSample[]>();
    for (const s of v.samples) { const g = JSON.stringify(key(s.labels)); groups.set(g, [...(groups.get(g) ?? []), s]); }
    const out: InstantSample[] = [];
    for (const g of groups.values()) out.push(...[...g].sort((a, b) => (n.op === 'topk' ? b.value - a.value : a.value - b.value)).slice(0, Math.max(0, Math.floor(k))));
    return { kind: 'vector', samples: out };
  }
  const groups = new Map<string, { labels: Labels; values: number[] }>();
  for (const s of v.samples) {
    const l = key(s.labels);
    const g = JSON.stringify(Object.keys(l).sort().map((k) => [k, l[k]]));
    if (!groups.has(g)) groups.set(g, { labels: l, values: [] });
    groups.get(g)!.values.push(s.value);
  }
  const out: InstantSample[] = [];
  for (const g of groups.values()) {
    const xs = g.values;
    const sum = xs.reduce((a, b) => a + b, 0);
    const mean = sum / xs.length;
    const value = n.op === 'sum' ? sum : n.op === 'avg' ? mean : n.op === 'min' ? Math.min(...xs) : n.op === 'max' ? Math.max(...xs) : n.op === 'count' ? xs.length : n.op === 'group' ? 1
      : n.op === 'stdvar' ? xs.reduce((a, x) => a + (x - mean) ** 2, 0) / xs.length : Math.sqrt(xs.reduce((a, x) => a + (x - mean) ** 2, 0) / xs.length);
    out.push({ labels: g.labels, value, t: at });
  }
  return { kind: 'vector', samples: out };
}

function arith(op: string, a: number, b: number): number {
  switch (op) {
    case '+': return a + b;
    case '-': return a - b;
    case '*': return a * b;
    case '/': return a / b;
    case '%': return a % b;
    case '^': return a ** b;
    case '==': return a === b ? 1 : 0;
    case '!=': return a !== b ? 1 : 0;
    case '<': return a < b ? 1 : 0;
    case '<=': return a <= b ? 1 : 0;
    case '>': return a > b ? 1 : 0;
    case '>=': return a >= b ? 1 : 0;
  }
  return NaN;
}

function binary(ds: DataSource, n: Extract<Node, { t: 'bin' }>, at: number): Value {
  const l = evaluate(ds, n.lhs, at);
  const r = evaluate(ds, n.rhs, at);
  const cmp = COMPARE.has(n.op);
  if (['and', 'or', 'unless'].includes(n.op)) {
    if (l.kind !== 'vector' || r.kind !== 'vector') throw new PromQLError(`set operator "${n.op}" not allowed in binary scalar expression`);
    const rs = new Set(r.samples.map((s) => sigOf(s.labels, n.on, n.ignoring)));
    if (n.op === 'and') return { kind: 'vector', samples: l.samples.filter((s) => rs.has(sigOf(s.labels, n.on, n.ignoring))) };
    if (n.op === 'unless') return { kind: 'vector', samples: l.samples.filter((s) => !rs.has(sigOf(s.labels, n.on, n.ignoring))) };
    const ls = new Set(l.samples.map((s) => sigOf(s.labels, n.on, n.ignoring)));
    return { kind: 'vector', samples: [...l.samples, ...r.samples.filter((s) => !ls.has(sigOf(s.labels, n.on, n.ignoring)))] };
  }
  if (l.kind === 'scalar' && r.kind === 'scalar') return { kind: 'scalar', value: arith(n.op, l.value, r.value) };
  if (l.kind === 'vector' && r.kind === 'scalar' || l.kind === 'scalar' && r.kind === 'vector') {
    const vecLeft = l.kind === 'vector';
    const v = (vecLeft ? l : r) as Extract<Value, { kind: 'vector' }>;
    const k = (vecLeft ? r : l) as Extract<Value, { kind: 'scalar' }>;
    const out: InstantSample[] = [];
    for (const s of v.samples) {
      const res = vecLeft ? arith(n.op, s.value, k.value) : arith(n.op, k.value, s.value);
      if (cmp && !n.bool) { if (res === 1) out.push(vecLeft ? s : { ...s, value: s.value }); }
      else out.push({ labels: dropName(s.labels), value: res, t: at });
    }
    return { kind: 'vector', samples: out };
  }
  if (l.kind === 'vector' && r.kind === 'vector') {
    const right = new Map<string, InstantSample>();
    for (const s of r.samples) {
      const sig = sigOf(s.labels, n.on, n.ignoring);
      if (right.has(sig)) throw new PromQLError('found duplicate series for the match group on the right hand-side of the operation: many-to-many matching not allowed: matching labels must be unique on one side');
      right.set(sig, s);
    }
    const out: InstantSample[] = [];
    for (const s of l.samples) {
      const o = right.get(sigOf(s.labels, n.on, n.ignoring));
      if (!o) continue;
      const res = arith(n.op, s.value, o.value);
      const labels = n.on ? Object.fromEntries(Object.entries(s.labels).filter(([k]) => n.on!.includes(k))) : dropName(s.labels);
      if (cmp && !n.bool) { if (res === 1) out.push(s); }
      else out.push({ labels, value: res, t: at });
    }
    return { kind: 'vector', samples: out };
  }
  throw new PromQLError(`binary expression must contain only scalar and instant vector types`);
}

export function evaluate(ds: DataSource, n: Node, at: number): Value {
  switch (n.t) {
    case 'num': return { kind: 'scalar', value: n.v };
    case 'str': return { kind: 'string', value: n.v };
    case 'paren': return evaluate(ds, n.expr, at);
    case 'neg': {
      const v = evaluate(ds, n.expr, at);
      if (v.kind === 'scalar') return { kind: 'scalar', value: -v.value };
      if (v.kind === 'vector') return { kind: 'vector', samples: v.samples.map((s) => ({ labels: dropName(s.labels), value: -s.value, t: at })) };
      return v;
    }
    case 'sel':
      if (n.range !== undefined) return { kind: 'matrix', series: rangeSel(ds, n, at) };
      return { kind: 'vector', samples: instant(ds, n, at) };
    case 'subq': return { kind: 'matrix', series: rangeInput(ds, n, at).series };
    case 'call': return callFn(ds, n, at);
    case 'agg': return aggregate(ds, n, at);
    case 'bin': return binary(ds, n, at);
  }
}

/** Parse and evaluate in one step. */
export function query(ds: DataSource, expr: string, at: number): Value {
  return evaluate(ds, parsePromQL(expr), at);
}

/** Prometheus' sample value text: 1, 0.5, 1e+06, NaN, +Inf. */
export function formatValue(v: number): string {
  if (Number.isNaN(v)) return 'NaN';
  if (v === Infinity) return '+Inf';
  if (v === -Infinity) return '-Inf';
  if (Number.isInteger(v) && Math.abs(v) < 1e21) return Math.abs(v) >= 1e6 ? v.toExponential().replace(/e\+?/, 'e+').replace('e+-', 'e-') : String(v);
  return String(Number(v.toPrecision(15)));
}

/** name{a="b", c="d"} as Prometheus prints a series. */
export function formatSeries(l: Labels): string {
  const name = l.__name__ ?? '';
  const rest = Object.keys(l).filter((k) => k !== '__name__').sort();
  return `${name}{${rest.map((k) => `${k}="${l[k].replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(', ')}}`;
}
