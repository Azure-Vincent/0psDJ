// A parser for the part of the PowerShell language used at an admin console:
// pipelines of commands with named/positional/switch parameters, expressions
// (variables, member access, method calls, comparison and logical operators,
// arrays, hashtables, script blocks, sub-expressions, casts), assignments, and
// if/elseif/else and foreach statements. Parsing is mode-sensitive like
// PowerShell: a statement starting with a bare word is a command, and its
// arguments are read in argument mode (bare words are strings).

export type Expr =
  | { k: 'str'; v: string }
  | { k: 'xstr'; parts: (string | Expr)[] }
  | { k: 'num'; v: number }
  | { k: 'var'; name: string }
  | { k: 'arr'; items: Expr[] }
  | { k: 'sub'; body: Statement[]; array?: boolean }
  | { k: 'hash'; entries: [Expr, Expr][] }
  | { k: 'block'; body: Statement[]; text: string }
  | { k: 'member'; obj: Expr; name: Expr; args?: Expr[]; isStatic?: boolean }
  | { k: 'index'; obj: Expr; idx: Expr }
  | { k: 'bin'; op: string; l: Expr; r: Expr }
  | { k: 'un'; op: string; e: Expr }
  | { k: 'type'; name: string }
  | { k: 'cast'; type: string; e: Expr };

export type Arg = { k: 'param'; name: string; value?: Expr; text: string } | { k: 'value'; e: Expr; text: string };

export interface CommandEl { k: 'cmd'; name: string; args: Arg[]; start: number; end: number; call?: boolean }
export interface ExprEl { k: 'expr'; e: Expr; start: number; end: number }
export type PipeEl = CommandEl | ExprEl;
export interface Pipeline { els: PipeEl[]; start: number; end: number }

export type Statement =
  | { k: 'pipe'; p: Pipeline }
  | { k: 'assign'; target: Expr; op: string; value: Pipeline }
  | { k: 'if'; clauses: { cond: Pipeline; body: Statement[] }[]; otherwise?: Statement[] }
  | { k: 'foreach'; v: string; coll: Pipeline; body: Statement[] };

export class PsParseError extends Error {
  constructor(message: string, public pos: number, public id = 'ParseException') {
    super(message);
  }
}

const WORD_END = new Set([' ', '\t', '\r', '\n', '|', ';', ')', '}', ',', '(', '{']);

export function parse(src: string): Statement[] {
  const p = new Parser(src);
  const body = p.statements(null);
  p.ws(true);
  if (p.i < src.length) {
    const c = src[p.i];
    throw new PsParseError(c === ')' || c === '}' ? `Unexpected token '${c}' in expression or statement.` : `Unexpected token '${src.slice(p.i).split(/\s/)[0]}' in expression or statement.`, p.i, 'UnexpectedToken');
  }
  return body;
}

class Parser {
  i = 0;
  constructor(public s: string) {}

  peek(n = 0): string { return this.s[this.i + n] ?? ''; }
  eof(): boolean { return this.i >= this.s.length; }

  /** Skip whitespace (and newlines when `nl`), comments and line continuations (` at line end). */
  ws(nl = false): void {
    for (;;) {
      const c = this.peek();
      if (c === ' ' || c === '\t' || c === '\r' || (nl && c === '\n')) { this.i++; continue; }
      if (c === '`' && (this.peek(1) === '\n' || this.peek(1) === '\r')) { this.i += 2; continue; }
      if (c === '<' && this.peek(1) === '#') {
        const j = this.s.indexOf('#>', this.i + 2);
        this.i = j < 0 ? this.s.length : j + 2;
        continue;
      }
      if (c === '#') {
        while (!this.eof() && this.peek() !== '\n') this.i++;
        continue;
      }
      break;
    }
  }

  statements(close: string | null): Statement[] {
    const out: Statement[] = [];
    for (;;) {
      this.ws(true);
      while (this.peek() === ';') { this.i++; this.ws(true); }
      if (this.eof()) break;
      if (close && this.peek() === close) break;
      if (!close && (this.peek() === ')' || this.peek() === '}')) break;
      out.push(this.statement());
      this.ws();
      if (this.peek() === ';' || this.peek() === '\n') { this.i++; continue; }
      if (this.eof() || (close && this.peek() === close)) continue;
      if (!close && (this.peek() === ')' || this.peek() === '}')) break;
      if (this.peek() !== '}' && this.peek() !== ')') throw new PsParseError(`Unexpected token '${this.s.slice(this.i).split(/\s/)[0]}' in expression or statement.`, this.i, 'UnexpectedToken');
    }
    return out;
  }

  keyword(w: string): boolean {
    const m = new RegExp(`^${w}(?![\\w-])`, 'i').exec(this.s.slice(this.i));
    return !!m;
  }

  block(): Statement[] {
    this.ws(true);
    if (this.peek() !== '{') throw new PsParseError('Missing statement block.', this.i, 'MissingStatementBlock');
    this.i++;
    const body = this.statements('}');
    this.ws(true);
    if (this.peek() !== '}') throw new PsParseError("Missing closing '}' in statement block or type definition.", this.i, 'MissingEndCurlyBrace');
    this.i++;
    return body;
  }

  condition(): Pipeline {
    this.ws(true);
    if (this.peek() !== '(') throw new PsParseError("Missing '(' after 'if' in if statement.", this.i, 'MissingOpenParenthesisInIfStatement');
    this.i++;
    this.ws(true);
    const p = this.pipeline();
    this.ws(true);
    if (this.peek() !== ')') throw new PsParseError("Missing closing ')' after expression in 'if' statement.", this.i, 'MissingEndParenthesisAfterStatement');
    this.i++;
    return p;
  }

  statement(): Statement {
    this.ws();
    if (this.keyword('if')) {
      this.i += 2;
      const clauses = [{ cond: this.condition(), body: this.block() }];
      let otherwise: Statement[] | undefined;
      for (;;) {
        const save = this.i;
        this.ws(true);
        if (this.keyword('elseif')) { this.i += 6; clauses.push({ cond: this.condition(), body: this.block() }); continue; }
        if (this.keyword('else')) { this.i += 4; otherwise = this.block(); }
        else this.i = save;
        break;
      }
      return { k: 'if', clauses, otherwise };
    }
    if (this.keyword('foreach')) {
      this.i += 7;
      this.ws();
      if (this.peek() !== '(') throw new PsParseError("Missing opening '(' after keyword 'foreach'.", this.i, 'MissingOpenParenthesisAfterKeyword');
      this.i++;
      this.ws();
      const v = this.variableName();
      this.ws();
      if (!this.keyword('in')) throw new PsParseError("Missing 'in' after variable in foreach loop.", this.i, 'MissingInInForeach');
      this.i += 2;
      this.ws();
      const coll = this.pipeline();
      this.ws();
      if (this.peek() !== ')') throw new PsParseError("Missing closing ')' in foreach statement.", this.i, 'MissingEndParenthesisAfterForeach');
      this.i++;
      return { k: 'foreach', v, coll, body: this.block() };
    }
    // Assignment: $var[.member|[index]]* (=|+=|-=) pipeline
    if (this.peek() === '$') {
      const save = this.i;
      try {
        const target = this.postfix(this.primary());
        this.ws();
        const m = /^(\+=|-=|=(?!=))/.exec(this.s.slice(this.i));
        if (m && (target.k === 'var' || target.k === 'member' || target.k === 'index')) {
          this.i += m[0].length;
          this.ws();
          return { k: 'assign', target, op: m[0], value: this.pipeline() };
        }
      } catch { /* not an assignment */ }
      this.i = save;
    }
    return { k: 'pipe', p: this.pipeline() };
  }

  variableName(): string {
    if (this.peek() !== '$') throw new PsParseError('Missing variable name.', this.i);
    this.i++;
    if (this.peek() === '{') {
      const j = this.s.indexOf('}', this.i);
      const n = this.s.slice(this.i + 1, j);
      this.i = j + 1;
      return n;
    }
    const m = /^(\?|\$|\^|_|[A-Za-z0-9_]+(:[A-Za-z0-9_]+)?)/.exec(this.s.slice(this.i));
    if (!m) throw new PsParseError("Variable reference is not valid. '$' was not followed by a valid variable name character. Consider using ${} to delimit the name.", this.i - 1, 'InvalidVariableReference');
    this.i += m[0].length;
    return m[0];
  }

  pipeline(): Pipeline {
    const start = this.i;
    const els: PipeEl[] = [];
    for (;;) {
      this.ws();
      els.push(this.element(els.length === 0));
      this.ws();
      if (this.peek() === '|' && this.peek(1) !== '|') {
        this.i++;
        this.ws(true);
        if (this.eof() || this.peek() === ';' || this.peek() === ')') throw new PsParseError('An empty pipe element is not allowed.', this.i, 'EmptyPipeElement');
        continue;
      }
      break;
    }
    return { els, start, end: this.i };
  }

  /** Does the text here start an expression (rather than a command name)? */
  startsExpression(): boolean {
    const c = this.peek();
    if (c === '$' || c === '(' || c === '@' || c === '"' || c === "'" || c === '[' || c === '{' || c === '!') return true;
    if (/[0-9]/.test(c)) return /^\d+(\.\d+)?([kmgt]b)?(?=[\s|;)}]|$|\.\.|[-+*/%,])/i.test(this.s.slice(this.i)) || /^0x[0-9a-f]+/i.test(this.s.slice(this.i));
    if (c === '-' && /[0-9]/.test(this.peek(1))) return true;
    if (c === '-' && /^-not\b/i.test(this.s.slice(this.i))) return true;
    return false;
  }

  element(first: boolean): PipeEl {
    const start = this.i;
    if (this.startsExpression() && !(this.peek() === '&')) {
      const e = this.expression();
      return { k: 'expr', e, start, end: this.i };
    }
    let call = false;
    if (this.peek() === '&') { call = true; this.i++; this.ws(); }
    let name: string;
    if (call && (this.peek() === '"' || this.peek() === "'")) {
      const e = this.primary();
      name = e.k === 'str' ? e.v : e.k === 'xstr' ? e.parts.filter((p) => typeof p === 'string').join('') : '';
    } else {
      const ns = this.i;
      while (!this.eof() && !WORD_END.has(this.peek()) && this.peek() !== '"' && this.peek() !== "'") this.i++;
      name = this.s.slice(ns, this.i);
    }
    if (!name) throw new PsParseError(first ? 'An expression was expected after \'(\'.' : 'An empty pipe element is not allowed.', this.i, 'ExpectedExpression');
    const args: Arg[] = [];
    for (;;) {
      this.ws();
      const c = this.peek();
      if (this.eof() || c === '|' || c === ';' || c === ')' || c === '}' || c === '\n') break;
      const as = this.i;
      if (c === '-' && /[A-Za-z]/.test(this.peek(1))) {
        this.i++;
        const ns = this.i;
        while (!this.eof() && /[A-Za-z0-9_]/.test(this.peek())) this.i++;
        const pname = this.s.slice(ns, this.i);
        if (this.peek() === ':') {
          this.i++;
          const value = this.argValue();
          args.push({ k: 'param', name: pname, value, text: this.s.slice(as, this.i) });
        } else if (!this.eof() && !WORD_END.has(this.peek())) {
          // "-foo.txt" style token: a string value, not a parameter.
          while (!this.eof() && !WORD_END.has(this.peek())) this.i++;
          args.push({ k: 'value', e: { k: 'str', v: this.s.slice(as, this.i) }, text: this.s.slice(as, this.i) });
        } else args.push({ k: 'param', name: pname, text: this.s.slice(as, this.i) });
        continue;
      }
      if (c === '-' && this.peek(1) === '-' && /\s|$/.test(this.peek(2))) { this.i += 2; continue; }
      const e = this.argValue();
      args.push({ k: 'value', e, text: this.s.slice(as, this.i) });
    }
    return { k: 'cmd', name, args, start, end: this.i, call };
  }

  /** A value in argument mode, with "a,b,c" forming an array. */
  argValue(): Expr {
    const items = [this.argItem()];
    for (;;) {
      const save = this.i;
      this.ws();
      if (this.peek() === ',') {
        this.i++;
        this.ws(true);
        items.push(this.argItem());
        continue;
      }
      this.i = save;
      break;
    }
    return items.length === 1 ? items[0] : { k: 'arr', items };
  }

  argItem(): Expr {
    const c = this.peek();
    if (c === '$' || c === '(' || c === '@' || c === '"' || c === "'" || c === '{' || c === '[') {
      const e = this.postfix(this.primary());
      // $env:USERPROFILE\Desktop: an argument continues as an expandable string.
      if (!this.eof() && !WORD_END.has(this.peek()) && this.peek() !== '"' && this.peek() !== "'") {
        const ns = this.i;
        while (!this.eof() && !WORD_END.has(this.peek())) this.i++;
        return { k: 'xstr', parts: [e, this.s.slice(ns, this.i)] };
      }
      return e;
    }
    // A bareword; quoted sections inside it (name="Allow RDP") join it without their quotes.
    let w = '';
    let quoted = false;
    while (!this.eof() && !WORD_END.has(this.peek())) {
      const ch = this.peek();
      if (ch === '"' || ch === "'") {
        const close = this.s.indexOf(ch, this.i + 1);
        if (close < 0) throw new PsParseError(`The string is missing the terminator: ${ch}.`, this.s.length, 'TerminatorExpectedAtEndOfString');
        w += this.s.slice(this.i + 1, close);
        this.i = close + 1;
        quoted = true;
        continue;
      }
      w += ch;
      this.i++;
    }
    if (quoted) return { k: 'str', v: w };
    if (/^-?\d+$/.test(w)) return { k: 'num', v: Number(w) };
    if (/^\$?(true|false)$/i.test(w)) return { k: 'str', v: w };
    return { k: 'str', v: w };
  }

  // ---- expressions --------------------------------------------------------

  expression(): Expr {
    return this.logical();
  }

  op(re: RegExp): string | null {
    const save = this.i;
    this.ws();
    const m = re.exec(this.s.slice(this.i));
    if (m) {
      this.i += m[0].length;
      this.ws(true);
      return m[1].toLowerCase();
    }
    this.i = save;
    return null;
  }

  logical(): Expr {
    let l = this.unaryNot();
    for (;;) {
      const o = this.op(/^-(and|or|xor)(?![\w])/i);
      if (!o) return l;
      l = { k: 'bin', op: o, l, r: this.unaryNot() };
    }
  }

  unaryNot(): Expr {
    const save = this.i;
    this.ws();
    if (/^-not(?![\w])/i.test(this.s.slice(this.i))) { this.i += 4; this.ws(); return { k: 'un', op: 'not', e: this.unaryNot() }; }
    if (this.peek() === '!') { this.i++; this.ws(); return { k: 'un', op: 'not', e: this.unaryNot() }; }
    this.i = save;
    return this.comparison();
  }

  comparison(): Expr {
    let l = this.array();
    for (;;) {
      const o = this.op(/^-([ci]?(?:eq|ne|gt|ge|lt|le|like|notlike|match|notmatch|contains|notcontains|in|notin|replace|split|join)|is|isnot|as|f)(?![\w])/i);
      if (!o) return l;
      l = { k: 'bin', op: o.replace(/^i(?=[a-z]{2})/, ''), l, r: this.array() };
    }
  }

  /** Comma operator in expression mode builds arrays: 1,2,3 */
  array(): Expr {
    const first = this.range();
    const items = [first];
    for (;;) {
      const save = this.i;
      this.ws();
      if (this.peek() === ',') { this.i++; this.ws(true); items.push(this.range()); continue; }
      this.i = save;
      break;
    }
    return items.length === 1 ? first : { k: 'arr', items };
  }

  range(): Expr {
    const l = this.additive();
    const save = this.i;
    this.ws();
    if (this.peek() === '.' && this.peek(1) === '.') { this.i += 2; this.ws(); return { k: 'bin', op: '..', l, r: this.additive() }; }
    this.i = save;
    return l;
  }

  additive(): Expr {
    let l = this.multiplicative();
    for (;;) {
      const save = this.i;
      this.ws();
      const c = this.peek();
      if ((c === '+' || c === '-') && this.peek(1) !== '=' && !(c === '-' && /[A-Za-z]/.test(this.peek(1)))) {
        this.i++;
        this.ws(true);
        l = { k: 'bin', op: c, l, r: this.multiplicative() };
        continue;
      }
      this.i = save;
      return l;
    }
  }

  multiplicative(): Expr {
    let l = this.unary();
    for (;;) {
      const save = this.i;
      this.ws();
      const c = this.peek();
      if ((c === '*' || c === '/' || c === '%') && this.peek(1) !== '=') {
        this.i++;
        this.ws(true);
        l = { k: 'bin', op: c, l, r: this.unary() };
        continue;
      }
      this.i = save;
      return l;
    }
  }

  unary(): Expr {
    this.ws();
    if (this.peek() === '-' && !/[A-Za-z]/.test(this.peek(1))) { this.i++; return { k: 'un', op: '-', e: this.unary() }; }
    if (this.peek() === '[') {
      const save = this.i;
      const t = this.typeLiteral();
      if (t) {
        if (this.peek() === ':' && this.peek(1) === ':') return this.postfix({ k: 'type', name: t });
        this.ws();
        if (!this.eof() && !/[|;)}\n,]/.test(this.peek()) && !/^-[a-z]/i.test(this.s.slice(this.i))) return { k: 'cast', type: t, e: this.unary() };
        return { k: 'type', name: t };
      }
      this.i = save;
    }
    return this.postfix(this.primary());
  }

  typeLiteral(): string | null {
    const m = /^\[([A-Za-z][\w.]*(\[\])?)\]/.exec(this.s.slice(this.i));
    if (!m) return null;
    this.i += m[0].length;
    return m[1];
  }

  postfix(e: Expr): Expr {
    for (;;) {
      const c = this.peek();
      if (c === '.' && /[A-Za-z_$"']/.test(this.peek(1))) {
        this.i++;
        e = this.memberAfterDot(e, false);
        continue;
      }
      if (c === ':' && this.peek(1) === ':') {
        this.i += 2;
        e = this.memberAfterDot(e, true);
        continue;
      }
      if (c === '[') {
        this.i++;
        this.ws();
        const idx = this.expression();
        this.ws();
        if (this.peek() !== ']') throw new PsParseError("Array index expression is missing or not valid.", this.i, 'MissingArrayIndexExpression');
        this.i++;
        e = { k: 'index', obj: e, idx };
        continue;
      }
      return e;
    }
  }

  memberAfterDot(obj: Expr, isStatic: boolean): Expr {
    let name: Expr;
    if (this.peek() === '$') name = { k: 'var', name: this.variableName() };
    else if (this.peek() === '"' || this.peek() === "'") name = this.primary();
    else {
      const ns = this.i;
      while (!this.eof() && /[A-Za-z0-9_]/.test(this.peek())) this.i++;
      name = { k: 'str', v: this.s.slice(ns, this.i) };
    }
    if (this.peek() === '(') {
      this.i++;
      const args: Expr[] = [];
      this.ws(true);
      while (this.peek() !== ')') {
        args.push(this.range());
        this.ws(true);
        if (this.peek() === ',') { this.i++; this.ws(true); continue; }
        if (this.peek() !== ')') throw new PsParseError("Missing ')' in method call.", this.i, 'MissingEndParenthesisInMethodCall');
      }
      this.i++;
      return { k: 'member', obj, name, args, isStatic };
    }
    return { k: 'member', obj, name, isStatic };
  }

  primary(): Expr {
    this.ws();
    const c = this.peek();
    const rest = this.s.slice(this.i);
    if (c === "'") return this.singleQuoted();
    if (c === '"') return this.doubleQuoted();
    if (c === '$') {
      if (this.peek(1) === '(') {
        this.i += 2;
        const body = this.statements(')');
        this.expect(')');
        return { k: 'sub', body };
      }
      return { k: 'var', name: this.variableName() };
    }
    if (c === '@' && this.peek(1) === '(') {
      this.i += 2;
      const body = this.statements(')');
      this.expect(')');
      return { k: 'sub', body, array: true };
    }
    if (c === '@' && this.peek(1) === '{') {
      this.i += 2;
      const entries: [Expr, Expr][] = [];
      for (;;) {
        this.ws(true);
        while (this.peek() === ';') { this.i++; this.ws(true); }
        if (this.peek() === '}') { this.i++; break; }
        if (this.eof()) throw new PsParseError("Missing closing '}' in statement block or type definition.", this.i, 'MissingEndCurlyBrace');
        let key: Expr;
        if (this.peek() === '"' || this.peek() === "'") key = this.primary();
        else {
          const ns = this.i;
          while (!this.eof() && /[A-Za-z0-9_.-]/.test(this.peek())) this.i++;
          key = { k: 'str', v: this.s.slice(ns, this.i) };
        }
        this.ws();
        if (this.peek() !== '=') throw new PsParseError("Missing '=' operator after key in hash literal.", this.i, 'MissingEqualsInHashLiteral');
        this.i++;
        this.ws(true);
        const save = this.i;
        let value: Expr;
        try {
          const st = this.statement();
          value = st.k === 'pipe' && st.p.els.length === 1 && st.p.els[0].k === 'expr' ? st.p.els[0].e : { k: 'sub', body: [st] };
        } catch (e) {
          this.i = save;
          throw e;
        }
        entries.push([key, value]);
      }
      return { k: 'hash', entries };
    }
    if (c === '(') {
      this.i++;
      this.ws(true);
      const st = this.statement();
      this.ws(true);
      this.expect(')');
      if (st.k === 'pipe' && st.p.els.length === 1 && st.p.els[0].k === 'expr') return st.p.els[0].e;
      return { k: 'sub', body: [st] };
    }
    if (c === '{') {
      const start = this.i;
      this.i++;
      const body = this.statements('}');
      this.expect('}');
      return { k: 'block', body, text: this.s.slice(start + 1, this.i - 1) };
    }
    const num = /^0x([0-9a-f]+)|^(\d+(?:\.\d+)?)([kmgt]b)?/i.exec(rest);
    if (num) {
      this.i += num[0].length;
      if (num[1]) return { k: 'num', v: parseInt(num[1], 16) };
      const mult = { kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4 }[(num[3] ?? '').toLowerCase()] ?? 1;
      return { k: 'num', v: Number(num[2]) * mult };
    }
    if (c === '[') {
      const t = this.typeLiteral();
      if (t) return { k: 'type', name: t };
    }
    // A bare word in expression position (e.g. a member name or "-Name foo" value inside parentheses).
    const w = /^[A-Za-z_][\w.:\\-]*/.exec(rest);
    if (w) {
      this.i += w[0].length;
      return { k: 'str', v: w[0] };
    }
    throw new PsParseError(c ? `Unexpected token '${rest.split(/\s/)[0]}' in expression or statement.` : 'An expression was expected.', this.i, c ? 'UnexpectedToken' : 'ExpectedExpression');
  }

  expect(ch: string): void {
    this.ws(true);
    if (this.peek() !== ch) {
      const msg = ch === ')' ? "Missing closing ')' in expression." : ch === '}' ? "Missing closing '}' in statement block or type definition." : `Missing '${ch}'.`;
      throw new PsParseError(msg, this.i, ch === ')' ? 'MissingEndParenthesisInExpression' : 'MissingEndCurlyBrace');
    }
    this.i++;
  }

  singleQuoted(): Expr {
    this.i++;
    let v = '';
    for (;;) {
      if (this.eof()) throw new PsParseError("The string is missing the terminator: '.", this.i, 'TerminatorExpectedAtEndOfString');
      const c = this.s[this.i++];
      if (c === "'") {
        if (this.peek() === "'") { v += "'"; this.i++; continue; }
        break;
      }
      v += c;
    }
    return { k: 'str', v };
  }

  doubleQuoted(): Expr {
    this.i++;
    const parts: (string | Expr)[] = [];
    let buf = '';
    const ESC: Record<string, string> = { n: '\n', t: '\t', r: '\r', '0': '\0', a: '\x07', b: '\b', e: '\x1b', f: '\f', v: '\v' };
    for (;;) {
      if (this.eof()) throw new PsParseError('The string is missing the terminator: ".', this.i, 'TerminatorExpectedAtEndOfString');
      const c = this.s[this.i];
      if (c === '"') {
        if (this.peek(1) === '"') { buf += '"'; this.i += 2; continue; }
        this.i++;
        break;
      }
      if (c === '`' && this.i + 1 < this.s.length) {
        const n = this.s[this.i + 1];
        buf += ESC[n] ?? n;
        this.i += 2;
        continue;
      }
      if (c === '$' && this.peek(1) === '(') {
        if (buf) { parts.push(buf); buf = ''; }
        this.i += 2;
        const body = this.statements(')');
        this.expect(')');
        parts.push({ k: 'sub', body });
        continue;
      }
      if (c === '$' && /[A-Za-z_?{]/.test(this.peek(1))) {
        if (buf) { parts.push(buf); buf = ''; }
        parts.push({ k: 'var', name: this.variableName() });
        continue;
      }
      buf += c;
      this.i++;
    }
    if (buf) parts.push(buf);
    if (parts.every((p) => typeof p === 'string')) return { k: 'str', v: parts.join('') };
    return { k: 'xstr', parts };
  }
}
