// PowerShell values. Objects are plain data (they live in session state that is
// structured-cloned between commands): a PSObject is a record with its .NET type
// name in `__t`; keys starting with "__" are hidden from formatting.

export type PSValue = null | undefined | string | number | boolean | PSObject | PSDate | PSBlock | PSHash | PSSecure | PSValue[];

export interface PSObject { __t: string; [prop: string]: unknown }
export interface PSDate { __t: 'System.DateTime'; ms: number }
export interface PSBlock { __t: 'System.Management.Automation.ScriptBlock'; text: string; body: unknown }
export interface PSHash { __t: 'System.Collections.Hashtable'; entries: Record<string, PSValue>; keys: string[] }
export interface PSSecure { __t: 'System.Security.SecureString'; plain: string }

export function obj(type: string, props: Record<string, unknown>): PSObject {
  return { __t: type, ...props };
}

export function isObj(v: unknown): v is PSObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && typeof (v as PSObject).__t === 'string';
}

export function isDate(v: unknown): v is PSDate {
  return isObj(v) && v.__t === 'System.DateTime';
}

export function isBlock(v: unknown): v is PSBlock {
  return isObj(v) && v.__t === 'System.Management.Automation.ScriptBlock';
}

export function isHash(v: unknown): v is PSHash {
  return isObj(v) && v.__t === 'System.Collections.Hashtable';
}

export function date(ms: number): PSDate {
  return { __t: 'System.DateTime', ms };
}

export function hash(entries: [string, PSValue][]): PSHash {
  const h: PSHash = { __t: 'System.Collections.Hashtable', entries: {}, keys: [] };
  for (const [k, v] of entries) hashSet(h, k, v);
  return h;
}

export function hashGet(h: PSHash, key: string): PSValue {
  const k = h.keys.find((x) => x.toLowerCase() === key.toLowerCase());
  return k === undefined ? null : h.entries[k];
}

export function hashSet(h: PSHash, key: string, v: PSValue): void {
  const k = h.keys.find((x) => x.toLowerCase() === key.toLowerCase());
  if (k === undefined) h.keys.push(key);
  h.entries[k ?? key] = v;
}

/** Visible property names of an object, in order. */
export function propNames(o: PSObject): string[] {
  return Object.keys(o).filter((k) => !k.startsWith('__'));
}

/** Case-insensitive property lookup; undefined when absent. */
export function getProp(o: unknown, name: string): PSValue | undefined {
  if (isHash(o)) {
    const k = o.keys.find((x) => x.toLowerCase() === name.toLowerCase());
    return k === undefined ? undefined : o.entries[k];
  }
  if (isObj(o)) {
    const k = Object.keys(o).find((x) => x.toLowerCase() === name.toLowerCase() && !x.startsWith('__'));
    return k === undefined ? undefined : (o[k] as PSValue);
  }
  return undefined;
}

export function typeName(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return 'System.String';
  if (typeof v === 'number') return Number.isInteger(v) ? 'System.Int32' : 'System.Double';
  if (typeof v === 'boolean') return 'System.Boolean';
  if (Array.isArray(v)) return 'System.Object[]';
  if (isObj(v)) return v.__t;
  return 'System.Object';
}

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

function hm(d: Date): { h: number; m: string; s: string; ap: string } {
  const h24 = d.getUTCHours();
  return { h: h24 % 12 === 0 ? 12 : h24 % 12, m: String(d.getUTCMinutes()).padStart(2, '0'), s: String(d.getUTCSeconds()).padStart(2, '0'), ap: h24 < 12 ? 'AM' : 'PM' };
}

/** en-US short date and time: "10/19/2026 8:33:19 AM" (how DateTime prints in tables and strings). */
export function shortDateTime(ms: number): string {
  const d = new Date(ms);
  const t = hm(d);
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()} ${t.h}:${t.m}:${t.s} ${t.ap}`;
}

/** Get-Date's default display: "Monday, October 19, 2026 8:33:19 AM". */
export function longDateTime(ms: number): string {
  const d = new Date(ms);
  const t = hm(d);
  return `${DAYS[d.getUTCDay()]}, ${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()} ${t.h}:${t.m}:${t.s} ${t.ap}`;
}

/** Conversion to string as PowerShell does it in strings and comparisons. */
export function toStr(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(Math.round(v * 1e7) / 1e7);
  if (typeof v === 'boolean') return v ? 'True' : 'False';
  if (Array.isArray(v)) return v.map(toStr).join(' ');
  if (isDate(v)) return shortDateTime(v.ms);
  if (isBlock(v)) return v.text;
  if (isHash(v)) return 'System.Collections.Hashtable';
  if (isObj(v) && v.__t === 'System.Security.SecureString') return 'System.Security.SecureString';
  if (isObj(v) && typeof v.__str === 'string') return v.__str;
  if (isObj(v)) return v.__t;
  return String(v);
}

export function toNum(v: unknown): number | null {
  if (typeof v === 'number') return v;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'string' && /^\s*-?(\d+\.?\d*|\.\d+)\s*$/.test(v)) return Number(v);
  if (typeof v === 'string' && /^\s*0x[0-9a-f]+\s*$/i.test(v)) return parseInt(v, 16);
  if (isDate(v)) return v.ms;
  return null;
}

export function toBool(v: unknown): boolean {
  if (v === null || v === undefined) return false;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') return v.length > 0;
  if (Array.isArray(v)) return v.length > 1 || (v.length === 1 && toBool(v[0]));
  return true;
}

/** PowerShell wildcard (-like, -Name filters): * ? [abc], case-insensitive. */
export function wildcard(pattern: string): RegExp {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') re += '.*';
    else if (c === '?') re += '.';
    else if (c === '[') {
      const j = pattern.indexOf(']', i);
      if (j > i) { re += pattern.slice(i, j + 1); i = j; } else re += '\\[';
    } else if (c === '`' && i + 1 < pattern.length) re += pattern[++i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    else re += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`, 'i');
}

export function hasWildcard(s: string): boolean {
  return /[*?[]/.test(s);
}

/** Equality as -eq does it: case-insensitive strings, numeric when the left side is numeric. */
export function psEquals(a: unknown, b: unknown, caseSensitive = false): boolean {
  if (a === null || a === undefined) return b === null || b === undefined;
  if (typeof a === 'number') { const n = toNum(b); return n !== null && n === a; }
  if (typeof a === 'boolean') return a === toBool(b);
  if (isDate(a)) return isDate(b) && a.ms === b.ms;
  const x = toStr(a), y = toStr(b);
  return caseSensitive ? x === y : x.toLowerCase() === y.toLowerCase();
}

export function psCompare(a: unknown, b: unknown): number {
  const na = toNum(a), nb = toNum(b);
  if (typeof a === 'number' || isDate(a)) {
    if (nb !== null && na !== null) return na - nb;
  }
  if (na !== null && nb !== null && typeof b === 'number') return na - nb;
  const x = toStr(a).toLowerCase(), y = toStr(b).toLowerCase();
  return x < y ? -1 : x > y ? 1 : 0;
}

export function flatten(v: unknown): PSValue[] {
  if (v === null || v === undefined) return [];
  return Array.isArray(v) ? (v as PSValue[]) : [v as PSValue];
}
