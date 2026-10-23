// Out-Default: how Windows PowerShell 5.1 turns objects into console text.
// Types with a registered view use it (fixed-width tables such as services,
// grouped views such as directory listings); other objects become a table when
// they have up to 4 properties, otherwise a list.

import { getProp, isDate, isHash, isObj, longDateTime, propNames, shortDateTime, toStr, type PSObject, type PSValue } from './values';

export interface Column {
  label: string;
  /** Property name, or a function computing the cell. */
  value: string | ((o: PSObject) => unknown);
  width?: number;
  align?: 'left' | 'right';
}

export type View =
  | { kind: 'table'; columns: Column[]; groupBy?: { prop: string; label: string; indent?: string } }
  | { kind: 'list'; props: string[] }
  /** Objects shown as their string form (MatchInfo). */
  | { kind: 'text' };

const VIEWS: Record<string, View> = {};

export function registerView(type: string, view: View): void {
  VIEWS[type] = view;
}

export function viewFor(type: string): View | undefined {
  return VIEWS[type];
}

/** A cell as text. */
export function cell(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return `{${v.map(cell).join(', ')}}`;
  if (isDate(v)) return shortDateTime(v.ms);
  if (isHash(v)) return 'System.Collections.Hashtable';
  return toStr(v);
}

function value(o: PSObject, c: Column): unknown {
  return typeof c.value === 'function' ? c.value(o) : getProp(o, c.value);
}

function isNumeric(v: unknown): boolean {
  return typeof v === 'number';
}

function fit(s: string, w: number): string {
  if (s.length <= w) return s;
  return w > 3 ? s.slice(0, w - 3) + '...' : s.slice(0, w);
}

export function formatTable(objs: PSObject[], columns: Column[], width = 120): string[] {
  const cells = objs.map((o) => columns.map((c) => value(o, c)));
  const align = columns.map((c, i) => c.align ?? (cells.length && cells.every((r) => r[i] === null || r[i] === undefined || isNumeric(r[i])) && cells.some((r) => isNumeric(r[i])) ? 'right' : 'left'));
  const widths = columns.map((c, i) => c.width ?? Math.max(c.label.length, ...cells.map((r) => cell(r[i]).split('\n')[0].length)));
  // Fit into the console width: the last column takes what is left.
  let used = widths.slice(0, -1).reduce((a, b) => a + b + 1, 0);
  if (used + widths[widths.length - 1] > width - 1) widths[widths.length - 1] = Math.max(columns[columns.length - 1].label.length, width - 1 - used);
  while (used > width - 10 && widths.length > 1) { used -= widths.pop()! + 1; columns = columns.slice(0, widths.length); }
  const fmt = (vals: string[]) => vals.map((v, i) => {
    const last = i === widths.length - 1;
    const t = fit(v, widths[i]);
    return align[i] === 'right' ? t.padStart(widths[i]) : last ? t : t.padEnd(widths[i]);
  }).join(' ').replace(/\s+$/, '');
  const lines = [fmt(columns.map((c) => c.label)), fmt(columns.map((c, i) => (align[i] === 'right' ? '-'.repeat(c.label.length).padStart(widths[i]) : '-'.repeat(c.label.length))))];
  for (const r of cells) lines.push(fmt(r.slice(0, widths.length).map((v) => cell(v).split('\n')[0])));
  return lines;
}

export function formatList(objs: PSObject[], props?: string[]): string[] {
  const out: string[] = [];
  for (const o of objs) {
    const names = props ?? propNames(o);
    const w = Math.max(0, ...names.map((n) => n.length));
    out.push('');
    for (const n of names) {
      const v = cell(getProp(o, n) ?? (o as Record<string, unknown>)[n]);
      const [first, ...more] = v.split('\n');
      out.push(`${n.padEnd(w)} : ${first}`.replace(/\s+$/, ''));
      for (const m of more) out.push(`${' '.repeat(w + 3)}${m}`);
    }
  }
  return out;
}

function defaultView(o: PSObject): View {
  const names = propNames(o);
  if (names.length <= 4) return { kind: 'table', columns: names.map((n) => ({ label: n, value: n })) };
  return { kind: 'list', props: names };
}

function formatGroup(objs: PSObject[], width: number): string[] {
  const view = viewFor(objs[0].__t) ?? defaultView(objs[0]);
  if (view.kind === 'list') return [...formatList(objs, view.props), '', ''];
  if (view.kind === 'text') return ['', ...objs.map((o) => toStr(o)), '', ''];
  if (view.groupBy) {
    const out: string[] = [];
    let i = 0;
    while (i < objs.length) {
      const key = toStr(getProp(objs[i], view.groupBy.prop) ?? objs[i][view.groupBy.prop]);
      const group: PSObject[] = [];
      while (i < objs.length && toStr(getProp(objs[i], view.groupBy.prop) ?? objs[i][view.groupBy.prop]) === key) group.push(objs[i++]);
      out.push('', `${view.groupBy.indent ?? '    '}${view.groupBy.label}: ${key}`, '', '');
      out.push(...formatTable(group, view.columns, width));
    }
    return [...out, '', ''];
  }
  return ['', ...formatTable(objs, view.columns, width), '', ''];
}

/** Format a stream of pipeline output for the console. */
export function formatOutput(items: PSValue[], width = 120): string {
  const lines: string[] = [];
  let i = 0;
  while (i < items.length) {
    const v = items[i];
    if (isObj(v) && !isDate(v) && !isHash(v) && v.__t !== 'System.Management.Automation.ScriptBlock' && v.__t !== 'System.Security.SecureString' && v.__t !== '__text') {
      const group: PSObject[] = [];
      while (i < items.length && isObj(items[i]) && (items[i] as PSObject).__t === v.__t) group.push(items[i++] as PSObject);
      lines.push(...formatGroup(group, width));
      continue;
    }
    if (isHash(v)) {
      const rows = v.keys.map((k) => ({ __t: 'ht', Name: k, Value: v.entries[k] }));
      lines.push('', ...formatTable(rows, [{ label: 'Name', value: 'Name' }, { label: 'Value', value: 'Value' }], width), '');
      i++;
      continue;
    }
    if (isObj(v) && v.__t === '__text') lines.push(String((v as PSObject).text));
    else if (isDate(v)) lines.push('', longDateTime(v.ms), '', '');
    else lines.push(cell(v));
    i++;
  }
  // Collapse runs of blank lines the way the console shows them, and trim the end.
  const out: string[] = [];
  for (const l of lines) {
    if (l === '' && out.length >= 2 && out[out.length - 1] === '' && out[out.length - 2] === '') continue;
    out.push(l);
  }
  while (out.length && out[out.length - 1] === '') out.pop();
  return out.join('\n');
}
