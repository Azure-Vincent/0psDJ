// Core cmdlets: the object pipeline (Where/ForEach/Select/Sort/Group/Measure),
// formatting and output, discovery (Get-Command, Get-Help, Get-Alias), and
// small utilities (Get-Date, Start-Sleep, Read-Host, ConvertTo-SecureString).

import { formatList, formatOutput, formatTable, registerView, viewFor, type Column } from '../format';
import { ALIASES, CMDLETS, cmdlet, invokeBlock, NATIVES, text, type Call } from '../runtime';
import {
  date, flatten, getProp, hasWildcard, hashGet, isBlock, isHash, isObj, obj, propNames, psCompare, psEquals, toBool, toNum, toStr, typeName, wildcard,
  type PSObject, type PSValue,
} from '../values';

const MGMT = 'Microsoft.PowerShell.Management';
const UTIL = 'Microsoft.PowerShell.Utility';
const CORE = 'Microsoft.PowerShell.Core';

registerView('Microsoft.PowerShell.Commands.GroupInfo', { kind: 'table', columns: [{ label: 'Count', value: 'Count', align: 'right' }, { label: 'Name', value: 'Name' }, { label: 'Group', value: (o) => `{${flatten(o.Group as PSValue).map(short).join(', ')}}` }] });
registerView('Microsoft.PowerShell.Commands.GenericMeasureInfo', { kind: 'list', props: ['Count', 'Average', 'Sum', 'Maximum', 'Minimum', 'Property'] });
registerView('Microsoft.PowerShell.Commands.TextMeasureInfo', { kind: 'table', columns: [{ label: 'Lines', value: 'Lines', align: 'right' }, { label: 'Words', value: 'Words', align: 'right' }, { label: 'Characters', value: 'Characters', align: 'right' }, { label: 'Property', value: 'Property' }] });
registerView('System.Management.Automation.CommandInfo', { kind: 'table', columns: [{ label: 'CommandType', value: 'CommandType', width: 15 }, { label: 'Name', value: 'Name', width: 50 }, { label: 'Version', value: 'Version', width: 14 }, { label: 'Source', value: 'Source' }] });
registerView('Microsoft.PowerShell.Commands.HistoryInfo', { kind: 'table', columns: [{ label: 'Id', value: 'Id', align: 'right', width: 4 }, { label: 'CommandLine', value: 'CommandLine' }] });
registerView('Microsoft.PowerShell.Commands.MatchInfo', { kind: 'text' });

function short(v: PSValue): string {
  if (isObj(v) && !isHash(v)) return v.__str !== undefined ? String(v.__str) : toStr(getProp(v, 'Name') ?? v.__t);
  return toStr(v);
}

/** A property spec of Select-Object / Sort-Object / Format-*: name, wildcard, block or @{Name=..;Expression=..}. */
function propValue(c: Call, o: PSValue, spec: PSValue): PSValue {
  if (isBlock(spec)) {
    const r = invokeBlock(c.ctx, spec, o);
    return r.length === 1 ? r[0] : r;
  }
  if (isHash(spec)) return propValue(c, o, hashGet(spec, 'Expression') ?? hashGet(spec, 'e') ?? null);
  const v = getProp(o, toStr(spec));
  return v === undefined ? null : v;
}

function propLabel(spec: PSValue): string {
  if (isHash(spec)) return toStr(hashGet(spec, 'Name') ?? hashGet(spec, 'n') ?? hashGet(spec, 'Label') ?? hashGet(spec, 'l') ?? '');
  if (isBlock(spec)) return spec.text.trim();
  return toStr(spec);
}

/** Expand wildcard property names against an object. */
function expandProps(o: PSValue, specs: PSValue[]): PSValue[] {
  const out: PSValue[] = [];
  for (const s of specs) {
    if (typeof s === 'string' && hasWildcard(s) && isObj(o)) {
      const re = wildcard(s);
      out.push(...propNames(o).filter((n) => re.test(n)));
    } else if (typeof s === 'string' && isObj(o)) {
      out.push(propNames(o).find((n) => n.toLowerCase() === s.toLowerCase()) ?? s);
    } else out.push(s);
  }
  return out;
}

cmdlet({
  name: 'Where-Object', module: CORE, synopsis: 'Selects objects from a collection based on their property values.',
  params: [{ name: 'FilterScript', aliases: ['Property'], type: 'any', position: 0 }, { name: 'Value', type: 'any', position: 1 }, { name: 'InputObject', type: 'any' },
    ...['EQ', 'NE', 'GT', 'GE', 'LT', 'LE', 'Like', 'NotLike', 'Match', 'NotMatch', 'Contains', 'NotContains', 'In', 'NotIn', 'CEQ', 'Not', 'Is'].map((name) => ({ name, type: 'switch' as const }))],
  run(c) {
    const input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    const f = c.p.FilterScript;
    if (isBlock(f)) return input.filter((o) => toBool(single(invokeBlock(c.ctx, f, o))));
    const prop = toStr(f);
    const v = c.p.Value;
    const op = ['EQ', 'NE', 'GT', 'GE', 'LT', 'LE', 'Like', 'NotLike', 'Match', 'NotMatch', 'Contains', 'NotContains', 'In', 'NotIn', 'CEQ', 'Not'].find((x) => c.has(x));
    return input.filter((o) => {
      const pv = getProp(o, prop) ?? null;
      switch (op) {
        case 'EQ': return psEquals(pv, v);
        case 'CEQ': return psEquals(pv, v, true);
        case 'NE': return !psEquals(pv, v);
        case 'GT': return psCompare(pv, v) > 0;
        case 'GE': return psCompare(pv, v) >= 0;
        case 'LT': return psCompare(pv, v) < 0;
        case 'LE': return psCompare(pv, v) <= 0;
        case 'Like': return wildcard(toStr(v)).test(toStr(pv));
        case 'NotLike': return !wildcard(toStr(v)).test(toStr(pv));
        case 'Match': return new RegExp(toStr(v), 'i').test(toStr(pv));
        case 'NotMatch': return !new RegExp(toStr(v), 'i').test(toStr(pv));
        case 'Contains': return flatten(pv).some((x) => psEquals(x, v));
        case 'NotContains': return !flatten(pv).some((x) => psEquals(x, v));
        case 'In': return flatten(v).some((x) => psEquals(pv, x));
        case 'NotIn': return !flatten(v).some((x) => psEquals(pv, x));
        case 'Not': return !toBool(pv);
        default: return toBool(pv);
      }
    });
  },
});

function single(v: PSValue[]): PSValue {
  return v.length === 0 ? null : v.length === 1 ? v[0] : v;
}

cmdlet({
  name: 'ForEach-Object', module: CORE, synopsis: 'Performs an operation against each item in a collection of input objects.',
  params: [{ name: 'Process', aliases: ['MemberName'], type: 'any', position: 0 }, { name: 'Begin', type: 'block' }, { name: 'End', type: 'block' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    const out: PSValue[] = [];
    if (isBlock(c.p.Begin)) out.push(...invokeBlock(c.ctx, c.p.Begin));
    const p = c.p.Process;
    for (const o of input) {
      if (isBlock(p)) out.push(...invokeBlock(c.ctx, p, o));
      else { const v = getProp(o, toStr(p)); if (v !== undefined && v !== null) out.push(...(Array.isArray(v) ? v : [v])); }
    }
    if (isBlock(c.p.End)) out.push(...invokeBlock(c.ctx, c.p.End));
    return out;
  },
});

cmdlet({
  name: 'Select-Object', module: UTIL, synopsis: 'Selects objects or object properties.',
  params: [{ name: 'Property', type: 'any', position: 0 }, { name: 'First', type: 'int' }, { name: 'Last', type: 'int' }, { name: 'Skip', type: 'int' }, { name: 'ExpandProperty', type: 'string' }, { name: 'Unique', type: 'switch' }, { name: 'Index', type: 'any' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    let input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    if (c.has('Unique') && !c.has('Property')) input = input.filter((o, i) => input.findIndex((x) => psEquals(x, o) && toStr(x) === toStr(o)) === i);
    if (c.has('Skip')) input = input.slice(toNum(c.p.Skip) ?? 0);
    if (c.has('First')) input = input.slice(0, toNum(c.p.First) ?? 0);
    if (c.has('Last')) input = input.slice(-(toNum(c.p.Last) ?? 0) || input.length);
    if (c.has('Index')) input = flatten(c.p.Index).map((i) => input[toNum(i) ?? 0]).filter((x) => x !== undefined);
    if (c.has('ExpandProperty')) {
      const name = c.str('ExpandProperty')!;
      const out: PSValue[] = [];
      for (const o of input) {
        const v = getProp(o, name);
        if (v === undefined) {
          c.error(`Property "${name}" cannot be found.`, { category: 'InvalidArgument', target: toStr(isObj(o) ? o.__t : o), exception: 'PSArgumentException', id: 'ExpandPropertyNotFound' });
          continue;
        }
        out.push(...(Array.isArray(v) ? v : [v]));
      }
      return out;
    }
    if (!c.has('Property')) return input;
    const specs = flatten(c.p.Property);
    let out = input.map((o) => {
      const props: Record<string, unknown> = {};
      for (const s of expandProps(o, specs)) props[propLabel(s)] = propValue(c, o, s);
      return obj(`Selected.${typeName(o)}`, props) as PSValue;
    });
    if (c.has('Unique')) out = out.filter((o, i) => out.findIndex((x) => JSON.stringify(x) === JSON.stringify(o)) === i);
    return out;
  },
});

cmdlet({
  name: 'Sort-Object', module: UTIL, synopsis: 'Sorts objects by property values.',
  params: [{ name: 'Property', type: 'any', position: 0 }, { name: 'Descending', type: 'switch' }, { name: 'Unique', type: 'switch' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const input = [...(c.has('InputObject') ? flatten(c.p.InputObject) : c.input)];
    const specs = c.has('Property') ? flatten(c.p.Property) : [];
    const key = (o: PSValue): PSValue[] => (specs.length ? specs.map((s) => propValue(c, o, s)) : [o]);
    const dir = c.has('Descending') ? -1 : 1;
    input.sort((a, b) => {
      const ka = key(a), kb = key(b);
      for (let i = 0; i < ka.length; i++) {
        const d = psCompare(ka[i], kb[i]);
        if (d !== 0) return d * dir;
      }
      return 0;
    });
    return c.has('Unique') ? input.filter((o, i) => i === 0 || !psEquals(key(o)[0], key(input[i - 1])[0])) : input;
  },
});

cmdlet({
  name: 'Group-Object', module: UTIL, synopsis: 'Groups objects that contain the same value for specified properties.',
  params: [{ name: 'Property', type: 'any', position: 0 }, { name: 'NoElement', type: 'switch' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    const spec = c.has('Property') ? flatten(c.p.Property)[0] : null;
    const groups: { name: string; items: PSValue[] }[] = [];
    for (const o of input) {
      const name = toStr(spec === null ? o : propValue(c, o, spec));
      let g = groups.find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (!g) groups.push((g = { name, items: [] }));
      g.items.push(o);
    }
    return groups.map((g) => obj('Microsoft.PowerShell.Commands.GroupInfo', c.has('NoElement') ? { Count: g.items.length, Name: g.name } : { Count: g.items.length, Name: g.name, Group: g.items }));
  },
});

cmdlet({
  name: 'Measure-Object', module: UTIL, synopsis: 'Calculates the numeric properties of objects, and the characters, words, and lines in string objects.',
  params: [{ name: 'Property', type: 'any', position: 0 }, { name: 'Sum', type: 'switch' }, { name: 'Average', type: 'switch' }, { name: 'Maximum', type: 'switch' }, { name: 'Minimum', type: 'switch' }, { name: 'Line', type: 'switch' }, { name: 'Word', type: 'switch' }, { name: 'Character', type: 'switch' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    if (c.has('Line') || c.has('Word') || c.has('Character')) {
      const s = input.map(toStr);
      return [obj('Microsoft.PowerShell.Commands.TextMeasureInfo', { Lines: c.has('Line') ? s.reduce((a, x) => a + x.split('\n').length, 0) : null, Words: c.has('Word') ? s.reduce((a, x) => a + x.split(/\s+/).filter(Boolean).length, 0) : null, Characters: c.has('Character') ? s.reduce((a, x) => a + x.length, 0) : null, Property: null })];
    }
    const prop = c.has('Property') ? c.str('Property')! : null;
    const vals = prop ? input.map((o) => getProp(o, prop)).filter((v) => v !== undefined) : input;
    const nums = vals.map((v) => toNum(v)).filter((n): n is number => n !== null);
    if (prop && vals.length === 0 && input.length) c.error(`The property "${prop}" cannot be found in the input for any objects.`, { category: 'InvalidArgument', target: '', exception: 'PSArgumentException', id: 'GenericMeasurePropertyNotFound' });
    return [obj('Microsoft.PowerShell.Commands.GenericMeasureInfo', {
      Count: vals.length,
      Average: c.has('Average') && nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : null,
      Sum: c.has('Sum') ? nums.reduce((a, b) => a + b, 0) : null,
      Maximum: c.has('Maximum') && nums.length ? Math.max(...nums) : null,
      Minimum: c.has('Minimum') && nums.length ? Math.min(...nums) : null,
      Property: prop,
    })];
  },
});

function columnsFor(c: Call, input: PSValue[]): Column[] | null {
  if (!c.has('Property')) return null;
  const specs = expandProps(input[0] ?? null, flatten(c.p.Property));
  return specs.map((s) => ({ label: propLabel(s), value: (o: PSObject) => propValue(c, o, s) }));
}

function asObjects(input: PSValue[]): PSObject[] {
  return input.map((o) => (isObj(o) && !isHash(o) ? o : obj('System.String', { Length: toStr(o).length, __str: toStr(o) })));
}

cmdlet({
  name: 'Format-Table', module: UTIL, synopsis: 'Formats the output as a table.',
  params: [{ name: 'Property', type: 'any', position: 0 }, { name: 'AutoSize', type: 'switch' }, { name: 'Wrap', type: 'switch' }, { name: 'HideTableHeaders', type: 'switch' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    if (!input.length) return [];
    const objs = asObjects(input);
    const view = viewFor(objs[0].__t);
    let cols = columnsFor(c, input) ?? (view?.kind === 'table' ? view.columns : propNames(objs[0]).length ? propNames(objs[0]).map((n) => ({ label: n, value: n })) : [{ label: 'Length', value: 'Length' }]);
    if (c.has('AutoSize')) cols = cols.map((col) => ({ ...col, width: undefined }));
    let lines = formatTable(objs, cols);
    if (c.has('HideTableHeaders')) lines = lines.slice(2);
    return ['', ...lines, ''].map(text);
  },
});

cmdlet({
  name: 'Format-List', module: UTIL, synopsis: 'Formats the output as a list of properties in which each property appears on a new line.',
  params: [{ name: 'Property', type: 'any', position: 0 }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    const objs = asObjects(input);
    const out: string[] = [];
    for (const o of objs) {
      const specs = c.has('Property') ? expandProps(o, flatten(c.p.Property)) : propNames(o);
      const row = obj(o.__t, Object.fromEntries(specs.map((s) => [propLabel(s), propValue(c, o, s)])));
      out.push(...formatList([row]));
    }
    return [...out, '', ''].map(text);
  },
});

cmdlet({
  name: 'Out-String', module: UTIL, synopsis: 'Outputs input objects as a string.',
  params: [{ name: 'Stream', type: 'switch' }, { name: 'Width', type: 'int' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const s = formatOutput(c.has('InputObject') ? flatten(c.p.InputObject) : c.input, toNum(c.p.Width) ?? 120);
    return c.has('Stream') ? s.split('\n') : [s + '\n'];
  },
});

cmdlet({ name: 'Out-Null', module: CORE, synopsis: 'Hides the output instead of sending it down the pipeline or displaying it.', params: [{ name: 'InputObject', type: 'any' }], run: () => [] });
cmdlet({ name: 'Out-Host', module: CORE, synopsis: 'Sends output to the command line.', params: [{ name: 'Paging', type: 'switch' }, { name: 'InputObject', type: 'any' }], run: (c) => (c.has('InputObject') ? flatten(c.p.InputObject) : c.input) });
cmdlet({ name: 'Write-Output', module: UTIL, synopsis: 'Writes the specified objects to the pipeline.', params: [{ name: 'InputObject', type: 'any', position: 0 }, { name: 'NoEnumerate', type: 'switch' }], run: (c) => (c.has('InputObject') ? flatten(c.p.InputObject) : c.input) });

cmdlet({
  name: 'Write-Host', module: UTIL, synopsis: 'Writes customized output to a host.',
  params: [{ name: 'Object', type: 'any', position: 0 }, { name: 'NoNewline', type: 'switch' }, { name: 'ForegroundColor', type: 'string' }, { name: 'BackgroundColor', type: 'string' }, { name: 'Separator', type: 'any' }],
  run(c) {
    c.host(flatten(c.p.Object ?? '').map(toStr).join(c.has('Separator') ? toStr(c.p.Separator) : ' '));
  },
});

cmdlet({ name: 'Write-Warning', module: UTIL, synopsis: 'Writes a warning message.', params: [{ name: 'Message', type: 'string', position: 0 }], run(c) { c.warn(c.str('Message') ?? ''); } });
cmdlet({ name: 'Write-Error', module: UTIL, synopsis: 'Writes an object to the error stream.', params: [{ name: 'Message', type: 'string', position: 0 }], cls: 'Microsoft.PowerShell.Commands.WriteErrorException', run(c) { c.error(c.str('Message') ?? '', { category: 'NotSpecified', target: '', exception: 'WriteErrorException', id: 'Microsoft.PowerShell.Commands.WriteErrorException' }); } });

cmdlet({
  name: 'Get-Date', module: UTIL, synopsis: 'Gets the current date and time.',
  params: [{ name: 'Date', type: 'any', position: 0 }, { name: 'Format', type: 'string' }, { name: 'UFormat', type: 'string' }],
  run(c) {
    const now = c.ctx.world.clock + (c.ctx.host.clockOffset ?? 0);
    const ms = c.has('Date') ? Date.parse(toStr(c.p.Date)) : now;
    if (Number.isNaN(ms)) { c.error(`Cannot bind parameter 'Date'. Cannot convert value "${toStr(c.p.Date)}" to type "System.DateTime".`, { category: 'InvalidArgument', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage', target: '' }); return []; }
    if (c.has('Format')) {
      const d = new Date(ms);
      const p = (n: number) => String(n).padStart(2, '0');
      const f = c.str('Format')!;
      if (f === 'o') return [d.toISOString().replace('Z', '0000Z')];
      return [f.replace(/yyyy/g, String(d.getUTCFullYear())).replace(/MM/g, p(d.getUTCMonth() + 1)).replace(/dd/g, p(d.getUTCDate())).replace(/HH/g, p(d.getUTCHours())).replace(/mm/g, p(d.getUTCMinutes())).replace(/ss/g, p(d.getUTCSeconds()))];
    }
    if (c.has('UFormat') && c.str('UFormat') === '%s') return [String(Math.floor(ms / 1000))];
    return [date(ms)];
  },
});

cmdlet({
  name: 'Start-Sleep', module: UTIL, synopsis: 'Suspends the activity in a script or session for the specified period of time.',
  params: [{ name: 'Seconds', aliases: ['s'], type: 'int', position: 0 }, { name: 'Milliseconds', aliases: ['ms'], type: 'int' }],
  run(c) {
    c.ctx.world.clock += Math.min(7_200_000, (toNum(c.p.Seconds) ?? 0) * 1000 + (toNum(c.p.Milliseconds) ?? 0));
  },
});

cmdlet({ name: 'Clear-Host', module: CORE, synopsis: 'Clears the display in the host program.', params: [], run(c) { c.ctx.clear = true; } });

cmdlet({
  name: 'Read-Host', module: UTIL, synopsis: 'Reads a line of input from the console.',
  params: [{ name: 'Prompt', type: 'any', position: 0 }, { name: 'AsSecureString', type: 'switch' }],
  run(c) {
    const a = c.ctx.ask(c.has('Prompt') ? `${toStr(c.p.Prompt)}: ` : '', c.has('AsSecureString'));
    return [c.has('AsSecureString') ? { __t: 'System.Security.SecureString', plain: a } : a];
  },
});

cmdlet({
  name: 'ConvertTo-SecureString', module: 'Microsoft.PowerShell.Security', synopsis: 'Converts plain text or encrypted strings to secure strings.',
  params: [{ name: 'String', type: 'string', position: 0 }, { name: 'AsPlainText', type: 'switch' }, { name: 'Force', type: 'switch' }],
  run(c) {
    if (c.has('AsPlainText') && !c.has('Force')) {
      c.error('The system cannot protect plain text input. To suppress this warning and convert the plain text to a SecureString, reissue the command specifying the Force parameter. For more information ,type: get-help ConvertTo-SecureString.', { category: 'InvalidArgument', target: '', exception: 'ArgumentException', id: 'ImportSecureString_InvalidArgument,Microsoft.PowerShell.Commands.ConvertToSecureStringCommand' });
      return [];
    }
    return [{ __t: 'System.Security.SecureString', plain: c.str('String') ?? toStr(c.input[0]) }];
  },
});

cmdlet({
  name: 'Get-History', module: CORE, synopsis: 'Gets a list of the commands entered during the current session.', params: [{ name: 'Count', type: 'int', position: 0 }],
  run(c) {
    const h = c.ctx.session.history.map((l, i) => obj('Microsoft.PowerShell.Commands.HistoryInfo', { Id: i + 1, CommandLine: l }));
    return c.has('Count') ? h.slice(-(toNum(c.p.Count) ?? 32)) : h.slice(-32);
  },
});

const MODULE_VERSION: Record<string, string> = { [MGMT]: '3.1.0.0', [UTIL]: '3.1.0.0', [CORE]: '3.0.0.0', 'Microsoft.PowerShell.Security': '3.0.0.0', NetSecurity: '2.0.0.0', NetTCPIP: '1.0.0.0', DnsClient: '1.0.0.0', NetAdapter: '2.0.0.0', 'Microsoft.PowerShell.LocalAccounts': '1.0.0.0', NetConnection: '1.0.0.0', ServerManager: '2.0.0.0', ActiveDirectory: '1.0.1.0', DnsServer: '2.0.0.0', ADDSDeployment: '1.0.0.0' };

function commandInfos(ctx: Call['ctx']): PSObject[] {
  const out: PSObject[] = [];
  for (const d of Object.values(CMDLETS)) {
    if (d.available && !d.available(ctx)) continue;
    const cdxml = ['NetSecurity', 'NetTCPIP', 'DnsClient', 'NetAdapter', 'NetConnection', 'DnsServer'].includes(d.module ?? '');
    out.push(obj('System.Management.Automation.CommandInfo', { CommandType: cdxml ? 'Function' : 'Cmdlet', Name: d.name, Version: MODULE_VERSION[d.module ?? ''] ?? '1.0.0.0', Source: d.module ?? '' }));
  }
  for (const [a, t] of Object.entries(ALIASES)) out.push(obj('System.Management.Automation.CommandInfo', { CommandType: 'Alias', Name: `${a} -> ${t}`, Version: '', Source: '', __alias: a }));
  for (const n of Object.values(NATIVES)) out.push(obj('System.Management.Automation.CommandInfo', { CommandType: 'Application', Name: `${n.name}.exe`, Version: '10.0.20348.1', Source: `C:\\Windows\\system32\\${n.name}.exe` }));
  return out;
}

cmdlet({
  name: 'Get-Command', module: CORE, synopsis: 'Gets all commands.',
  params: [{ name: 'Name', type: 'strings', position: 0 }, { name: 'Module', type: 'strings' }, { name: 'Verb', type: 'strings' }, { name: 'Noun', type: 'strings' }, { name: 'CommandType', type: 'strings' }],
  run(c) {
    let all = commandInfos(c.ctx);
    if (!c.has('Name')) all = all.filter((x) => x.CommandType !== 'Alias' && x.CommandType !== 'Application');
    if (c.has('Name')) {
      const res: PSObject[] = [];
      for (const n of c.strs('Name')!) {
        const re = wildcard(n);
        const hit = all.filter((x) => re.test(String(x.__alias ?? x.Name)) || re.test(String(x.Name).replace(/\.exe$/, '')));
        if (!hit.length && !hasWildcard(n)) c.error(`The term '${n}' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.`, { category: 'ObjectNotFound', target: n, exception: 'CommandNotFoundException', id: 'CommandNotFoundException,Microsoft.PowerShell.Commands.GetCommandCommand' });
        res.push(...hit);
      }
      all = res;
    }
    if (c.has('Module')) all = all.filter((x) => c.strs('Module')!.some((m) => wildcard(m).test(String(x.Source))));
    if (c.has('Verb')) all = all.filter((x) => c.strs('Verb')!.some((v) => wildcard(v).test(String(x.Name).split('-')[0])));
    if (c.has('Noun')) all = all.filter((x) => c.strs('Noun')!.some((v) => wildcard(v).test(String(x.Name).split('-').slice(1).join('-'))));
    if (c.has('CommandType')) all = all.filter((x) => c.strs('CommandType')!.some((t) => t.toLowerCase() === String(x.CommandType).toLowerCase()));
    return all.sort((a, b) => String(a.Name).localeCompare(String(b.Name)));
  },
});

cmdlet({
  name: 'Get-Alias', module: UTIL, synopsis: 'Gets the aliases for the current session.',
  params: [{ name: 'Name', type: 'strings', position: 0 }, { name: 'Definition', type: 'strings' }],
  run(c) {
    let list = Object.entries(ALIASES).filter(([, t]) => !t.endsWith('.exe') && t !== 'mkdir');
    if (c.has('Name')) list = list.filter(([a]) => c.strs('Name')!.some((n) => wildcard(n).test(a)));
    if (c.has('Definition')) list = list.filter(([, t]) => c.strs('Definition')!.some((n) => wildcard(n).test(t)));
    if (c.has('Name') && !list.length && !c.strs('Name')!.some(hasWildcard)) c.error(`This command cannot find a matching alias because an alias with the name '${c.str('Name')}' does not exist.`, { category: 'ObjectNotFound', target: c.str('Name'), exception: 'ItemNotFoundException', id: 'ItemNotFoundException,Microsoft.PowerShell.Commands.GetAliasCommand' });
    return list.sort().map(([a, t]) => obj('System.Management.Automation.CommandInfo', { CommandType: 'Alias', Name: `${a} -> ${t}`, Version: '', Source: '' }));
  },
});

cmdlet({
  name: 'Get-Help', module: CORE, synopsis: 'Displays information about PowerShell commands and concepts.',
  params: [{ name: 'Name', type: 'string', position: 0 }, { name: 'Full', type: 'switch' }, { name: 'Examples', type: 'switch' }, { name: 'Detailed', type: 'switch' }, { name: 'Online', type: 'switch' }],
  run(c) {
    const n = c.str('Name');
    if (!n) return ['', 'TOPIC', '    Windows PowerShell Help System', '', 'SHORT DESCRIPTION', '    Displays help about Windows PowerShell cmdlets and concepts.', '', '    Get-Command lists the commands of this simulated server; Get-Help <command>', '    shows the syntax of one of them.', ''].map(text);
    const target = ALIASES[n.toLowerCase()] ?? n;
    const d = CMDLETS[target.toLowerCase()];
    if (!d) {
      c.error(`Get-Help could not find ${n} in a help file in this session. To download updated help topics type: "Update-Help". To get help online, search for the help topic in the TechNet library at https:/go.microsoft.com/fwlink/?LinkID=107116.`, { category: 'ResourceUnavailable', target: '', exception: 'HelpNotFoundException', id: 'HelpNotFound,Microsoft.PowerShell.Commands.GetHelpCommand' });
      return [];
    }
    const syntax = d.syntax ?? `${d.name} ${d.params.filter((p) => p.name !== 'InputObject').map((p) => {
      const t = p.type === 'switch' ? '' : ` <${p.type === 'int' ? 'Int32' : p.type === 'strings' ? 'String[]' : p.type === 'block' ? 'ScriptBlock' : p.type === 'bool' ? 'Boolean' : p.type === 'any' ? 'Object' : 'String'}>`;
      return p.position !== undefined ? `[[-${p.name}]${t}]` : `[-${p.name}${t}]`;
    }).join(' ')} [<CommonParameters>]`;
    return ['', 'NAME', `    ${d.name}`, '', 'SYNOPSIS', `    ${d.synopsis}`, '', '', 'SYNTAX', `    ${syntax}`, '', '', 'ALIASES', `    ${Object.entries(ALIASES).filter(([, t]) => t === d.name).map(([a]) => a).join('\n    ') || 'None'}`, '', '', 'REMARKS',
      '    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.',
      '        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.', ''].map(text);
  },
});

cmdlet({
  name: 'Select-String', module: UTIL, synopsis: 'Finds text in strings and files.',
  params: [{ name: 'Pattern', type: 'strings', position: 0 }, { name: 'Path', type: 'strings', position: 1 }, { name: 'SimpleMatch', type: 'switch' }, { name: 'NotMatch', type: 'switch' }, { name: 'CaseSensitive', type: 'switch' }, { name: 'Context', type: 'any' }, { name: 'InputObject', type: 'any' }],
  run(c) {
    const pats = c.strs('Pattern') ?? [];
    const res = pats.map((p) => (c.has('SimpleMatch') ? new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), c.has('CaseSensitive') ? '' : 'i') : new RegExp(p, c.has('CaseSensitive') ? '' : 'i')));
    const hit = (s: string) => res.some((r) => r.test(s)) !== c.has('NotMatch');
    const out: PSValue[] = [];
    if (c.has('Path')) {
      const files = readLines(c, c.strs('Path')!);
      for (const f of files) f.lines.forEach((l, i) => { if (hit(l)) out.push(obj('Microsoft.PowerShell.Commands.MatchInfo', { LineNumber: i + 1, Line: l, Path: f.path, Filename: f.path.split('\\').pop(), Pattern: pats[0], __str: `${f.path}:${i + 1}:${l}` })); });
      return out;
    }
    const input = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    for (const o of input) {
      for (const l of toStr(o).split('\n')) if (hit(l)) out.push(obj('Microsoft.PowerShell.Commands.MatchInfo', { LineNumber: 1, Line: l, Path: 'InputStream', Filename: 'InputStream', Pattern: pats[0], __str: l }));
    }
    return out;
  },
});

/** Read files for Select-String (implemented in the file system module). */
export let readLines: (c: Call, paths: string[]) => { path: string; lines: string[] }[] = () => [];
export function setReadLines(f: typeof readLines): void {
  readLines = f;
}

cmdlet({
  name: 'exit', module: CORE, synopsis: 'Exits the current session.', params: [{ name: 'Code', type: 'int', position: 0 }],
  run(c) {
    c.host(`exit: this is the ${c.ctx.host.hostname} console; close the terminal tab instead`);
  },
});

