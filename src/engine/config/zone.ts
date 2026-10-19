// Minimal BIND master-file parser (RFC 1035 §5): $ORIGIN, $TTL, SOA, NS, A, CNAME,
// PTR, MX. Supports "@", relative and absolute names, and multi-line SOA records.

export interface ZoneRecord {
  name: string; // absolute, lower-case, with trailing dot
  ttl: number;
  type: 'SOA' | 'NS' | 'A' | 'CNAME' | 'PTR' | 'MX' | 'TXT';
  data: string;
}

export interface Zone {
  origin: string;
  records: ZoneRecord[];
  serial: number;
}

export class ZoneError extends Error {}

function absolute(name: string, origin: string): string {
  if (name === '@') return origin;
  if (name.endsWith('.')) return name.toLowerCase();
  return `${name}.${origin}`.toLowerCase();
}

export function parseZone(text: string, origin: string, file: string): Zone {
  let curOrigin = origin.endsWith('.') ? origin : origin + '.';
  let ttl = 3600;
  let lastName = curOrigin;
  const records: ZoneRecord[] = [];
  let serial = 0;
  // Join parenthesised multi-line records; remember whether the record's first
  // line started with whitespace (meaning "same owner name as previous record").
  const joined: { text: string; line: number; blankOwner: boolean }[] = [];
  let buf = '';
  let startLine = 0;
  let blankOwner = false;
  let depth = 0;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/;.*$/, '');
    if (depth === 0) {
      startLine = i + 1;
      blankOwner = /^\s/.test(line);
    }
    for (const ch of line) {
      if (ch === '(') depth++;
      if (ch === ')') depth--;
    }
    buf += ' ' + line.replace(/[()]/g, ' ');
    if (depth === 0) {
      if (buf.trim()) joined.push({ text: buf.trim(), line: startLine, blankOwner });
      buf = '';
    }
  });
  if (depth !== 0) throw new ZoneError(`${file}:${startLine}: unbalanced parentheses`);

  for (const { text: l, line, blankOwner: startsBlank } of joined) {
    const toks = l.split(/\s+/);
    if (toks[0] === '$ORIGIN') { curOrigin = absolute(toks[1], curOrigin); continue; }
    if (toks[0] === '$TTL') { ttl = parseInt(toks[1], 10); continue; }
    let i = 0;
    let name = lastName;
    if (!startsBlank) { name = absolute(toks[0], curOrigin); i = 1; }
    let rttl = ttl;
    if (/^\d+$/.test(toks[i] ?? '')) rttl = Number(toks[i++]);
    if (toks[i] === 'IN') i++;
    const type = (toks[i++] ?? '').toUpperCase();
    const rdata = toks.slice(i);
    lastName = name;
    switch (type) {
      case 'SOA':
        if (rdata.length < 7) throw new ZoneError(`${file}:${line}: SOA record incomplete`);
        serial = Number(rdata[2]);
        records.push({ name, ttl: rttl, type: 'SOA', data: rdata.join(' ') });
        break;
      case 'A':
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(rdata[0] ?? '')) throw new ZoneError(`${file}:${line}: bad dotted quad`);
        records.push({ name, ttl: rttl, type: 'A', data: rdata[0] });
        break;
      case 'NS':
      case 'CNAME':
      case 'PTR':
        if (!rdata[0]) throw new ZoneError(`${file}:${line}: unexpected end of input`);
        records.push({ name, ttl: rttl, type, data: absolute(rdata[0], curOrigin) });
        break;
      case 'MX':
        records.push({ name, ttl: rttl, type: 'MX', data: `${rdata[0]} ${absolute(rdata[1], curOrigin)}` });
        break;
      case 'TXT':
        records.push({ name, ttl: rttl, type: 'TXT', data: rdata.join(' ') });
        break;
      default:
        throw new ZoneError(`${file}:${line}: unknown RR type '${type}'`);
    }
  }
  if (!records.some((r) => r.type === 'SOA')) throw new ZoneError(`${file}: no SOA record`);
  return { origin: curOrigin, records, serial };
}

export type DnsAnswer =
  | { rcode: 'NOERROR'; answers: ZoneRecord[]; authoritative: boolean }
  | { rcode: 'NXDOMAIN'; answers: []; authoritative: boolean; soa?: ZoneRecord }
  | { rcode: 'REFUSED' | 'SERVFAIL'; answers: []; authoritative: false };

/** Answer an A query from a set of authoritative zones (follows in-zone CNAMEs). */
export function answerQuery(zones: Zone[], qname: string, qtype: 'A' | 'PTR' = 'A'): DnsAnswer {
  const name = qname.toLowerCase().endsWith('.') ? qname.toLowerCase() : qname.toLowerCase() + '.';
  const zone = zones
    .filter((z) => name === z.origin || name.endsWith('.' + z.origin))
    .sort((a, b) => b.origin.length - a.origin.length)[0];
  if (!zone) return { rcode: 'REFUSED', answers: [], authoritative: false };
  const answers: ZoneRecord[] = [];
  let cur = name;
  for (let hops = 0; hops < 8; hops++) {
    const direct = zone.records.filter((r) => r.name === cur && r.type === qtype);
    if (direct.length) { answers.push(...direct); break; }
    const cname = zone.records.find((r) => r.name === cur && r.type === 'CNAME');
    if (cname) { answers.push(cname); cur = cname.data; continue; }
    break;
  }
  if (answers.length) return { rcode: 'NOERROR', answers, authoritative: true };
  const exists = zone.records.some((r) => r.name === name);
  if (exists) return { rcode: 'NOERROR', answers: [], authoritative: true };
  return { rcode: 'NXDOMAIN', answers: [], authoritative: true, soa: zone.records.find((r) => r.type === 'SOA') };
}
