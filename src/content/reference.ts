// Reference library: commands, files/logs and recovery procedures, with facets
// (OS, service, protocol, symptom, kind) and stable ids that lessons, guides
// and case studies deep-link to ("reference?id=<id>").

import { COMMAND_REFS } from './commands';
import { FILE_REFS } from './reference/files';
import { PROCEDURES } from './reference/procedures';
import type { CommandRef, FileRef, Procedure } from './types';

export { FILE_REFS, PROCEDURES };

export type RefEntry =
  | { kind: 'command'; id: string; title: string; os: string; services: string[]; protocols: string[]; symptoms: string[]; text: string; item: CommandRef }
  | { kind: 'file'; id: string; title: string; os: string; services: string[]; protocols: string[]; symptoms: string[]; text: string; item: FileRef }
  | { kind: 'procedure'; id: string; title: string; os: string; services: string[]; protocols: string[]; symptoms: string[]; text: string; item: Procedure };

/** Platform strings are free text ("Ubuntu/Debian", "Windows Server 2022"); facet them by OS family. */
export function osFamily(platform: string): string {
  const p = platform.toLowerCase();
  if (p.includes('pfsense') || p.includes('opnsense') || p.includes('freebsd')) return 'pfSense';
  if (p.includes('docker')) return 'Docker';
  if (p.includes('windows')) return 'Windows';
  if (p.includes('cisco') || p.includes('ios')) return 'Cisco IOS';
  return 'Linux';
}

export const REF_ENTRIES: RefEntry[] = [
  ...COMMAND_REFS.map((c): RefEntry => ({
    kind: 'command', id: c.id, title: c.name, os: osFamily(c.platform), services: c.services ?? [], protocols: c.protocols ?? [], symptoms: c.symptoms ?? [],
    text: `${c.name} ${c.category} ${c.purpose} ${c.syntax} ${c.interpretation} ${c.limitations} ${(c.errors ?? []).map((e) => e.message).join(' ')}`, item: c,
  })),
  ...FILE_REFS.map((f): RefEntry => ({
    kind: 'file', id: f.id, title: f.path, os: osFamily(f.platform), services: f.services, protocols: [], symptoms: [],
    text: `${f.path} ${f.platform} ${f.purpose} ${f.contents} ${f.problems}`, item: f,
  })),
  ...PROCEDURES.map((p): RefEntry => ({
    kind: 'procedure', id: p.id, title: p.title, os: osFamily(p.platform), services: p.services, protocols: [], symptoms: p.symptoms,
    text: `${p.title} ${p.platform} ${p.purpose} ${p.steps.map((s) => `${s.title} ${s.command ?? ''}`).join(' ')} ${p.symptoms.join(' ')}`, item: p,
  })),
];

const BY_ID = new Map(REF_ENTRIES.map((e) => [e.id, e]));

export function getRef(id: string): RefEntry | undefined {
  return BY_ID.get(id);
}

export function refTitle(id: string): string {
  const e = BY_ID.get(id);
  if (!e) return id;
  return e.kind === 'command' ? `${e.title} (${e.item.platform})` : e.title;
}

export function refLink(id: string): string {
  return `reference?id=${encodeURIComponent(id)}`;
}
