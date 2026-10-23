// A small XML parser and printer for pfSense's config.xml: elements, text,
// empty elements (<any/>), comments and the XML declaration. Attributes are
// accepted and ignored (config.xml does not use them). Errors carry the line
// number, as PHP's XML parser reports them when pfSense reads a broken file.

export interface XmlNode {
  name: string;
  children: XmlNode[];
  text: string;
}

export class XmlError extends Error {
  constructor(message: string, public line: number) {
    super(message);
  }
}

const ENT: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

function unescape(s: string): string {
  return s.replace(/&(lt|gt|amp|quot|apos|#\d+);/g, (_m, e: string) => (e.startsWith('#') ? String.fromCharCode(Number(e.slice(1))) : ENT[e]));
}

export function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function parseXml(src: string): XmlNode {
  let i = 0;
  const line = () => src.slice(0, i).split('\n').length;
  const root: XmlNode = { name: '#document', children: [], text: '' };
  const stack: XmlNode[] = [root];
  while (i < src.length) {
    const lt = src.indexOf('<', i);
    const textEnd = lt < 0 ? src.length : lt;
    if (textEnd > i) {
      const t = src.slice(i, textEnd);
      if (t.trim()) {
        if (stack.length === 1) { i = textEnd; throw new XmlError('Extra content at the end of the document', line()); }
        stack[stack.length - 1].text += unescape(t);
      }
      i = textEnd;
      if (lt < 0) break;
    }
    if (src.startsWith('<?', i)) {
      const e = src.indexOf('?>', i);
      if (e < 0) throw new XmlError('XML declaration not finished', line());
      i = e + 2;
      continue;
    }
    if (src.startsWith('<!--', i)) {
      const e = src.indexOf('-->', i);
      if (e < 0) throw new XmlError('Comment not terminated', line());
      i = e + 3;
      continue;
    }
    if (src.startsWith('<![CDATA[', i)) {
      const e = src.indexOf(']]>', i);
      if (e < 0) throw new XmlError('CData section not finished', line());
      stack[stack.length - 1].text += src.slice(i + 9, e);
      i = e + 3;
      continue;
    }
    const gt = src.indexOf('>', i);
    if (gt < 0) throw new XmlError("Couldn't find end of Start Tag", line());
    const raw = src.slice(i + 1, gt);
    if (raw.startsWith('/')) {
      const name = raw.slice(1).trim();
      const open = stack.pop()!;
      if (open === root || open.name !== name) throw new XmlError(`Opening and ending tag mismatch: ${open === root ? '(none)' : open.name} and ${name}`, line());
      i = gt + 1;
      continue;
    }
    const selfClose = raw.endsWith('/');
    const name = (selfClose ? raw.slice(0, -1) : raw).trim().split(/\s+/)[0];
    if (!/^[A-Za-z_][\w.-]*$/.test(name)) throw new XmlError(`StartTag: invalid element name '${name}'`, line());
    if (stack.length === 1 && root.children.length) throw new XmlError('Extra content at the end of the document', line());
    const node: XmlNode = { name, children: [], text: '' };
    stack[stack.length - 1].children.push(node);
    if (!selfClose) stack.push(node);
    i = gt + 1;
  }
  if (stack.length > 1) throw new XmlError(`Premature end of data in tag ${stack[stack.length - 1].name}`, line());
  if (!root.children.length) throw new XmlError('Document is empty', 1);
  return root.children[0];
}

export function child(n: XmlNode | undefined, name: string): XmlNode | undefined {
  return n?.children.find((c) => c.name === name);
}

export function children(n: XmlNode | undefined, name: string): XmlNode[] {
  return n?.children.filter((c) => c.name === name) ?? [];
}

export function textOf(n: XmlNode | undefined, name: string): string | undefined {
  const c = child(n, name);
  return c ? c.text.trim() : undefined;
}

export function el(name: string, content?: string | XmlNode[]): XmlNode {
  return Array.isArray(content) ? { name, children: content, text: '' } : { name, children: [], text: content ?? '' };
}

/** Print with tab indentation, as pfSense writes config.xml. */
export function printXml(n: XmlNode, depth = 0): string {
  const pad = '\t'.repeat(depth);
  if (!n.children.length) return n.text === '' ? `${pad}<${n.name}></${n.name}>` : `${pad}<${n.name}>${escapeXml(n.text)}</${n.name}>`;
  return [`${pad}<${n.name}>`, ...n.children.map((c) => printXml(c, depth + 1)), `${pad}</${n.name}>`].join('\n');
}
