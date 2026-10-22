import { describe, expect, it } from 'vitest';
import { writeFile } from '../src/engine/fs';
import { Lab } from './helpers';

// Expected outputs were produced with GNU sed 4.9 on the same input.
function lab() {
  const l = new Lab();
  writeFile(l.world.hosts.ws01, '/root/f', 'a\nb\nc\nd\ne\n', 0);
  writeFile(l.world.hosts.ws01, '/root/g', 'x\na/b,c\ny\n', 0);
  return (cmd: string) => l.run('ws01', 'root', cmd).output;
}

describe('sed (GNU subset)', () => {
  it('ranges follow GNU semantics when an earlier d skipped a line', () => {
    const sed = lab();
    expect(sed("sed '3d;/b/,3s/^/-/' f")).toBe('a\n-b\nd\ne');
    expect(sed("sed '2,3d;3,4d' f")).toBe('a\ne');
    expect(sed("sed '1d;1,2s/^/-/' f")).toBe('-b\nc\nd\ne');
    expect(sed("sed '/b/,1d' f")).toBe('a\nc\nd\ne');
    expect(sed("sed '/c/,$d' f")).toBe('a\nb');
    expect(sed("sed '/b/,+1d' f")).toBe('a\nd\ne');
    expect(sed("sed '2,4!d' f")).toBe('b\nc\nd');
  });

  it('parses escaped slashes, spaces before commands and s flags', () => {
    const sed = lab();
    expect(sed("sed '/a\\/b,c/d' g")).toBe('x\ny');
    expect(sed("sed '/b/ s/b/X;Y/' f")).toBe('a\nX;Y\nc\nd\ne');
    expect(sed("sed 's/./X/2g' g")).toBe('x\naXXXX\ny');
    expect(sed("sed 's/B/z/I' f")).toBe('a\nz\nc\nd\ne');
    expect(sed("sed 's/a/$1/' f")).toBe('$1\nb\nc\nd\ne');
    expect(sed("sed '/*/d' f")).toBe('a\nb\nc\nd\ne');
    expect(sed("sed -n '2,3p' f")).toBe('b\nc');
  });

  it('treats several files as one stream (without -i)', () => {
    const sed = lab();
    expect(sed('sed 1d f f')).toBe('b\nc\nd\ne\na\nb\nc\nd\ne');
    expect(sed("sed '$d' f f")).toBe('a\nb\nc\nd\ne\na\nb\nc\nd');
  });

  it('reports script errors like GNU sed, even for commands that never run', () => {
    const sed = lab();
    expect(sed("sed '/zzz/s/a/b' f")).toBe("sed: -e expression #1, char 10: unterminated `s' command");
    expect(sed("sed '2dx' f")).toBe('sed: -e expression #1, char 3: extra characters after command');
    expect(sed("sed '5' f")).toBe('sed: -e expression #1, char 1: missing command');
    expect(sed("sed 's/a/b/q' f")).toBe("sed: -e expression #1, char 7: unknown option to `s'");
    expect(sed("sed '1,d' f")).toBe("sed: -e expression #1, char 3: unexpected `,'");
  });
});
