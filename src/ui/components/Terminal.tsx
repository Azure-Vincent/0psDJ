import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import type { Shell } from '../../engine/shell/shell';
import type { EditorRequest } from '../../engine/shell/types';
import { Editor } from './Editor';

interface Line {
  kind: 'cmd' | 'out' | 'err' | 'note';
  prompt?: string;
  text: string;
}

interface Pending {
  line: string;
  prompt: string;
  answers: string[];
  question: { text: string; secret: boolean };
  /** Index in `lines` where this command's output begins (replaced on each replay). */
  start: number;
}

export function Terminal({ shell, banner, onExecuted, autoFocus }: { shell: Shell; banner?: string; onExecuted?: () => void; autoFocus?: boolean }) {
  const [lines, setLines] = useState<Line[]>(() => (banner ? [{ kind: 'note', text: banner }] : []));
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState<number | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [editor, setEditor] = useState<EditorRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
  }, [lines, pending]);

  useEffect(() => {
    if (autoFocus) inputRef.current?.focus();
  }, [autoFocus]);

  const run = (line: string, answers: string[], prompt: string, start: number) => {
    setBusy(true);
    // Let React paint "busy" before long simulations (e.g. 2-minute TCP timeouts run instantly but sync).
    setTimeout(() => {
      const r = shell.execute(line, answers);
      setBusy(false);
      if (inputRef.current?.offsetParent) inputRef.current.focus();
      if (r.needInput) {
        setLines((ls) => {
          const head = ls.slice(0, start);
          const partial = r.needInput!.partial ? r.needInput!.partial.split('\n').map((t) => ({ kind: 'out' as const, text: t })) : [];
          return [...head, ...partial];
        });
        setPending({ line, prompt, answers, question: { text: r.needInput.text, secret: r.needInput.secret }, start });
        return;
      }
      setPending(null);
      if (r.clear) {
        setLines([]);
      } else {
        setLines((ls) => {
          const head = ls.slice(0, start);
          return r.output ? [...head, ...r.output.split('\n').map((t) => ({ kind: (r.code !== 0 && r.code !== -1 ? 'err' : 'out') as Line['kind'], text: t }))] : head;
        });
      }
      if (r.editor) setEditor(r.editor);
      onExecuted?.();
    }, 0);
  };

  const submit = () => {
    if (busy) return;
    if (pending) {
      const answer = input;
      setInput('');
      setLines((ls) => [...ls, { kind: 'out', text: pending.question.text + (pending.question.secret ? '' : answer) }]);
      const answers = [...pending.answers, answer];
      setPending(null);
      // Replay from the command's start; the replay regenerates all output including prompts.
      run(pending.line, answers, pending.prompt, pending.start);
      return;
    }
    const line = input;
    setInput('');
    setHistIdx(null);
    const prompt = shell.prompt();
    if (!line.trim()) {
      setLines((ls) => [...ls, { kind: 'cmd', prompt, text: '' }]);
      return;
    }
    setHistory((h) => [...h.filter((x) => x !== line), line].slice(-100));
    const next = [...lines, { kind: 'cmd' as const, prompt, text: line }];
    setLines(next);
    run(line, [], prompt, next.length);
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      submit();
    } else if (e.key === 'ArrowUp' && !pending) {
      e.preventDefault();
      const idx = histIdx === null ? history.length - 1 : Math.max(0, histIdx - 1);
      if (history[idx] !== undefined) { setHistIdx(idx); setInput(history[idx]); }
    } else if (e.key === 'ArrowDown' && !pending) {
      e.preventDefault();
      if (histIdx === null) return;
      const idx = histIdx + 1;
      if (idx >= history.length) { setHistIdx(null); setInput(''); } else { setHistIdx(idx); setInput(history[idx]); }
    } else if ((e.key === 'c' && e.ctrlKey) && pending) {
      e.preventDefault();
      setLines((ls) => [...ls, { kind: 'out', text: pending.question.text + '^C' }]);
      setPending(null);
      setInput('');
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setLines([]);
    }
  };

  const promptText = pending ? pending.question.text : shell.prompt();
  const isRoot = !pending && promptText.trimEnd().endsWith('#');

  return (
    <>
      <div className="terminal" ref={boxRef} onClick={() => window.getSelection()?.toString() || inputRef.current?.focus()} role="log" aria-live="polite">
        {lines.map((l, i) =>
          l.kind === 'cmd' ? (
            <div key={i}>
              <span className={l.prompt?.trimEnd().endsWith('#') ? 'root-prompt' : 'prompt'}>{l.prompt}</span>
              <span className="cmd">{l.text}</span>
            </div>
          ) : (
            <div key={i} className={l.kind === 'err' ? 'err' : l.kind === 'note' ? 'note' : undefined}>{l.text || ' '}</div>
          ),
        )}
        <div>
          <span className={pending ? undefined : isRoot ? 'root-prompt' : 'prompt'}>{busy ? '' : promptText}</span>
          {busy && <span className="note">running…</span>}
          <input
            ref={inputRef}
            type={pending?.question.secret ? 'password' : 'text'}
            value={input}
            readOnly={busy}
            style={busy ? { width: 0 } : undefined}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKey}
            spellCheck={false}
            autoComplete="off"
            aria-label="terminal input"
          />
        </div>
      </div>
      {editor && (
        <Editor
          request={editor}
          onClose={() => setEditor(null)}
          onSave={(content) => {
            const err = shell.saveFile(editor, content);
            if (err) return `[ Error writing ${editor.path}: ${err} ]`;
            setLines((ls) => [...ls, { kind: 'note', text: `[ Wrote ${content.split('\n').length} lines to ${editor.path} ]` }]);
            setEditor(null);
            onExecuted?.();
            return null;
          }}
        />
      )}
    </>
  );
}
