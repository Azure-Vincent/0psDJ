import { useState } from 'react';
import type { EditorRequest } from '../../engine/shell/types';

export function Editor({ request, onSave, onClose }: { request: EditorRequest; onSave: (content: string) => string | null; onClose: () => void }) {
  const [text, setText] = useState(request.content);
  const [error, setError] = useState<string | null>(null);
  const dirty = text !== request.content;
  return (
    <div className="modal-bg" role="dialog" aria-modal="true" aria-label={`Editing ${request.path}`}>
      <div className="modal">
        <div className="spread">
          <strong className="mono">{request.hostId}:{request.path}{request.isNew ? ' (new file)' : ''}{request.readOnly ? ' [read-only]' : ''}</strong>
          <span className="muted small">In-app editor standing in for nano/vi. Saving writes the file in the simulated host with your user's permissions.</span>
        </div>
        <textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} readOnly={request.readOnly} autoFocus
          onKeyDown={(e) => {
            if (e.key === 'Tab') {
              e.preventDefault();
              const t = e.currentTarget;
              const s = t.selectionStart;
              setText(text.slice(0, s) + '\t' + text.slice(t.selectionEnd));
              requestAnimationFrame(() => { t.selectionStart = t.selectionEnd = s + 1; });
            }
          }} />
        {error && <div className="feedback bad">{error}</div>}
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <button onClick={() => { if (!dirty || confirm('Discard unsaved changes?')) onClose(); }}>Close</button>
          <button className="primary" disabled={request.readOnly || !dirty} onClick={() => setError(onSave(text.endsWith('\n') || text === '' ? text : text + '\n'))}>Save</button>
        </div>
      </div>
    </div>
  );
}
