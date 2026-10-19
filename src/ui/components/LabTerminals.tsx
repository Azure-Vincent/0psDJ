import { useMemo, useState } from 'react';
import { Shell, type CommandLogEntry } from '../../engine/shell/shell';
import type { World } from '../../engine/types';
import { Terminal } from './Terminal';

export interface TermSpec {
  hostId: string;
  user: string;
  label: string;
  banner?: string;
}

/**
 * A set of terminals sharing one simulated world. The world is owned by the
 * caller (via get/set) so other panels (verification, history) see the same state.
 */
export function LabTerminals({ specs, getWorld, setWorld, onCommand, height = 460 }: {
  specs: TermSpec[];
  getWorld: () => World;
  setWorld: (w: World) => void;
  onCommand?: (e: CommandLogEntry) => void;
  height?: number | string;
}) {
  const [active, setActive] = useState(0);
  const shells = useMemo(
    () => specs.map((s) => {
      const w = getWorld();
      const home = w.hosts[s.hostId].users[s.user].home;
      return new Shell(getWorld, setWorld, { hostId: s.hostId, user: s.user, cwd: w.hosts[s.hostId].fs[home] ? home : '/' }, onCommand);
    }),
    // Shells are created once per mounted lab; the parent remounts (key) to reset.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height, minHeight: 0 }}>
      <div className="term-tabs" role="tablist">
        {specs.map((s, i) => (
          <button key={i} role="tab" aria-selected={active === i} className={active === i ? 'active' : ''} onClick={() => setActive(i)}>
            {s.label}
          </button>
        ))}
      </div>
      {specs.map((s, i) => (
        <div key={i} style={{ display: active === i ? 'flex' : 'none', flex: 1, minHeight: 0, flexDirection: 'column' }}>
          <Terminal shell={shells[i]} banner={s.banner} autoFocus={active === i} />
        </div>
      ))}
    </div>
  );
}
