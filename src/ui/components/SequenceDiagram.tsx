import { useEffect, useMemo, useState } from 'react';
import type { TraceEvent } from '../../engine/sim/trace';
import { PacketLayers } from './PacketLayers';

export interface Lane {
  id: string;
  label: string;
  sub: string;
}

const ROW = 34;
const TOP = 56;
const LANE_W = 158;
const LEFT = 30;

const PHASE_COLORS: Record<string, string> = {
  DNS: '#8250df', ARP: '#bf8700', TCP: '#1f6feb', 'SSH transport': '#0969da', 'SSH key exchange': '#0a7ea4',
  'SSH authentication': '#1a7f37', 'SSH session': '#1a7f37', ICMP: '#cf222e', Teardown: '#6e7781',
};

function short(s: string, n = 46): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

export function SequenceDiagram({ events, lanes, segmentOf }: { events: TraceEvent[]; lanes: Lane[]; segmentOf?: (host: string, iface?: string) => string }) {
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(900);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    setStep(0);
    setSelected(null);
    setPlaying(false);
  }, [events]);

  useEffect(() => {
    if (!playing) return;
    if (step >= events.length) {
      setPlaying(false);
      return;
    }
    const t = setTimeout(() => setStep((s) => Math.min(events.length, s + 1)), speed);
    return () => clearTimeout(t);
  }, [playing, step, events.length, speed]);

  const laneX = useMemo(() => Object.fromEntries(lanes.map((l, i) => [l.id, LEFT + i * LANE_W + LANE_W / 2])), [lanes]);
  const width = LEFT * 2 + lanes.length * LANE_W;
  const height = TOP + Math.max(events.length, 1) * ROW + 30;
  const current = selected ?? (step > 0 ? step - 1 : null);
  const ev = current !== null ? events[current] : null;

  const t0 = events[0]?.time ?? 0;

  return (
    <div>
      <div className="row" style={{ marginBottom: 8 }}>
        <button onClick={() => { setStep(0); setSelected(null); setPlaying(false); }} aria-label="Reset">⏮ Reset</button>
        <button onClick={() => { setPlaying(false); setSelected(null); setStep((s) => Math.max(0, s - 1)); }} disabled={step === 0}>◀ Back</button>
        <button onClick={() => { setPlaying(false); setSelected(null); setStep((s) => Math.min(events.length, s + 1)); }} disabled={step >= events.length}>Step ▶</button>
        <button className="primary" onClick={() => { setSelected(null); if (step >= events.length) setStep(0); setPlaying((p) => !p); }}>{playing ? '❚❚ Pause' : '▶ Play'}</button>
        <label className="small muted">Speed{' '}
          <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
            <option value={1600}>slow</option>
            <option value={900}>normal</option>
            <option value={350}>fast</option>
          </select>
        </label>
        <button onClick={() => { setPlaying(false); setStep(events.length); }}>Show all</button>
        <span className="muted small">Step {step} / {events.length}</span>
      </div>
      <div className="seq-wrap">
        <div className="seq-svg">
          <svg width={width} height={height} role="img" aria-label="Protocol sequence diagram">
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
              </marker>
            </defs>
            {lanes.map((l) => (
              <g key={l.id}>
                <text x={laneX[l.id]} y={20} textAnchor="middle" fontWeight={700} fontSize={13}>{l.label}</text>
                <text x={laneX[l.id]} y={36} textAnchor="middle" fontSize={11} style={{ fill: 'var(--muted)' }}>{l.sub}</text>
                <line className="lane" x1={laneX[l.id]} x2={laneX[l.id]} y1={44} y2={height - 10} />
              </g>
            ))}
            {events.slice(0, step).map((e, i) => {
              const y = TOP + i * ROW + ROW / 2;
              const color = e.delivered === false ? 'var(--err)' : e.packet?.app?.encrypted ? 'var(--ok)' : PHASE_COLORS[e.phase] ?? 'var(--muted)';
              const isSel = current === i;
              const x1 = laneX[e.from] ?? LEFT;
              const x2 = laneX[e.to] ?? LEFT;
              const label = short(e.title, Math.max(24, Math.abs(x2 - x1) / 6.2));
              return (
                <g key={e.id} className={`msg${isSel ? ' sel' : ''}`} onClick={() => { setSelected(i); setPlaying(false); }} style={{ color }}>
                  <rect className="hit" x={0} y={y - ROW / 2} width={width} height={ROW} fill="transparent" />
                  <text x={4} y={y + 4} fontSize={10} style={{ fill: 'var(--muted)' }}>{i + 1}</text>
                  {e.kind === 'internal' ? (
                    <>
                      <rect x={x1 - 80} y={y - 11} width={160} height={22} rx={4} fill="var(--panel-2)" stroke={color} />
                      <text x={x1} y={y + 4} textAnchor="middle" fontSize={10.5}>{short(e.title, 30)}</text>
                    </>
                  ) : x1 === x2 ? (
                    <>
                      <path d={`M ${x1} ${y - 8} h 28 v 16 h -26`} fill="none" stroke={color} markerEnd="url(#arrow)" />
                      <text className="lbl" x={x1 + 34} y={y + 4}>{short(e.title, 34)}</text>
                    </>
                  ) : (
                    <>
                      <line x1={x1} x2={x2} y1={y} y2={y} stroke={color} strokeWidth={isSel ? 2.5 : 1.6} strokeDasharray={e.kind === 'arp' ? '5 3' : undefined} markerEnd={e.delivered === false ? undefined : 'url(#arrow)'} />
                      {e.via.map((v) => laneX[v] !== undefined && <circle key={v} cx={laneX[v]} cy={y} r={3.5} fill={color} />)}
                      {e.delivered === false && <text x={x2 - 6} y={y + 5} fill="var(--err)" fontWeight={700} fontSize={15}>✕</text>}
                      <text className="lbl" x={(x1 + x2) / 2} y={y - 5} textAnchor="middle" style={{ fill: color }}>{label}</text>
                    </>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
        <div className="inspector">
          {!ev ? (
            <div className="muted">Press <strong>Step ▶</strong> or <strong>Play</strong>. Click any message to inspect it. Arrows: green = encrypted SSH packets, red ✕ = not delivered, dashed = ARP, dots = routers that forwarded the packet.</div>
          ) : (
            <>
              <div className="spread">
                <span className="badge accent" style={{ background: 'transparent', color: PHASE_COLORS[ev.phase], borderColor: PHASE_COLORS[ev.phase] }}>{ev.phase}</span>
                <span className="muted small mono">t = +{((ev.time - t0) / 1000).toFixed(3)} s</span>
              </div>
              <h3 style={{ marginTop: 8 }}>{ev.title}</h3>
              {ev.kind !== 'internal' && (
                <div className="small muted">
                  {ev.from} → {ev.to}{ev.via.length ? ` (via ${ev.via.join(', ')})` : ''}{ev.outcome ? ` · ${ev.outcome}` : ''}
                </div>
              )}
              {ev.kind === 'internal' && <div className="small muted">Inside {ev.from}: no packet on the wire</div>}
              {ev.detail && ev.detail.split('\n').map((p, i) => <p key={i}>{p}</p>)}
              {(ev.packet || ev.arp) && (
                <PacketLayers
                  packet={ev.packet}
                  arp={ev.arp}
                  l2={ev.hops?.filter((h) => h.srcMac && h.dstMac).map((h) => ({ src: h.srcMac!, dst: h.dstMac!, note: `${h.host} ${h.egress} → ${segmentOf ? segmentOf(h.host, h.egress) : ''}` }))}
                />
              )}
              {ev.hops && ev.hops.length > 0 && (
                <details className="layer">
                  <summary>Path taken (per-hop decisions)</summary>
                  <table><tbody>{ev.hops.map((h, i) => <tr key={i}><td className="mono">{h.host}</td><td>{h.note}</td></tr>)}</tbody></table>
                </details>
              )}
              <h3>Connection and session state after this step</h3>
              <table>
                <thead><tr><th>Host</th><th>TCP</th><th>SSH</th><th>Crypto</th></tr></thead>
                <tbody>
                  {Object.entries(ev.state).filter(([h]) => lanes.some((l) => l.id === h)).map(([h, s]) => (
                    <tr key={h}><td>{h}</td><td className="mono">{s.tcp ?? '—'}</td><td>{s.ssh ?? '—'}</td><td>{s.crypto ?? '—'}</td></tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
