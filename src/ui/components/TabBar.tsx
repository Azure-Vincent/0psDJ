import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';

export interface TabItem {
  id: string;
  label: ReactNode;
  /** Tooltip, e.g. the full name when the label is shortened. */
  title?: string;
}

/**
 * One row of tabs that never wraps: when it is wider than the page it scrolls
 * sideways (wheel, touch, arrow keys), fades the edge that hides more tabs and
 * keeps the active tab in view. Keyboard: Left/Right/Home/End (WAI-ARIA tabs).
 */
export function TabBar({ items, active, onSelect, label }: { items: TabItem[]; active: string; onSelect: (id: string) => void; label: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  const measure = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const left = el.scrollLeft > 1;
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setEdges((e) => (e.left === left && e.right === right ? e : { left, right }));
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    // A vertical wheel scrolls the row sideways, but only while it has somewhere to go.
    const wheel = (e: WheelEvent) => {
      if (Math.abs(e.deltaY) <= Math.abs(e.deltaX) || el.scrollWidth <= el.clientWidth) return;
      const max = el.scrollWidth - el.clientWidth;
      if ((e.deltaY < 0 && el.scrollLeft <= 0) || (e.deltaY > 0 && el.scrollLeft >= max)) return;
      e.preventDefault();
      el.scrollLeft += e.deltaY;
    };
    el.addEventListener('wheel', wheel, { passive: false });
    return () => { ro.disconnect(); el.removeEventListener('wheel', wheel); };
  }, [measure, items.length]);

  // Bring the active tab into view horizontally (never scrolls the page).
  useEffect(() => {
    const el = ref.current;
    const btn = el?.querySelector<HTMLElement>('[aria-selected="true"]');
    if (!el || !btn) return;
    const pad = 24;
    if (btn.offsetLeft < el.scrollLeft + pad) el.scrollLeft = btn.offsetLeft - pad;
    else if (btn.offsetLeft + btn.offsetWidth > el.scrollLeft + el.clientWidth - pad) el.scrollLeft = btn.offsetLeft + btn.offsetWidth - el.clientWidth + pad;
    measure();
  }, [active, measure]);

  const onKey = (e: KeyboardEvent) => {
    const i = items.findIndex((t) => t.id === active);
    const n = e.key === 'ArrowRight' ? (i + 1) % items.length
      : e.key === 'ArrowLeft' ? (i - 1 + items.length) % items.length
        : e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : -1;
    if (n < 0) return;
    e.preventDefault();
    onSelect(items[n].id);
    ref.current?.querySelectorAll<HTMLElement>('[role="tab"]')[n]?.focus();
  };

  return (
    <div ref={ref} className={`tabs${edges.left ? ' fade-l' : ''}${edges.right ? ' fade-r' : ''}`} role="tablist" aria-label={label} onScroll={measure} onKeyDown={onKey}>
      {items.map((t) => (
        <button key={t.id} type="button" role="tab" aria-selected={t.id === active} tabIndex={t.id === active ? 0 : -1} title={t.title} className={t.id === active ? 'active' : ''} onClick={() => onSelect(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}
