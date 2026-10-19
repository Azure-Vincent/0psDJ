import { useEffect, useState } from 'react';
import { ProgressProvider, go, useProgress, useRoute } from './state';
import { Dashboard } from './pages/Dashboard';
import { Curriculum } from './pages/Curriculum';
import { LessonPage } from './pages/LessonPage';
import { TroubleshootList, TroubleshootWorkspace } from './pages/Troubleshoot';
import { Commands } from './pages/Commands';
import { PacketLab } from './pages/PacketLab';
import { Glossary } from './pages/Glossary';
import { History } from './pages/History';
import { Settings } from './pages/Settings';
import { Search } from './pages/Search';
import { LESSONS } from '../content/lessons';

const NAV: [string, string, string?][] = [
  ['dashboard', 'Dashboard'],
  ['curriculum', 'Curriculum'],
  ['#Lessons', ''],
  ...LESSONS.map((l): [string, string, string] => [`lesson/${l.id}/what`, l.title.split(':')[0], `lesson/${l.id}`]),
  ['#Practice', ''],
  ['troubleshoot', 'Troubleshooting lab', 'troubleshoot'],
  ['commands', 'Diagnostic commands'],
  ['packets', 'Packet Lab'],
  ['#Reference', ''],
  ['glossary', 'Glossary'],
  ['history', 'History'],
  ['settings', 'Settings'],
];

function Shell() {
  const route = useRoute();
  const { progress } = useProgress();
  const [q, setQ] = useState('');

  useEffect(() => {
    const t = progress.settings.theme;
    if (t === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
  }, [progress.settings.theme]);

  useEffect(() => {
    document.querySelector('.main')?.scrollTo({ top: 0 });
  }, [route.join('/')]);

  const [head, a, b] = route;
  let page;
  switch (head) {
    case 'curriculum': page = <Curriculum />; break;
    case 'lesson': page = <LessonPage key={a} lessonId={a ?? 'ssh'} section={b ?? 'what'} />; break;
    case 'troubleshoot': page = a ? <TroubleshootWorkspace key={a} id={a} /> : <TroubleshootList />; break;
    case 'commands': page = <Commands />; break;
    case 'packets': page = <PacketLab />; break;
    case 'glossary': page = <Glossary />; break;
    case 'history': page = <History id={a} />; break;
    case 'settings': page = <Settings />; break;
    case 'search': page = <Search key={window.location.hash} />; break;
    default: page = <Dashboard />;
  }
  const isActive = (path: string, prefix?: string) => (prefix ? route.join('/').startsWith(prefix) : route.join('/') === path || head === path);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand"><span aria-hidden>⧉</span> Infrastructure Lab</div>
        <form className="search" onSubmit={(e) => { e.preventDefault(); if (q.trim()) go(`search?q=${encodeURIComponent(q.trim())}`); }}>
          <input placeholder="Search lessons, commands…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search" />
        </form>
        <nav className="nav">
          {NAV.map(([path, label, prefix]) =>
            path.startsWith('#') ? <div key={path} className="group">{path.slice(1)}</div> : (
              <a key={path} href={`#/${path}`} className={isActive(path, prefix) ? 'active' : ''}>{label}</a>
            ),
          )}
        </nav>
        <div className="sidebar-foot">Offline · progress saved locally</div>
      </aside>
      <main className="main">{page}</main>
    </div>
  );
}

export function App() {
  return (
    <ProgressProvider>
      <Shell />
    </ProgressProvider>
  );
}
