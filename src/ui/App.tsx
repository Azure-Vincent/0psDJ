import { useEffect, useState } from 'react';
import { ProgressProvider, go, useProgress, useRoute } from './state';
import { Dashboard } from './pages/Dashboard';
import { Curriculum } from './pages/Curriculum';
import { LessonPage } from './pages/LessonPage';
import { TroubleshootList, TroubleshootWorkspace } from './pages/Troubleshoot';
import { GuidedLabList, GuidedLabPage } from './pages/GuidedLab';
import { Reference } from './pages/Reference';
import { CaseStudyList, CaseStudyPage } from './pages/CaseStudies';
import { Certification } from './pages/Certification';
import { PacketLab } from './pages/PacketLab';
import { Glossary } from './pages/Glossary';
import { History } from './pages/History';
import { Settings } from './pages/Settings';
import { Search } from './pages/Search';
import { Builder } from './pages/Builder';
import { LESSONS } from '../content/lessons';
import { CURRICULUM } from '../content/curriculum';

const NAV: [string, string, string?][] = [
  ['dashboard', 'Dashboard'],
  ['curriculum', 'Curriculum'],
  // Lessons grouped by curriculum module, in module order.
  ...CURRICULUM.flatMap((m): [string, string, string?][] => {
    const ls = LESSONS.filter((l) => l.moduleId === m.id);
    return ls.length ? [[`#${m.title}`, ''], ...ls.map((l): [string, string, string] => [`lesson/${l.id}/what`, l.title.split(':')[0], `lesson/${l.id}`])] : [];
  }),
  ['#Practice', ''],
  ['labs', 'Guided labs', 'labs'],
  ['builder', 'Infrastructure Builder'],
  ['troubleshoot', 'Troubleshooting lab', 'troubleshoot'],
  ['cases', 'Case studies', 'cases'],
  ['packets', 'Packet Lab'],
  ['#Reference', ''],
  ['reference', 'Reference library'],
  ['certification', 'Certification map'],
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
    case 'builder': page = <Builder />; break;
    case 'labs': page = a ? <GuidedLabPage key={a} id={a} /> : <GuidedLabList />; break;
    case 'troubleshoot': page = a ? <TroubleshootWorkspace key={a} id={a} /> : <TroubleshootList />; break;
    case 'commands': page = <Reference initialTab="command" />; break;
    case 'reference': page = <Reference />; break;
    case 'cases': page = a ? <CaseStudyPage key={a} id={a} /> : <CaseStudyList />; break;
    case 'certification': page = <Certification />; break;
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
