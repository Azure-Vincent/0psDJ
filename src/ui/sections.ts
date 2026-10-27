import type { Section } from '../content/types';

/** The tabs of a lesson page, in order. */
export const SECTIONS: Section[] = [
  { id: 'what', title: 'What is it?', short: 'Overview' },
  { id: 'internals', title: 'How it works' },
  { id: 'visualize', title: 'Visualize' },
  { id: 'deploy', title: 'Deploy' },
  { id: 'config', title: 'Configuration', short: 'Config' },
  { id: 'operate', title: 'Operate & recover', short: 'Operate' },
  { id: 'troubleshoot', title: 'Troubleshooting', short: 'Troubleshoot' },
  { id: 'assess', title: 'Assessment' },
];
