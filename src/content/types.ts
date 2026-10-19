// Content data model. Lessons, exercises and references are plain data so new
// services can be added without touching the UI (see docs/ARCHITECTURE.md).

import type { ConceptId } from '../engine/scenarios/types';

export type Level = 'beginner' | 'intermediate' | 'advanced';

/** Markdown-lite text: paragraphs, "- " lists, "### " headings, "> " callouts, ``` code, `inline`, **bold**. */
export type RichText = string;

export interface Reference {
  title: string;
  url: string;
}

export interface DeploymentStep {
  title: string;
  command?: string;
  /** What the command does. */
  what: RichText;
  /** Why it is necessary. */
  why: RichText;
  /** What successful output looks like. */
  expected?: string;
  /** True when the same command can be tried in the simulator sandbox. */
  simulated?: boolean;
}

export interface DeploymentGuide {
  id: string;
  platform: string;
  summary: RichText;
  prerequisites: string[];
  steps: DeploymentStep[];
}

export interface ConfigDirective {
  name: string;
  compiledDefault: string;
  distroDefault?: string;
  recommended: string;
  explanation: RichText;
  security: RichText;
}

export interface Section {
  id: 'what' | 'internals' | 'visualize' | 'deploy' | 'config' | 'troubleshoot' | 'assess';
  title: string;
}

export interface Lesson {
  id: string;
  moduleId: string;
  title: string;
  level: Level;
  summary: string;
  concepts: ConceptId[];
  what: RichText;
  internals: RichText;
  deployment: DeploymentGuide[];
  configIntro: RichText;
  configFiles: { platform: string; items: { path: string; purpose: string }[] }[];
  directives: ConfigDirective[];
  troubleshootingIntro: RichText;
  errorMap: { message: string; layer: string; meaning: string; firstCheck: string }[];
  scenarioIds: string[];
  assessmentId: string;
  references: Reference[];
}

// --- Assessments --------------------------------------------------------------

interface QuestionBase {
  id: string;
  prompt: RichText;
  /** Optional exhibit (log excerpt, command output, config). */
  exhibit?: string;
  concepts: ConceptId[];
  explanation: RichText;
  level: Level;
}

export interface SingleChoice extends QuestionBase {
  kind: 'single';
  options: { text: string; correct?: boolean; misconception?: string }[];
}

export interface MultiChoice extends QuestionBase {
  kind: 'multi';
  options: { text: string; correct?: boolean; misconception?: string }[];
}

export interface OrderQuestion extends QuestionBase {
  kind: 'order';
  /** Items in the correct order; the UI shuffles them deterministically. */
  items: string[];
}

export interface ShortAnswer extends QuestionBase {
  kind: 'text';
  /** Accepted answers (case-insensitive, whitespace-normalised) or regular expressions. */
  accept: (string | RegExp)[];
  placeholder?: string;
}

/** The learner writes an nftables rule; it is evaluated against test packets by the engine. */
export interface NftRuleQuestion extends QuestionBase {
  kind: 'nft-rule';
  /** Rules already present before the learner's rule (chain policy is drop). */
  context: string[];
  tests: { description: string; packet: { src: string; dport: number; proto: 'tcp' | 'udp' }; expect: 'accept' | 'drop' }[];
}

/** The learner writes sshd_config lines; graded on the effective configuration. */
export interface SshdConfigQuestion extends QuestionBase {
  kind: 'sshd-config';
  checks: { description: string; key: string; expect: unknown; context?: { user: string; address: string } }[];
}

export type Question = SingleChoice | MultiChoice | OrderQuestion | ShortAnswer | NftRuleQuestion | SshdConfigQuestion;

export interface Assessment {
  id: string;
  title: string;
  questions: Question[];
}

// --- Commands -----------------------------------------------------------------

export interface CommandRef {
  id: string;
  name: string;
  platform: 'Linux' | 'Windows';
  category: string;
  purpose: RichText;
  syntax: string;
  args: { arg: string; meaning: string }[];
  example: { command: string; output: string };
  interpretation: RichText;
  limitations: RichText;
  /** Name of the simulator command that implements it, if any. */
  simulator?: string;
}

export interface CommandExercise {
  id: string;
  kind: 'choose-command' | 'spot-abnormal';
  situation: RichText;
  /** For choose-command: accepted command names (first word), optionally required flags/arguments as regexes. */
  acceptCommands?: string[];
  mustMatch?: RegExp[];
  /** For spot-abnormal: output lines and the index of the abnormal line(s). */
  output?: string[];
  abnormal?: number[];
  explanation: RichText;
  concepts: ConceptId[];
}

// --- Glossary & curriculum -------------------------------------------------------

export interface GlossaryEntry {
  term: string;
  definition: RichText;
  related?: string[];
}

export interface Topic {
  title: string;
  level: Level;
  status: 'available' | 'partial' | 'planned';
  /** Where to go when available: a route such as "lesson/ssh". */
  link?: string;
  note?: string;
}

export interface CurriculumModule {
  id: string;
  title: string;
  summary: string;
  dependsOn: string[];
  topics: Topic[];
}
