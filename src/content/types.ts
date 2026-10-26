// Content data model. Lessons, exercises and references are plain data so new
// services can be added without touching the UI (see docs/ARCHITECTURE.md).

import type { ConceptId } from '../engine/scenarios/types';

export type Level = 'beginner' | 'intermediate' | 'advanced';

/** Markdown-lite text: paragraphs, "- " lists, "### " headings, "> " callouts, ``` code, `inline`, **bold**, [links](#/lesson/id/section) to app pages. */
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
  id: 'what' | 'internals' | 'visualize' | 'deploy' | 'config' | 'operate' | 'troubleshoot' | 'assess';
  title: string;
  /** Tab label when the title is long (the title becomes its tooltip). */
  short?: string;
}

// --- Diagrams (data-driven, rendered as SVG) ----------------------------------

/** A layered diagram: dependencies (or topology). Row 0 is drawn at the top. */
export interface LayeredDiagram {
  title: string;
  /** Optional caption shown under the diagram. */
  caption?: RichText;
  rows: { label?: string; nodes: { id: string; label: string; sub?: string; kind?: 'client' | 'server' | 'network' | 'service' | 'os' | 'data' | 'external' }[] }[];
  /** [from, to, label?]: "from depends on / connects to" "to". */
  edges: [string, string, string?][];
}

/** A hand-specified message sequence (for technologies the simulator does not model). */
export interface StaticSequence {
  title: string;
  caption?: RichText;
  lanes: { id: string; label: string; sub?: string }[];
  steps: { from: string; to: string; label: string; note?: RichText; fail?: boolean }[];
}

// --- Operate & recover guide (one per technology) -------------------------------

export type GuideFileKind = 'config' | 'config-dir' | 'auth' | 'log' | 'unit' | 'startup' | 'cert' | 'data' | 'runtime' | 'registry' | 'eventlog' | 'binary';

export interface GuideFile {
  path: string;
  platform: string;
  kind: GuideFileKind;
  /** What it contains. */
  contains: RichText;
  /** When it is read or written (boot, service start, every login, ...). */
  accessed: RichText;
  /** What goes wrong with bad values or permissions. */
  problems: RichText;
  /** Expected owner/mode, if it matters. */
  perms?: string;
}

export interface ManagementTask {
  task: string;
  command: string;
  explain: RichText;
  risk?: RichText;
  /** True when the command works in the simulator sandbox. */
  sim?: boolean;
}

export interface DiagnosticStep {
  /** The question this step answers ("Is the daemon running?"). */
  question: string;
  /** Why this check comes now and what its result tells you (the reasoning, for beginners). */
  why?: RichText;
  command: string;
  /** What healthy output looks like. */
  healthy: string;
  /** What a failure looks like and what it means. */
  broken: RichText;
  /** Where to go next depending on the result. */
  next: RichText;
  sim?: boolean;
}

export interface FailureMode {
  symptom: string;
  causes: RichText[];
  /** Commands that tell the causes apart. */
  diagnose: string[];
  fix: RichText;
  verify: string;
}

export interface ServiceGuide {
  /** One paragraph: what the service is for. */
  purpose: RichText;
  /** Answers to the architecture questions (internals, protocols, auth, boot, crash behaviour ...). */
  architecture: { q: string; a: RichText }[];
  ports: { port: string; proto: string; purpose: string }[];
  processes: { name: string; platform: string; role: RichText }[];
  dependencies: LayeredDiagram;
  sequence?: StaticSequence;
  files: GuideFile[];
  management: { platform: string; tasks: ManagementTask[] }[];
  /** Reload vs restart vs interface restart vs reboot, for this technology. */
  actions: { action: string; when: RichText; effect: RichText; risk: RichText }[];
  /** Ordered troubleshooting workflow (layer by layer). */
  workflow: DiagnosticStep[];
  failures: FailureMode[];
  verification: { check: string; command: string; expect: string }[];
  /** Reference-library entry ids (commands, files, procedures). */
  refIds: string[];
}

/**
 * The beginner's way into a lesson: plain language first, one idea at a time,
 * each with a concrete example from the lab. Shown before the in-depth text.
 */
export interface Primer {
  /** What it is and why it matters, in one or two plain sentences. */
  oneLiner: string;
  /** An everyday comparison (and where it stops being accurate). */
  analogy: RichText;
  /** The few ideas everything else builds on, each with a concrete example. */
  ideas: { title: string; explain: RichText; example: RichText }[];
  /** One concrete case followed from start to finish. */
  walkthrough: { title: string; intro?: RichText; steps: { label: string; detail: RichText; show?: string }[] };
  /** Wrong beliefs that cause real mistakes, and what is true instead. */
  misconceptions: { myth: string; truth: RichText }[];
  /** Quick self-check; the answer is revealed on request. */
  checks: { q: string; a: RichText }[];
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
  /** Beginner-friendly explanation shown before the in-depth text (registered in content/primers). */
  primer?: Primer;
  deployment: DeploymentGuide[];
  configIntro: RichText;
  configFiles: { platform: string; items: { path: string; purpose: string }[] }[];
  directives: ConfigDirective[];
  /** Day-to-day operation (managing the service, safe changes and restarts), shown at the top of "Operate & recover". */
  operateIntro?: RichText;
  troubleshootingIntro: RichText;
  errorMap: { message: string; layer: string; meaning: string; firstCheck: string }[];
  scenarioIds: string[];
  assessmentId: string;
  references: Reference[];
  /** "simulated" lessons have a sandbox and tickets; "reference" lessons are taught from documentation and real-system examples only. */
  mode?: 'simulated' | 'reference';
  /** Service guide, shown across tabs: architecture (How it works), diagrams (Visualize), files (Config), management (Operate), workflow and failures (Troubleshooting). */
  guide?: ServiceGuide;
  /** End-to-end case studies related to this lesson. */
  caseStudyIds?: string[];
  /** Certification objective ids (e.g. "N10-009:5.3", "CCNA:2.1") this lesson supports. */
  objectives?: string[];
}

// --- Case studies -----------------------------------------------------------------

export interface CaseStudy {
  id: string;
  letter: string;
  title: string;
  level: Level;
  platforms: string[];
  /** Interactive ticket that reproduces this case in the simulator, if any. */
  scenarioId?: string;
  /** Where the example output comes from (simulator, or representative output of a named real platform/version). */
  outputSource: RichText;
  symptoms: RichText;
  environment: LayeredDiagram;
  expected: RichText;
  dependencies: string[];
  investigation: { title: string; host?: string; command: string; output: string; interpretation: RichText }[];
  rootCause: RichText;
  repair: { title: string; host?: string; commands: string; why: RichText }[];
  restart: RichText;
  verify: { command: string; host?: string; output: string; meaning: RichText }[];
  prevention: RichText[];
  lessonIds: string[];
  refIds?: string[];
}

// --- Reference library ------------------------------------------------------------

export interface FileRef {
  id: string;
  path: string;
  platform: string;
  kind: GuideFileKind;
  services: string[];
  purpose: RichText;
  contents: RichText;
  accessed: RichText;
  permissions: string;
  problems: RichText;
  example?: string;
  relatedCommands?: string[];
}

export interface Procedure {
  id: string;
  title: string;
  platform: string;
  services: string[];
  symptoms: string[];
  purpose: RichText;
  /** Ordered steps; commands are shown verbatim. */
  steps: { title: string; command?: string; why: RichText }[];
  risks: RichText;
  verify: RichText;
}

// --- Certification mapping ----------------------------------------------------------

export interface CertObjective {
  id: string;
  title: string;
  coverage: 'covered' | 'partial' | 'gap';
  /** App routes that cover it (lesson/..., troubleshoot/..., cases/..., reference?id=...). */
  links: string[];
  note?: RichText;
}

export interface CertExam {
  id: string;
  name: string;
  code: string;
  version: string;
  officialUrl: string;
  domains: { id: string; title: string; weight: string; objectives: CertObjective[] }[];
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
  platform: 'Linux' | 'Windows' | 'Docker' | 'pfSense' | 'Cisco IOS';
  category: string;
  purpose: RichText;
  syntax: string;
  args: { arg: string; meaning: string }[];
  example: { command: string; output: string };
  interpretation: RichText;
  limitations: RichText;
  /** Name of the simulator command that implements it, if any. */
  simulator?: string;
  /** Common error messages and what they mean. */
  errors?: { message: string; meaning: string }[];
  /** Privileges required (root/sudo, Administrator, group membership ...). */
  permissions?: string;
  /** What can go wrong when running it (disconnects, data loss ...). */
  risks?: string;
  /** Platform/version compatibility notes. */
  compat?: string;
  /** Services, protocols and symptoms this command is used for (reference facets). */
  services?: string[];
  protocols?: string[];
  symptoms?: string[];
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
