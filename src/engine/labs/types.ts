// Guided multi-step labs: the learner builds something in the simulated network
// one step at a time; each step has checks the engine evaluates against the
// current world, and the last step re-runs every check after rebooting all hosts.

import type { ConceptId } from '../scenarios/types';
import type { World } from '../types';

export interface LabCheckResult {
  ok: boolean;
  /** What was found (shown under the check). */
  detail: string;
}

export interface LabCheck {
  id: string;
  /** What must be true, phrased as a requirement. */
  description: string;
  check(world: World): LabCheckResult;
}

export interface LabStep {
  id: string;
  title: string;
  /** The outcome this step must achieve (markdown). */
  objective: string;
  /** Background: why this is done and how it works (markdown). */
  background: string;
  /** Concrete actions, in order (markdown each). */
  tasks: string[];
  hints: string[];
  checks: LabCheck[];
  /** Reference solution (used for "show solution" and to fast-forward to a step). */
  solution: { host: string; user: string; commands: string[]; answers?: string[] }[];
  /** Reference solution done in a web interface (pfSense webConfigurator): the clicks, and their effect (applied after the commands). */
  gui?: { steps: string[]; apply(world: World): World };
  /** Links into lessons and the reference library ("lesson/netif/internals", "reference?id=ip"). */
  learn: { label: string; link: string }[];
  concepts: ConceptId[];
  /** Run the checks of every previous step after rebooting all hosts (the final step). */
  afterReboot?: boolean;
  /** Integrated labs: the stage this step belongs to (default: configure). */
  stage?: 'configure' | 'verify';
  /** Integrated labs, guided mode: the important commands of this step, explained. */
  commands?: CommandExplain[];
}

/** One important command or change, explained the way an experienced colleague would. */
export interface CommandExplain {
  host: string;
  command: string;
  /** What it does. */
  what: string;
  /** Why this step needs it. */
  why: string;
  /** Where the configuration (or the state it shows) lives. */
  where?: string;
  /** What successful execution looks like. */
  success: string;
  /** How to check that it worked (which may differ from "the command printed no error"). */
  verify?: string;
}

export interface LabTerminal {
  hostId: string;
  user: string;
  label: string;
  banner: string;
  /** 'pfweb': a browser on fromHost (logged in locally as user) opened on hostId's pfSense webConfigurator. */
  kind?: 'terminal' | 'pfweb';
  fromHost?: string;
}

export interface GuidedLab {
  id: string;
  title: string;
  level: 'beginner' | 'intermediate' | 'advanced';
  /** Rough time for a learner, e.g. "60–90 min". */
  duration: string;
  summary: string;
  /** The story: what you are asked to do and why. */
  brief: string;
  objectives: string[];
  /** Lessons worth doing first. */
  prerequisites: { label: string; link: string }[];
  terminals: LabTerminal[];
  /** Shown next to the topology before the lab starts (markdown): the machines this lab adds or changes. */
  setupNote?: string;
  steps: LabStep[];
  build(): World;
  /** Present on integrated (multi-subject) labs. */
  integrated?: IntegratedInfo;
}

// ---------------------------------------------------------------------------
// Integrated labs: several subjects in one realistic situation, in six stages
// (environment, dependencies, configuration, verification, troubleshooting,
// review) and three learning modes.
// ---------------------------------------------------------------------------

export type LabMode = 'guided' | 'assisted' | 'independent';

/** A component on a request path. probe() runs real commands on a copy of the lab. */
export interface PathNode {
  id: string;
  label: string;
  /** What this component contributes (shown when the learner inspects it). */
  role: string;
  host?: string;
  /** Is this hop working now? evidence: the command and its output (never the cause). */
  probe(world: World): { ok: boolean; evidence: string };
}

export interface RequestPath {
  id: string;
  /** e.g. "dev02 opens http://www.corp.lab". */
  label: string;
  nodes: PathNode[];
}

/** The problem introduced after the build works (stage 5). */
export interface LabFault {
  title: string;
  /** How the problem is reported (a user's words, not the cause). */
  report: string;
  /** Break the learner's working lab. */
  inject(world: World): void;
  /** Catalog cause ids (scenarios/catalog.ts) that are the root cause. */
  rootCauses: string[];
  /** Causes offered in the diagnosis form. */
  candidates: string[];
  hints: string[];
  /** Repaired when these pass (on the learner's world, then again after a reboot). */
  checks: LabCheck[];
  /** Reference repair. */
  solution: { host: string; user: string; commands: string[] }[];
  explanation: { rootCause: string; evidence: string; lesson: string };
  /** The subjects a correct diagnosis demonstrates. */
  concepts: ConceptId[];
}

export interface ReviewQuestion {
  id: string;
  question: string;
  choices: string[];
  answer: number;
  explanation: string;
  concepts: ConceptId[];
}

export interface IntegratedInfo {
  number: number;
  scenario: { organisation: string; situation: string; goal: string; whyItMatters: string };
  technologies: string[];
  systems: { host: string; role: string }[];
  /** How the lab starts (what is there, what is missing or broken). */
  startingState: string[];
  /** Commands and tools that apply here, with reference-library ids. */
  tools: { command: string; platform: 'Linux' | 'Windows' | 'pfSense' | 'Cisco IOS'; use: string; refId?: string }[];
  /** Stage 2: how the technologies depend on each other (markdown), and the paths to probe. */
  dependencies: { explanation: string; paths: RequestPath[] };
  mistakes: string[];
  /** How completion is verified (plain language). */
  verification: string;
  fault: LabFault;
  review: ReviewQuestion[];
  /** Lessons that lead into this lab (lesson ids); they are recommended, not required. */
  after: string[];
}
