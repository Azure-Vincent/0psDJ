// Recovery and maintenance procedures (reference library). Ids are "proc:<name>".

import type { Procedure } from '../types';
import { PROCEDURES_LINUX } from './proceduresLinux';
import { PROCEDURES_PLATFORM } from './proceduresPlatform';

export const PROCEDURES: Procedure[] = [...PROCEDURES_LINUX, ...PROCEDURES_PLATFORM];
