// Recovery and maintenance procedures (reference library). Ids are "proc:<name>".

import type { Procedure } from '../types';
import { PROCEDURES_LINUX } from './proceduresLinux';
import { PROCEDURES_PLATFORM } from './proceduresPlatform';
import { KRB_PROCEDURES } from './kerberosRefs';
import { MAIL_PROCEDURES } from './mailRefs';
import { DB_PROCEDURES } from './dbRefs';

export const PROCEDURES: Procedure[] = [...PROCEDURES_LINUX, ...KRB_PROCEDURES, ...PROCEDURES_PLATFORM, ...MAIL_PROCEDURES, ...DB_PROCEDURES];
