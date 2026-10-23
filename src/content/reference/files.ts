// Files, directories, logs, registry keys and event logs (reference library).
// Ids are "file:<short-name>".

import type { FileRef } from '../types';
import { FILES_LINUX } from './filesLinux';
import { FILES_PLATFORM } from './filesPlatform';
import { KRB_FILE_REFS } from './kerberosRefs';

export const FILE_REFS: FileRef[] = [...FILES_LINUX, ...KRB_FILE_REFS, ...FILES_PLATFORM];
