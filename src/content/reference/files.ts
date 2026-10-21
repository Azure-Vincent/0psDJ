// Files, directories, logs, registry keys and event logs (reference library).
// Ids are "file:<short-name>".

import type { FileRef } from '../types';
import { FILES_LINUX } from './filesLinux';
import { FILES_PLATFORM } from './filesPlatform';

export const FILE_REFS: FileRef[] = [...FILES_LINUX, ...FILES_PLATFORM];
