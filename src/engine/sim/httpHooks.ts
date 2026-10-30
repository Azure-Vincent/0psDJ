// Extensions registered by other simulators: docker-proxy forwards a published
// port to its container, and application servers (gunicorn in containers, the
// Prometheus stack) answer HTTP themselves. Kept free of runtime imports so any
// module can register at load time.

import type { Host, World } from '../types';
import type { HttpRequestInfo, HttpResponse } from './http';

export const httpHooks: {
  proxy?: (world: World, host: Host, port: number) => { host: Host; port: number } | null;
  apps: Record<string, (world: World, host: Host, req: HttpRequestInfo) => HttpResponse>;
} = { apps: {} };
