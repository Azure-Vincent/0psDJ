// Lab 1 world: the corp.lab network plus srv02, a freshly installed Debian
// server cabled to sw01 port swp10 that the learner builds into a production
// server step by step.

import { addUser, createHost } from '../lab/builder';
import { buildSshLab, DEBIAN_SSHD_CONFIG, installHostKeys } from '../lab/sshLab';
import { trustCorpRoot } from '../lab/pkiLab';
import { mkdir, writeFile } from '../fs';
import { recomputeL2 } from '../sim/l2';
import { bootHost } from '../sim/services';
import type { World } from '../types';

export const SRV02_MAC = '52:54:00:c3:00:14';
export const SRV02_PASSWORD = 'srv02-alice';

/** /etc/network/interfaces as the Debian installer writes it when the NIC was configured by DHCP. */
export const SRV02_INSTALLER_INTERFACES = `# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug eth0
iface eth0 inet dhcp
`;

const SRV02_NGINX_CONF = `user www-data;
worker_processes auto;
http {
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
    }
}
`;

export function buildLab1World(): World {
  const world = buildSshLab();
  const t = world.clock;
  const sw = world.hosts.sw01;
  // A free port on the switch, not yet in its configuration (ifupdown2 leaves it down).
  sw.ifaces.push({ name: 'swp10', mac: '52:54:00:5e:00:0a', segment: null, address: null, prefix: null, up: false, addrs6: [] });
  world.links = [...(world.links ?? []), { a: { host: 'srv02', iface: 'eth0' }, b: { host: 'sw01', iface: 'swp10' } }];

  const srv = createHost(world, {
    id: 'srv02', hostname: 'srv02', domain: 'corp.lab', role: 'New Linux server (freshly installed, to be built in Lab 1)',
    ifaces: [{ name: 'eth0', mac: SRV02_MAC, segment: null }],
    services: ['nftables', 'ssh', 'nginx'],
  });
  // Debian installs nftables disabled; nginx and ssh are enabled by their packages.
  srv.services.nftables.enabled = false;
  writeFile(srv, '/etc/network/interfaces', SRV02_INSTALLER_INTERFACES, t);
  writeFile(srv, '/etc/resolv.conf', '', t);
  writeFile(srv, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  installHostKeys(srv, t);
  mkdir(srv, '/etc/nginx', t);
  writeFile(srv, '/etc/nginx/nginx.conf', SRV02_NGINX_CONF, t);
  trustCorpRoot(srv, t);
  addUser(srv, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: SRV02_PASSWORD }, t);
  recomputeL2(world);
  bootHost(world, srv);
  world.clock += 5 * 60_000;
  return world;
}
