// The container lab: corp.lab plus dock01, a Debian 12 server on the server
// VLAN (switch port swp11) running Docker Engine 26. It starts with the images
// the team uses already pulled and no containers; tickets and Lab 4 build on it.

import { mkdir, readFile, writeFile } from '../fs';
import { addPulledImage } from '../sim/docker';
import { recomputeL2 } from '../sim/l2';
import { bootHost, reloadService, serviceDef } from '../sim/services';
import type { World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { trustCorpRoot } from './pkiLab';
import { buildSshLab, DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const DOCK01_IP = '10.0.20.40';
export const DOCK01_ALICE_PASSWORD = 'dock01-alice';
export const DOCKER_IMAGES = ['nginx:1.25', 'postgres:16', 'corp/inventory:1.4'];

export function buildDockerLab(): World {
  const world = buildSshLab();
  const t = world.clock;

  // Switch port swp11, access port in the server VLAN.
  const sw = world.hosts.sw01;
  const swCfg = readFile(sw, '/etc/network/interfaces')!
    .replace('bridge-ports swp1 swp2 swp3 swp4 swp5 swp6 swp7 swp8 swp9', 'bridge-ports swp1 swp2 swp3 swp4 swp5 swp6 swp7 swp8 swp9 swp11')
    .replace('\nauto br0\n', '\nauto swp11\niface swp11\n    alias dock01\n    bridge-access 20\n\nauto br0\n');
  writeFile(sw, '/etc/network/interfaces', swCfg, t);
  sw.ifaces.push({ name: 'swp11', mac: '52:54:00:5e:00:0b', segment: null, address: null, prefix: null, up: false, addrs6: [] });
  world.links = [...(world.links ?? []), { a: { host: 'dock01', iface: 'eth0' }, b: { host: 'sw01', iface: 'swp11' } }];

  const h = createHost(world, {
    id: 'dock01', hostname: 'dock01', domain: 'corp.lab', role: 'Container host (Docker Engine 26)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:d0:00:28', segment: null }],
    services: ['systemd-timesyncd', 'nftables', 'ssh', 'docker'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${DOCK01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  mkdir(h, '/etc/docker', t);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: DOCK01_ALICE_PASSWORD }, t);
  for (const img of DOCKER_IMAGES) addPulledImage(h, img, t);

  // DNS: dock01 and the application name.
  const ns1 = world.hosts.ns1;
  const zone = readFile(ns1, '/etc/bind/db.corp.lab')!
    .replace(/(\d{10}) ; serial/, (_m, s) => `${Number(s) + 1} ; serial`)
    .replace('\nwww     IN CNAME srv01\n', '\nwww     IN CNAME srv01\ndock01  IN A    10.0.20.40\ninventory IN CNAME dock01\n');
  writeFile(ns1, '/etc/bind/db.corp.lab', zone, t);
  reloadService(world, ns1, serviceDef('named')!);

  recomputeL2(world);
  bootHost(world, sw);
  bootHost(world, h);
  world.clock += 5 * 60_000;
  return world;
}
