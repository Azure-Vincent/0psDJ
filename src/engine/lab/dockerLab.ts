// dock01: a Debian 12 server on the server VLAN (switch port swp11) running
// Docker Engine 26, with the images the team uses already pulled and no
// containers. Container tickets and Lab 4 start from it.

import { mkdir, writeFile } from '../fs';
import { addPulledImage } from '../sim/docker';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { trustCorpRoot } from './pkiLab';
import { buildSshLab, DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const DOCK01_IP = '10.0.20.40';
export const DOCK01_ALICE_PASSWORD = 'dock01-alice';
export const DOCKER_IMAGES = ['nginx:1.25', 'postgres:16', 'corp/inventory:1.4'];

/** Create dock01 (cabled to sw01 swp11); buildSshLab boots it with the rest of the lab. */
export function installDock01(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'dock01', hostname: 'dock01', domain: 'corp.lab', role: 'Container host (Docker Engine 26)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:d0:00:28', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'docker'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${DOCK01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  mkdir(h, '/etc/docker', t);
  mkdir(h, '/srv', t);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: DOCK01_ALICE_PASSWORD }, t);
  for (const img of DOCKER_IMAGES) addPulledImage(h, img, t);
  return h;
}

/** The lab world (dock01 is part of it). */
export function buildDockerLab(): World {
  return buildSshLab();
}
