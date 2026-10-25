// Time service of the lab: ext01 stands in for the provider's stratum-1 server
// (a GPS reference clock), rtr01 runs chrony as the internal NTP server for
// every corp.lab network, and the Debian machines run systemd-timesyncd
// pointed at rtr01 (timesyncd.conf from krbLab).

import { mkdir, writeFile } from '../fs';
import type { World } from '../types';
import { TIMESYNCD_CONF } from './krbLab';

export const RTR01_CHRONY_CONF = `# Welcome to the chrony configuration file. See chrony.conf(5) for more
# information about usable directives.

# Upstream: the provider's time server ntp.example.net (ISP contract NET-12).
server 203.0.113.80 iburst

# Serve time to the internal networks (CHG-0912): office, servers, VLAN 30.
allow 10.0.10.0/24
allow 10.0.20.0/24
allow 10.0.30.0/24

# This directive specify the location of the file containing ID/key pairs for
# NTP authentication.
keyfile /etc/chrony/chrony.keys

# This directive specify the file into which chronyd will store the rate
# information.
driftfile /var/lib/chrony/chrony.drift

# Save NTS keys and cookies.
ntsdumpdir /var/lib/chrony

# Log files location.
logdir /var/log/chrony

# Stop bad estimates upsetting machine clock.
maxupdateskew 100.0

# This directive enables kernel synchronisation (every 11 minutes) of the
# real-time clock. Note that it can't be used along with the 'rtcfile' directive.
rtcsync

# Step the system clock instead of slewing it if the adjustment is larger than
# one second, but only in the first three clock updates.
makestep 1 3

# Get TAI-UTC offset and leap seconds from the system tz database.
leapsectz right/UTC
`;

export const EXT01_CHRONY_CONF = `# ntp.example.net: public stratum-1 server of the provider.
# Reference: GPS receiver with PPS output.
refclock PPS /dev/pps0 lock NMEA refid GPS
refclock SHM 0 offset 0.5 delay 0.2 refid NMEA noselect
allow all
driftfile /var/lib/chrony/chrony.drift
makestep 1 3
rtcsync
`;

/** Write the chrony configurations (rtr01 and ext01) and dock01's timesyncd.conf; buildSshLab boots them. */
export function installNtp(world: World): void {
  const t = world.clock;
  for (const [id, conf] of [['rtr01', RTR01_CHRONY_CONF], ['ext01', EXT01_CHRONY_CONF]] as const) {
    const h = world.hosts[id];
    mkdir(h, '/etc/chrony', t);
    writeFile(h, '/etc/chrony/chrony.conf', conf, t);
    writeFile(h, '/etc/chrony/chrony.keys', '#1 MD5 HEX:0123456789ABCDEF\n', t, { mode: 0o640, group: '_chrony' });
  }
  const dock = world.hosts.dock01;
  if (dock) {
    mkdir(dock, '/etc/systemd', t);
    writeFile(dock, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  }
}
