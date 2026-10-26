// Beginner primers by lesson id (see Primer in ../types).

import type { Primer } from '../types';
import { DHCP_PRIMER, IPNET_PRIMER, IPV6_PRIMER, MTU_PRIMER, NAT_PRIMER, NETIF_PRIMER, TLS_PRIMER, TRANSPORT_PRIMER, VLAN_PRIMER } from './network';
import { AD_KERBEROS_PRIMER, DOCKER_PRIMER, KERBEROS_PRIMER, WINDOWS_RDP_PRIMER } from './platforms';
import { WEBPROXY_PRIMER } from '../ops/webproxy';
import { NTP_PRIMER } from '../ops/ntp';
import { LOGGING_PRIMER } from '../ops/logging';
import { NETOPS_PRIMER, NFTABLES_PRIMER, PFSENSE_PRIMER, RECOVERY_PRIMER, SSH_PRIMER, SYSTEMD_PRIMER } from './services';

export const PRIMERS: Record<string, Primer> = {
  ipnet: IPNET_PRIMER,
  transport: TRANSPORT_PRIMER,
  dhcp: DHCP_PRIMER,
  nat: NAT_PRIMER,
  vlan: VLAN_PRIMER,
  ipv6: IPV6_PRIMER,
  netif: NETIF_PRIMER,
  mtu: MTU_PRIMER,
  tls: TLS_PRIMER,
  ssh: SSH_PRIMER,
  nftables: NFTABLES_PRIMER,
  pfsense: PFSENSE_PRIMER,
  systemd: SYSTEMD_PRIMER,
  netops: NETOPS_PRIMER,
  recovery: RECOVERY_PRIMER,
  'windows-rdp': WINDOWS_RDP_PRIMER,
  'ad-kerberos': AD_KERBEROS_PRIMER,
  kerberos: KERBEROS_PRIMER,
  docker: DOCKER_PRIMER,
  webproxy: WEBPROXY_PRIMER,
  ntp: NTP_PRIMER,
  logging: LOGGING_PRIMER,
};
