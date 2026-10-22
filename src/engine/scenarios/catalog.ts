// Catalogue of plausible causes for "I can't SSH to the server". Each entry
// states the evidence it produces, which is what the learner must compare
// against what they actually observe.

import type { Cause } from './types';

export const CAUSES: Record<string, Cause> = Object.fromEntries(
  ([
    {
      id: 'server-down', title: 'Server is powered off / unreachable', category: 'Network path', concept: 'net.arp',
      signature: 'Nothing answers on any protocol: ping fails, and the last router (or the client, if on the same subnet) cannot ARP the server, so you get "No route to host" or timeouts.',
      check: 'ping the IP, look at "ip neigh" on the last-hop router for FAILED entries, check the hypervisor/console.',
    },
    {
      id: 'dns-wrong-record', title: 'DNS returns the wrong address for the server', category: 'Name resolution', concept: 'dns.zone',
      signature: 'The name resolves, but to an address that is not the server\'s. Connecting by IP works while connecting by name fails. "dig name" disagrees with "ip addr" on the server.',
      check: 'Compare "dig srv01.corp.lab" / "getent hosts" on the client with "ip -4 addr" on the server; inspect the zone file on the DNS server.',
    },
    {
      id: 'dns-zone-error', title: 'DNS zone failed to load (server answers SERVFAIL)', category: 'Name resolution', concept: 'dns.zone',
      signature: 'Clients report "Temporary failure in name resolution" / SERVFAIL for every name in the zone. The DNS server is running, but its log shows the zone was "not loaded due to errors".',
      check: 'dig @ns1 name (look at status:), journalctl -u named on the DNS server, named-checkzone.',
    },
    {
      id: 'dns-client-config', title: 'Client resolver misconfigured (/etc/resolv.conf)', category: 'Name resolution', concept: 'dns.resolution',
      signature: 'Only this client fails to resolve names; other machines resolve fine. /etc/resolv.conf points at a wrong or unreachable nameserver or lacks the search domain.',
      check: 'cat /etc/resolv.conf; dig @<correct server> name; compare with another client.',
    },
    {
      id: 'hosts-file-override', title: 'Stale /etc/hosts entry on the client', category: 'Name resolution', concept: 'dns.resolution',
      signature: 'getent hosts (used by ssh) returns a different address than dig (which bypasses /etc/hosts).',
      check: 'getent hosts name vs dig name; grep the name in /etc/hosts.',
    },
    {
      id: 'routing-server-gateway', title: 'Server has no route back to the client (missing default gateway)', category: 'Network path', concept: 'net.routing',
      signature: 'SYNs reach the server (visible in tcpdump on the server, firewall counters increase) but no SYN-ACK leaves. The client times out. "ip route" on the server has no default route. Same-subnet hosts can still connect.',
      check: 'ip route on the server; tcpdump -i eth0 port 22 on the server during a connection attempt; ping the server from another subnet.',
    },
    {
      id: 'routing-client', title: 'Client routing problem (wrong/missing gateway on the client)', category: 'Network path', concept: 'net.routing',
      signature: '"Network is unreachable" immediately (no route at all), or every remote network fails (ping of the gateway or other subnets fails too).',
      check: 'ip route and ip route get <server-ip> on the client; ping the default gateway.',
    },
    {
      id: 'firewall-drop', title: 'Host firewall silently drops SSH', category: 'Firewall', concept: 'fw.stateful',
      signature: 'ssh hangs and ends with "Connection timed out" after retransmitting SYNs, while ping (ICMP) to the same IP works. nft counters on the dropping rule/policy increase. The sshd log shows nothing for the attempt.',
      check: 'nc -zv -w 5 host 22; nft list ruleset on the server (check the input chain and its policy); tcpdump on the server.',
    },
    {
      id: 'firewall-reject', title: 'Firewall actively rejects SSH', category: 'Firewall', concept: 'net.icmp',
      signature: 'The connection fails immediately. With "reject with tcp reset" it looks like "Connection refused"; with "reject with icmp(x) admin-prohibited" the client prints "No route to host" even though routing is fine. tcpdump shows an ICMP "admin prohibited filter" reply.',
      check: 'nft -a list ruleset on the server; tcpdump on the client for ICMP; compare "ping" (works) vs ssh.',
    },
    {
      id: 'firewall-not-persistent', title: 'Firewall rule was added at runtime and lost at reboot', category: 'Persistence', concept: 'fw.persistence',
      signature: 'It worked until the server rebooted. The running ruleset matches /etc/nftables.conf, and that file lacks the rule that used to be there.',
      check: 'Compare "nft list ruleset" with /etc/nftables.conf; journalctl -b for the reboot time.',
    },
    {
      id: 'sshd-not-running', title: 'sshd is not running', category: 'Service', concept: 'svc.systemd',
      signature: 'Immediate "Connection refused" (the server kernel answers SYN with RST). "ss -tlnp" shows nothing on :22 and systemctl shows the unit inactive or failed.',
      check: 'systemctl status ssh; ss -tlnp; journalctl -u ssh.',
    },
    {
      id: 'sshd-config-error', title: 'sshd configuration error prevents it from (re)starting', category: 'Configuration', concept: 'ssh.config',
      signature: 'systemctl shows ssh.service failed with status=255; the journal (from ExecStartPre "sshd -t") names the file and line: "Bad configuration option" or similar.',
      check: 'sshd -t; journalctl -u ssh -n 20; systemctl status ssh.',
    },
    {
      id: 'service-not-enabled', title: 'sshd is disabled and did not start at boot', category: 'Persistence', concept: 'svc.systemd',
      signature: 'After a reboot the service is "inactive (dead)" and "systemctl is-enabled ssh" says disabled. Starting it by hand fixes it only until the next reboot.',
      check: 'systemctl is-enabled ssh; systemctl status ssh.',
    },
    {
      id: 'sshd-wrong-port', title: 'sshd listens on a different port', category: 'Configuration', concept: 'svc.listening',
      signature: 'Port 22 is refused (RST) while sshd is active; ss -tlnp shows sshd on another port; sshd -T | grep port shows it.',
      check: 'ss -tlnp on the server; sshd -T | grep ^port; grep -r Port /etc/ssh/sshd_config*.',
    },
    {
      id: 'sshd-listen-address', title: 'sshd bound only to a specific/loopback address', category: 'Configuration', concept: 'svc.listening',
      signature: 'Remote connections are refused, but "ssh localhost" works on the server; ss shows sshd on 127.0.0.1:22 (or another IP) instead of 0.0.0.0:22.',
      check: 'ss -tlnp; sshd -T | grep listenaddress.',
    },
    {
      id: 'host-key-changed', title: 'Server host key changed (known_hosts mismatch)', category: 'Client', concept: 'ssh.hostkeys',
      signature: '"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" followed by "Host key verification failed". TCP and key exchange work; the client aborts before authentication. sshd logs "Connection closed by <client> [preauth]".',
      check: 'Compare the fingerprint printed by the client with "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" on the server console.',
    },
    {
      id: 'kex-mismatch', title: 'No common key-exchange/cipher algorithm', category: 'Cryptography', concept: 'ssh.kex',
      signature: '"Unable to negotiate with <ip> port 22: no matching key exchange method found. Their offer: ..." The TCP connection succeeds and the identification strings are exchanged.',
      check: 'ssh -v; sshd -T | grep -i kexalgorithms; journalctl -u ssh.',
    },
    {
      id: 'invalid-credentials', title: 'Wrong user name or password', category: 'Authentication', concept: 'ssh.userauth',
      signature: '"Permission denied, please try again" for passwords; the server logs "Failed password for <user>" (or "Invalid user <name>" if the account does not exist).',
      check: 'journalctl -u ssh on the server for "Failed password" / "Invalid user"; id <user> on the server.',
    },
    {
      id: 'auth-method-disabled', title: 'The authentication method being used is disabled on the server', category: 'Authentication', concept: 'ssh.userauth',
      signature: 'The client is never asked for a password; it ends with "Permission denied (publickey)". The method list in parentheses is what the server allows.',
      check: 'ssh -v (look at "Authentications that can continue"); sshd -T | grep passwordauthentication.',
    },
    {
      id: 'authorized-keys-missing', title: 'The user\'s public key is not in authorized_keys', category: 'Authentication', concept: 'ssh.authorized-keys',
      signature: 'ssh -v shows "Offering public key" followed by no "Server accepts key". With LogLevel VERBOSE the server logs "Failed publickey". No permission errors are logged.',
      check: 'Compare ~/.ssh/id_*.pub on the client with ~user/.ssh/authorized_keys on the server (ssh-keygen -lf on both).',
    },
    {
      id: 'server-file-permissions', title: 'Unsafe permissions on the user\'s home, ~/.ssh or authorized_keys (StrictModes)', category: 'Permissions', concept: 'linux.permissions',
      signature: 'The key is in authorized_keys but is not accepted. The server logs "Authentication refused: bad ownership or modes for directory/file ...".',
      check: 'journalctl -u ssh; ls -ld ~user ~user/.ssh; ls -l ~user/.ssh/authorized_keys.',
    },
    {
      id: 'client-key-permissions', title: 'Client private key permissions too open', category: 'Client', concept: 'linux.permissions',
      signature: 'The client prints "WARNING: UNPROTECTED PRIVATE KEY FILE!" and "Load key ...: bad permissions"; the server accepted the key offer but never receives a signature.',
      check: 'ls -l ~/.ssh/id_* on the client.',
    },
    {
      id: 'user-not-allowed', title: 'Account not authorized for SSH (AllowUsers/AllowGroups/DenyUsers)', category: 'Authorization', concept: 'ssh.authz',
      signature: 'Correct key/password still yields "Permission denied". The server logs "User <name> from <ip> not allowed because not listed in AllowUsers" (or similar).',
      check: 'journalctl -u ssh; sshd -T -C user=<name>,addr=<ip> | grep -i allow.',
    },
    {
      id: 'web-not-running', title: 'Web server (nginx) not running / not listening on :80', category: 'Service', concept: 'svc.listening',
      signature: 'curl fails immediately with "Couldn\'t connect to server" (connection refused, RST from the server kernel). ss -tlnp shows nothing on :80; systemctl status nginx is inactive or failed. The firewall counters for port 80 still increase (the SYN is accepted, then refused by the kernel).',
      check: 'ss -tlnp and systemctl status nginx on the server; compare with nft counters.',
    },
    {
      id: 'fw-cidr-error', title: 'Firewall rule matches the wrong network (prefix/mask error)', category: 'Firewall', concept: 'net.cidr',
      signature: 'Traffic from a network that should be allowed is dropped by a rule intended for a different network; the counter on that rule increases with your attempts, and your source address falls inside its prefix.',
      check: 'nft -a list ruleset; work out the address range of each prefix (a /23 covers two /24s); journalctl -k if the rule logs.',
    },
    {
      id: 'fw-missing-established', title: 'Return traffic not allowed (no "ct state established,related accept")', category: 'Firewall', concept: 'fw.stateful',
      signature: 'Connections INITIATED by the protected host fail (DNS lookups, updates, outbound HTTP) while inbound services still work. Replies arrive on the interface (tcpdump) but are dropped by the input policy.',
      check: 'nft list chain inet filter input (is there an established,related rule?); tcpdump on the host while running dig; conntrack -L.',
    },
    {
      id: 'fw-router-forward', title: 'A firewall in the path (router forward chain) blocks the traffic', category: 'Firewall', concept: 'fw.path',
      signature: 'Clients on other subnets time out, but the server\'s own firewall shows no matching packets and tcpdump on the server sees nothing. Other ports through the same router work. The router\'s forward chain counters/policy drop it.',
      check: 'tcpdump on the server (silent?); on the router: nft list chain inet filter forward; traceroute -T -p PORT from the client.',
    },
    {
      id: 'client-netmask', title: 'Client has the wrong subnet mask (prefix length)', category: 'Network path', concept: 'net.cidr',
      signature: 'The client believes remote hosts are on its own link: "ip route get <remote>" shows no "via", it ARPs for the remote address directly, ARP fails and it reports "No route to host" / "Destination Host Unreachable" from its own address. Local-subnet hosts still work.',
      check: 'ip -4 addr (prefix length); ip route; ip route get <remote IP>; ip neigh (FAILED entry for the remote IP).',
    },
    {
      id: 'router-forwarding-disabled', title: 'The router does not forward (net.ipv4.ip_forward=0)', category: 'Network path', concept: 'net.routing',
      signature: 'The router itself answers (ping 10.0.10.1 works) but everything beyond it fails: the router returns ICMP host unreachable for packets it is asked to route. tcpdump on the router shows them arriving on one interface and never leaving on the other.',
      check: 'On the router: sysctl net.ipv4.ip_forward; grep -r ip_forward /etc/sysctl.conf /etc/sysctl.d/; tcpdump on both interfaces.',
    },
    {
      id: 'listen-loopback', title: 'Service listens only on 127.0.0.1 (loopback)', category: 'Service', concept: 'svc.listening',
      signature: 'Connections from other hosts are refused (RST) while the same request from the server itself works. ss -tlnp shows 127.0.0.1:PORT instead of 0.0.0.0:PORT.',
      check: 'ss -tlnp on the server; the service\'s listen/bind configuration (nginx: listen; sshd: ListenAddress).',
    },
    {
      id: 'dhcp-server-down', title: 'DHCP server not running / not serving this network', category: 'Service', concept: 'net.dhcp',
      signature: 'Clients log "No DHCPOFFERS received" and end up without an IPv4 address ("Network is unreachable"). The server log shows nothing for their DISCOVERs, or the service failed at start ("Not configured to listen on any interfaces!").',
      check: 'systemctl status isc-dhcp-server and journalctl -u isc-dhcp-server on the server; /etc/default/isc-dhcp-server (INTERFACESv4); tcpdump port 67 on the server.',
    },
    {
      id: 'dhcp-pool-exhausted', title: 'DHCP pool exhausted (no free leases)', category: 'Configuration', concept: 'net.dhcp',
      signature: 'New clients get no address while clients that already hold a lease keep working. The server logs "DHCPDISCOVER from … : network …: no free leases".',
      check: 'journalctl -u isc-dhcp-server; count active leases in /var/lib/dhcp/dhcpd.leases against the range in dhcpd.conf.',
    },
    {
      id: 'dhcp-bad-option', title: 'DHCP hands out a wrong option (router or DNS server)', category: 'Configuration', concept: 'net.dhcp',
      signature: 'DHCP clients get an address but their default route or DNS server is wrong, so only some things fail; statically configured hosts are fine. The client\'s lease file and ip route/resolv.conf show the wrong value.',
      check: 'On the client: ip route, cat /etc/resolv.conf, cat /var/lib/dhcp/dhclient.eth0.leases. On the server: the option lines in dhcpd.conf.',
    },
    {
      id: 'nat-missing-masquerade', title: 'Outbound NAT (masquerade/SNAT) missing', category: 'Network path', concept: 'net.nat',
      signature: 'Inside clients time out to Internet hosts, while the router itself can reach them. tcpdump on the router\'s Internet interface shows private source addresses leaving; replies never come back (the Internet cannot route private addresses).',
      check: 'tcpdump -n on the router\'s outside interface; nft list table ip nat; conntrack -L.',
    },
    {
      id: 'nat-wrong-dnat', title: 'Port forward (DNAT) points to the wrong inside address', category: 'Configuration', concept: 'net.nat',
      signature: 'Outside clients fail to reach the published service; on the router the translated destination is not the server (ARP for it fails, or another host answers). Inside clients reaching the server directly are fine.',
      check: 'nft list table ip nat; conntrack -L (look at the translated destination); ip neigh on the router.',
    },
    {
      id: 'nat-filter-order', title: 'Forward rule written for the public (pre-NAT) port/address', category: 'Firewall', concept: 'net.nat',
      signature: 'The port forward is correct, but the forward chain drops the traffic: the filter sees the destination AFTER DNAT (inside address and port), so a rule matching the public port never matches.',
      check: 'nft -a list ruleset on the router: compare the forward rule with the dnat target; counters on the rule stay at 0.',
    },
    {
      id: 'vlan-access-wrong', title: 'Switch access port in the wrong VLAN', category: 'Network path', concept: 'net.vlan',
      signature: 'The link is up and the host\'s own configuration is correct, but it cannot reach its gateway or anything else in its subnet: ARP (or NDP) requests go unanswered because the switch puts the port into another broadcast domain. The host may even see broadcasts (DHCP, ARP) from the other VLAN.',
      check: 'On the switch: bridge vlan show (PVID of the port), bridge fdb show (which VLAN the host\'s MAC was learned in), and the bridge-access line in /etc/network/interfaces.',
    },
    {
      id: 'vlan-trunk-missing', title: 'VLAN not allowed on the trunk', category: 'Network path', concept: 'net.vlan',
      signature: 'Hosts in one VLAN reach each other but not their gateway on the router; other VLANs work. The router\'s sub-interface is up with the right address, but its tagged frames are dropped by the switch port.',
      check: 'bridge vlan show on the switch: is the VLAN listed (tagged) on the trunk port? tcpdump -e on the router\'s parent interface shows tags leaving but nothing coming back.',
    },
    {
      id: 'vlan-subif-mismatch', title: 'Router sub-interface uses the wrong VLAN ID', category: 'Configuration', concept: 'net.vlan',
      signature: 'Same symptoms as a trunk without the VLAN: the gateway of one VLAN is unreachable. The switch carries the right VLAN, but the router tags its frames with a different ID (or sends them untagged).',
      check: 'ip -d link show on the router (vlan protocol 802.1Q id N) vs bridge vlan show on the switch.',
    },
    {
      id: 'ipv6-icmp-blocked', title: 'Firewall drops ICMPv6 (Neighbor Discovery)', category: 'Firewall', concept: 'net.ndp',
      signature: 'IPv4 works, IPv6 to one host fails with "Address unreachable" from the last router: Neighbor Solicitations for the host get no answer because its input chain drops ICMPv6. Unlike ARP, NDP is filtered by nftables.',
      check: 'ip -6 neigh on the router shows the host FAILED; nft list ruleset on the host: is there an icmpv6 / ipv6-icmp accept rule before the policy drop?',
    },
    {
      id: 'ipv6-forwarding-off', title: 'IPv6 forwarding disabled on the router', category: 'Network path', concept: 'net.ipv6',
      signature: 'Hosts still autoconfigure IPv6 addresses (radvd keeps advertising) and can reach the router itself, but nothing beyond it over IPv6; packets are discarded silently (no ICMPv6 error), so IPv6 connections time out while IPv4 works.',
      check: 'sysctl net.ipv6.conf.all.forwarding on the router; /etc/sysctl.d/*; journalctl -u radvd ("IPv6 forwarding seems to be disabled").',
    },
    {
      id: 'ipv6-server-no-route', title: 'Server has no IPv6 default route', category: 'Network path', concept: 'net.ipv6',
      signature: 'IPv6 packets reach the server (tcpdump there shows SYNs) but replies cannot be routed back to other subnets; the client times out. The server reaches hosts on its own /64 only.',
      check: 'ip -6 route on the server (no "default via"); the inet6 stanza in /etc/network/interfaces.',
    },
    {
      id: 'tls-cert-expired', title: 'The server certificate has expired', category: 'Cryptography', concept: 'tls.pki',
      signature: 'Every client that verifies certificates fails with "certificate has expired" (curl (60), browsers NET::ERR_CERT_DATE_INVALID), from every network, at the same moment. TCP connects fine; the TLS handshake is aborted by the client after it receives the certificate.',
      check: 'openssl s_client -connect host:443 </dev/null | openssl x509 -noout -dates (what the server actually presents); openssl x509 -noout -enddate -in the configured file; compare with "date".',
    },
    {
      id: 'tls-key-mismatch', title: 'Certificate and private key do not belong together', category: 'Configuration', concept: 'tls.pki',
      signature: 'nginx -t fails with "SSL_CTX_use_PrivateKey(...) failed ... key values mismatch". A reload fails, so the old certificate stays in memory and keeps being served; a restart or reboot takes the HTTPS site down entirely.',
      check: 'nginx -t; journalctl -u nginx; compare "openssl x509 -noout -modulus -in CERT | openssl md5" with "openssl rsa -noout -modulus -in KEY | openssl md5".',
    },
    {
      id: 'tls-name-mismatch', title: 'Certificate does not cover the host name clients use', category: 'Cryptography', concept: 'tls.pki',
      signature: 'The chain verifies, but the client rejects the name: curl "(60) SSL: no alternative certificate subject name matches target host name". Names listed in the certificate\'s subjectAltName work; others fail.',
      check: 'openssl x509 -noout -ext subjectAltName on the served certificate; curl -v (subjectAltName lines); which ssl_certificate does the server block use?',
    },
    {
      id: 'tls-chain-incomplete', title: 'Server does not send the intermediate CA certificate', category: 'Configuration', concept: 'tls.pki',
      signature: 'Clients that trust the root still fail with "unable to get local issuer certificate" (depth 0) and s_client shows a chain of length 1 ("unable to verify the first certificate"). Browsers that cached the intermediate may still work, which makes it look intermittent.',
      check: 'openssl s_client -connect host:443 (Certificate chain section: how many certificates?); grep -c BEGIN on the ssl_certificate file; openssl verify -untrusted INTERMEDIATE CERT.',
    },
    {
      id: 'tls-untrusted-root', title: 'Client does not trust the issuing root CA', category: 'Client', concept: 'tls.pki',
      signature: 'Only some clients fail with "unable to get local issuer certificate" while others connect fine to the same server. The server sends the complete chain (s_client depth=1 error), but this client\'s trust store lacks the root.',
      check: 'Compare the failing client with a working one; grep the root\'s subject in /etc/ssl/certs/ca-certificates.crt; ls /usr/local/share/ca-certificates.',
    },
    {
      id: 'mtu-mismatch', title: 'MTU mismatch on a link', category: 'Network path', concept: 'net.mtu',
      signature: 'Small packets work (ping, DNS, ssh login, curl -I, TCP handshakes) but large transfers and TLS handshakes stall after the first packets. The two ends of one link use different MTUs, so full-size frames are dropped silently by the side with the smaller MTU; no ICMP error is generated.',
      check: 'ip link on both ends of each link on the path; ping -M do -s 1472 (and smaller) to find the largest size that passes; tracepath; tcpdump showing repeated retransmissions of full-size segments.',
    },
    {
      id: 'pmtud-blackhole', title: 'Path MTU discovery black hole (ICMP "fragmentation needed" filtered)', category: 'Firewall', concept: 'net.mtu',
      signature: 'Like an MTU problem: small packets work, large ones stall. A router on the path has a smaller MTU and sends ICMP "fragmentation needed", but a firewall drops it, so the sender never lowers its segment size.',
      check: 'ping -M do -s SIZE: an error reply (Frag needed) means PMTUD works; silence means the ICMP is lost. Check firewalls for rules dropping ICMP type 3 / ICMPv6 type 2.',
    },
    {
      id: 'dhcp-relay-wrong-server', title: 'DHCP relay forwards to the wrong (or no) server', category: 'Configuration', concept: 'net.dhcp',
      signature: 'Only clients on the relayed network (another VLAN than the DHCP server) get no address. The DHCP server logs nothing for them; on the router the relay sends the requests to an address where no DHCP server answers (ARP for it fails, or ICMP port unreachable comes back), or the relay service is not running.',
      check: 'systemctl status isc-dhcp-relay and /etc/default/isc-dhcp-relay (SERVERS) on the router; tcpdump -n -i <server side> port 67 or arp on the router; journalctl -u isc-dhcp-server on the server.',
    },
    {
      id: 'dhcp-relay-upstream', title: 'Relay does not receive the server\'s replies', category: 'Configuration', concept: 'net.dhcp',
      signature: 'The DHCP server logs DISCOVER and OFFER "via <relay address>", so requests arrive and are answered, yet clients never see an offer. The replies (server → giaddr, UDP 67) reach the router but are dropped: the relay does not listen on the server-side interface (-iu missing) and the router\'s firewall drops them on the fallback socket.',
      check: 'tcpdump on the router\'s server-side interface (replies arrive?) and client-side interface (nothing leaves?); OPTIONS/INTERFACES in /etc/default/isc-dhcp-relay; nft list ruleset (input policy) on the router.',
    },
    {
      id: 'dhcp-no-subnet', title: 'DHCP server has no subnet declaration for the relayed network', category: 'Configuration', concept: 'net.dhcp',
      signature: 'Relayed clients get no address. The server receives their requests and logs "DHCPDISCOVER from <mac> via <giaddr>: unknown network segment": it cannot find a subnet that contains the relay\'s address (giaddr), so it does not answer.',
      check: 'journalctl -u isc-dhcp-server on the server; the subnet declarations in dhcpd.conf compared with the relay agent\'s address on the client network.',
    },
    {
      id: 'nic-renamed', title: 'Network configuration refers to an interface name that no longer exists', category: 'Configuration', concept: 'net.interfaces',
      signature: 'After new hardware, a VM migration or a template change the host has no address at all. "ip -br link" shows a NIC with a different name (ens18, enp1s0) in state DOWN; networking.service failed with "Cannot find device \\"eth0\\"". Nothing in the network changed.',
      check: 'ip -br link and ip -br addr on the host console; journalctl -u networking -b; compare the iface names in /etc/network/interfaces (or netplan/NetworkManager) with the NICs that exist.',
    },
    {
      id: 'bridge-port-missing', title: 'Switch port not attached to the bridge', category: 'Network path', concept: 'net.interfaces',
      signature: 'One host is isolated although its own configuration and its cable (link UP, carrier) are fine. Its frames reach the switch port but the port is not a member of the (virtual) switch: "bridge link show" lacks it and "ip -d link show <port>" shows no "master". ARP for the host fails from the gateway.',
      check: 'bridge link show / bridge vlan show on the switch; ip -d link show <port>; bridge-ports in the switch configuration.',
    },
  ] as Cause[]).map((c) => [c.id, c]),
);
