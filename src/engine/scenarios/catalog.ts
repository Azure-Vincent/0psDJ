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
      id: 'web-config-error', title: 'nginx configuration error: the service failed to (re)start', category: 'Configuration', concept: 'svc.systemd',
      signature: 'nginx is "failed" after a restart and nothing listens on :80 or :443 (connection refused). journalctl -u nginx and nginx -t show an [emerg] line naming the file and line (a missing certificate, a typo, a bad listen).',
      check: 'nginx -t; systemctl status nginx; journalctl -u nginx -n 20.',
    },
    {
      id: 'web-file-permissions', title: 'Web files not readable by the nginx worker (www-data)', category: 'Permissions', concept: 'linux.permissions',
      signature: 'The site answers 403 Forbidden. error.log: open() "…/index.html" failed (13: Permission denied) or "… is forbidden (13: Permission denied)". The workers run as www-data: every directory on the path needs x, the file needs r.',
      check: 'tail /var/log/nginx/error.log; namei -l /var/www/html/index.html (or ls -ld each directory); sudo -u www-data cat the file.',
    },
    {
      id: 'web-content-changed', title: 'Site content replaced (defacement)', category: 'Service', concept: 'svc.listening',
      signature: 'The server answers 200 OK, but the page is not the expected one. The file under the web root changed (ls -l: new time, owner or mode); access.log shows who requested it.',
      check: 'curl the page and compare; ls -l and diff against the backup or package copy; who can write the file (ls -l, find -perm -o+w).',
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
    {
      id: 'dhcp6-client-firewall', title: 'Client firewall drops DHCPv6 replies (UDP 546)', category: 'Firewall', concept: 'net.ipv6',
      signature: 'The client has a link-local address only. The DHCPv6 server logs Solicit and Advertise for it again and again, tcpdump on the client shows the Advertise arriving on port 546, but dhclient -6 never logs "RCV: Advertise". The client\'s input chain has a default-drop policy and no "udp dport 546" rule; "ct state established,related" does not help because the request went to a multicast group.',
      check: 'journalctl -u isc-dhcp-server on the server (Advertise sent?); tcpdump -n -i eth0 port 546 on the client (arriving?); nft list ruleset on the client.',
    },
    {
      id: 'dhcp6-server-firewall', title: 'DHCPv6 server firewall drops requests (UDP 547)', category: 'Firewall', concept: 'net.ipv6',
      signature: 'DHCPv6 clients get no address and the server logs nothing at all for them, although tcpdump on the server\'s interface shows the Solicit messages to ff02::1:2 port 547. dhcpd -6 uses an ordinary UDP socket, so (unlike DHCPv4, which reads with packet sockets) the server\'s input chain must accept UDP 547.',
      check: 'tcpdump -n -i <if> port 547 on the server; journalctl -u isc-dhcp-server (no Solicit lines); nft list ruleset (input chain) on the server.',
    },
    {
      id: 'dhcp6-wrong-interface', title: 'dhcpd -6 configured for the wrong interface', category: 'Configuration', concept: 'net.ipv6',
      signature: 'isc-dhcp-server fails to start (or starts only IPv4): "No subnet6 declaration for eth3 (fe80::...)", "Not configured to listen on any interfaces!". INTERFACESv6 names an interface (often the parent of a VLAN sub-interface) that has no global address inside any subnet6 declaration.',
      check: 'systemctl status isc-dhcp-server; INTERFACESv6 in /etc/default/isc-dhcp-server; ip -6 addr on the named interface compared with the subnet6 declarations in dhcpd6.conf.',
    },
    {
      id: 'krb-clock-skew', title: 'Client clock differs from the KDC by more than 5 minutes', category: 'Authentication', concept: 'ad.kerberos',
      signature: 'kinit fails with "Clock skew too great while getting initial credentials" (and SSO logins fail with the same error on the server side). The KDC logs "PREAUTH_FAILED ... Clock skew too great". "date" on the client and on the KDC differ by more than the allowed 300 s; timedatectl shows "System clock synchronized: no" and often "NTP service: inactive".',
      check: 'date (or date +%s) on the client and the KDC; timedatectl; journalctl -u krb5-kdc on the KDC; systemctl status systemd-timesyncd.',
    },
    {
      id: 'krb-missing-srv', title: 'DNS SRV records for the KDC are missing', category: 'Name resolution', concept: 'ad.dns',
      signature: 'kinit fails immediately with "Cannot find KDC for realm" without contacting any server. krb5.conf has no kdc line for the realm (dns_lookup_kdc), and "host -t SRV _kerberos._udp.<domain>" returns NXDOMAIN. The KDC itself is running and reachable.',
      check: 'host -t SRV _kerberos._udp.corp.lab and _kerberos._tcp; [realms] in /etc/krb5.conf; the zone file and its serial on the DNS server.',
    },
    {
      id: 'krb-kdc-firewall', title: 'Firewall blocks the KDC (port 88)', category: 'Firewall', concept: 'ad.kerberos',
      signature: 'kinit waits several seconds and fails with "Cannot contact any KDC for realm". SRV records resolve, the KDC process is running and listening (ss -ulnp shows krb5kdc on :88), but its log shows no AS_REQ from the client. tcpdump on the KDC shows requests to port 88 arriving; the input chain has no rule for UDP/TCP 88.',
      check: 'ss -ulnp and ss -tlnp on the KDC; journalctl -u krb5-kdc (any AS_REQ?); tcpdump -n -i eth0 port 88; nft list ruleset on the KDC.',
    },
    {
      id: 'krb-kdc-down', title: 'KDC service not running', category: 'Service', concept: 'ad.kerberos',
      signature: 'kinit fails quickly with "Cannot contact any KDC for realm": the KDC host answers with ICMP port unreachable because nothing listens on UDP 88. "systemctl status krb5-kdc" shows inactive or failed.',
      check: 'systemctl status krb5-kdc; ss -ulnp | grep :88; journalctl -u krb5-kdc.',
    },
    {
      id: 'krb-stale-keytab', title: 'Server keytab has an old key version (kvno)', category: 'Cryptography', concept: 'ad.kerberos',
      signature: 'kinit and kvno work, but Kerberos (GSSAPI) logins to one server fail and ssh falls back to keys or passwords. "kvno host/<server>" on a client shows a key version that "klist -k /etc/krb5.keytab" on the server does not have: the principal\'s key was changed on the KDC (cpw -randkey, a second ktadd) and the server\'s keytab was not updated. sshd at LogLevel DEBUG1 logs "Key version number for principal in key table is incorrect".',
      check: 'kvno host/srv01.corp.lab on the client; klist -k /etc/krb5.keytab on the server; getprinc host/srv01.corp.lab on the KDC (Key: vno ...).',
    },
    {
      id: 'krb-wrong-password', title: 'Wrong password or unknown principal', category: 'Authentication', concept: 'ad.kerberos',
      signature: 'kinit fails with "Password incorrect while getting initial credentials" (KDC log: PREAUTH_FAILED) or "Client \'name@REALM\' not found in Kerberos database" (CLIENT_NOT_FOUND). The KDC is reached and answers: this is about the account, not the infrastructure.',
      check: 'journalctl -u krb5-kdc on the KDC; kadmin.local -q "getprinc <user>" (exists? failed attempts?).',
    },
    {
      id: 'win-rdp-firewall', title: 'Windows Defender Firewall blocks RDP (Remote Desktop rules disabled)', category: 'Firewall', concept: 'win.rdp',
      signature: 'RDP and "nc -zv <server> 3389" time out (dropped, no answer), while on the server TermService runs and listens on 3389. Get-NetFirewallRule -DisplayGroup "Remote Desktop" shows the rules with Enabled False (or missing), and the profile\'s default inbound action is Block.',
      check: 'nc -zv -w 3 <server> 3389 from the client; on the server Get-NetTCPConnection -LocalPort 3389 -State Listen; Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table Name, Enabled, Profile, Action; the Firewall operational log (2004/2005/2006).',
    },
    {
      id: 'win-rdp-profile', title: 'Connection in the wrong network profile (Public) for the RDP rules', category: 'Firewall', concept: 'win.rdp',
      signature: 'RDP times out, yet the Remote Desktop rules are enabled. Their Profile is Domain and/or Private, and Get-NetConnectionProfile shows NetworkCategory Public: Windows applies only the rules of the active profile. Typical after a network change (new switch port, new VLAN) on a server that is not domain-joined.',
      check: 'Get-NetConnectionProfile; Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table Name, Enabled, Profile; Get-NetFirewallProfile.',
    },
    {
      id: 'win-rdp-disabled', title: 'Remote Desktop turned off (fDenyTSConnections = 1)', category: 'Configuration', concept: 'win.rdp',
      signature: 'RDP is refused immediately (TCP reset). TermService is Running, but nothing listens on the RDP port. HKLM\\System\\CurrentControlSet\\Control\\Terminal Server has fDenyTSConnections = 1 ("Remote Desktop: Off"); a policy value under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services overrides it if present.',
      check: 'Get-NetTCPConnection -LocalPort 3389 -State Listen; Get-Service TermService; Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" | Select-Object fDenyTSConnections.',
    },
    {
      id: 'win-termservice-disabled', title: 'Remote Desktop Services (TermService) stopped or disabled', category: 'Service', concept: 'win.services',
      signature: 'RDP is refused immediately: nothing listens on the RDP port. Get-Service TermService shows Stopped; with StartType Disabled, Start-Service fails and the System log has event 7000 ("cannot be started, either because it is disabled..."). Event 7036 records when it stopped.',
      check: 'Get-Service TermService | Select-Object Name, Status, StartType; Get-WinEvent -LogName System -MaxEvents 20 (7036, 7040, 7000); sc.exe qc TermService.',
    },
    {
      id: 'win-rdp-port', title: 'RDP listener moved to another port (PortNumber)', category: 'Configuration', concept: 'win.rdp',
      signature: 'Connections to 3389 are refused, yet TermService runs and listens on another port (Get-NetTCPConnection / netstat -ano). PortNumber under ...\\Terminal Server\\WinStations\\RDP-Tcp is not 3389; the firewall rules still allow only 3389, so the new port times out from clients.',
      check: 'Get-NetTCPConnection -State Listen; Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" | Select-Object PortNumber; Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Get-NetFirewallPortFilter.',
    },
    {
      id: 'win-rdp-rights', title: 'User lacks the right to log on through Remote Desktop', category: 'Authorization', concept: 'win.rdp',
      signature: 'The connection and NLA authentication succeed, then the logon is refused: "not authorized for remote login" (FreeRDP: ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES). Security event 4625 with Logon Type 10 and Status 0xC000015B. The user is in neither Remote Desktop Users nor Administrators (or a "Deny log on through Remote Desktop Services" right applies).',
      check: 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 5 | Format-List Message; Get-LocalGroupMember "Remote Desktop Users"; on domain members gpresult /r for the user rights policy.',
    },
    {
      id: 'win-account-disabled', title: 'User account disabled', category: 'Authentication', concept: 'win.rdp',
      signature: 'Authentication fails although the password is right: FreeRDP reports ERRCONNECT_ACCOUNT_DISABLED, the server logs 4625 with Status 0xC0000072, and Get-LocalUser shows Enabled False. Event 4725 records who disabled it and when.',
      check: 'Get-LocalUser <name>; Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625,4725} -MaxEvents 5 | Format-List.',
    },
    {
      id: 'win-wrong-password', title: 'Wrong user name or password', category: 'Authentication', concept: 'win.rdp',
      signature: 'NLA fails with ERRCONNECT_LOGON_FAILURE ("The logon attempt failed"); the server logs 4625 with Status 0xC000006D (Sub Status 0xC000006A for a bad password, 0xC0000064 for an unknown user). The network path and the service are fine.',
      check: 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 5 | Format-List Message; Get-LocalUser; try +auth-only from the client.',
    },
    {
      id: 'dom-member-dns', title: 'Domain member uses a DNS server without the AD zone', category: 'Name resolution', concept: 'ad.dns',
      signature: 'Domain logons on the member fail ("The Local Security Authority cannot be contacted", 4625 status 0xC000005E) while local accounts work. nltest /sc_query reports ERROR_NO_LOGON_SERVERS, NETLOGON 5719 at boot, gpupdate fails. The member\'s DNS servers are not AD DNS servers, so Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.<domain> says the name does not exist.',
      check: 'Get-DnsClientServerAddress; Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab; nltest /dsgetdc:ad.corp.lab; Get-WinEvent -LogName System (NETLOGON 5719).',
    },
    {
      id: 'dom-dc-firewall', title: 'DC firewall blocks the directory (LDAP)', category: 'Firewall', concept: 'ad.kerberos',
      signature: 'The member finds the DC in DNS (the SRV records resolve) but cannot contact it: nltest /dsgetdc fails, Test-NetConnection <dc> -Port 389 times out while port 53 works. Domain logons fail with no logon servers (0xC000005E). On the DC the Active Directory Domain Services firewall rules are disabled.',
      check: 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.<domain>; Test-NetConnection <dc> -Port 389 / 88 / 53; on the DC Get-NetFirewallRule -DisplayGroup "Active Directory Domain Services".',
    },
    {
      id: 'dom-trust-broken', title: 'Broken secure channel (machine account password mismatch)', category: 'Authentication', concept: 'ad.kerberos',
      signature: 'Every domain user fails on one member ("The trust relationship between this workstation and the primary domain failed", 4625 status 0xC000018D) while the DC is reachable and the same accounts work elsewhere. Test-ComputerSecureChannel returns False, nltest /sc_verify reports ERROR_ACCESS_DENIED with the DC named, NETLOGON 3210 in the System log. Typical after a snapshot revert or a reset of the computer account.',
      check: 'Test-ComputerSecureChannel; nltest /sc_verify:<domain>; Get-WinEvent -LogName System (NETLOGON 3210); on the DC Get-ADComputer <name> and Security 4724 for <NAME>$.',
    },
    {
      id: 'dom-account-locked', title: 'Domain account locked out', category: 'Authentication', concept: 'ad.kerberos',
      signature: 'Logons with the correct password are refused with "account locked out" (FreeRDP ERRCONNECT_ACCOUNT_LOCKED_OUT, status 0xC0000234). Get-ADUser <user> -Properties LockedOut shows True; the DC logged 4740 naming the computer that relayed the bad passwords. Often a device with saved old credentials.',
      check: 'Search-ADAccount -LockedOut; Get-ADUser <user> -Properties LockedOut, BadLogonCount; Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4740} on the DC; 4625 events (source address) on the relaying server.',
    },
    {
      id: 'dom-group-membership', title: 'User missing from the AD group that grants the logon right', category: 'Authorization', concept: 'win.rdp',
      signature: 'Authentication succeeds, then the logon is refused (ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES, 4625 Logon Type 10 status 0xC000015B). The server\'s local Remote Desktop Users group contains a domain group, and the user is no longer a member of that group in AD (Security 4729 on the DC).',
      check: 'Get-LocalGroupMember "Remote Desktop Users" on the server; Get-ADGroupMember <group> and Get-ADPrincipalGroupMembership <user> on the DC.',
    },
    {
      id: 'pf-forward-no-rule', title: 'pfSense port forward without a filter rule for the translated destination', category: 'Firewall', concept: 'pfsense.nat',
      signature: 'Connections to the published address time out from outside; inside they work. pfctl -sn shows the rdr, but the firewall log shows the default deny on WAN with the destination already translated to the inside server. The port forward has no associated rule (no link icon) and Firewall > Rules > WAN has no pass to the server.',
      check: 'Status > System Logs > Firewall (or tail /var/log/filter.log); pfctl -sn; pfctl -sr | grep vtnet0; Firewall > NAT > Port Forward: filter rule association.',
    },
    {
      id: 'pf-rule-order', title: 'pfSense block rule above the pass rule it should leave room for (first match wins)', category: 'Firewall', concept: 'pfsense.rules',
      signature: 'One kind of traffic that a pass rule should allow is blocked, and the firewall log names a block rule of the same interface, not the default deny. In the rule list (or pfctl -vvsr) the block is above the pass, whose counters stay at 0.',
      check: 'The firewall log entry\'s rule; Firewall > Rules > <interface> order; pfctl -vvsr (evaluations and packets per rule).',
    },
    {
      id: 'pf-outbound-manual', title: 'pfSense manual outbound NAT has no mapping for the network', category: 'Configuration', concept: 'pfsense.nat',
      signature: 'One internal network cannot reach the Internet while others can and DNS works. Nothing is blocked in the firewall log; pfctl -ss shows the connection leaving WAN with its private source address. Firewall > NAT > Outbound is in Manual mode and no mapping covers that network.',
      check: 'Firewall > NAT > Outbound (mode and mappings); pfctl -sn (nat on the WAN interface: which sources?); pfctl -ss for the client.',
    },
    {
      id: 'pf-alias-wrong', title: 'pfSense alias holds a wrong address', category: 'Configuration', concept: 'pfsense.rules',
      signature: 'Rules and NAT entries look right in the lists (they name an alias) but act on the wrong host: pfctl -sn / -ss show the translation or match to an unexpected address, and pfctl -t <ALIAS> -T show lists it. Recent alias edits in the config history.',
      check: 'pfctl -t <ALIAS> -T show; Firewall > Aliases; pfctl -sn and pfctl -ss for the connection; Diagnostics > Backup & Restore > Config History.',
    },
    {
      id: 'pf-rule-source', title: 'pfSense rule matches only the interface\'s own subnet ("LAN net"), not the networks routed behind it', category: 'Firewall', concept: 'pfsense.rules',
      signature: 'Hosts directly on the interface\'s subnet pass, hosts on networks routed to the firewall through that interface are blocked by the default deny (firewall log: blocked on that interface, source in a routed network). The pass rule\'s source is the "<interface> net" macro.',
      check: 'Firewall log entries (source address, interface, rule); Firewall > Rules > <interface> source; pfctl -sr | grep <interface>.',
    },
    {
      id: 'score-password-changed', title: 'The account\'s password was changed (no longer the one the client uses)', category: 'Authentication', concept: 'ssh.userauth',
      signature: 'Password logins with the expected password fail; the server logs "Failed password for <user>" and "pam_unix(sshd:auth): authentication failure". The journal shows a password change (chpasswd / passwd: "password changed for <user>") around the time the failures started. Go clients: "unable to authenticate, attempted methods [none password]".',
      check: 'journalctl -u ssh -n 30; journalctl -t chpasswd -t passwd; try the expected password on the console (su - <user>).',
    },
    {
      id: 'pam-faillock-lockout', title: 'Account locked by pam_faillock after repeated failures', category: 'Authentication', concept: 'ssh.userauth',
      signature: 'Even the correct password fails. The server logs "pam_faillock(sshd:auth): Consecutive login failures for user <user> account temporarily locked" and no pam_unix check. faillock --user <user> lists recent failures (often from one source). With a non-zero unlock_time the failures are intermittent.',
      check: 'faillock --user <user>; cat /etc/security/faillock.conf (deny, unlock_time); grep pam_faillock /etc/pam.d/common-auth; journalctl -u ssh.',
    },
    {
      id: 'root-login-prohibited', title: 'PermitRootLogin forbids password logins for root (no / prohibit-password)', category: 'Authorization', concept: 'ssh.config',
      signature: 'Only root fails; password authentication is offered but every password is refused. The log shows "Failed password for root" without a pam_unix line ("ROOT LOGIN REFUSED" with PermitRootLogin no). sshd -T -C user=root,host=..,addr=.. shows permitrootlogin no or prohibit-password.',
      check: 'sshd -T -C user=root,host=<client>,addr=<ip> | grep -i permitrootlogin; grep -ri permitrootlogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/.',
    },
    {
      id: 'account-expired', title: 'Account expired (chage -E / /etc/shadow expiry date in the past)', category: 'Authorization', concept: 'ssh.userauth',
      signature: 'Authentication succeeds, then the server closes the connection: OpenSSH "Your account has expired" / "Connection closed", Go "ssh: handshake failed: EOF". The log shows "pam_unix(sshd:account): account <user> has expired" and "fatal: Access denied for user <user> by PAM account configuration".',
      check: 'chage -l <user> (Account expires); grep <user> /etc/shadow (8th field); journalctl -u ssh.',
    },
    {
      id: 'account-locked', title: 'Password locked (passwd -l / usermod -L)', category: 'Authentication', concept: 'ssh.userauth',
      signature: 'Password logins fail with the right password ("Failed password" + pam_unix authentication failure) while key logins may still work. passwd -S <user> shows L and the /etc/shadow hash starts with "!".',
      check: 'passwd -S <user>; grep <user> /etc/shadow; unlock with passwd -u <user> or usermod -U <user>.',
    },
    {
      id: 'service-masked', title: 'Service unit masked (systemctl mask: linked to /dev/null)', category: 'Service', concept: 'svc.systemd',
      signature: 'The service is down and cannot be started or enabled: "Failed to start X.service: Unit X.service is masked.", systemctl status shows "Loaded: masked", is-enabled prints "masked". It stays down after reboots. Clients get "connection refused".',
      check: 'systemctl status UNIT; systemctl is-enabled UNIT; ls -l /etc/systemd/system/UNIT; fix with systemctl unmask UNIT && systemctl enable --now UNIT.',
    },
    {
      id: 'docker-port-loopback', title: 'Container port published on 127.0.0.1 only', category: 'Configuration', concept: 'docker.networking',
      signature: 'curl on the Docker host (localhost:PORT) works; from any other machine the connection is refused. docker ps shows 127.0.0.1:PORT->…; ss -tlnp shows docker-proxy on 127.0.0.1:PORT only.',
      check: 'docker ps (PORTS column); docker port NAME; the ports: entry in compose.yaml ("127.0.0.1:8000:8000" vs "8000:8000").',
    },
    {
      id: 'docker-service-name', title: 'The app looks for a service name that does not exist on its network', category: 'Name resolution', concept: 'docker.networking',
      signature: 'The container exits at start and keeps restarting ("Restarting (…)"); its log says it cannot resolve the database host ("could not translate host name … to address"). Containers find each other by service/container name only on the same user-defined network.',
      check: 'docker compose ps -a; docker compose logs app; compare DB_HOST in the environment with the service names in compose.yaml; docker exec <db> getent hosts NAME (embedded DNS 127.0.0.11).',
    },
    {
      id: 'docker-host-forward-drop', title: 'Host firewall drops forwarded traffic to containers', category: 'Firewall', concept: 'docker.networking',
      signature: 'Published port times out from other machines although docker ps shows it published and the container answers locally. Traffic to a published port is DNATed and FORWARDED to the container (it never reaches INPUT): a forward chain with policy drop in /etc/nftables.conf blocks it. Restarting nftables also removes Docker\'s own rules until dockerd is restarted.',
      check: 'nft list ruleset (the forward chains of every table); nft list table ip nat (Docker\'s DNAT rules present?); systemctl restart docker after changing nftables.',
    },
    {
      id: 'docker-port-conflict', title: 'Host port already taken by another container', category: 'Service', concept: 'docker.lifecycle',
      signature: 'docker compose up fails with "Bind for 0.0.0.0:PORT failed: port is already allocated"; the service container stays "Created". Something else answers on the port (often a leftover container started by hand).',
      check: 'docker ps -a (which container publishes the port); docker compose up -d output; docker rm -f the leftover, then docker compose up -d.',
    },
    {
      id: 'docker-no-restart-policy', title: 'Containers have no restart policy (gone after a reboot)', category: 'Persistence', concept: 'docker.lifecycle',
      signature: 'Everything worked until the host rebooted (or dockerd restarted); now the containers are "Exited" and nothing listens on the published port. docker inspect shows RestartPolicy "no".',
      check: "docker ps -a; docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' NAME; add restart: unless-stopped to each service and docker compose up -d.",
    },
    {
      id: 'docker-daemon-config', title: 'dockerd does not start (invalid /etc/docker/daemon.json)', category: 'Configuration', concept: 'docker.lifecycle',
      signature: 'Every docker command says "Cannot connect to the Docker daemon … Is the docker daemon running?"; systemctl status docker is failed; journalctl -u docker shows "unable to configure the Docker daemon with file /etc/docker/daemon.json: …".',
      check: 'systemctl status docker; journalctl -u docker -n 20; validate the JSON (dockerd --validate --config-file /etc/docker/daemon.json on a real host).',
    },
    {
      id: 'proxy-upstream-port', title: 'proxy_pass points at a port nothing listens on (502 Bad Gateway)', category: 'Configuration', concept: 'web.proxy',
      signature: 'The proxy answers at once with "502 Bad Gateway"; error.log says "connect() failed (111: Connection refused) while connecting to upstream" and names the upstream address and port. The application answers when you go to it directly on its real port.',
      check: 'tail /var/log/nginx/error.log on the proxy (upstream: "http://IP:PORT/..."); ss -tlnp on the backend; curl the upstream URL from the proxy host itself.',
    },
    {
      id: 'proxy-uri-rewrite', title: 'proxy_pass URI: the location prefix reaches the backend (404 from the application)', category: 'Configuration', concept: 'web.proxy',
      signature: 'The proxy works but every page is "404 Not Found"; the body is the application\'s own (JSON, framework error page), not nginx\'s. Without a URI part ("proxy_pass http://app:8000;") nginx passes /prefix/path unchanged; with one ("http://app:8000/") it replaces the matched prefix.',
      check: 'The backend\'s access log (docker logs, app log) shows which path it received; compare location and proxy_pass in nginx.conf (trailing slash).',
    },
    {
      id: 'proxy-upstream-unresolvable', title: 'Upstream host name does not resolve: nginx refuses to start', category: 'Configuration', concept: 'web.proxy',
      signature: 'nginx is failed after a restart or reboot, so every site on that server is down (connection refused); journalctl -u nginx and nginx -t show "[emerg] host not found in upstream \"NAME:PORT\"". nginx resolves proxy_pass names once, when it loads the configuration; a failed reload keeps the old configuration running, which hides the error until the next restart.',
      check: 'nginx -t; journalctl -u nginx -n 20; getent hosts NAME on the proxy.',
    },
    {
      id: 'proxy-backend-acl', title: 'Backend firewall does not allow the proxy (504 Gateway Time-out)', category: 'Firewall', concept: 'web.proxy',
      signature: 'The proxy answers "504 Gateway Time-out" after its proxy_connect_timeout (60 s by default); error.log says "upstream timed out (110: Connection timed out) while connecting to upstream". The backend works from client machines: its firewall allows them but not the proxy\'s address, which is the source of proxied connections.',
      check: 'nc -zv -w 3 BACKEND PORT from the proxy host (times out) and from a client (works); nft list ruleset on the backend (which sources are accepted).',
    },
    {
      id: 'proxy-upstream-scheme', title: 'proxy_pass https:// to a backend that speaks plain HTTP (502)', category: 'Configuration', concept: 'web.proxy',
      signature: '"502 Bad Gateway" at once; error.log says "SSL_do_handshake() failed (SSL: … wrong version number) while SSL handshaking to upstream": nginx started a TLS handshake and got an HTTP answer back.',
      check: 'error.log on the proxy; curl -v http://BACKEND:PORT/ vs curl -v https://BACKEND:PORT/ from the proxy host.',
    },
    {
      id: 'ntp-server-firewall', title: 'Firewall drops NTP (UDP 123) to the time server', category: 'Firewall', concept: 'ntp.sync',
      signature: 'Clients log "Timed out waiting for reply from IP:123" (systemd-timesyncd) or show "^?" with Reach 0 (chronyc sources); timedatectl says "System clock synchronized: no" while the NTP service is active. On the server, tcpdump shows the requests arriving and no replies, chronyd does not count them (chronyc clients), and the input chain has no accept rule for udp dport 123.',
      check: 'journalctl -u systemd-timesyncd on a client; tcpdump -n udp port 123 and nft list ruleset on the server; chronyc clients.',
    },
    {
      id: 'ntp-allow-missing', title: 'chrony does not serve the client\'s network (no allow line)', category: 'Authorization', concept: 'ntp.sync',
      signature: 'Clients of one network time out while other networks are synchronized by the same server. The requests reach chronyd (tcpdump on the server, the firewall accepts them), but chronyd drops them silently: chronyc clients lists the client with a growing Drop count, and chrony.conf has no allow line covering it.',
      check: 'chronyc clients (root) and the allow/deny lines in /etc/chrony/chrony.conf on the server; tcpdump -n udp port 123.',
    },
    {
      id: 'ntp-upstream-unreachable', title: 'The time server itself is not synchronized (no usable upstream)', category: 'Network path', concept: 'ntp.sync',
      signature: 'Clients receive replies but stay unsynchronized and log no error: timedatectl timesync-status shows "Leap: not synchronized" and stratum 16 from the server. On the server, chronyc tracking shows Reference ID 00000000 / Leap status Not synchronised, chronyc sources shows the upstream as "^?" with Reach 0, and the journal says "Can\'t synchronise: no selectable sources".',
      check: 'timedatectl timesync-status on a client; chronyc tracking, chronyc sources and journalctl -u chrony on the server; the server/pool lines in chrony.conf.',
    },
    {
      id: 'ntp-server-down', title: 'chronyd is not running on the time server', category: 'Service', concept: 'ntp.sync',
      signature: 'No client synchronizes; the server\'s kernel answers requests with ICMP port unreachable (nothing on UDP 123 in ss -ulnp). systemctl status chrony shows failed, and journalctl -u chrony gives the reason (for example "Fatal error : Invalid directive at line N").',
      check: 'systemctl status chrony; journalctl -u chrony -n 20; ss -ulnp on the server.',
    },
    {
      id: 'syslog-receiver-firewall', title: 'The log server\'s firewall drops syslog (514)', category: 'Firewall', concept: 'logs.central',
      signature: 'Nothing new arrives from any sender; the senders\' rsyslog logs "cannot connect to LOGSERVER:514: Connection timed out" and suspends its forwarding action. On the log server rsyslogd listens on 514 (ss -tulnp) but the input chain has no rule for it, and tcpdump shows SYNs without replies.',
      check: 'journalctl -u rsyslog on a sender; ss -tulnp, nft list ruleset and tcpdump -n port 514 on the log server.',
    },
    {
      id: 'syslog-protocol-mismatch', title: 'Sender forwards over UDP (@) to a TCP-only receiver', category: 'Configuration', concept: 'logs.central',
      signature: 'One sender is missing on the log server and logs no error at all: its rule uses a single "@" (UDP) while the receiver only has imtcp. The receiver answers the datagrams with ICMP port unreachable, which rsyslog ignores.',
      check: 'Compare the forwarding lines (@ = UDP, @@ or protocol="tcp" = TCP) with the receiver\'s inputs (ss -tulnp); tcpdump -n port 514 on the receiver.',
    },
    {
      id: 'syslog-selector-excludes', title: 'Forwarding selector leaves out some facilities (e.g. auth,authpriv.none)', category: 'Configuration', concept: 'logs.central',
      signature: 'A sender\'s messages arrive, except for some programs: sshd (auth), sudo/PAM (authpriv)... The selector of the forwarding rule excludes their facilities ("*.*;auth,authpriv.none"); the sender still writes them locally.',
      check: 'The selector in front of the forwarding action; compare ls /var/log/remote/HOST/ on the log server with the sender\'s local files; logger -p authpriv.notice test.',
    },
    {
      id: 'syslog-input-missing', title: 'Log server has no input on 514 (module not loaded)', category: 'Service', concept: 'logs.central',
      signature: 'rsyslogd on the log server is active and writes its own logs, but nothing listens on 514: senders are refused ("Connection refused", action suspended). rsyslogd -N1 / the journal show "input module name \'imtcp\' is unknown" (input() without module(load=...)) or the input lines are missing.',
      check: 'ss -tulnp and rsyslogd -N1 on the log server; journalctl -u rsyslog.',
    },
    {
      id: 'nfs-exports-not-loaded', title: '/etc/exports edited but the export table was not reloaded (exportfs -ra)', category: 'Service', concept: 'files.nfs',
      signature: 'A client listed in /etc/exports is refused ("mount.nfs4: access denied by server while mounting"), while exportfs -v on the server does not show the new entry. The NFS server reads /etc/exports only when it starts or when exportfs -ra / exportfs -r runs.',
      check: 'Compare cat /etc/exports with exportfs -v (or showmount -e) on the server; the mount error on the client.',
    },
    {
      id: 'nfs-root-squash', title: 'root on the client is squashed to nobody (root_squash)', category: 'Permissions', concept: 'files.nfs',
      signature: 'The share is mounted read-write and ordinary users can write, but root on the client gets "Permission denied": the server maps UID 0 to nobody (65534), which has no write permission on the exported directory. exportfs -v shows root_squash.',
      check: 'exportfs -v on the server (root_squash / no_root_squash); ls -ln of the exported directory; id on the client; which user the failing job runs as.',
    },
    {
      id: 'nfs-firewall', title: 'The NFS server\'s firewall drops NFS (TCP 2049)', category: 'Firewall', concept: 'files.nfs',
      signature: 'Mounts hang and fail with "Connection timed out"; showmount -e reports "RPC: Timed out". The server listens on 2049 (ss -tlnp) and exports the share (exportfs -v), but the input chain has no accept rule for 2049/111, and tcpdump shows SYNs without replies.',
      check: 'mount -a / journalctl -b on the client; ss -tlnp, exportfs -v, nft list ruleset and tcpdump -n port 2049 on the server.',
    },
    {
      id: 'nfs-uid-mismatch', title: 'The same user has different UIDs on client and server', category: 'Permissions', concept: 'files.nfs',
      signature: 'A user can read the share but gets "Permission denied" writing where the same user can write on the server, and ls -l on the client shows numbers or another user\'s name as owner. NFS (sec=sys) sends numeric UIDs: id alice differs between the two hosts.',
      check: 'id USER on client and server; ls -ln on the mount and on the server.',
    },
    {
      id: 'smb-no-passdb', title: 'The user has a Unix account but no Samba password (smbpasswd -a missing)', category: 'Authentication', concept: 'files.smb',
      signature: 'Every attempt fails at session setup ("NT_STATUS_LOGON_FAILURE", Windows: "System error 1326 ... user name or password is incorrect") even with the right password, while other users connect. The server log (auth_audit) says status [NT_STATUS_NO_SUCH_USER], and pdbedit -L does not list the user: Samba keeps its own password database, separate from /etc/shadow.',
      check: 'pdbedit -L on the server; the Auth: line in /var/log/samba/log.CLIENT (NO_SUCH_USER versus WRONG_PASSWORD).',
    },
    {
      id: 'smb-wrong-password', title: 'The user types the wrong password', category: 'Authentication', concept: 'files.smb',
      signature: 'Session setup fails with NT_STATUS_LOGON_FAILURE; the server log shows status [NT_STATUS_WRONG_PASSWORD] for a user that pdbedit -L lists.',
      check: 'The Auth: line in /var/log/samba/log.CLIENT; pdbedit -L.',
    },
    {
      id: 'smb-valid-users', title: 'The share\'s "valid users" does not include the user (group membership)', category: 'Authorization', concept: 'files.smb',
      signature: 'The logon succeeds (smbclient -L works) but connecting to one share fails with "tree connect failed: NT_STATUS_ACCESS_DENIED" (Windows: System error 5, Access is denied). The server log says "user \'X\' (from session setup) not permitted to access this share"; the share has valid users = @group and id X on the server does not list that group.',
      check: 'testparm -s (valid users of the share); id USER on the server; /var/log/samba/log.CLIENT.',
    },
    {
      id: 'smb-share-path', title: 'The share\'s path does not exist on the server', category: 'Configuration', concept: 'files.smb',
      signature: 'The share is listed (smbclient -L) but connecting to it fails with "tree connect failed: NT_STATUS_BAD_NETWORK_NAME" (Windows: System error 67, The network name cannot be found). The server log says "canonicalize_connect_path failed for service X, path /..." and the path in smb.conf differs from the real directory (often only in case).',
      check: 'testparm -s (path); ls -ld of that path on the server; /var/log/samba/log.CLIENT.',
    },
    {
      id: 'smb-read-only', title: 'The share is read-only ("read only = yes" is Samba\'s default)', category: 'Configuration', concept: 'files.smb',
      signature: 'Users connect and can list and read, but every write fails with "NT_STATUS_ACCESS_DENIED opening remote file" although the Unix permissions of the directory allow that user to write. testparm -s shows no "read only = No" (or writable = yes) for the share.',
      check: 'testparm -s for the share; ls -ld of its path on the server.',
    },
    {
      id: 'gpo-wrong-ou', title: 'The computer object is not in the OU the GPO is linked to', category: 'Configuration', concept: 'ad.gpo',
      signature: 'gpupdate succeeds but the setting never arrives; gpresult /r lists only Default Domain Policy, and the computer\'s DN under COMPUTER SETTINGS is CN=...,CN=Computers,... while the GPO is linked to an OU (Get-GPInheritance on that OU lists it). Joining without -OUPath puts computers in the Computers container, where no GPO can be linked.',
      check: 'gpresult /r on the member (its DN and applied GPOs); Get-ADComputer NAME; Get-GPInheritance -Target "OU=...".',
    },
    {
      id: 'gpo-filter-token', title: 'Security filtering: the computer\'s new group membership is not in its token yet (restart needed)', category: 'Authorization', concept: 'ad.gpo',
      signature: 'The GPO is filtered to a group (Authenticated Users only has GpoRead) and the computer was added to that group, yet gpresult /r keeps listing the GPO as "Filtering: Denied (Security)" and the group is missing from "The computer is a part of the following security groups". A computer\'s groups come from its Kerberos ticket, obtained at startup: gpupdate /force does not refresh them.',
      check: 'Get-GPPermission -All on the GPO; Get-ADGroupMember on the filter group; the security groups at the end of gpresult /r; when the computer last started.',
    },
    {
      id: 'gpo-blocked-inheritance', title: 'Block Inheritance on the OU stops a domain-level GPO', category: 'Configuration', concept: 'ad.gpo',
      signature: 'A GPO linked to the domain root no longer applies to computers in one OU: gpresult /r there lists neither it nor the other domain GPOs (only Default Domain Policy if enforced, or nothing from the domain). Get-GPInheritance on the OU shows GpoInheritanceBlocked: Yes; the GPO is missing from InheritedGpoLinks.',
      check: 'Get-GPInheritance -Target "OU=..." (GpoInheritanceBlocked, InheritedGpoLinks); the domain\'s links; whether the link is enforced.',
    },
    {
      id: 'gpo-sysvol-unreachable', title: 'Members cannot read SYSVOL on the DC (SMB 445 blocked)', category: 'Firewall', concept: 'ad.gpo',
      signature: 'gpupdate /force: "Computer policy could not be updated successfully ... Windows attempted to read the file \\\\ad.corp.lab\\sysvol\\...\\gpt.ini from a domain controller and was not successful"; event 1058 in the System log. Logons and DC location work (LDAP, Kerberos), but TCP 445 to the DC is dropped: the DC\'s File and Printer Sharing (SMB-In) rule was disabled.',
      check: 'gpupdate /force and Get-WinEvent -LogName System on the member; Test-NetConnection DC -Port 445; Get-NetFirewallRule -Name FPS-SMB-In-TCP on the DC.',
    },
    {
      id: 'wfw-program-mismatch', title: 'The allow rule names a program that does not own the listening socket', category: 'Firewall', concept: 'win.firewall',
      signature: 'Connections time out although an enabled Allow rule covers the port and address. Get-NetFirewallApplicationFilter on the rule shows a Program (for example w3wp.exe), while Get-NetTCPConnection -State Listen shows the port owned by another process: for IIS and WinRM that is System (PID 4, http.sys). With LogBlocked on, pfirewall.log has DROP lines for the port.',
      check: 'Get-NetFirewallRule ... | Get-NetFirewallApplicationFilter; Get-NetTCPConnection -LocalPort <port> -State Listen (OwningProcess); pfirewall.log.',
    },
    {
      id: 'wfw-block-precedence', title: 'A Block rule matches the traffic, and Block wins over every Allow rule', category: 'Firewall', concept: 'win.firewall',
      signature: 'An enabled Allow rule matches the packets, yet they are dropped: an enabled Block rule matches them too (often added "after" the allow, expecting rule order to count). Windows Defender Firewall has no rule order: Block beats Allow.',
      check: 'Get-NetFirewallRule -Action Block -Enabled True with its port and address filters; pfirewall.log DROP lines for the port.',
    },
    {
      id: 'wfw-remote-scope', title: 'The allow rule\'s RemoteAddress does not include the real sender', category: 'Firewall', concept: 'win.firewall',
      signature: 'Only one client (or one network) is dropped; others get through the same rule. Get-NetFirewallAddressFilter on the rule shows a RemoteAddress that does not contain the sender\'s address, which pfirewall.log DROP lines show as src-ip.',
      check: 'pfirewall.log (src-ip of the DROP lines); Get-NetFirewallRule ... | Get-NetFirewallAddressFilter.',
    },
    {
      id: 'wfw-outbound-default', title: 'Default outbound action Block, with no outbound rule for the connection the server makes', category: 'Firewall', concept: 'win.firewall',
      signature: 'Connections that the server itself starts fail (Test-NetConnection, net use, updates), while every inbound service works and other machines reach the same destination. Get-NetFirewallProfile shows DefaultOutboundAction Block; pfirewall.log has DROP lines with path SEND.',
      check: 'Get-NetFirewallProfile | Format-Table Name, DefaultOutboundAction; Get-NetFirewallRule -Direction Outbound -Enabled True | Get-NetFirewallPortFilter; Test-NetConnection <dest> -Port <port>.',
    },
    {
      id: 'wfw-local-rules-ignored', title: 'Group Policy sets AllowLocalFirewallRules False: local rules do not count', category: 'Firewall', concept: 'win.firewall',
      signature: 'A local rule is enabled and correct but has no effect; rules delivered by Group Policy work. Get-NetFirewallProfile -PolicyStore ActiveStore shows AllowLocalFirewallRules False (the default local view says NotConfigured), and Get-NetFirewallRule -PolicyStore RSOP has no rule for the port.',
      check: 'gpresult /r; Get-NetFirewallProfile -PolicyStore ActiveStore; Get-NetFirewallRule -PolicyStore RSOP; on the DC, the GPO\'s firewall rules and profile settings.',
    },
    {
      id: 'gpo-link-disabled', title: 'The GPO link is disabled', category: 'Configuration', concept: 'ad.gpo',
      signature: 'The GPO is linked to the right OU but Get-GPInheritance / Get-GPO shows the link with Enabled: False; gpresult does not list the GPO at all.',
      check: 'Get-GPInheritance -Target "OU=..."; Set-GPLink -LinkEnabled Yes.',
    },
    {
      id: 'krb-w32time-disabled', title: 'The Windows Time service is disabled on the member: its clock drifted beyond Kerberos\'s 5 minutes', category: 'Service', concept: 'ad.kerberos',
      signature: 'NLA succeeds (+auth-only works, NTLM does not care about time), but the logon itself fails with "There is a time and/or date difference between the client and server."; gpupdate fails with "LDAP Bind function call failed" (1006); LsaSrv 40960 names 0xc0000133. Get-Date on the member is minutes off the DC, w32tm /query reports "The service has not been started", and Get-Service W32Time shows Stopped/Disabled.',
      check: 'Get-Date on both; w32tm /stripchart /computer:dc01 /samples:1 /dataonly; Get-Service W32Time; Get-WinEvent -LogName System (40960, 1006).',
    },
    {
      id: 'krb-dc-ntp-blocked', title: 'The DC\'s firewall drops NTP (UDP 123): members cannot synchronise their clocks', category: 'Firewall', concept: 'ad.kerberos',
      signature: 'The member\'s W32Time runs, but w32tm /resync says "The computer did not resync because no time data was available." and the System log has Time-Service 47 (no valid response from the DC). w32tm /stripchart to the DC shows error 0x800705B4 (timeout). Its clock drifted past 5 minutes, so Kerberos fails with clock skew (0xc0000133). On the DC the rule "Active Directory Domain Controller - W32Time (NTP-UDP-In)" is disabled.',
      check: 'w32tm /resync and w32tm /stripchart /computer:dc01 on the member; Get-NetFirewallRule -DisplayName "*W32Time*" on the DC.',
    },
    {
      id: 'krb-dc-kdc-blocked', title: 'The DC\'s firewall drops Kerberos (TCP/UDP 88)', category: 'Firewall', concept: 'ad.kerberos',
      signature: 'DC location works (DNS, LDAP 389), logons still succeed because Negotiate falls back to NTLM (4624 shows Package Name NTLM V2), but nothing Kerberos-only works: gpupdate fails with "Windows could not resolve the computer name" (1055), klist -li 0x3e7 get krbtgt fails with 0xc000005e (no logon servers), Test-NetConnection DC -Port 88 fails. On the DC the Kerberos Key Distribution Center firewall rules are disabled while the Kdc service runs.',
      check: 'klist -li 0x3e7 get krbtgt and Test-NetConnection dc01 -Port 88 on the member; Get-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center" and Get-Service Kdc on the DC.',
    },
    {
      id: 'krb-kdc-stopped', title: 'The KDC service (Kerberos Key Distribution Center) is stopped on the DC', category: 'Service', concept: 'ad.kerberos',
      signature: 'Same symptoms as a blocked port 88 (logons fall back to NTLM, Group Policy fails with 1055, klist get fails with 0xc000005e), but Test-NetConnection DC -Port 88 is refused at once rather than timing out, the firewall rules are enabled, and on the DC Get-Service Kdc shows Stopped (Disabled).',
      check: 'Get-Service Kdc on the DC (StartType too); Test-NetConnection dc01 -Port 88 on the member; netstat -ano on the DC (nothing on :88).',
    },
    {
      id: 'mail-aliases-not-rebuilt', title: '/etc/aliases was edited but newaliases was not run', category: 'Configuration', concept: 'mail.smtp',
      signature: 'Mail to the new address is rejected at RCPT TO with "550 5.1.1 ... User unknown in local recipient table" although the alias is in /etc/aliases. Postfix reads the compiled /etc/aliases.db (hash:/etc/aliases), which is older than the text file: postfix check warns "database /etc/aliases.db is older than source file /etc/aliases".',
      check: 'postfix check; ls -l --time-style=full-iso /etc/aliases /etc/aliases.db; postconf alias_maps.',
    },
    {
      id: 'mail-unknown-recipient', title: 'The address does not exist (typing error, account never created)', category: 'Client', concept: 'mail.smtp',
      signature: '550 5.1.1 User unknown in local recipient table for an address that is neither a Unix account nor in /etc/aliases at all; other addresses work.',
      check: 'getent passwd NAME and grep NAME /etc/aliases on the mail server; the exact address in the rejection.',
    },
    {
      id: 'mail-relay-denied', title: 'The client may not relay (not in mynetworks and not logged in)', category: 'Authorization', concept: 'mail.smtp',
      signature: 'Mail for outside domains is refused at RCPT TO with "454 4.7.1 ... Relay access denied" (or 554 5.7.1); mail for the server\'s own domains is accepted. The client sent on port 25 without logging in, or from an address outside mynetworks.',
      check: 'The rejection in mail.log (NOQUEUE: reject: RCPT ... Relay access denied); postconf mynetworks smtpd_relay_restrictions; send through 587 with a login.',
    },
    {
      id: 'mail-inet-interfaces', title: 'Postfix listens on loopback only (inet_interfaces)', category: 'Service', concept: 'mail.smtp',
      signature: 'Connections to ports 25 and 587 are refused immediately from other machines, while Postfix is active and works locally (swaks --server localhost). ss -tlnp shows 127.0.0.1:25 and ::1:25 owned by master. postfix reload does not change it: inet_interfaces only takes effect on stop/start.',
      check: 'ss -tlnp | grep master; postconf inet_interfaces; swaks --server localhost on the server itself.',
    },
    {
      id: 'mail-service-down', title: 'Postfix or Dovecot is not running', category: 'Service', concept: 'svc.systemd',
      signature: 'Connections are refused on every port of that service (25/587 for Postfix, 143/993 for Dovecot); systemctl status shows inactive or failed, with the reason in journalctl -u.',
      check: 'systemctl status postfix dovecot; ss -tlnp; journalctl -u postfix -u dovecot -n 20.',
    },
    {
      id: 'mail-mailbox-location', title: 'Postfix delivers to a different mailbox than Dovecot reads', category: 'Configuration', concept: 'mail.imap',
      signature: 'Senders see success and mail.log says status=sent, but the mail never appears over IMAP. The delivery line says "delivered to mailbox" (mbox in /var/mail) while Dovecot reads maildir:~/Maildir, or the other way round. Older mail is still visible.',
      check: 'The local delivery line in mail.log; postconf home_mailbox mail_spool_directory; doveconf mail_location; ls -l /var/mail ~USER/Maildir/new.',
    },
    {
      id: 'mail-maildir-permissions', title: 'Postfix cannot write into the user\'s Maildir (permissions)', category: 'Permissions', concept: 'linux.permissions',
      signature: 'Mail is accepted but stays in the queue: mail.log says status=deferred (maildir delivery failed: create maildir file ...: Permission denied), and mailq shows the same reason. Local delivery runs as the recipient, who must be able to write ~/Maildir/tmp and new.',
      check: 'mailq; the deferred reason in mail.log; ls -ld ~USER ~USER/Maildir ~USER/Maildir/*.',
    },
    {
      id: 'mail-sasl-socket', title: 'Postfix cannot reach Dovecot\'s auth socket (SMTP AUTH broken)', category: 'Service', concept: 'mail.smtp',
      signature: 'Port 587 accepts the connection and STARTTLS, then drops it; reading mail works. mail.log: "warning: SASL: Connect to private/auth failed: No such file or directory" (or Connection refused) followed by "fatal: no SASL authentication mechanisms". /var/spool/postfix/private/auth is missing, or Dovecot does not have the unix_listener for it under service auth.',
      check: 'ls -l /var/spool/postfix/private/; doveconf -n | grep -A5 "service auth"; postconf smtpd_sasl_type smtpd_sasl_path; tail /var/log/mail.log.',
    },
    {
      id: 'mail-wrong-password', title: 'The user\'s password is wrong', category: 'Authentication', concept: 'mail.imap',
      signature: 'SMTP AUTH answers 535 5.7.8 authentication failed, or IMAP NO [AUTHENTICATIONFAILED]; doveadm auth test USER fails with the password the user typed and succeeds with the right one. The log has pam_unix authentication failure lines for that user.',
      check: 'doveadm auth test USER; grep "auth failed\\|authentication failure" /var/log/mail.log /var/log/auth.log.',
    },
    {
      id: 'mail-tls-keypair', title: 'The TLS certificate and key configured in Postfix do not match (STARTTLS disabled)', category: 'Cryptography', concept: 'tls.pki',
      signature: 'The EHLO reply has no STARTTLS and port 587 cannot be used ("Host did not advertise STARTTLS", Outlook: the server does not support secure connections). Postfix keeps running: each smtpd logs "cannot get RSA private key from file ...: disabling TLS support" and "key values mismatch". The moduli of smtpd_tls_cert_file and smtpd_tls_key_file differ.',
      check: 'postconf smtpd_tls_cert_file smtpd_tls_key_file; openssl x509 -noout -modulus / openssl rsa -noout -modulus (md5 of each); openssl s_client -starttls smtp -connect HOST:587.',
    },
    {
      id: 'mail-relayhost-unresolvable', title: 'The next hop (relayhost) does not resolve', category: 'Name resolution', concept: 'mail.smtp',
      signature: 'Outside mail is accepted and then waits in the deferred queue; nothing bounces for days. mailq and mail.log give the reason "Host or domain name not found. Name service error for name=... type=A". Internal mail is unaffected. Postfix\'s SMTP client asks DNS directly, so /etc/hosts does not help.',
      check: 'mailq; postconf relayhost; dig NAME on the mail server.',
    },
    {
      id: 'mail-relay-unreachable', title: 'The relay or the remote mail server cannot be reached (down, firewall, wrong port)', category: 'Network path', concept: 'mail.smtp',
      signature: 'Outside mail waits in the deferred queue with "connect to HOST[IP]:25: Connection timed out", "Connection refused" or "No route to host": the name resolves, but no SMTP session starts.',
      check: 'mailq; swaks --server RELAY --quit-after banner from the mail server; nc -vz RELAY 25.',
    },
    {
      id: 'db-listen-localhost', title: 'PostgreSQL listens on localhost only (listen_addresses)', category: 'Service', concept: 'db.access',
      signature: 'Clients on other machines get "Connection refused" on port 5432 while psql on the server itself works. ss -tlnp shows postgres on 127.0.0.1:5432 and [::1]:5432 only; SHOW listen_addresses says localhost (the default). A reload does not change it: the log says the parameter cannot be changed without restarting the server.',
      check: 'ss -tlnp | grep 5432 on the server; SHOW listen_addresses; grep listen_addresses /etc/postgresql/15/main/postgresql.conf conf.d/*.',
    },
    {
      id: 'db-hba-no-entry', title: 'No pg_hba.conf line matches the client (host, user, database)', category: 'Authorization', concept: 'db.access',
      signature: '"FATAL:  no pg_hba.conf entry for host \"IP\", user \"U\", database \"D\"" (twice with sslmode=prefer: SSL encryption, then no encryption). The server answers, but no line allows that combination; the password is never asked.',
      check: 'Read pg_hba.conf top to bottom (or SELECT * FROM pg_hba_file_rules as superuser) for a line matching type, database, user and the client address.',
    },
    {
      id: 'db-missing-grant', title: 'The role lacks a privilege on the table (GRANT missing)', category: 'Authorization', concept: 'db.admin',
      signature: 'The login works and other tables work, but statements on one table fail with "ERROR:  permission denied for table T" (pg_dump: "query failed: ERROR: permission denied for table T" at LOCK TABLE). \dp shows no entry for the role on that table, typically a newly created one.',
      check: '\dp TABLE in psql; compare with the tables that work; \ddp for default privileges.',
    },
    {
      id: 'db-md5-secret', title: 'The role\'s password is stored as MD5, but pg_hba.conf requires scram-sha-256', category: 'Authentication', concept: 'db.access',
      signature: '"password authentication failed" although the password is right. The server log DETAIL says "User \"U\" does not have a valid SCRAM secret."; pg_authid.rolpassword starts with md5. Typical after a migration from an older server.',
      check: 'Server log DETAIL line; SELECT rolname, rolpassword FROM pg_authid WHERE rolname = \'U\'; (superuser).',
    },
    {
      id: 'db-wrong-password', title: 'Wrong password (or an outdated ~/.pgpass entry)', category: 'Authentication', concept: 'db.access',
      signature: '"FATAL:  password authentication failed for user \"U\"" and the server log DETAIL "Password does not match for user \"U\"." (or "Role \"U\" does not exist."). Other users connect fine.',
      check: 'Server log DETAIL; the matching line in the client\'s ~/.pgpass (host:port:db:user:password, mode 0600).',
    },
    {
      id: 'db-connect-privilege', title: 'The role may not connect to the database (CONNECT privilege)', category: 'Authorization', concept: 'db.admin',
      signature: '"FATAL:  permission denied for database \"D\"" with "DETAIL:  User does not have CONNECT privilege." after successful authentication. \l shows the database\'s access privileges without the role (and without PUBLIC).',
      check: '\l in psql (Access privileges column); GRANT CONNECT ON DATABASE D TO ROLE.',
    },
    {
      id: 'bk-timer-invalid', title: 'The backup timer has no valid schedule (systemd refused its OnCalendar=)', category: 'Configuration', concept: 'bk.schedule',
      signature: 'The job is missing from systemctl list-timers; systemctl status of the timer shows failed (Result: resources) and the journal "Failed to parse calendar specification, ignoring: …" plus "Timer unit lacks value setting. Refusing."',
      check: 'systemctl list-timers; systemctl status NAME.timer; systemd-analyze calendar "SPEC" for each OnCalendar= line.',
    },
    {
      id: 'bk-timer-disabled', title: 'The backup timer is disabled or stopped', category: 'Persistence', concept: 'bk.schedule',
      signature: 'The timer is not in systemctl list-timers; systemctl is-enabled says disabled and is-active inactive; the unit files are fine.',
      check: 'systemctl is-enabled NAME.timer; systemctl is-active NAME.timer; systemctl list-timers --all.',
    },
    {
      id: 'bk-hostkey-changed', title: 'The backup server\'s SSH host key changed (known_hosts mismatch)', category: 'Cryptography', concept: 'bk.transport',
      signature: 'The job fails before authentication: "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" and "Host key verification failed." from the ssh subprocess; every client of the server fails at once.',
      check: 'journalctl -u the backup unit; ssh-keyscan the server and compare ssh-keygen -lf with the fingerprint published by its administrators.',
    },
    {
      id: 'bk-key-rejected', title: 'The backup server rejects the client\'s SSH key', category: 'Authentication', concept: 'bk.transport',
      signature: '"Permission denied (publickey)" from the ssh subprocess; the server logs a failed publickey login (or "not from a permitted host" for a from= restriction).',
      check: 'The key the job uses (/root/.ssh), the repository user\'s authorized_keys on the server (with its options), and the server\'s sshd log.',
    },
    {
      id: 'bk-stale-lock', title: 'A stale lock in the backup repository', category: 'Service', concept: 'bk.operate',
      signature: '"unable to create lock in backend: repository is already locked … the `unlock` command can be used to remove stale locks" right after the repository is opened; the lock is old and no restic process is running.',
      check: 'The lock\'s age, host and PID in the message; ps on that host; the repository\'s locks/ directory.',
    },
    {
      id: 'bk-envfile-missing', title: 'The backup unit\'s EnvironmentFile= is missing', category: 'Configuration', concept: 'bk.schedule',
      signature: 'The service fails instantly with Result=resources: "Failed to load environment files: No such file or directory", and the backup program never runs.',
      check: 'systemctl cat the unit (EnvironmentFile=); ls the file; systemctl status for the result.',
    },
    {
      id: 'bk-wrong-password', title: 'Wrong or unreadable repository password', category: 'Authentication', concept: 'bk.operate',
      signature: '"Fatal: wrong password or no key found", or "Readfile: open …: permission denied" / "… does not exist" for the password file.',
      check: 'RESTIC_PASSWORD_FILE in the environment file, the password file\'s owner and mode, and restic snapshots run by hand with the same settings.',
    },
    {
      id: 'bk-disk-full', title: 'The backup storage is full', category: 'Service', concept: 'bk.operate',
      signature: 'Writes fail on the server: "no space left on device" (local) or sftp "Failure" (SSH_FX_FAILURE) while saving; all clients of the server fail on the same night.',
      check: 'df -h and du -sh on the backup server; restic stats for the repositories; the retention (forget --prune) of each job.',
    },
    {
      id: 'bk-file-deleted', title: 'Data was deleted or changed by a user (restore needed)', category: 'Configuration', concept: 'bk.restore',
      signature: 'Nothing fails: a file or directory is missing or wrong, and the backups still contain the earlier version.',
      check: 'restic snapshots; restic ls SNAPSHOT PATH to find the version; restore to a separate target and compare.',
    },
    {
      id: 'bk-exclude-too-broad', title: 'An exclude pattern drops data that must be backed up', category: 'Configuration', concept: 'bk.restore',
      signature: 'Backups succeed but restic ls shows the directory without the file; the exclude file or --exclude has a pattern that matches it (a pattern without "/" matches names anywhere).',
      check: 'restic ls latest PATH versus ls on the server; the excludes the job uses; a test restore.',
    },
    {
      id: 'db-firewall', title: 'The database server\'s firewall drops PostgreSQL (TCP 5432)', category: 'Firewall', concept: 'fw.path',
      signature: 'Clients hang and fail with "Connection timed out"; pg_isready reports "no response". On the server, PostgreSQL is online and listens on the network (pg_lsclusters, ss -tlnp), but the input chain has no accept rule for 5432 and tcpdump shows SYNs without replies. Nothing appears in the PostgreSQL log.',
      check: 'pg_isready -h SERVER from the client; on the server pg_lsclusters, ss -tlnp | grep 5432, nft list ruleset and tcpdump -n port 5432.',
    },
    {
      id: 'db-service-down', title: 'PostgreSQL is not running', category: 'Service', concept: 'svc.systemd',
      signature: 'Every client is refused (TCP "Connection refused", or for local psql "No such file or directory" on the socket /var/run/postgresql/.s.PGSQL.5432); pg_lsclusters shows down; systemctl status shows failed or inactive, and the log names the reason.',
      check: 'pg_lsclusters; systemctl status postgresql@15-main; journalctl -u postgresql@15-main; tail the cluster log.',
    },
    {
      id: 'db-datadir-perms', title: 'The data directory has the wrong owner or mode (the server refuses to start)', category: 'Permissions', concept: 'db.admin',
      signature: 'The cluster does not start; the log says "FATAL:  data directory \"…\" has wrong ownership" (HINT: started by the user that owns the data directory) or "has invalid permissions" (DETAIL: should be u=rwx (0700) or u=rwx,g=rx (0750)). Typical after copying or restoring files as root.',
      check: 'ls -ld /var/lib/postgresql/15/main and the files under it; the FATAL line in the log.',
    },
    {
      id: 'db-data-deleted', title: 'Rows were deleted or changed by a statement (a data problem, not a service problem)', category: 'Configuration', concept: 'db.admin',
      signature: 'Everything connects and runs, but rows are missing or wrong; queries return fewer rows than expected. The cause is a statement (DELETE/UPDATE without WHERE, a faulty job), not the server.',
      check: 'Count the rows now; compare with the last backup (pg_restore -l, or restore into a scratch database); check log_statement output if enabled.',
    },
    {
      id: 'mon-scrape-blocked', title: 'A firewall blocks the scrape (exporter fine, port unreachable from the monitoring server)', category: 'Firewall', concept: 'mon.metrics',
      signature: 'The target is down in Prometheus with "context deadline exceeded" (drop) or "connection refused"; on the machine itself curl localhost:9100/metrics works and the exporter runs.',
      check: 'The target\'s lastError (curl …/api/v1/targets); curl the exporter from the monitoring server and locally; nft list ruleset on the target.',
    },
    {
      id: 'mon-exporter-down', title: 'The exporter is not running (it failed to start)', category: 'Service', concept: 'mon.metrics',
      signature: 'The target is down with "connect: connection refused"; systemctl status of the exporter shows failed, and the journal names the reason (an unknown flag, a bad listen address).',
      check: 'systemctl status prometheus-node-exporter; journalctl -u prometheus-node-exporter; the ARGS line in /etc/default/prometheus-node-exporter; ss -tlnp.',
    },
    {
      id: 'mon-config-invalid', title: 'An invalid Prometheus configuration or rule file', category: 'Configuration', concept: 'mon.alerting',
      signature: 'After a restart Prometheus is failed ("Error loading config"); after a reload it keeps running the old configuration ("Error reloading config", prometheus_config_last_reload_successful 0), so changes never take effect.',
      check: 'promtool check config /etc/prometheus/prometheus.yml (it also checks the rule files); journalctl -u prometheus.',
    },
    {
      id: 'mon-notify-failed', title: 'Alertmanager cannot deliver notifications', category: 'Service', concept: 'mon.alerting',
      signature: 'Alerts are firing in Prometheus and active in Alertmanager, but nobody is notified; Alertmanager logs "Notify for alerts failed" with the SMTP (or webhook) error.',
      check: 'journalctl -u prometheus-alertmanager; amtool alert; the receiver and global smtp_* settings; the mail server\'s log.',
    },
    {
      id: 'mon-silenced', title: 'A silence (or inhibition) hides the alert', category: 'Configuration', concept: 'mon.alerting',
      signature: 'The alert fires in Prometheus but amtool alert does not list it (amtool alert -s shows it as suppressed); amtool silence query shows a broad or long silence.',
      check: 'amtool silence query; amtool alert query -s; the inhibit_rules in alertmanager.yml.',
    },
    {
      id: 'mon-alert-true', title: 'The alert is right: the monitored service really has a problem', category: 'Service', concept: 'mon.alerting',
      signature: 'The alert\'s condition is confirmed on the machine itself (a failed job, a full disk, a stopped service); fixing that resolves the alert.',
      check: 'Read the alert\'s expression and labels, then look at the machine and service it names.',
    },
    {
      id: 'snmp-agent-localhost', title: 'snmpd only listens on localhost (agentaddress)', category: 'Configuration', concept: 'mon.snmp',
      signature: 'Every remote SNMP request times out ("Timeout: No Response"), while snmpget on the agent itself works; ss -ulnp shows 127.0.0.1:161 only.',
      check: 'ss -ulnp | grep 161 on the agent; the agentaddress line of /etc/snmp/snmpd.conf.',
    },
    {
      id: 'snmp-access-denied', title: 'The SNMP request is not allowed (community, source or view)', category: 'Authentication', concept: 'mon.snmp',
      signature: 'v2c: "Timeout: No Response" from an agent that is listening (a wrong community or source address is silently dropped), or "No Such Object" for OIDs outside the view. v3: "Unknown user name", "Authentication failure", or authorizationError.',
      check: 'The rocommunity / rouser lines and views in snmpd.conf; the community, user and security level the manager uses.',
    },
  ] as Cause[]).map((c) => [c.id, c]),
);
