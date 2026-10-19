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
  ] as Cause[]).map((c) => [c.id, c]),
);
