import { test } from 'vitest'; import { writeFileSync } from 'node:fs'; import { Lab } from './helpers';
test('x', () => { const l = new Lab(); const out: string[] = [];
const cmds: [string,string,string][] = [
['ws01','alice','ip -br link'],['ws01','alice','ip -br addr'],['ws01','alice','ip route'],['ws01','alice','ip neigh'],['ws01','alice','ip route get 10.0.20.10'],['ws01','alice','ping -c 2 10.0.10.1'],['ws01','alice','traceroute -n 10.0.20.10'],['rtr01','root','sysctl net.ipv4.ip_forward'],['rtr01','root','ip route'],['ws01','alice','cat /etc/network/interfaces'],['ws01','alice','systemctl status networking'],
['ws01','alice','getent hosts srv01.corp.lab'],['ws01','alice','dig +short srv01.corp.lab'],['ws01','alice','cat /etc/nsswitch.conf'],['ns1','root','systemctl status named'],['ns1','root','named-checkzone corp.lab /etc/bind/db.corp.lab'],['ns1','root','rndc reload'],['ns1','root','ss -tulnp'],['ns1','root','journalctl -u named -n 5'],['srv01','root','ss -tan'],
['ns1','root','systemctl status isc-dhcp-server'],['ns1','root','cat /etc/default/isc-dhcp-server'],['ns1','root','cat /etc/dhcp/dhcpd.conf'],['ns1','root','dhcpd -t'],['ns1','root','journalctl -u isc-dhcp-server -n 8'],['ws02','root','dhclient -v eth0'],['ws02','dana','cat /var/lib/dhcp/dhclient.eth0.leases'],['ns1','root','cat /var/lib/dhcp/dhcpd.leases'],
['rtr01','root','nft list table ip nat'],['rtr01','root','conntrack -L'],['ext01','guest','curl -I http://203.0.113.2/'],['rtr01','root','nft list chain inet filter forward'],
['rtr01','root','cat /etc/radvd.conf'],['rtr01','root','systemctl status radvd'],['dev01','erin','ip -6 addr'],['dev01','erin','ip -6 route'],['dev01','erin','ip -6 neigh'],['dev01','erin','rdisc6 eth0'],['dev01','erin','ping -6 -c 2 2001:db8:20::10'],['rtr01','root','sysctl net.ipv6.conf.all.forwarding'],['dev01','erin','curl -6 -I http://srv01.corp.lab/'],
['srv01','root','nft -a list ruleset'],['srv01','root','systemctl status nftables'],['srv01','root','nft -c -f /etc/nftables.conf'],['srv01','root','iptables -S'],['ws01','alice','nc -zv srv01.corp.lab 443'],
];
for (const [h,u,c] of cmds) out.push(`### ${u}@${h}$ ${c}\n${l.run(h,u,c).output}\n`);
writeFileSync('/tmp/claude-0/-home-user-0psDJ/9187335e-bd15-5f8d-886b-3ea0eb1742e7/scratchpad/healthy.txt', out.join('\n')); });
