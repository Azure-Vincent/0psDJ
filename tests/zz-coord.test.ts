import { test } from 'vitest';
import { writeFileSync } from 'node:fs';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { rebootAll } from '../src/engine/scenarios/engine';
import { Lab } from './helpers';
const SP = '/tmp/claude-0/-home-user-0psDJ/9187335e-bd15-5f8d-886b-3ea0eb1742e7/scratchpad/';
function dump(id: string, cmds: ([string, string, string] | 'REBOOT')[], file: string) {
  const w = buildSshLab(); findScenario(id)!.setup(w);
  let l = new Lab(w); const out: string[] = [];
  for (const c of cmds) {
    if (c === 'REBOOT') { l = new Lab(rebootAll(l.world)); out.push('### --- every host rebooted ---\n'); continue; }
    const [h, u, cmd] = c; const r = l.run(h, u, cmd, ['ws01-alice']); out.push(`### ${u}@${h}$ ${cmd}\n${r.output}\n`);
  }
  writeFileSync(SP + file, out.join('\n'));
}
test('dump', () => {
  dump('ssh-config-typo', [['srv01','root','cat /etc/ssh/sshd_config.d/10-hardening.conf'],['srv01','root','cp -a /etc/ssh/sshd_config.d/10-hardening.conf /root/10-hardening.conf.bak'],['srv01','root',"sed -i 's/PubkeyAuthentcation/PubkeyAuthentication/' /etc/ssh/sshd_config.d/10-hardening.conf"],['srv01','root','sshd -t'],['srv01','root','systemctl reload ssh'],['srv01','root','systemctl restart ssh'],['srv01','root','systemctl status ssh'],['srv01','root','ss -tlnp'],['srv01','root','sshd -T | grep -E "^(port|pubkeyauthentication|passwordauthentication|permitrootlogin)"'],['ws01','alice','nc -zv srv01.corp.lab 22'],['ws01','alice','ssh srv01.corp.lab hostname'],'REBOOT',['srv01','root','systemctl is-enabled ssh'],['ws01','alice','ssh srv01.corp.lab hostname']], 'case-A-fix.txt');
  dump('case-no-internet', [['rtr01','root','cp -a /etc/nftables.conf /root/nftables.conf.bak'],['rtr01','root',"sed -i 's/oifname \"eth2\" ip saddr 10.0.10.0\\/24 masquerade/oifname \"eth2\" masquerade/' /etc/nftables.conf"],['rtr01','root','nft -c -f /etc/nftables.conf'],['rtr01','root','systemctl reload nftables'],['rtr01','root','nft list table ip nat'],['srv01','root','curl -m 5 -I http://203.0.113.80/'],['srv01','root','getent hosts ns1.corp.lab'],['srv01','root',"sed -i 's/nameserver 8.8.8.8/search corp.lab\\nnameserver 10.0.10.53/' /etc/resolv.conf"],['srv01','root','cat /etc/resolv.conf'],['srv01','root','getent hosts ns1.corp.lab'],['rtr01','root','conntrack -L'],['rtr01','root','tcpdump -n -i eth2 -c 4 tcp'],['ws01','alice','curl -I http://203.0.113.80/'],'REBOOT',['srv01','root','curl -I http://203.0.113.80/'],['srv01','root','getent hosts ns1.corp.lab']], 'case-B-fix.txt');
  dump('case-dns-outage', [['ns1','root','tcpdump -n -i eth0 -c 4 port 53'],['ns1','root','cp -a /etc/nftables.conf /root/nftables.conf.bak'],['ns1','root',"sed -i 's#ip saddr 10.0.0.0/24#ip saddr 10.0.0.0/16#' /etc/nftables.conf"],['ns1','root','nft -c -f /etc/nftables.conf'],['ns1','root','systemctl reload nftables'],['ns1','root','nft list chain inet filter input'],['ws01','alice','dig +short srv01.corp.lab'],['ws01','alice','ssh srv01.corp.lab hostname'],['ws02','dana','curl -I http://srv01.corp.lab/'],['dev01','erin','getent hosts www.corp.lab'],'REBOOT',['dev01','erin','getent hosts www.corp.lab'],['ws01','alice','ssh srv01.corp.lab hostname']], 'case-G-fix.txt');
});
