// Lesson F: safe infrastructure recovery. The subject is the operational process
// of changing and recovering systems, not a single daemon, so the ServiceGuide's
// architecture questions are answered for that process. Practice happens in the
// existing simulator tickets (ssh-monday-reboot, ssh-config-typo, ...).
// Commands marked sim / simulated were checked against the simulator; everything
// else is representative of the named real platform.

import type { Assessment, Lesson, ServiceGuide } from '../types';

export const RECOVERY_GUIDE: ServiceGuide = {
  purpose:
    'Most outages are caused by changes, and most long outages are caused by changes made without a way back. **Safe change and recovery** is the operational process around every configuration change: record how things are now, back up what you will touch, validate the new configuration before it is loaded, keep a second way into the machine, apply the change with the smallest possible action (reload one service, not reboot the server), verify from the client\'s point of view, keep a rollback ready (ideally one that runs by itself), and write down what happened. This lesson treats that process as the "service": its components, its dependencies, the commands that implement each step on each platform, and how to tell a **workaround** (symptom gone for now) from a **permanent fix** (cause removed, survives a reboot).',
  architecture: [
    { q: 'What does it accomplish?', a: 'It makes every change **reversible** and **verifiable**: you know the state before, you can prove the state after, and if the change fails you can return to the known-good state quickly, even if the change cut off your own access. It also limits the **blast radius**: only the component you changed is restarted, at a time when the impact is acceptable, and the users who depend on it are told.' },
    { q: 'How does it work internally?', a: 'As a loop with checkpoints:\n- **Plan**: what changes, who is affected, what depends on it, how to roll back, when (maintenance window).\n- **Record** the current effective state (`sshd -T`, `nft list ruleset`, `ip -d addr`, `systemctl show`, `Get-NetIPConfiguration`).\n- **Back up** every file or setting you will touch (`cp -a`, etckeeper/git, `reg export`, pfSense config history).\n- **Validate** the new configuration offline (`sshd -t`, `nginx -t`, `nft -c -f`, `named-checkconf`, `visudo -c`, `docker compose config`).\n- **Arm a safety net**: keep the current session open, have console/iLO ready, schedule an automatic rollback.\n- **Apply** with the smallest action (reload > restart of one unit > restart of a stack > interface restart > reboot).\n- **Verify** from a client and from a **new** session; then cancel the rollback.\n- **Prove persistence** (is it in the file? is the unit enabled? reboot test in the window).\n- **Document** the change or incident.' },
    { q: 'Which protocols and mechanisms does it use?', a: 'Plain files plus version control (git through etckeeper on Linux, a Git repository for Compose files), the service managers\' own **validate** and **reload** paths (systemd `ExecReload=`, which on Debian runs `sshd -t` before SIGHUP; `nft -f`, which loads a file atomically), timers for automatic rollback (`systemd-run --on-active=`, `at`, Windows Task Scheduler), and **out-of-band** management channels (serial/virtual console, IPMI, HPE iLO, Dell iDRAC, the hypervisor console) that do not depend on the network configuration you are changing.' },
    { q: 'Which ports and transport does it rely on?', a: 'Your **in-band** access is exactly what a bad change breaks: SSH TCP 22, RDP TCP/UDP 3389, WinRM TCP 5985 (HTTP) / 5986 (HTTPS), the pfSense web GUI on TCP 443. **Out-of-band** access should be on a separate management network: IPMI-over-LAN UDP 623, iLO/iDRAC web and virtual console on TCP 443 (plus vendor ports for the remote console), a physical or serial console with no network at all. Before changing the firewall or addressing of the interface you are connected through, make sure at least one of these does not traverse it.' },
    { q: 'Which processes and OS components implement it?', a: '**Linux**: systemd (PID 1) for units, reloads, enablement and transient timers (`systemd-run`); `atd` for `at` jobs; the validation built into daemons (`sshd -t`, `nginx -t`, `named-checkconf`, `dhcpd -t`, `nft -c`); etckeeper (git in `/etc`, auto-commits around apt/dnf runs). **Windows**: the Service Control Manager (`services.exe`) for service start/stop, dependencies and recovery actions; the registry; Group Policy (Backup-GPO); Task Scheduler. **pfSense**: `config.xml` with automatic revisions in `/cf/conf/backup/`, the console menu ("15) Restore recent configuration"). **Docker**: `dockerd`, Compose (`docker compose config`, `up -d` recreates only changed services).' },
    { q: 'Which components does a change depend on?', a: 'Before you touch anything you need: (1) a **verified backup** of the current configuration, taken **before** the change; (2) a **recorded baseline** of the effective state, to compare with after; (3) a **validation** tool for the new configuration; (4) **alternative access** that does not depend on what you change; (5) a **dependency map**: which units or services depend on the one you restart (`systemctl list-dependencies --reverse`, `Get-Service -DependentServices`, Windows `DependOnService`), and which clients depend on it (DNS, DHCP, authentication are shared dependencies of almost everything); (6) an agreed **window** and a person who can say "roll back".' },
    { q: 'How do changes travel?', a: 'From the **file on disk**, through **validation**, into the **running process** (only when you reload or restart), and from there to **clients**, often with delay: DNS answers are cached for the record\'s TTL, DHCP clients keep their lease until renewal (T1 = half the lease time), ARP and neighbour caches age out, and established connections keep flowing through a stateful firewall because `ct state established` matches them. So your still-open SSH session proves nothing about **new** connections: test from a second, new session.' },
    { q: 'How do authentication and authorisation work?', a: 'Changes should be made with **personal accounts plus sudo** (Linux) or named admin accounts (Windows), so the journal, `sudo` log lines and Windows Security log show who did what. Version control adds the "what exactly changed" (`git -C /etc log -p`). Change approval and peer review are the authorisation layer of the process: an approved change record says what may be changed, when, and what the rollback is. Emergency changes during an incident are still recorded, afterwards.' },
    { q: 'What happens at boot?', a: 'Everything is rebuilt **from the persistent configuration**; runtime-only changes disappear. Runtime only: `nft add rule ...`, `ip addr add`, `ip route add`, `sysctl -w`, `systemctl start` of a disabled unit, `firewall-cmd` without `--permanent`, `Set-NetIPAddress` is persistent but `route add` without `-p` on Windows is not, a container started with `docker run` without a restart policy. Persistent: `/etc/nftables.conf` (loaded by the enabled nftables.service), `/etc/network/interfaces` / netplan / NetworkManager profiles, `/etc/sysctl.d/*.conf`, `systemctl enable`, `firewall-cmd --permanent`, `route -p add`, `restart: unless-stopped` in compose.yaml. The `ssh-monday-reboot` ticket is exactly this: an SSH rule added by hand and a disabled unit, both invisible until the reboot.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If **your session** dies mid-change, whatever you were typing stops: a half-applied sequence of commands can leave the system worse than before. Mitigations: put the whole change in one atomic operation (`nft -f file` replaces the ruleset in one transaction; `systemctl reload` keeps the old daemon if validation fails), run long changes inside `tmux`/`screen` so they continue without you, and **arm an automatic rollback before applying** so a lock-out undoes itself. If a **service** dies after the change, systemd `Restart=on-failure` (or Windows recovery actions) may restart it repeatedly: that hides the problem until the start limit is hit ("Start request repeated too quickly").' },
  ],
  ports: [
    { port: '22', proto: 'TCP', purpose: 'SSH: in-band Linux/pfSense administration (keep one session open while changing)' },
    { port: '3389', proto: 'TCP/UDP', purpose: 'RDP: in-band Windows administration' },
    { port: '5985 / 5986', proto: 'TCP', purpose: 'WinRM HTTP / HTTPS: PowerShell remoting, survives a Remote Desktop Services restart' },
    { port: '443', proto: 'TCP', purpose: 'pfSense web GUI; iLO / iDRAC web interface and virtual console (vendor-specific extra ports)' },
    { port: '623', proto: 'UDP', purpose: 'IPMI over LAN (BMC): power control, serial-over-LAN console' },
    { port: 'none', proto: 'serial / VGA', purpose: 'Physical or hypervisor console: works with no network configuration at all' },
  ],
  processes: [
    { name: 'systemd (PID 1)', platform: 'Linux', role: 'Starts, reloads and restarts units; enables them at boot; runs transient timers created by `systemd-run` (used for automatic rollback).' },
    { name: 'atd', platform: 'Linux', role: 'Runs one-off `at` jobs (alternative scheduled rollback). Package `at`; check `systemctl is-active atd` before relying on it.' },
    { name: 'etckeeper / git', platform: 'Debian/Ubuntu, RHEL (EPEL)', role: 'Keeps `/etc` in a git repository and commits automatically before and after package operations.' },
    { name: 'services.exe (Service Control Manager)', platform: 'Windows Server 2019/2022, Windows 10/11', role: 'Starts and stops services in dependency order, applies recovery actions (restart after failure), logs events 7000–7045 in the System log.' },
    { name: 'php-fpm / config.xml writer', platform: 'pfSense CE 2.7', role: 'Every Save in the GUI writes `/cf/conf/config.xml` and keeps the previous revision in `/cf/conf/backup/`.' },
    { name: 'dockerd + docker compose', platform: 'Docker Engine 27', role: 'Compose compares the desired state (compose.yaml) with running containers and recreates only those whose configuration changed.' },
  ],
  dependencies: {
    title: 'What a safe change depends on (top needs everything below it)',
    caption: 'A change is only as safe as its weakest preparation: without a pre-change backup, a validation step or a second way in, the rollback plan is a hope.',
    rows: [
      { label: 'Outcome', nodes: [{ id: 'verified', label: 'Verified change', sub: 'client test + reboot', kind: 'client' }, { id: 'doc', label: 'Documented', sub: 'change/incident record', kind: 'data' }] },
      { label: 'Apply', nodes: [{ id: 'apply', label: 'Smallest action', sub: 'reload > restart', kind: 'service' }, { id: 'rollback', label: 'Rollback armed', sub: 'systemd-run / at', kind: 'service' }] },
      { label: 'Prepare', nodes: [{ id: 'validate', label: 'Syntax validated', sub: 'sshd -t, nft -c -f', kind: 'data' }, { id: 'backup', label: 'Backup taken', sub: 'cp -a, etckeeper', kind: 'data' }, { id: 'baseline', label: 'Baseline recorded', sub: 'sshd -T, nft list', kind: 'data' }] },
      { label: 'Access', nodes: [{ id: 'session', label: 'Open session', sub: 'existing SSH / RDP', kind: 'network' }, { id: 'oob', label: 'Out-of-band', sub: 'console, iLO, IPMI', kind: 'external' }] },
      { label: 'Process', nodes: [{ id: 'deps', label: 'Dependency map', sub: 'list-dependencies', kind: 'os' }, { id: 'window', label: 'Maint. window', sub: 'approved, users told', kind: 'os' }] },
    ],
    edges: [
      ['verified', 'apply'], ['verified', 'baseline', 'compare'], ['doc', 'verified'],
      ['apply', 'validate'], ['apply', 'rollback'], ['apply', 'session'], ['apply', 'deps'], ['apply', 'window'],
      ['rollback', 'backup'], ['rollback', 'oob', 'if locked out'], ['validate', 'backup'],
    ],
  },
  sequence: {
    title: 'Changing srv01\'s firewall with an automatic rollback',
    caption: 'The rollback is armed **before** the risky step, and cancelled only after a **new** connection from a client succeeds.',
    lanes: [{ id: 'a', label: 'admin (session 1)', sub: 'ssh to srv01' }, { id: 's', label: 'srv01', sub: 'nftables, systemd' }, { id: 't', label: 'rollback timer', sub: 'systemd-run' }, { id: 'c', label: 'admin (session 2)', sub: 'new ssh / nc' }],
    steps: [
      { from: 'a', to: 's', label: 'cp -a nftables.conf backup', note: 'Backup first, with a timestamp in the name. Also save `nft list ruleset` as the baseline.' },
      { from: 'a', to: 's', label: 'nft -c -f /etc/nftables.conf', note: '`-c` parses and checks without loading. A syntax error stops here, nothing changed.' },
      { from: 'a', to: 't', label: 'systemd-run --on-active=5min', note: 'Schedules `nft -f` of the backup in 5 minutes, independent of your session.' },
      { from: 'a', to: 's', label: 'systemctl reload nftables', note: 'Loads the new file atomically. Your existing session survives (established state).' },
      { from: 'c', to: 's', label: 'NEW ssh / nc -zv srv01 22', note: 'Only a new connection proves the new rules allow SSH.', fail: true },
      { from: 't', to: 's', label: 'restore backup if not stopped', note: 'If you were locked out, the timer puts the old ruleset back after 5 minutes.' },
      { from: 'a', to: 't', label: 'systemctl stop run-r….timer', note: 'Test passed: cancel the rollback. Then reboot-test in the window.' },
    ],
  },
  files: [
    { path: '<file>.YYYY-MM-DD-HHMM (e.g. /etc/nftables.conf.2026-10-21-0930)', platform: 'Linux', kind: 'data', perms: 'same owner, mode and SELinux label as the original (cp -a)', contains: 'A copy of a configuration file taken immediately before editing it: `cp -a /etc/nftables.conf /etc/nftables.conf.$(date +%F-%H%M)`.', accessed: 'Read only when rolling back.', problems: 'A backup placed in an **include directory** may be loaded as configuration. Safe: `sshd_config.d/10-hardening.conf.bak` (only `*.conf` is included) and `sudoers.d/admins.bak` (files containing a dot are skipped). Dangerous: `/etc/nginx/sites-enabled/default.bak` (Debian includes `sites-enabled/*`, so both copies load and nginx reports a duplicate server). When in doubt keep backups in `/root/backup/`.' },
    { path: '/etc/.git (etckeeper)', platform: 'Debian/Ubuntu, RHEL (EPEL)', kind: 'data', perms: 'root only (0700)', contains: 'Full history of `/etc`: who changed what and when, including automatic commits around every `apt`/`dnf` run.', accessed: '`etckeeper commit "msg"`, `git -C /etc log`, `git -C /etc diff`, and by the apt/dnf hooks.', problems: 'Contains copies of secrets (`/etc/shadow`, private keys): never push it to a shared server unencrypted. Only helps if people commit with a meaningful message.' },
    { path: '/etc/nftables.conf (persistent) vs `nft list ruleset` (runtime)', platform: 'Debian 12 (simulator)', kind: 'config', perms: 'root:root 0755 on Debian (it is executable, starts with #!/usr/sbin/nft -f)', contains: 'The ruleset loaded at boot by `nftables.service`. It should start with `flush ruleset` so that loading it replaces, not appends.', accessed: 'At boot and on `systemctl reload/restart nftables` (`nft -f`).', problems: 'Runtime-only rules (`nft add rule`) are not in this file and vanish at the next reboot or reload. Compare the two before every change: differences are undocumented changes.' },
    { path: '/etc/systemd/system/*.target.wants/', platform: 'Linux (systemd)', kind: 'startup', contains: 'Symlinks created by `systemctl enable`: they decide what starts at boot.', accessed: 'At boot and on `daemon-reload`.', problems: 'A unit that is `active` but `disabled` runs now and is missing after the reboot (the second fault in `ssh-monday-reboot`). Check `systemctl is-enabled` as well as `is-active`.' },
    { path: '/run/systemd/transient/run-r*.timer', platform: 'Linux (systemd)', kind: 'runtime', contains: 'The transient timer and service created by `systemd-run --on-active=...`.', accessed: 'Until the timer fires or is stopped; lost at reboot.', problems: 'If you forget to cancel it after a successful change, the rollback still runs and undoes your good change. `systemctl list-timers` shows pending ones.' },
    { path: '/var/spool/cron/atjobs/ (Debian) or /var/spool/at/ (RHEL)', platform: 'Linux', kind: 'data', contains: 'Queued `at` jobs (used for scheduled rollback).', accessed: 'By atd when the job is due.', problems: 'If atd is not installed or not running, the rollback silently never happens. `atq` lists, `atrm N` cancels.' },
    { path: 'journal (journalctl)', platform: 'Linux (systemd)', kind: 'log', contains: 'The timeline of the change: reloads, "Reload failed", unit failures, sudo commands run, reboots (`journalctl --list-boots`).', accessed: 'Continuously.', problems: 'Only survives reboots if persistent storage is used (`/var/log/journal` exists); otherwise the evidence of the failure disappears with the reboot you used to "fix" it.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>', platform: 'Windows Server 2019/2022, Windows 10/11', kind: 'registry', contains: 'Service definition: `Start` (2 automatic, 3 manual, 4 disabled), `DependOnService`, `ObjectName`, `FailureActions` (recovery).', accessed: 'By the SCM at boot and when the service is started.', problems: 'Export before editing: `reg export HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService C:\\Backup\\TermService.reg`. A wrong `DependOnService` makes the service fail to start with error 1068 ("The dependency service or group failed to start").' },
    { path: 'C:\\Backup\\GPO\\{GUID}\\ (Backup-GPO)', platform: 'Windows Server with the GroupPolicy module', kind: 'data', contains: 'A backup of one or all Group Policy Objects (settings, security filtering is restored with the GPO).', accessed: '`Backup-GPO -All -Path C:\\Backup\\GPO`; `Restore-GPO -Name "..." -Path ...`.', problems: 'Links to OUs are not part of a GPO backup; record them separately (`Get-GPInheritance -Target "OU=Servers,DC=corp,DC=lab"`).' },
    { path: '/cf/conf/config.xml and /cf/conf/backup/config-<timestamp>.xml', platform: 'pfSense CE 2.7', kind: 'config', contains: 'The whole firewall configuration in one XML file, plus previous revisions written automatically on every change (Diagnostics > Backup & Restore > Config History).', accessed: 'At boot and whenever a page is saved/applied.', problems: 'Only a configurable number of revisions is kept, so download a full backup before a big change. Restoring a revision needs a filter reload or reboot to take effect, depending on what changed.' },
    { path: 'compose.yaml + .env (in a git repository)', platform: 'Docker Engine 27 / Compose v2', kind: 'config', contains: 'Desired state of a stack: images (pin tags or digests), ports, volumes, networks, restart policies.', accessed: 'On every `docker compose up/config`.', problems: 'An unpinned `image: nginx:latest` makes "rollback" impossible because the old image is gone or different. Data lives in volumes, which `git revert` does not restore.' },
    { path: 'Incident / change record (ticket, wiki)', platform: 'Any', kind: 'data', contains: 'Timeline, impact, detection, root cause, contributing factors, workaround, permanent fix, follow-ups.', accessed: 'During and after the incident; at the next similar incident.', problems: 'Written days later from memory, it loses the timestamps that matter. Note times and commands as you go.' },
  ],
  management: [
    {
      platform: 'Debian / Ubuntu',
      tasks: [
        { task: 'Status of the component you will change', command: 'systemctl status nftables\nsystemctl is-enabled ssh nftables nginx', explain: 'Before a change, note **Active** and **Loaded … enabled/disabled**. After a change, the last journal lines in `status` show "Reload failed" or the validation error.', sim: true },
        { task: 'Record the effective state (baseline)', command: 'sshd -T | tee /root/sshd-before.txt\nnft list ruleset | tee /root/nft-before.txt\nip -d addr show eth0\nsystemctl show ssh -p ActiveState,SubState,UnitFileState', explain: 'The **effective** configuration, not the file: what is actually running. After the change, diff the new output against this baseline.' },
        { task: 'Back up the file before editing', command: 'cp -a /etc/nftables.conf /etc/nftables.conf.$(date +%F-%H%M)\netckeeper commit "before CHG-2210: open tcp/443"', explain: '`-a` keeps owner, mode, timestamps and (on RHEL) the SELinux label, so the copy can be restored as-is. etckeeper records the pre-change state in git.' },
        { task: 'Validate before loading', command: 'sshd -t\nnginx -t\nnft -c -f /etc/nftables.conf', explain: 'Each checks the files without touching the running service. `sshd -t` and `nft -c` are silent on success; `nginx -t` says "test is successful". On ns1 the equivalents are `named-checkzone corp.lab /etc/bind/db.corp.lab` and `dhcpd -t`; elsewhere `named-checkconf`, `visudo -c`, `netplan generate`.', sim: true },
        { task: 'Reload (preferred)', command: 'systemctl reload ssh\nsystemctl reload nftables', explain: 'Re-reads configuration without stopping the service. On Debian, `ssh.service` reload runs `sshd -t` first; nftables reload runs `nft -f /etc/nftables.conf`, which is atomic: on a syntax error the old ruleset stays loaded and the unit logs "Reload failed".', sim: true },
        { task: 'Restart one unit', command: 'systemctl restart nginx', explain: 'Stop + start. Needed when the change cannot be reloaded (listening port, binary upgrade) or the service is stuck.', risk: 'If the new configuration is invalid the service stays down. Validate first.', sim: true },
        { task: 'Start / stop', command: 'systemctl start nginx\nsystemctl stop nginx', explain: 'Stop only for a planned outage or to free a resource; start after a fix. Starting does not enable.', risk: 'Stopping a shared dependency (DNS, DHCP, a database) stops everything that uses it.', sim: true },
        { task: 'Enable / disable at boot', command: 'systemctl enable --now ssh\nsystemctl disable ssh', explain: 'Makes the running state and the boot state agree. `--now` also starts it.', sim: true },
        { task: 'Failed units after a change or reboot', command: 'systemctl --failed\njournalctl -b -p err', explain: 'What did not come up, and the error-level messages of this boot.', sim: true },
        { task: 'Who depends on it (blast radius)?', command: 'systemctl list-dependencies --reverse nftables\nsystemctl list-dependencies ssh', explain: '`--reverse` lists units that want/require this one: those are affected when you stop or restart it. The forward list shows what it needs.', sim: true },
        { task: 'Recent logs and why it failed to start', command: 'journalctl -u nftables -n 20\njournalctl -xeu ssh', explain: 'Look for "Bad configuration option", "syntax error", "Reload failed", "Start request repeated too quickly".', sim: true },
        { task: 'Arm an automatic rollback', command: 'systemd-run --on-active=5min /usr/sbin/nft -f /root/nftables.conf.bak\n# or: echo "/usr/sbin/nft -f /root/nftables.conf.bak" | at now + 5 minutes\nsystemctl list-timers "run-*"', explain: 'Runs the restore in 5 minutes whether or not your session survives. Cancel with `systemctl stop run-r<id>.timer` (or `atrm <job>`) only after a new connection succeeds.', risk: 'The backup must replace the whole ruleset: it must begin with `flush ruleset` (Debian\'s /etc/nftables.conf does; the output of `nft list ruleset` does not, so add the line if you saved it that way).' },
        { task: 'Restore after a config error', command: 'cp -a /etc/nftables.conf.2026-10-21-0930 /etc/nftables.conf\nnft -c -f /etc/nftables.conf && systemctl reload nftables', explain: 'Restore the pre-change copy, validate it (it may be older than you think), then reload. Or with etckeeper: `git -C /etc checkout HEAD~1 -- nftables.conf`.' },
        { task: 'Network changes on Ubuntu (netplan)', command: 'netplan generate\nnetplan try --timeout 120', explain: '`generate` validates the YAML and renders backend files; `try` applies and **reverts automatically** unless you press Enter within the timeout. Not in the simulator (ifupdown).', risk: '`netplan apply` has no automatic revert.' },
      ],
    },
    {
      platform: 'RHEL / Rocky / Alma 9',
      tasks: [
        { task: 'Same systemd workflow', command: 'systemctl status sshd\nsshd -t && systemctl reload sshd\nsystemctl list-dependencies --reverse sshd', explain: 'Unit names differ (sshd.service, named.service, httpd.service); the method is identical.' },
        { task: 'firewalld: runtime first, then permanent', command: 'firewall-cmd --add-service=https\n# test from a client, then:\nfirewall-cmd --runtime-to-permanent\nfirewall-cmd --check-config', explain: 'A runtime-only change is its own rollback: `firewall-cmd --reload` (or a reboot) returns to the permanent configuration. Only make it permanent after testing.', risk: 'Forgetting `--runtime-to-permanent` produces the "worked until reboot" fault.' },
        { task: 'SELinux labels after restoring a file', command: 'restorecon -Rv /etc/ssh', explain: '`cp -a` preserves the label; restoring with `mv` from /root or editing with some tools can leave a wrong label, so the daemon is denied access ("Permission denied" in `ausearch -m avc -ts recent`).' },
        { task: 'Network changes (NetworkManager)', command: 'nmcli connection modify eth0 ipv4.addresses 10.0.20.11/24\nnmcli connection up eth0', explain: 'There is no `try` in nmcli: arm a `systemd-run` rollback first, or use `nmstatectl apply --no-commit --timeout 60 new.yml` followed by `nmstatectl commit`, which reverts automatically if not committed.', risk: '`nmcli connection up` on the interface you are connected through drops your session if the new settings are wrong.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022',
      tasks: [
        { task: 'Record state before the change', command: 'Get-NetIPConfiguration -All | Out-File C:\\Backup\\before-ip.txt\nGet-Service | Select-Object Name, Status, StartType | Export-Csv C:\\Backup\\before-services.csv -NoTypeInformation\nGet-NetFirewallRule -DisplayGroup "Remote Desktop" | Export-Clixml C:\\Backup\\fw-rdp.xml', explain: 'Text and CSV for humans and `Compare-Object`; Export-Clixml keeps full objects for later comparison.' },
        { task: 'Back up registry, firewall and GPOs', command: 'reg export "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" C:\\Backup\\ts.reg /y\nnetsh advfirewall export C:\\Backup\\firewall.wfw\nBackup-GPO -All -Path C:\\Backup\\GPO', explain: '`reg import` restores the key; `netsh advfirewall import` restores the whole firewall policy; `Restore-GPO` restores a GPO (links are separate).' },
        { task: 'Status, start, stop, restart', command: 'Get-Service TermService\nStart-Service W32Time\nStop-Service Spooler\nRestart-Service DNS', explain: 'There is no generic "reload" for Windows services: most re-read configuration only on restart. Some have their own (e.g. `gpupdate /force` for policy, `ipconfig /registerdns`).', risk: 'Restart-Service refuses when other running services depend on it unless `-Force` is added, which stops and restarts the dependents too.' },
        { task: 'Startup type (boot behaviour)', command: 'Set-Service W32Time -StartupType Automatic\nGet-Service W32Time | Select-Object Name, Status, StartType', explain: 'Status is "now", StartType is "after reboot": the same distinction as active vs enabled on Linux.' },
        { task: 'Dependencies', command: 'Get-Service TermService -DependentServices\nGet-Service TermService -RequiredServices\nsc.exe enumdepend TermService', explain: 'Dependents are stopped with the service. Required services must be running for it to start.' },
        { task: 'Failed services and why', command: 'Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName="Service Control Manager"; Id=7000,7009,7031,7034; StartTime=(Get-Date).AddHours(-24)}', explain: '7000 failed to start (with the error), 7009 start timeout, 7031/7034 terminated unexpectedly (7031 also names the recovery action taken).' },
        { task: 'Automatic rollback', command: 'schtasks /create /tn "CHG-2210 rollback" /sc once /st 14:35 /ru SYSTEM /tr "netsh advfirewall import C:\\Backup\\firewall.wfw"\nschtasks /delete /tn "CHG-2210 rollback" /f', explain: 'Same idea as systemd-run: restores the firewall policy at 14:35 unless you delete the task after testing. On a VM, also take a hypervisor checkpoint (Hyper-V `Checkpoint-VM`).' },
      ],
    },
    {
      platform: 'pfSense CE 2.7',
      tasks: [
        { task: 'Back up before a change', command: 'Diagnostics > Backup & Restore > Download configuration as XML', explain: 'One file contains everything. Config History (same page) also keeps automatic revisions with the user and page that saved them.' },
        { task: 'Compare and revert a revision', command: 'Diagnostics > Backup & Restore > Config History: Diff / Revert', explain: 'Diff two revisions to see exactly what changed; Revert restores one.' },
        { task: 'Reload vs service restart vs reboot', command: 'Status > Filter Reload\nStatus > Services (restart one service)\nDiagnostics > Reboot', explain: 'A filter reload re-applies rules without dropping existing states; restarting one service (Unbound, DHCP, OpenVPN) affects only that service; a reboot drops everything.' },
        { task: 'Status, logs, failures', command: 'Status > Services\nStatus > System Logs > Firewall / System / General\nStatus > Dashboard (notices)', explain: 'Services that failed to start show a red stop icon; the System log usually says why.' },
        { task: 'Recover from the console', command: 'Console menu: 15) Restore recent configuration\nConsole menu: 8) Shell → pfctl -d (temporarily disable the packet filter)', explain: 'Use the console when a rule change locked you out of the GUI. `pfctl -d` disables filtering (and NAT) until the next filter reload: an emergency step only, re-enable with `pfctl -e`.', risk: 'With the filter disabled the firewall forwards without filtering.' },
        { task: 'Keep the anti-lockout rule', command: 'System > Advanced > Admin Access > Anti-lockout (leave unchecked "Disable")', explain: 'Automatically allows the LAN to reach the GUI and SSH regardless of the rules you add.' },
      ],
    },
    {
      platform: 'Docker / Compose',
      tasks: [
        { task: 'Validate the change', command: 'docker compose config --quiet\ndockerd --validate --config-file=/etc/docker/daemon.json', explain: '`compose config` parses, merges and interpolates the files (silent with --quiet on success). `dockerd --validate` (Engine 23+) checks daemon.json and prints "configuration OK".' },
        { task: 'Status, logs, failures', command: 'docker compose ps -a\ndocker compose logs --tail 50 web\ndocker inspect -f "{{.State.ExitCode}} {{.State.Error}}" web-1', explain: '`ps -a` shows exited and restarting containers; logs and exit code say why.' },
        { task: 'Apply only what changed', command: 'git -C /srv/app pull\ndocker compose up -d', explain: '`up -d` recreates only services whose configuration or image changed; others keep running.', risk: '`docker compose restart` does **not** apply compose.yaml changes: it restarts the same containers with the old configuration.' },
        { task: 'Restart vs recreate vs daemon restart', command: 'docker compose restart web\ndocker compose up -d --force-recreate web\nsystemctl restart docker', explain: 'Restart keeps the container; recreate builds a new one from the current definition; restarting dockerd stops every container on the host unless `"live-restore": true` is set.' },
        { task: 'Roll back', command: 'git -C /srv/app revert --no-edit HEAD\ndocker compose up -d', explain: 'Works only if images are pinned (tag or digest) and still available, and the change did not migrate data in a volume.' },
      ],
    },
  ],
  actions: [
    { action: 'Reload (systemctl reload, filter reload, gpupdate)', when: 'Configuration change the service can re-read: sshd authentication options, nginx sites, nftables rules, bind zones (`rndc reload`), pfSense rules.', effect: 'New configuration for new work; existing sessions and connections continue. On Debian the reload validates first and keeps the old configuration if the new one is invalid.', risk: 'Lowest. Still verify with a new connection: reload success means "parsed", not "works for users".' },
    { action: 'Restart one service (systemctl restart, Restart-Service, docker compose up -d <svc>)', when: 'The change cannot be reloaded (listening port, module, binary upgrade) or the service is hung.', effect: 'Short outage of that service only. Dependents may be restarted too (Windows `-Force`, systemd `PartOf=`/`BindsTo=`).', risk: 'An invalid configuration leaves it down. Restarting Remote Desktop Services disconnects every RDP session, including yours.' },
    { action: 'Restart a dependency or a stack', when: 'The failed component is a shared dependency (DNS, DHCP, a database, dockerd).', effect: 'Everything that depends on it is interrupted.', risk: 'Wide blast radius: list reverse dependencies first and do it in a window.' },
    { action: 'Interface restart (ifdown/ifup, nmcli con up, Restart-NetAdapter)', when: 'Only when the interface configuration itself changed and cannot be applied otherwise.', effect: 'Removes and re-adds addresses and routes; every connection over the interface drops.', risk: 'Classic self-lock-out. Use netplan try, nmstatectl --no-commit, or a scheduled rollback, from a console if possible.' },
    { action: 'Reboot', when: 'Kernel or firmware updates, and as a **planned persistence test** in a maintenance window. Not as a troubleshooting step.', effect: 'Rebuilds everything from persistent configuration; runtime-only changes disappear; disabled units do not start.', risk: 'Longest outage, destroys runtime evidence (and the non-persistent journal), and a hidden persistence fault turns it into an extended outage.' },
    { action: 'Rollback (restore backup + validate + reload)', when: 'The change fails verification and the cause is not obvious within the agreed time.', effect: 'Returns to the last known-good state; buys time to analyse the failed change offline.', risk: 'Restoring a backup taken **after** the change, or one that does not replace the whole configuration (an `nft` backup without `flush ruleset`), restores nothing.' },
  ],
  workflow: [
    { question: 'What changed, and when?', why: 'Most outages are caused by a change, so the most recent change is the most likely suspect.', command: 'journalctl --since "-2h" -u nftables -u ssh\njournalctl --list-boots', healthy: 'A clear timeline: the change at 09:30, "Reloading nftables.service", no errors.', broken: '"Reload failed for nftables.service" or a reboot you did not expect. If nothing was logged, ask: who was on the box, what does the change calendar say, what does `git -C /etc log` (etckeeper) show?', next: 'Most incidents follow a change: start from it. Then confirm the impact (step 2).' },
    { question: 'What exactly is broken, from the client\'s point of view?', why: 'Describe the problem the way users experience it, and test the same way, so you know when it is really fixed.', command: 'nc -zv srv01.corp.lab 22\ncurl -I http://srv01.corp.lab/', healthy: 'Connection to srv01.corp.lab (10.0.20.10) 22 port [tcp/ssh] succeeded!\nHTTP/1.1 200 OK', broken: 'Timeout, refused, wrong status. Test from more than one network: if every client fails for everything by name, suspect a shared dependency (DNS) before the individual services (`case-dns-outage`).', next: 'Note the time and the impact for the incident record; then find the failing component.', sim: true },
    { question: 'Which component is not running as intended?', why: 'Narrow the problem down to one component before touching anything.', command: 'systemctl --failed\nsystemctl status ssh', healthy: '0 loaded units listed.\nActive: active (running)', broken: '`failed (Result: exit-code)` → start/validation error. `inactive (dead)` with `disabled` → it was never started at boot.', next: 'Failed → step 5 (validate). Disabled → `systemctl enable --now`.', sim: true },
    { question: 'Does the running state match the persistent state?', why: 'A fix only in the running system disappears at reboot; a fault only in the saved files appears at the next reboot.', command: 'nft list ruleset\ncat /etc/nftables.conf\nsystemctl is-enabled ssh', healthy: 'The loaded ruleset contains the same rules as the file; units that are active are also enabled.', broken: 'A rule in the runtime ruleset that is missing from the file (added by hand: it will vanish at reboot) or the reverse (file changed but never loaded). `disabled` for a running unit.', next: 'Make the persistent configuration the single source of truth before going further.', sim: true },
    { question: 'Is the configuration valid?', why: 'Checking the configuration before applying it means the fix itself cannot take the service down.', command: 'sshd -t\nnginx -t\nnft -c -f /etc/nftables.conf', healthy: '(silent)\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n(silent)', broken: '"/etc/ssh/sshd_config.d/10-hardening.conf line 5: Bad configuration option: PubkeyAuthentcation", "Error: syntax error, unexpected acept": the tool names the file and line.', next: 'Fix that line or restore the backup, validate again, then reload.', sim: true },
    { question: 'What would a restart affect?', why: 'A restart affects everything that depends on the component, not just the broken part. Know who you will interrupt.', command: 'systemctl list-dependencies --reverse nftables\nsystemctl list-dependencies --reverse ssh', healthy: 'nftables.service\n● └─sysinit.target', broken: 'A long list of dependents (a database, a network-online target) means a restart has a wide impact: schedule it or use reload.', next: 'Pick the smallest action that applies the fix.', sim: true },
    { question: 'Fix forward or roll back?', why: 'If the cause is not clear within the agreed time, going back to the last known good state is often faster and safer than more experiments.', command: 'cp -a /etc/nftables.conf.2026-10-21-0930 /etc/nftables.conf\nnft -c -f /etc/nftables.conf', healthy: 'Backup restored, validates silently.', broken: 'No backup, or the backup was taken after the change: you must fix forward under pressure. This is why the backup comes first.', next: 'Decide by time box: if the cause is not clear within the agreed time, roll back and analyse afterwards.' },
    { question: 'Apply with the smallest action', why: 'Prefer reload over restart, and restart one component rather than rebooting the whole machine.', command: 'systemctl reload nftables\nsystemctl restart ssh', healthy: '(no output) and `systemctl status` shows the unit active with no "failed" line.', broken: '"Job for nftables.service failed." → the file still does not validate; the old ruleset is still loaded.', next: 'Verify from the client (step 9).', sim: true },
    { question: 'Is the service available to its users, now and after a reboot?', why: 'The fix is only proven when users can work again, and it still works after a reboot.', command: 'nc -zv srv01.corp.lab 22\nreboot\nsystemctl is-active ssh nftables nginx', healthy: 'succeeded!\n[ simulated reboot of srv01 ]\nactive\nactive\nactive', broken: 'Works now, fails after the reboot → a runtime-only change or a disabled unit (`ssh-monday-reboot`).', next: 'Only a client-side test after a reboot proves a permanent fix. Do the reboot test in the window, not at 03:00 on Monday.', sim: true },
    { question: 'Is it documented?', why: 'A written record lets the next person avoid the same incident, and shows which safeguard was missing.', command: 'journalctl -u nftables -u ssh -b', healthy: 'Timeline lines you can copy into the incident record: when it broke, when it was detected, what was done, when it recovered.', broken: 'No record, or a record that says "restarted the service, works now" with no cause: the incident will repeat.', next: 'Write the record: timeline, impact, detection, root cause, contributing factors, workaround, permanent fix, follow-ups.', sim: true },
  ],
  failures: [
    { symptom: 'It worked until the reboot', causes: ['a rule, address, route or sysctl was changed at runtime only (`nft add rule`, `ip addr add`, `sysctl -w`)', 'the unit is running but disabled', 'firewalld change made without `--permanent` / `--runtime-to-permanent`', 'Windows route added without `route -p`'], diagnose: ['nft list ruleset vs cat /etc/nftables.conf', 'systemctl is-enabled ssh nftables', 'journalctl -b -1 (previous boot, if persistent)'], fix: 'Put the change in the persistent configuration (file, `systemctl enable`, `--permanent`), reload, and reboot-test in a window.', verify: 'reboot; then a client-side test (nc -zv / ssh / curl)' },
    { symptom: 'Restarting fixed it, but it keeps coming back', causes: ['memory leak: the restart frees memory and the leak starts again', 'disk full: the restart releases a deleted-but-open log file, space returns, then fills again', 'DHCP pool exhausted: clients that renew get an address, new ones do not', 'a dependency that is intermittently unavailable (DNS, database)', 'crash loop hidden by `Restart=on-failure` or Windows recovery actions'], diagnose: ['journalctl -u <unit> --since "-24h" | grep -iE "start|fail|oom"', 'df -h; lsof +L1', 'Get-WinEvent System 7031/7034 counts'], fix: 'Treat the restart as the **workaround** and record it as such. Find the trend (memory over time, which log grows, pool size vs clients) and fix that: log rotation, a bigger pool, a patched version, a resource limit.', verify: 'Watch the metric (memory, disk, pool usage) over a full cycle, not just "service is up".' },
    { symptom: 'Locked out after a firewall or network change', causes: ['new ruleset lacks the management rule or `ct state established,related accept`', 'address/gateway change on the interface you were connected through', 'pfSense rule above the anti-lockout or anti-lockout disabled'], diagnose: ['console / iLO / hypervisor: nft list ruleset', 'ip -br addr; ip route', 'journalctl -u nftables -n 20'], fix: 'From out-of-band access, restore the backup and reload (or wait for the armed rollback). Next time arm `systemd-run --on-active=5min` / `netplan try` before applying.', verify: 'A NEW ssh session from a client, not the old one.' },
    { symptom: 'Service will not start after editing its configuration', causes: ['syntax error or misspelt keyword', 'file restored with wrong owner/mode/SELinux label', 'backup file placed where the include pattern loads it'], diagnose: ['systemctl status <unit>', 'sshd -t / nginx -t / nft -c -f / named-checkconf / visudo -c', 'ls -lZ <file> (RHEL)'], fix: 'Correct the line the validator names or restore the pre-change copy; validate until clean; then start. Next time validate before restart, and prefer reload (it keeps the old process when validation fails).', verify: 'systemctl is-active <unit>; client test' },
    { symptom: 'Restarting one thing broke another', causes: ['dependents were stopped with it (Windows `Restart-Service -Force`, systemd `PartOf=`/`Requires=`)', 'clients of a shared service (DNS, database) lost connections and did not reconnect', 'restarting Remote Desktop Services / sshd-socket ended admin sessions'], diagnose: ['systemctl list-dependencies --reverse <unit>', 'Get-Service <name> -DependentServices', 'journalctl --since "-15min" -p warning'], fix: 'Start the dependents, check each client. In future map reverse dependencies first and restart only the affected component.', verify: 'systemctl --failed shows nothing; Get-Service dependents Running' },
    { symptom: 'The "workaround" made things worse', causes: ['changing DNS to a public resolver that cannot reach or does not know the internal zone (`case-no-internet`)', 'opening a firewall hole broader than needed (`udp sport 53 accept` instead of the established rule in `fw-no-established`)', 'disabling a security control to make an error disappear (StrictModes, NLA, the firewall)'], diagnose: ['compare with the baseline (before.txt) and the incident timeline', 'cat /etc/resolv.conf; nft list ruleset'], fix: 'Undo every troubleshooting change that did not fix the cause, then fix the cause. Record each change you make during an incident so it can be rolled back.', verify: 'Compare the final state with the baseline: only the intended change remains.' },
    { symptom: 'Rollback did not restore service', causes: ['backup taken after the change or from the wrong host', 'backup does not replace everything (nft dump without `flush ruleset`, partial .reg)', 'service not reloaded after restoring the file', 'clients still use cached results (DNS TTL, DHCP lease, ARP)', 'the change also altered data (database or volume migration)'], diagnose: ['diff -u /root/nft-before.txt <(nft list ruleset)', 'systemctl status <unit>', 'dig +noall +answer name (TTL)'], fix: 'Restore the correct backup completely, validate, reload; flush or wait for caches; restore data from its own backup if the change migrated it.', verify: 'The effective state equals the baseline; clients succeed.' },
  ],
  verification: [
    { check: 'The change is in the persistent configuration', command: 'grep -n "dport 22" /etc/nftables.conf', expect: 'The rule appears in the file, not only in `nft list ruleset`.' },
    { check: 'Configuration validates', command: 'nft -c -f /etc/nftables.conf && sshd -t && nginx -t', expect: 'No errors; nginx "test is successful".' },
    { check: 'Units are running and enabled', command: 'systemctl is-active ssh nftables nginx; systemctl is-enabled ssh nftables nginx', expect: 'active ×3, enabled ×3' },
    { check: 'No failed units', command: 'systemctl --failed', expect: '0 loaded units listed.' },
    { check: 'Clients succeed with NEW connections', command: 'nc -zv srv01.corp.lab 22 (from ws01); curl -I http://srv01.corp.lab/', expect: 'succeeded! / HTTP/1.1 200 OK' },
    { check: 'Survives a reboot (in the window)', command: 'reboot, then the client tests again', expect: 'Same results as before the reboot.' },
    { check: 'Pending rollbacks cancelled', command: 'systemctl list-timers "run-*"; atq', expect: 'No leftover rollback timers or at jobs.' },
    { check: 'Only the intended change remains', command: 'diff -u /root/nft-before.txt <(nft list ruleset)', expect: 'The diff shows the planned rule and nothing else.' },
  ],
  refIds: ['systemctl', 'journalctl', 'nft', 'sshd-t', 'named-checkzone', 'netplan', 'firewall-cmd', 'get-service', 'restart-service', 'sc', 'get-winevent', 'docker-compose', 'pfsense-console', 'file:nftables.conf', 'file:etc', 'file:journal', 'file:etc-systemd-system', 'file:config.xml', 'file:pfsense-conf-backup', 'file:compose-yaml', 'file:netplan', 'file:reg-services', 'proc:safe-config-change', 'proc:rollback', 'proc:incident-record', 'proc:nft-safe-reload', 'proc:remote-network-change', 'proc:netplan-try', 'proc:sshd-safe-restart', 'proc:recover-sshd-console', 'proc:pfsense-restore-config', 'proc:pfsense-lockout', 'proc:compose-change', 'proc:systemd-unit-failed'],
};

export const RECOVERY_LESSON: Lesson = {
  id: 'recovery',
  moduleId: 'F',
  title: 'Safe infrastructure recovery',
  level: 'intermediate',
  summary: 'How to change and repair live systems without making things worse: back up, record, validate, keep a way back in, apply the smallest change, verify from the client, roll back when needed, and tell a workaround from a fix.',
  concepts: ['ops.recovery', 'fw.persistence', 'svc.systemd', 'logs.journal', 'net.ops', 'fw.stateful'],
  mode: 'simulated',
  guide: RECOVERY_GUIDE,
  caseStudyIds: ['ssh-refused', 'linux-no-internet', 'shared-dependency', 'pfsense-blocks', 'rdp-after-change'],
  objectives: ['N10-009:3.1', 'N10-009:3.3', 'N10-009:5.1'],

  what: `
Every other lesson teaches how a technology works and how to find a fault. This one teaches **how to touch production safely** while you fix it, because the most common cause of an outage is a change, and the most common cause of a *long* outage is a change made without a way back.

### The problems it solves
- **Lock-outs.** A firewall, network or sshd change that cuts off the administrator's own access turns a five-minute change into a trip to the data centre.
- **"It worked until the reboot."** Changes made only to the running system (a rule added by hand, a unit started but not enabled) vanish at the next restart, often days later when nobody remembers them.
- **Fixes that are not fixes.** Restarting a service frequently makes the symptom disappear for a while without touching the cause.
- **Workarounds that add faults.** Changes made "to try something" during an incident and never undone become the next incident.
- **Unnecessary downtime.** Rebooting a server to fix one daemon, or restarting a shared service in business hours, interrupts users who were not affected.

### Why restarting sometimes helps, and sometimes does not
Restarting a service clears its **runtime state**: memory, open connections, caches, a process that hung. So a restart fixes problems that live only in that state, such as a stuck process, a leaked resource, or a configuration change that was saved but never loaded.

It does **not** fix anything in the **saved state**: a wrong setting in a configuration file, a missing dependency, a full disk, a port already used by another program, a firewall rule or a wrong DNS record. In those cases the service fails again straight away, or comes back and fails later. Worse, the restart can hide the evidence (open connections, the last error) and cut off users who were working fine.

So before restarting, ask: "Do I know what is wrong, and does it live in memory or on disk?" If you do not know yet, look first (status, logs, the configuration checker), then restart only the one component that needs it.

### The habits, in one list
- **Back up** each file or setting before you change it, with a timestamp in the name or in version control.
- **Record the original effective state** (\`sshd -T\`, \`nft list ruleset\`, \`ip -d addr\`, \`systemctl show\`, \`Get-NetIPConfiguration\`).
- **Validate syntax** before loading (\`sshd -t\`, \`nginx -t\`, \`nft -c -f\`, \`named-checkconf\`, \`visudo -c\`, \`docker compose config\`).
- **Test before you depend on it**: a second session, a staging system, \`netplan try\`.
- **Keep alternative administrative access**: console, IPMI/iLO/iDRAC, hypervisor console, the existing SSH session, pfSense's anti-lockout rule.
- **Restart only the affected component**, and prefer reload to restart; never reboot as a fix.
- **Know the dependencies** before restarting something (\`systemctl list-dependencies --reverse\`, Windows \`DependOnService\`).
- **Avoid unnecessary downtime**: maintenance windows, draining, rolling changes.
- **Roll back** failed changes quickly, ideally automatically.
- **Verify from the client's point of view**, now and after a reboot.
- **Document** the incident and its remediation.

> The practice for this lesson happens in the existing tickets: \`ssh-monday-reboot\`, \`ssh-config-typo\`, \`ssh-port-moved\`, \`fw-no-established\`, \`case-no-internet\` and \`case-dns-outage\`. Each of them was caused by a change made without one of these habits. The simulator models Debian 12 hosts; Windows, pfSense and Docker steps are representative of the named real versions.
`,

  internals: `
### A safe change, step by step
The habits listed in the overview fit together in a fixed order. Example: changing sshd's configuration on a remote server you reach over SSH.
1. **Record the effective state** (\`sshd -T > /root/sshd-before.txt\`), so you can compare later.
2. **Back up the file** with a timestamp (\`cp -a /etc/ssh/sshd_config /root/sshd_config.2026-10-21-0930\`).
3. **Edit** the file.
4. **Validate** it without applying it (\`sshd -t\`). Fix any error before going on.
5. **Arm an automatic rollback** *before* the risky step, so a lock-out undoes itself: \`systemd-run --on-active=5min sh -c 'cp /root/sshd_config.2026-10-21-0930 /etc/ssh/sshd_config && systemctl reload ssh'\`.
6. **Apply** the change in the gentlest way (\`systemctl reload ssh\`, not restart).
7. **Test with a new connection** from a client, keeping your current session open. Your open session proves nothing: it was set up under the old rules.
8. **Cancel the rollback** (\`systemctl stop run-r….timer\`) and **document** the change. Cancel only now: cancelling earlier removes your safety net, and forgetting to cancel undoes your good change.

The same eight steps apply to a firewall (\`nft list ruleset\`, \`nft -c -f\`, \`systemctl reload nftables\`), a web server (\`nginx -T\`, \`nginx -t\`) or a network change (\`netplan try\` does steps 5 to 8 for you).

### Runtime state versus persistent state
Every system has two copies of its configuration: the **files on disk** and the **state loaded in memory**. They agree only when someone has loaded the files and nobody has changed the running state since.

| Change | Takes effect now? | Survives reboot? |
|---|---|---|
| \`nft add rule inet filter input tcp dport 22 accept\` | yes | **no** |
| edit \`/etc/nftables.conf\` | **no** (until reload) | yes |
| edit + \`systemctl reload nftables\` | yes | yes |
| \`systemctl start ssh\` on a disabled unit | yes | **no** |
| \`systemctl enable ssh\` | **no** (add \`--now\`) | yes |
| \`ip addr add 10.0.20.11/24 dev eth0\` | yes | **no** |
| \`sysctl -w net.ipv4.ip_forward=1\` | yes | **no** (needs /etc/sysctl.d/) |
| \`firewall-cmd --add-service=https\` | yes | **no** (needs \`--permanent\`/\`--runtime-to-permanent\`) |
| Windows \`route add\` without \`-p\` | yes | **no** |

A reboot rebuilds everything from the files. That is why a runtime-only "fix" is a **workaround with a timer**, and why the only proof that a fix is permanent is a client-side test **after** a reboot.

### Workaround versus permanent fix
- A **workaround** restores service without removing the cause: restarting a leaking daemon, deleting logs on a full disk, adding a rule by hand, pointing a client at another DNS server. Workarounds are legitimate (users need service *now*) but must be **recorded as workarounds**, with a follow-up for the real fix, and undone if they do not help.
- A **permanent fix** removes the cause in the persistent configuration and is verified to survive a restart.

Lab examples:
- **ssh-monday-reboot**: last Wednesday an admin re-allowed SSH with \`nft add rule\` after rewriting \`/etc/nftables.conf\` without the SSH rule. That was a workaround; it vanished at the weekend reboot, together with a unit someone had disabled. The fix: add the rule to the file, reload, \`systemctl enable --now ssh\`, reboot-test.
- **case-no-internet**: while investigating, someone changed srv01's DNS to 8.8.8.8 "in case it was DNS". It did not help (the cause was NAT on rtr01), and it **added a second fault**: 8.8.8.8 does not know \`corp.lab\` and was unreachable for the same reason. The fix includes undoing the workaround.
- **fw-no-established**: the tempting workaround \`udp sport 53 accept\` would make DNS work and open the server to any packet with source port 53. The fix is restoring \`ct state established,related accept\`.

### Why a restart can "fix" things without fixing them
A restart resets **runtime state**. If the fault lives in runtime state, the symptom goes away, and comes back when the state builds up again:
- **Memory leak**: the process grows until it is killed or swaps; a restart frees the memory and the clock starts again.
- **Disk full**: a daemon holds a deleted (but still open) log file; restarting it closes the file and the space reappears, until the log fills it again. \`lsof +L1\` shows such files. The permanent fix is log rotation that tells the daemon to **reopen** its log files after rotating them (logrotate's \`postrotate\` step, for nginx \`nginx -s reopen\`), plus monitoring of disk usage, so the restart is never needed.
- **DHCP**: renewing a lease on one client works while the pool is exhausted for new clients.
- **Runtime-only configuration**: a restart (or reboot) can also *remove* a working runtime change, which is the opposite surprise.
- **Flapping**: \`Restart=on-failure\` (Linux) or service recovery actions (Windows) restart a crashing service automatically. Users notice only short outages until the start limit is hit: "Start request repeated too quickly". Then find out **why** it dies instead of restarting it again. \`status=9/KILL\` means the process was killed with SIGKILL; when nobody did that by hand, it is usually the kernel's OOM killer ending a process that used too much memory (\`journalctl -k | grep -i oom\`). \`systemctl show app -p NRestarts\` shows how often systemd restarted it.
- **Cleared caches and connections**: a restart drops stuck connections, cached negative DNS answers, or a deadlock, without explaining why they happened.

If a restart "fixes" something, ask *what state did the restart reset?* That state, and why it went bad, is the cause.

### Why reload is safer than restart
On Debian, \`systemctl reload ssh\` runs \`sshd -t\` first and only then signals the daemon; if validation fails, systemd reports "Reload failed" and the **old daemon keeps running**. \`systemctl restart ssh\` stops the old daemon first, so an invalid configuration leaves nothing listening (the \`ssh-config-typo\` ticket). nftables reloads with \`nft -f\`, which applies the whole file in **one transaction**: a syntax error changes nothing.

### Existing connections lie
After a firewall change, your open SSH session still works because its packets match \`ct state established\`. That proves nothing about new connections. Always test with a **new** session from a client before closing the old one, and arm an automatic rollback in case the new session fails.

### Dependencies decide the blast radius
Stopping or restarting a unit affects everything that depends on it. \`systemctl list-dependencies --reverse <unit>\` lists the units that would be affected; on Windows, \`Get-Service <name> -DependentServices\` (the registry value \`DependOnService\` of each dependent points back to it). Shared infrastructure (DNS, DHCP, authentication, the default gateway) is a dependency of almost everything, which is why one bad change on ns1 looked like "everything is broken" in \`case-dns-outage\`.
`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu 24.04',
      summary: 'A complete safe change on srv01: open TCP 443 in the nftables firewall. The same pattern applies to any configuration file. Steps marked "simulated" work in the sandbox terminal on srv01 as root; the others are for a real VM.',
      prerequisites: ['Console access to the VM (hypervisor console, iLO/iDRAC, or serial) in case the change locks you out.', 'An open SSH session that you will keep open until the end.', 'An approved change with a rollback plan and, for production, a maintenance window.'],
      steps: [
        { title: 'Check what you are about to change', command: 'systemctl status nftables', what: 'Shows whether the firewall unit is loaded, enabled at boot, and the last reload result.', why: 'If the unit is already in a bad state, you need to know before your change, not discover it afterwards and blame the change.', expected: '● nftables.service - nftables\n     Loaded: loaded (/lib/systemd/system/nftables.service; enabled; preset: enabled)\n     Active: active (exited) since ...', simulated: true },
        { title: 'Record the effective state (baseline)', command: 'nft list ruleset | tee /root/nft-before.txt', what: 'Saves the ruleset that is actually loaded.', why: 'The running state may differ from the file (runtime-only rules). After the change, `diff` against this proves that only the intended rule changed.', expected: 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n...' },
        { title: 'Compare the running state with the file', command: 'cat /etc/nftables.conf', what: 'Shows the persistent configuration that is loaded at boot.', why: 'If the loaded ruleset has rules the file lacks, someone made a runtime-only change: put it into the file first or it will disappear with your reload.', simulated: true },
        { title: 'Back up the file with a timestamp', command: 'cp -a /etc/nftables.conf /etc/nftables.conf.$(date +%F-%H%M)', what: 'Copies the file, preserving owner, mode and timestamps, to e.g. /etc/nftables.conf.2026-10-21-0930.', why: 'The rollback needs the exact pre-change file. With etckeeper installed, also run `etckeeper commit "before CHG-2210"` so the change is visible in `git -C /etc log`.', expected: '(no output)' },
        { title: 'Check what depends on the unit', command: 'systemctl list-dependencies --reverse nftables', what: 'Lists units that want or require nftables.service.', why: 'Tells you what a restart could disturb. A reload of nftables affects no other unit; a reboot affects everything.', expected: 'nftables.service\n● └─sysinit.target\n●   └─basic.target\n●     └─multi-user.target', simulated: true },
        { title: 'Edit the file', command: 'nano /etc/nftables.conf', what: 'Add `tcp dport 443 accept` next to the existing `tcp dport { 22, 80 }` or equivalent rules in the input chain.', why: 'Changes go into the persistent file, never only into the running ruleset.', simulated: true },
        { title: 'Validate without loading', command: 'nft -c -f /etc/nftables.conf', what: '`-c` (check) parses the file and checks it against the kernel without committing anything.', why: 'A typo is caught here instead of during the reload. Silent output means valid.', expected: '(no output when valid)\nError: syntax error, unexpected acept   (example of an error)', simulated: true },
        { title: 'Arm an automatic rollback', command: 'systemd-run --on-active=5min /usr/sbin/nft -f /etc/nftables.conf.2026-10-21-0930', what: 'Creates a transient timer that reloads the backup in 5 minutes, whether or not your session survives. Alternative: `echo "/usr/sbin/nft -f /etc/nftables.conf.2026-10-21-0930" | at now + 5 minutes`.', why: 'If the new ruleset locks you out, the old one comes back by itself. Debian\'s nftables.conf starts with `flush ruleset`, so loading the backup replaces the whole ruleset.', expected: 'Running timer as unit: run-r0b5e3c6a1f6d4b3c9e2a7d8f4c1b2a3e.timer\nWill run service as unit: run-r0b5e3c6a1f6d4b3c9e2a7d8f4c1b2a3e.service' },
        { title: 'Apply with a reload', command: 'systemctl reload nftables', what: 'Loads /etc/nftables.conf atomically.', why: 'If it fails, the old ruleset stays loaded and `systemctl status nftables` shows "Reload failed" with the error.', expected: '(no output on success)', simulated: true },
        { title: 'Test with a NEW connection from a client', command: 'nc -zv srv01.corp.lab 22\ncurl -I http://srv01.corp.lab/', what: 'Run from ws01 (a second terminal): confirms SSH is still allowed for new connections and the web site answers.', why: 'Your existing session survives any ruleset because it matches `ct state established`. Only a new connection proves the new rules.', expected: 'Connection to srv01.corp.lab (10.0.20.10) 22 port [tcp/ssh] succeeded!\nHTTP/1.1 200 OK', simulated: true },
        { title: 'Cancel the rollback', command: 'systemctl list-timers "run-*"\nsystemctl stop run-r0b5e3c6a1f6d4b3c9e2a7d8f4c1b2a3e.timer', what: 'Stops the pending rollback timer.', why: 'Otherwise the rollback runs anyway and silently undoes a good change.', expected: '(no output)' },
        { title: 'Prove the change survives a reboot (in the window)', command: 'reboot\n# then, from ws01:\nnc -zv srv01.corp.lab 22', what: 'Rebuilds the system from persistent configuration.', why: 'The `ssh-monday-reboot` ticket is what happens when this step is skipped.', expected: '[ simulated reboot of srv01 ]\n...\nConnection to srv01.corp.lab (10.0.20.10) 22 port [tcp/ssh] succeeded!', simulated: true },
        { title: 'Other validators to know', command: 'sshd -t\nnginx -t\nnamed-checkconf && named-checkzone corp.lab /etc/bind/db.corp.lab\ndhcpd -t -cf /etc/dhcp/dhcpd.conf\nvisudo -c\nnetplan generate', what: 'The syntax check for each common service. `named-checkzone` also reports the serial it loaded.', why: 'Every daemon you change has one; using it before the reload is what separates a safe change from a gamble. `netplan try` additionally reverts a network change automatically unless confirmed within 120 seconds.', expected: 'zone corp.lab/IN: loaded serial 2026101901\nOK' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky Linux 9 / AlmaLinux 9',
      summary: 'Same process; the differences are firewalld\'s runtime/permanent split (which gives you a built-in rollback), SELinux labels when restoring files, and NetworkManager instead of ifupdown/netplan. Run on a real VM.',
      prerequisites: ['Console access (hypervisor, iLO/iDRAC).', 'An open SSH session.', 'Optional: etckeeper from EPEL (`dnf install etckeeper && etckeeper init`).'],
      steps: [
        { title: 'Record the baseline', command: 'firewall-cmd --list-all > /root/fw-before.txt\nsshd -T > /root/sshd-before.txt\nnmcli -f all connection show eth0 > /root/eth0-before.txt', what: 'Saves the effective firewall zone, sshd configuration and network profile.', why: 'You compare against these after the change and during an incident.', expected: '' },
        { title: 'Change the runtime only', command: 'firewall-cmd --add-service=https', what: 'Opens HTTPS in the runtime configuration only.', why: 'Runtime changes are discarded by `firewall-cmd --reload` or a reboot, so a mistake can be undone by reloading the permanent configuration.', expected: 'success' },
        { title: 'Test from a client, then make it permanent', command: 'firewall-cmd --runtime-to-permanent\nfirewall-cmd --check-config', what: 'Copies the tested runtime configuration to the permanent one and checks the XML.', why: 'Forgetting this step is the RHEL version of "it worked until the reboot".', expected: 'success\nsuccess' },
        { title: 'Restore a file with the right SELinux label', command: 'cp -a /etc/ssh/sshd_config.2026-10-21-0930 /etc/ssh/sshd_config\nrestorecon -v /etc/ssh/sshd_config\nsshd -t && systemctl reload sshd', what: 'Restores the backup, makes sure its SELinux context is correct, validates and reloads.', why: 'A file with the wrong label (e.g. moved from /root) is denied to the daemon even though the Unix permissions look right.', expected: '' },
        { title: 'Network change with automatic revert', command: 'nmstatectl apply --no-commit --timeout 60 eth0-new.yml\n# test from a client, then:\nnmstatectl commit', what: 'nmstate creates a NetworkManager checkpoint, applies, and rolls back after 60 seconds unless committed.', why: 'NetworkManager\'s `nmcli connection up` has no built-in revert. Without nmstate, arm `systemd-run --on-active=5min /usr/bin/nmcli connection up eth0-old` first.', expected: '' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server 2019 / 2022',
      summary: 'The same discipline with Windows tools: export what you will change, keep a second way in (console, WinRM from another host), restart only the affected service, verify from a client. Run in an elevated PowerShell on a real server.',
      prerequisites: ['Hypervisor console or iLO/iDRAC access.', 'A second administrative path (WinRM from a management host) when changing RDP.', 'For VMs: permission to take a checkpoint.'],
      steps: [
        { title: 'Record the original settings', command: 'Get-NetIPConfiguration -All | Out-File C:\\Backup\\before-ip.txt\nGet-Service | Select-Object Name, Status, StartType | Export-Csv C:\\Backup\\before-services.csv -NoTypeInformation', what: 'Saves the IP configuration and the state and startup type of every service.', why: 'After the change, `Compare-Object (Import-Csv C:\\Backup\\before-services.csv) (Get-Service | Select Name,Status,StartType) -Property Name,Status,StartType` shows what changed.', expected: '' },
        { title: 'Back up registry keys, firewall policy and GPOs', command: 'reg export "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" C:\\Backup\\ts.reg /y\nnetsh advfirewall export C:\\Backup\\firewall.wfw\nBackup-GPO -Name "CORP - Server Baseline 2026" -Path C:\\Backup\\GPO', what: 'Exports the Remote Desktop registry key, the complete Windows Firewall policy and one GPO.', why: 'Each has a matching restore: `reg import`, `netsh advfirewall import`, `Restore-GPO`.', expected: 'The operation completed successfully.\nOk.' },
        { title: 'Snapshot the VM (if virtual)', command: 'Checkpoint-VM -Name app01 -SnapshotName "before CHG-2210"', what: 'Run on the Hyper-V host: takes a checkpoint of the whole VM.', why: 'A last-resort rollback. Do not keep checkpoints for long, and never revert a domain controller to a checkpoint outside supported mechanisms.', expected: '' },
        { title: 'Check dependencies before restarting', command: 'Get-Service TermService -DependentServices\nGet-Service TermService -RequiredServices', what: 'Shows what stops with the service and what it needs.', why: 'Restart-Service on a service with running dependents fails unless you add -Force, which restarts the dependents too.', expected: 'Status   Name               DisplayName\n------   ----               -----------\nRunning  UmRdpService       Remote Desktop Services UserMode Po...' },
        { title: 'Arm a scheduled rollback for risky firewall changes', command: 'schtasks /create /tn "CHG-2210 rollback" /sc once /st 14:35 /ru SYSTEM /tr "netsh advfirewall import C:\\Backup\\firewall.wfw"', what: 'Creates a one-off task that restores the firewall policy at 14:35.', why: 'Same safety net as systemd-run on Linux. Delete it with `schtasks /delete /tn "CHG-2210 rollback" /f` after the test passes.', expected: 'SUCCESS: The scheduled task "CHG-2210 rollback" has successfully been created.' },
        { title: 'Apply and restart only the affected service', command: 'Restart-Service W32Time', what: 'Restarts the one service whose configuration changed.', why: 'A reboot is not a fix and destroys evidence; restart only what the change requires. Group Policy changes need `gpupdate /force`, not a reboot, unless a setting says so.', expected: '' },
        { title: 'Verify from a client', command: 'Test-NetConnection app01 -Port 3389', what: 'Run from another machine: checks TCP reachability of the service.', why: 'The server reporting "Running" is not the same as users being able to connect.', expected: 'ComputerName     : app01\nRemoteAddress    : 10.0.20.21\nRemotePort       : 3389\nTcpTestSucceeded : True' },
      ],
    },
    {
      id: 'pfsense',
      platform: 'pfSense CE 2.7',
      summary: 'pfSense keeps the whole configuration in one XML file and saves a revision on every change, so backup and rollback are built in. The risk is locking yourself out of the GUI with a rule change. The simulator does not model pfSense.',
      prerequisites: ['Console access (VGA/serial, or the hypervisor console).', 'Access from the LAN, where the anti-lockout rule applies.'],
      steps: [
        { title: 'Download a full backup', command: 'Diagnostics > Backup & Restore > Backup area: All > Download configuration as XML', what: 'Saves config.xml to your workstation.', why: 'Config History lives on the firewall itself; a downloaded copy survives a disk failure or reinstall.', expected: 'config-fw01.corp.lab-20261021093012.xml' },
        { title: 'Keep the anti-lockout rule', command: 'System > Advanced > Admin Access > Anti-lockout: leave "Disable webConfigurator anti-lockout rule" unchecked', what: 'An automatic LAN rule that always allows the GUI and SSH.', why: 'Rules you add on LAN cannot then block your own management access.', expected: '' },
        { title: 'Make the change and apply', command: 'Firewall > Rules > LAN > edit > Save > Apply Changes', what: 'Saving writes config.xml and a revision; Apply reloads the filter.', why: 'A filter reload keeps existing states, so test with a new connection.', expected: 'The changes have been applied successfully.' },
        { title: 'Review or revert', command: 'Diagnostics > Backup & Restore > Config History', what: 'Lists revisions with time, user and description; Diff compares two; Revert restores one.', why: 'This is the rollback; use it as soon as verification fails.', expected: '' },
        { title: 'Recover from the console if locked out', command: 'Console menu: 15) Restore recent configuration', what: 'Lists recent revisions and restores the one you choose, then reboots or reloads as needed.', why: 'Works when the GUI is unreachable.', expected: '' },
      ],
    },
    {
      id: 'docker',
      platform: 'Docker Engine 27 / Compose v2',
      summary: 'Compose files are the persistent configuration of a container stack: keep them in git, validate them, apply with `up -d` (which recreates only changed services), and roll back by reverting the commit. The simulator does not model Docker.',
      prerequisites: ['The stack directory is a git repository.', 'Images pinned by tag or digest.', 'Data in named volumes is backed up separately.'],
      steps: [
        { title: 'Record the running state', command: 'docker compose ps\ndocker compose config > /root/app-config-before.yml', what: 'Lists containers and saves the fully resolved configuration.', why: 'The resolved config includes .env interpolation, so it is the exact desired state before the change.', expected: 'NAME        IMAGE          COMMAND                  SERVICE   CREATED       STATUS        PORTS\napp-web-1   nginx:1.27.2   "/docker-entrypoint.…"   web       3 days ago    Up 3 days     0.0.0.0:8080->80/tcp' },
        { title: 'Validate the new file', command: 'docker compose config --quiet', what: 'Parses and merges compose.yaml and .env without starting anything.', why: 'YAML indentation and unknown keys are caught before `up`.', expected: '(no output when valid)' },
        { title: 'Apply only what changed', command: 'git commit -am "web: publish 8443"\ndocker compose up -d', what: 'Recreates the services whose configuration changed; others keep running.', why: '`docker compose restart` would restart the old container without applying the change.', expected: '[+] Running 1/1\n ✔ Container app-web-1  Started' },
        { title: 'Verify from a client', command: 'curl -I http://srv01.corp.lab:8080/', what: 'Tests through the published port, from another host.', why: 'A container "Up" can still be unreachable (port binding, firewall, wrong network).', expected: 'HTTP/1.1 200 OK' },
        { title: 'Roll back', command: 'git revert --no-edit HEAD\ndocker compose up -d', what: 'Restores the previous compose file and recreates the affected services.', why: 'Works because the old image tag still exists; if the change migrated data in a volume, restore the volume backup too.', expected: '' },
      ],
    },
  ],

  configIntro: `
The settings below are not one service's directives: they are the knobs that decide how a system behaves when something goes wrong, and whether your recovery tools work when you need them. Check them **before** an incident.
`,

  configFiles: [
    {
      platform: 'Linux (Debian/Ubuntu, RHEL)',
      items: [
        { path: '/etc/nftables.conf', purpose: 'Persistent firewall ruleset (Debian); starts with `flush ruleset` so `nft -f` replaces everything.' },
        { path: '/etc/systemd/system/<unit>.d/*.conf', purpose: 'Drop-ins (systemctl edit) for Restart=, StartLimit*, dependencies. Never edit /lib/systemd/system files.' },
        { path: '/etc/systemd/system/*.target.wants/', purpose: 'Enablement symlinks: what starts at boot.' },
        { path: '/etc/.git', purpose: 'etckeeper history of /etc.' },
        { path: '/var/log/journal/', purpose: 'Persistent journal; without it, logs from before a reboot are gone.' },
        { path: '/etc/netplan/*.yaml (Ubuntu), /etc/NetworkManager/system-connections/ (RHEL), /etc/network/interfaces (Debian)', purpose: 'Persistent network configuration.' },
        { path: '/etc/sysctl.d/*.conf', purpose: 'Persistent kernel parameters (sysctl -w is runtime only).' },
      ],
    },
    {
      platform: 'Windows Server',
      items: [
        { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>', purpose: 'Service start type, dependencies (DependOnService) and recovery actions.' },
        { path: 'services.msc > <service> > Recovery', purpose: 'First/second/subsequent failure actions (restart, run a program, reboot).' },
        { path: '%SystemRoot%\\System32\\winevt\\Logs\\System.evtx', purpose: 'Service Control Manager events (7000, 7031, 7034, 7036).' },
        { path: 'Group Policy backups (Backup-GPO)', purpose: 'Restorable copies of GPOs.' },
      ],
    },
    {
      platform: 'pfSense / Docker',
      items: [
        { path: '/cf/conf/config.xml, /cf/conf/backup/', purpose: 'pfSense configuration and automatic revisions.' },
        { path: 'compose.yaml, .env', purpose: 'Desired state of a container stack (keep in git).' },
        { path: '/etc/docker/daemon.json', purpose: 'Daemon settings such as "live-restore".' },
      ],
    },
  ],

  directives: [
    { name: 'flush ruleset (first line of /etc/nftables.conf)', compiledDefault: '(none: nft -f appends)', distroDefault: 'present in Debian\'s default file', recommended: 'Always the first line of a full ruleset file and of every ruleset backup', explanation: 'Makes `nft -f file` replace the whole ruleset in one transaction instead of adding to what is loaded.', security: 'A backup saved with `nft list ruleset > file` lacks this line; restoring it would duplicate tables or fail, so the "rollback" leaves the bad rules in place.' },
    { name: 'Restart= (systemd unit)', compiledDefault: 'no', distroDefault: 'on-failure for ssh.service, nginx: none', recommended: 'on-failure for long-running daemons', explanation: 'Whether systemd restarts the service after it exits. `on-failure` covers non-zero exits, signals and watchdog timeouts.', security: 'Automatic restarts keep users served but can hide a crash loop: check `NRestarts` (`systemctl show -p NRestarts`) and the journal, not only "active".' },
    { name: 'StartLimitIntervalSec= / StartLimitBurst=', compiledDefault: '10s / 5', recommended: 'Defaults; raise only with a reason', explanation: 'If a unit is started more than Burst times within Interval, systemd stops trying: "Start request repeated too quickly". `systemctl reset-failed <unit>` clears the counter.', security: 'The limit is what turns a flapping service into a visibly failed one; disabling it hides problems.' },
    { name: 'RestartPreventExitStatus=', compiledDefault: '(empty)', distroDefault: '255 for Debian ssh.service', recommended: 'Keep the vendor value', explanation: 'Exit codes that must not trigger an automatic restart. sshd exits 255 on a configuration error, so systemd does not loop on a broken config.', security: 'Explains why a bad sshd_config keeps SSH down until someone uses the console.' },
    { name: 'KillMode=', compiledDefault: 'control-group', distroDefault: 'process for ssh.service', recommended: 'Vendor value', explanation: 'Which processes are killed on stop. With `process`, only sshd\'s listener is killed; existing SSH sessions survive a restart.', security: 'That is why restarting sshd from an SSH session is usually survivable; restarting Remote Desktop Services is not.' },
    { name: 'Storage= (/etc/systemd/journald.conf)', compiledDefault: 'auto (persistent only if /var/log/journal exists)', recommended: 'persistent on servers', explanation: 'Whether the journal survives reboots. Check with `journalctl --list-boots`: only one boot listed means logs are volatile.', security: 'Without persistent logs, rebooting to "fix" a problem deletes the evidence of what happened.' },
    { name: 'netplan try --timeout', compiledDefault: '120 seconds', recommended: 'Long enough to test from a client (e.g. 120–300)', explanation: 'netplan applies the new configuration and reverts it unless Enter is pressed before the timeout.', security: 'Use `try` rather than `apply` for any change to the interface you are connected through.' },
    { name: 'Service recovery actions (Windows)', compiledDefault: 'Varies per service', recommended: 'Restart for the first two failures, then take no action and alert', explanation: 'Set in services.msc > Recovery or `sc.exe failure <name> reset= 86400 actions= restart/60000/restart/60000//`. The SCM logs event 7031 with the action taken.', security: 'Like Restart=on-failure: keeps the service up, but count the 7031/7034 events to notice a crashing service.' },
    { name: '"live-restore": true (/etc/docker/daemon.json)', compiledDefault: 'false', recommended: 'true on single hosts (not supported with Swarm)', explanation: 'Keeps containers running while dockerd is stopped or restarted (e.g. for a daemon upgrade or daemon.json change).', security: 'Without it, `systemctl restart docker` stops every container on the host.' },
    { name: 'Config History backup count (pfSense)', compiledDefault: 'Set in Diagnostics > Backup & Restore > Config History', recommended: 'Enough revisions to cover a week of changes; plus off-box downloads', explanation: 'How many previous config.xml revisions are kept on the firewall.', security: 'Old revisions roll off: a fault introduced weeks ago may no longer have a local "before" copy.' },
  ],

  troubleshootingIntro: `
### Recovery has an order
1. **Stabilise and scope.** What is broken, for whom, since when? Test from a client. Write down the time.
2. **Look at the most recent change first.** Change records, \`journalctl\`, \`git -C /etc log\`, pfSense Config History, \`Get-WinEvent\` for event 7040 (service start type changed).
3. **Prefer the action with the smallest impact** that could work: reload, then restart one component, then a dependency; a reboot is not a diagnostic step.
4. **Time-box fixing forward.** If the cause is not clear within the agreed time, roll back to the backup and investigate the failed change offline.
5. **Undo your own experiments** that did not help. Every change made during an incident goes in the timeline.
6. **Verify from the client, then after a reboot**, then cancel any pending rollback.
7. **Document**: the incident record is how the next person avoids repeating it.

### Incident record template
- **Summary**: one sentence (what failed, for how long, for whom).
- **Timeline** (with times): change made, first symptom, detection (monitoring or user?), each diagnostic step and change, workaround, recovery, permanent fix.
- **Impact**: which users and services, how long, data loss yes/no.
- **Detection**: how we found out, and how we could have found out sooner.
- **Root cause**: the technical cause (e.g. "SSH rule added at runtime only, lost at reboot").
- **Contributing factors**: why it was possible (no reboot test, no review, unit disabled in an experiment, missing monitoring).
- **Workaround**: what restored service temporarily, and whether it is still in place.
- **Permanent fix**: the change to the persistent configuration and how it was verified.
- **Follow-ups**: actions with owners and dates (add monitoring, add reboot test to the change template, remove the workaround).

Keep it blameless: the question is which safeguard was missing, not who typed the command.
`,

  errorMap: [
    { message: 'Job for nftables.service failed. / Reload failed for nftables.service', layer: 'Validation (reload)', meaning: 'The new file did not load. nft applies files atomically, so the previous ruleset is still active.', firstCheck: 'systemctl status nftables (shows the file:line error); nft -c -f /etc/nftables.conf' },
    { message: 'Bad configuration option: PubkeyAuthentcation', layer: 'Validation (sshd -t)', meaning: 'A misspelt keyword; after a restart sshd is down, after a reload the old sshd keeps running.', firstCheck: 'sshd -t; journalctl -u ssh -n 20' },
    { message: 'nginx: [emerg] unknown directive "servr_name" in /etc/nginx/sites-enabled/default:5', layer: 'Validation (nginx -t)', meaning: 'Syntax error in the named file and line; nginx refuses to load it.', firstCheck: 'nginx -t' },
    { message: '>>> /etc/sudoers.d/admins: syntax error near line 3 <<<', layer: 'Validation (visudo)', meaning: 'A broken sudoers file can make sudo unusable for everyone, which removes your own way to fix it.', firstCheck: 'Always edit with visudo -f; visudo -c to check all files' },
    { message: '<unit>.service: Start request repeated too quickly.', layer: 'Service (flapping)', meaning: 'The unit crashed and was restarted more than StartLimitBurst times in StartLimitIntervalSec; systemd gave up.', firstCheck: 'journalctl -u <unit> -b (the first failure explains the loop); systemctl reset-failed <unit> after fixing' },
    { message: 'Error 1068: The dependency service or group failed to start.', layer: 'Service dependencies (Windows)', meaning: 'A service listed in DependOnService is disabled or failing.', firstCheck: 'Get-Service <name> -RequiredServices; System log event 7001' },
    { message: 'Error 1053: The service did not respond to the start or control request in a timely fashion.', layer: 'Service (Windows)', meaning: 'The service did not report "running" within the SCM timeout (event 7009/7000).', firstCheck: 'Get-WinEvent System, Service Control Manager 7000/7009; the application\'s own log' },
    { message: 'No space left on device', layer: 'Resources', meaning: 'Disk (or inodes) full: services fail to write logs, PID files or data, and often fail to start.', firstCheck: 'df -h; df -i; du -xh /var | sort -h | tail; lsof +L1 (deleted but open files)' },
    { message: 'Changes will revert in 120 seconds', layer: 'netplan try', meaning: 'The new network configuration is active on probation; it reverts unless confirmed.', firstCheck: 'Test from a client in another session; press Enter only if it works' },
    { message: 'Temporary failure in name resolution (after a "quick DNS change")', layer: 'Workaround side effect', meaning: 'A troubleshooting change (e.g. nameserver 8.8.8.8) replaced a working resolver with one that cannot answer internal names or is unreachable.', firstCheck: 'cat /etc/resolv.conf; compare with the baseline; dig @10.0.10.53 name' },
  ],

  scenarioIds: ['ssh-monday-reboot', 'ssh-config-typo', 'fw-no-established', 'case-no-internet', 'case-dns-outage', 'ssh-port-moved'],
  assessmentId: 'recovery',
  references: [
    { title: 'systemd.service(5): Restart=, RestartPreventExitStatus=, ExecReload=', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html' },
    { title: 'systemd.unit(5): StartLimitIntervalSec=, dependencies', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html' },
    { title: 'systemd-run(1): transient timers', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html' },
    { title: 'nft(8): -c / --check and atomic ruleset loading', url: 'https://www.netfilter.org/projects/nftables/manpage.html' },
    { title: 'netplan try', url: 'https://netplan.readthedocs.io/en/stable/netplan-try/' },
    { title: 'etckeeper', url: 'https://etckeeper.branchable.com/' },
    { title: 'Red Hat: Using firewalld (runtime and permanent configuration)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_firewalls_and_packet_filters/using-and-configuring-firewalld_firewall-packet-filters' },
    { title: 'Microsoft Learn: Backup-GPO', url: 'https://learn.microsoft.com/powershell/module/grouppolicy/backup-gpo' },
    { title: 'Netgate docs: Backup and Recovery (pfSense)', url: 'https://docs.netgate.com/pfsense/en/latest/backup/index.html' },
    { title: 'Docker docs: docker compose up / config', url: 'https://docs.docker.com/reference/cli/docker/compose/' },
    { title: 'Docker docs: Live restore', url: 'https://docs.docker.com/engine/daemon/live-restore/' },
    { title: 'Google SRE Book: Postmortem Culture', url: 'https://sre.google/sre-book/postmortem-culture/' },
  ],
};

export const RECOVERY_ASSESSMENT: Assessment = {
  id: 'recovery',
  title: 'Safe infrastructure recovery knowledge check',
  questions: [
    {
      id: 'recovery-q-order',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/recovery/internals'],
      prompt: 'You must add a rule to srv01\'s firewall over SSH. Put the steps of a safe change in order.',
      items: [
        'Record the effective state (nft list ruleset) as a baseline',
        'Back up /etc/nftables.conf with a timestamp',
        'Edit /etc/nftables.conf',
        'Validate the file with nft -c -f',
        'Arm an automatic rollback (systemd-run --on-active=5min)',
        'systemctl reload nftables',
        'Test with a NEW connection from a client',
        'Cancel the rollback and document the change',
      ],
      concepts: ['ops.recovery', 'fw.persistence'],
      explanation: 'Baseline and backup come before any edit; validation before loading; the rollback is armed before the risky step; only a new client connection proves the result; cancel the rollback last, or it will undo the good change.',
    },
    {
      id: 'recovery-q-monday',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/recovery/internals'],
      prompt: 'Monday after a patch reboot, SSH to srv01 times out. Last Wednesday an admin "fixed SSH quickly" after rewriting /etc/nftables.conf. What do these outputs show?',
      exhibit: '# history | grep nft   (Wednesday)\nnft -f /etc/nftables.conf\nnft add rule inet filter input tcp dport 22 accept\n\n# grep -c "dport 22" /etc/nftables.conf\n0',
      options: [
        { text: 'The Wednesday command was a workaround: it changed only the running ruleset, which the reboot rebuilt from a file without the SSH rule.', correct: true },
        { text: 'The patch broke nftables; reinstall the package.', misconception: 'Nothing points to the package. The loaded ruleset matches the file exactly; the file never had the rule.' },
        { text: 'Run the same nft add rule again; it fixed it last time.', misconception: 'That repeats the workaround and the fault returns at the next reboot. Put the rule in /etc/nftables.conf and reload.' },
        { text: 'The reboot did not load /etc/nftables.conf.', misconception: 'It did: the loaded ruleset lacks the rule precisely because it was loaded from the file.' },
      ],
      concepts: ['fw.persistence', 'ops.recovery'],
      explanation: '`nft add rule` modifies only the kernel\'s running ruleset. The persistent source is /etc/nftables.conf, loaded at boot by nftables.service. In the `ssh-monday-reboot` ticket a second fault (ssh.service disabled) appears once the firewall is fixed, which is why you re-test after each fix.',
    },
    {
      id: 'recovery-q-reload',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/recovery/internals'],
      prompt: 'An admin added a line to an sshd drop-in and ran `systemctl reload ssh` on Debian 12. Users with open sessions notice nothing. What is the state of SSH now?',
      exhibit: '     Active: active (running) since Mon 2026-10-19 07:58:05 UTC; 35min ago\n    Process: 405 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)\n   Main PID: 407 (sshd)\n...\nsshd[431]: /etc/ssh/sshd_config.d/10-hardening.conf line 5: Bad configuration option: PubkeyAuthentcation\nsystemd[1]: ssh.service: Control process exited, code=exited, status=255/EXCEPTION\nsystemd[1]: Reload failed for ssh.service - OpenBSD Secure Shell server.',
      options: [
        { text: 'SSH is down for new connections.', misconception: 'The reload validates first; when validation fails, systemd does not signal the daemon, so the old sshd (PID 407) keeps accepting connections.' },
        { text: 'The old sshd is still running with the old configuration; the new line was not applied and the file now contains an error that will stop sshd at the next restart or reboot.', correct: true },
        { text: 'sshd ignored the bad line and applied the rest.', misconception: 'sshd does not partially apply: sshd -t failed, so nothing new was loaded.' },
        { text: 'Existing sessions will be closed within ClientAliveInterval.', misconception: 'Sessions are separate processes and are unaffected by a failed reload.' },
      ],
      concepts: ['svc.systemd', 'ssh.config', 'ops.recovery'],
      explanation: 'Reload is safer than restart, but it leaves a time bomb: the broken file will stop sshd at the next restart or reboot. Fix or restore the file now and verify with `sshd -t` (exhibit from the simulator).',
    },
    {
      id: 'recovery-q-persistent',
      kind: 'multi',
      level: 'beginner',
      learn: ['lesson/recovery/internals'],
      prompt: 'Which of these changes survive a reboot without any further action? (Select all that apply.)',
      options: [
        { text: 'Adding a rule to /etc/nftables.conf and running systemctl reload nftables (nftables.service enabled)', correct: true },
        { text: 'systemctl enable --now ssh', correct: true },
        { text: 'firewall-cmd --permanent --add-service=https (followed by firewall-cmd --reload)', correct: true },
        { text: 'nft add rule inet filter input tcp dport 443 accept', misconception: 'Runtime only: lost at reboot or at the next reload of /etc/nftables.conf.' },
        { text: 'sysctl -w net.ipv4.ip_forward=1', misconception: 'Runtime only: persist it in /etc/sysctl.d/*.conf.' },
        { text: 'systemctl start nginx on a disabled unit', misconception: 'start is "now"; enable is "at boot". A disabled unit stays stopped after reboot.' },
      ],
      concepts: ['fw.persistence', 'svc.systemd'],
      explanation: 'A reboot rebuilds runtime state from persistent configuration and enabled units. Anything else is a workaround that expires at the next restart.',
    },
    {
      id: 'recovery-q-disk',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/recovery/internals'],
      prompt: 'nginx on a server stops answering every few days. Each time, restarting it "fixes" the problem. During the last incident you saw the following. What is the best classification of "restart nginx"?',
      exhibit: '$ df -h /var\nFilesystem      Size  Used Avail Use% Mounted on\n/dev/vda1        20G   20G     0 100% /\n$ sudo lsof +L1 | head -3\nCOMMAND  PID     USER   FD   TYPE DEVICE   SIZE/OFF NLINK  NODE NAME\nnginx    812 www-data    5w   REG  254,1 9663676416     0 39321 /var/log/nginx/access.log.1 (deleted)',
      options: [
        { text: 'A permanent fix: the service runs normally afterwards.', misconception: 'The symptom returns every few days. The restart only closes a deleted log file that still holds 9 GB; the cause (logs that are deleted instead of rotated properly) remains.' },
        { text: 'A workaround: the restart releases the space held by a deleted-but-open log; the permanent fix is correct log rotation (reopen logs after rotating) and monitoring disk usage.', correct: true },
        { text: 'A rollback.', misconception: 'Nothing was restored to a previous configuration.' },
        { text: 'Unnecessary: the disk being full is unrelated.', misconception: '100% use on / prevents nginx from writing logs and temporary files; this is the cause of the outage.' },
      ],
      concepts: ['ops.recovery', 'linux.fs'],
      explanation: 'A deleted file keeps its blocks until the last process closes it (NLINK 0, "(deleted)"). Proper logrotate configuration signals nginx to reopen its logs (postrotate `nginx -s reopen` / `invoke-rc.d nginx rotate`). Record the restart as a workaround and the rotation fix as the follow-up.',
    },
    {
      id: 'recovery-q-workaround-dns',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/recovery/troubleshoot'],
      prompt: 'In the `case-no-internet` ticket, srv01 could not reach the update mirror. Before you arrived, a colleague set `nameserver 8.8.8.8` in srv01\'s /etc/resolv.conf "in case it was DNS". You found and fixed the real cause (NAT on rtr01). What should happen to the resolver change?',
      options: [
        { text: 'Leave it: public DNS is more reliable.', misconception: '8.8.8.8 does not know corp.lab, so internal names (ns1.corp.lab, the database) stop resolving. The workaround added a second fault.' },
        { text: 'Undo it (nameserver 10.0.10.53, search corp.lab), and record both the change and its removal in the incident timeline.', correct: true },
        { text: 'Add 8.8.8.8 as a second nameserver next to 10.0.10.53.', misconception: 'Resolvers do not try the next server on NXDOMAIN; if 8.8.8.8 answers first, internal names fail intermittently.' },
        { text: 'Restart systemd-resolved to clear the cache.', misconception: 'The file content is the problem; and Debian 12 in this lab does not use systemd-resolved.' },
      ],
      concepts: ['ops.recovery', 'dns.resolution'],
      explanation: 'Troubleshooting changes that do not fix the cause must be reverted. Compare the final state with a baseline so that only intended changes remain.',
    },
    {
      id: 'recovery-q-rollback-cmd',
      kind: 'text',
      level: 'advanced',
      learn: ['lesson/recovery/internals', 'lesson/recovery/operate'],
      prompt: 'Before reloading a new firewall on a remote Debian server, you want systemd to load the backup /root/nftables.conf.bak automatically in 5 minutes unless you cancel it. Type the command.',
      accept: [/^(sudo\s+)?systemd-run\s+--on-active=(5min|5m|300s?|"5min"|'5min')\s+(\/usr\/sbin\/)?nft\s+-f\s+\/root\/nftables\.conf\.bak$/],
      placeholder: 'command',
      concepts: ['ops.recovery', 'fw.persistence'],
      explanation: '`systemd-run --on-active=5min /usr/sbin/nft -f /root/nftables.conf.bak` creates a transient timer + service. After a new connection succeeds, cancel it with `systemctl stop run-r<id>.timer`. `echo "/usr/sbin/nft -f /root/nftables.conf.bak" | at now + 5 minutes` is the at(1) alternative. The backup must start with `flush ruleset`.',
    },
    {
      id: 'recovery-q-access',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/recovery/what', 'lesson/recovery/operate'],
      prompt: 'You are about to change the address and gateway of eth0 on a remote server, and your SSH session runs over eth0. Which measures actually protect you from a lock-out? (Select all that apply.)',
      options: [
        { text: 'Open the hypervisor console or iLO/iDRAC before starting', correct: true },
        { text: 'Use netplan try (Ubuntu) or nmstatectl apply --no-commit (RHEL), or arm a systemd-run rollback', correct: true },
        { text: 'Keep the existing SSH session open', misconception: 'Helpful for firewall changes, but an address change on the interface you use breaks your current session too. It is not enough on its own here.' },
        { text: 'Run the change inside tmux so it completes even if the session drops', correct: true },
        { text: 'Make the change at night so fewer users notice', misconception: 'A maintenance window reduces impact on users; it does not give you a way back in.' },
      ],
      concepts: ['ops.recovery', 'net.ops'],
      explanation: 'Out-of-band access does not depend on the network configuration; automatic revert undoes a bad change without you; tmux prevents a half-applied sequence. An open session survives firewall changes thanks to connection tracking, but not an address change on its own interface.',
    },
    {
      id: 'recovery-q-reverse-deps',
      kind: 'text',
      level: 'intermediate',
      learn: ['lesson/recovery/internals'],
      prompt: 'Before restarting nftables on srv01, you want to see which units depend on nftables.service (the units that would be affected). Type the systemctl command.',
      accept: [/^(sudo\s+)?systemctl\s+list-dependencies\s+--reverse\s+nftables(\.service)?$/, /^(sudo\s+)?systemctl\s+list-dependencies\s+nftables(\.service)?\s+--reverse$/],
      placeholder: 'command',
      concepts: ['svc.systemd', 'ops.recovery'],
      explanation: '`systemctl list-dependencies --reverse nftables` shows the units that want or require it. On Windows the equivalent is `Get-Service <name> -DependentServices`.',
    },
    {
      id: 'recovery-q-flapping',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/recovery/internals'],
      prompt: 'Monitoring shows the app "up" all week, but users report short outages several times a day. Then this appears. What does it tell you?',
      exhibit: 'systemd[1]: app.service: Main process exited, code=killed, status=9/KILL\nsystemd[1]: app.service: Failed with result \'signal\'.\nsystemd[1]: app.service: Scheduled restart job, restart counter is at 5.\nsystemd[1]: app.service: Start request repeated too quickly.\nsystemd[1]: app.service: Failed with result \'signal\'.\nsystemd[1]: Failed to start app.service - Example App.',
      options: [
        { text: 'The service has been crashing and Restart=on-failure has been hiding it; it has now hit the start limit. Find why it is killed (e.g. the OOM killer: journalctl -k | grep -i oom) instead of just restarting it.', correct: true },
        { text: 'Raise StartLimitBurst so systemd keeps restarting it.', misconception: 'That hides the crash loop even better; the outages continue.' },
        { text: 'Reboot the server: it resets all counters.', misconception: 'A reboot is not a diagnostic step; the process will be killed again for the same reason.' },
        { text: 'The configuration file has a syntax error.', misconception: 'A config error normally fails immediately on start (status=1 or 255 from ExecStartPre); here the running process was killed with SIGKILL.' },
      ],
      concepts: ['svc.systemd', 'ops.recovery', 'logs.journal'],
      explanation: 'status=9/KILL with repeated restarts is typical of the kernel OOM killer (a memory leak). Automatic restarts are a workaround; the fix is the leak or the memory limit. `systemctl show app -p NRestarts` shows how often it was restarted.',
    },
    {
      id: 'recovery-q-validate',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/recovery/what'],
      prompt: 'Which command checks /etc/nftables.conf for errors **without** changing the loaded ruleset?',
      options: [
        { text: 'nft -c -f /etc/nftables.conf', correct: true },
        { text: 'nft -f /etc/nftables.conf', misconception: 'That loads the file (atomically). It does not merely check it.' },
        { text: 'systemctl restart nftables', misconception: 'That applies the file; a failure would be discovered by applying it.' },
        { text: 'nft list ruleset', misconception: 'That shows what is loaded now, not whether the file is valid.' },
      ],
      concepts: ['fw.persistence', 'ops.recovery'],
      explanation: '`-c` (`--check`) parses and checks the file against the kernel without committing. The other validators to know: sshd -t, nginx -t, named-checkconf / named-checkzone, dhcpd -t, visudo -c, netplan generate, docker compose config.',
    },
    {
      id: 'recovery-q-incident',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/recovery/troubleshoot'],
      prompt: 'In an incident record for `ssh-monday-reboot`, which entry belongs under **contributing factors** rather than **root cause**?',
      options: [
        { text: 'The SSH allow rule existed only in the runtime ruleset and ssh.service was disabled.', misconception: 'That is the technical root cause: the direct reason SSH failed after the reboot.' },
        { text: 'Changes were not reboot-tested and runtime fixes were not recorded or reviewed.', correct: true },
        { text: 'Added the rule to /etc/nftables.conf, reloaded, and ran systemctl enable --now ssh.', misconception: 'That is the permanent fix.' },
        { text: 'Monday 07:58: first user report.', misconception: 'That is a timeline / detection entry.' },
      ],
      concepts: ['ops.recovery'],
      explanation: 'Root cause = what technically broke; contributing factors = which safeguards were missing so it could happen and stay hidden; follow-ups turn the contributing factors into actions (reboot test in the change template, config management).',
    },
  ],
};
