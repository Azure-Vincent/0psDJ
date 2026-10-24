// Lesson F: Linux service administration with systemd, the journal and the
// filesystem layout. Simulator-backed commands are marked sim/simulated and
// their sample output was captured from the lab (Debian 12 hosts srv01, ns1).

import type { Assessment, Lesson, ServiceGuide } from '../types';

// ---------------------------------------------------------------------------
// Operate & recover guide: the "service" is systemd itself plus journald.
// ---------------------------------------------------------------------------

export const SYSTEMD_GUIDE: ServiceGuide = {
  purpose:
    '**systemd** is PID 1 on Debian, Ubuntu, RHEL and almost every current Linux distribution: the first process the kernel starts and the parent of every service. It reads **unit files**, works out which units are needed for the requested **target** (normally `multi-user.target`), starts them in dependency order, puts each one in its own **cgroup**, restarts them when their policy says so, and records everything they print in the **journal** (`systemd-journald`). When a service "does not start", the answer is almost always in two places: `systemctl status <unit>` (what systemd did and the exit code) and `journalctl -u <unit>` (what the program said). This lesson is about operating systemd and journald themselves; the SSH, nftables and DHCP lessons build on it.',
  architecture: [
    { q: 'What does it accomplish?', a: 'It boots the system to a defined state (a target), supervises long-running services (start, stop, restart on failure, resource limits), activates services on demand (sockets, timers, paths, devices), mounts filesystems from `/etc/fstab`, and collects logs from the kernel, services and syslog() in one indexed journal.' },
    { q: 'How does it work internally?', a: 'systemd loads every unit file from its search path (`/etc/systemd/system` overrides `/run/systemd/system`, which overrides `/lib/systemd/system` = `/usr/lib/systemd/system`), plus units created at boot by **generators** (e.g. `systemd-sysv-generator` turns `/etc/init.d` scripts into units in `/run/systemd/generator.late`). It builds a dependency graph from `Wants=`/`Requires=` (what must also start) and `After=`/`Before=` (in which order), then queues **jobs** (start, stop, restart, reload) and runs them in parallel where ordering allows. Each service runs in a cgroup such as `/system.slice/ssh.service`, so systemd always knows every process that belongs to it, even after forks.' },
    { q: 'Which protocols does it use?', a: 'No network protocol. Clients (`systemctl`, `journalctl`, `loginctl`) talk to PID 1 over **D-Bus** (socket `/run/dbus/system_bus_socket`, or the private `/run/systemd/private` when D-Bus is down). Services report readiness with `sd_notify()` over `/run/systemd/notify` (that is what `Type=notify` waits for). journald receives log lines on `/run/systemd/journal/socket` (native), `/dev/log` (classic syslog) and `/run/systemd/journal/stdout` (service stdout/stderr).' },
    { q: 'Which ports and transport?', a: 'None for systemd itself. With **socket activation** systemd opens a service\'s listening port on its behalf (e.g. Ubuntu 22.10+ `ssh.socket` holds TCP 22 and starts `ssh.service` on the first connection), so `ss -tlnp` shows `systemd` as the owner of the port. Remote log shipping (`systemd-journal-upload`, or rsyslog forwarding) uses its own ports and is optional.' },
    { q: 'Which processes and OS components implement it?', a: '`/lib/systemd/systemd` (PID 1), `systemd-journald` (logging), `systemd-logind` (user sessions), `systemd-udevd` (devices), `systemd-tmpfiles` (creates `/run` and `/var` paths at boot), optional `systemd-networkd` and `systemd-resolved` (network and DNS, default on Ubuntu server), and the client tools `systemctl`, `journalctl`, `systemd-analyze`, `systemd-run`, `loginctl`. Many hosts also run **rsyslog**, which reads from the journal and writes classic text files in `/var/log`.' },
    { q: 'Which other services does it depend on?', a: 'Very few: the kernel, cgroup v2 (`/sys/fs/cgroup`), a readable root filesystem with the unit files, and `/run` (tmpfs). Everything else depends on systemd. D-Bus is needed by `systemctl` for most operations; if D-Bus is broken, `systemctl` falls back to the private socket.' },
    { q: 'How do requests travel?', a: '`sudo systemctl restart nginx` → systemctl sends a D-Bus call to PID 1 → PID 1 checks polkit/root → queues a restart job → runs `ExecStop` (or sends SIGTERM to the cgroup, then SIGKILL after `TimeoutStopSec`) → runs `ExecStartPre`, then `ExecStart` → waits for readiness according to `Type=` → marks the unit `active (running)` or `failed` → systemctl prints nothing on success, or "Job for nginx.service failed because ..." on failure. Every step is logged by `systemd[1]` in the journal with the unit name attached.' },
    { q: 'How do authentication and authorisation work?', a: 'Changing units requires root, or a polkit rule that grants `org.freedesktop.systemd1.manage-units`. Read-only commands (`systemctl status`, `is-active`, `cat`) work for everyone. Reading other users\' and system logs requires root or membership in **adm** or **systemd-journal**; otherwise journalctl prints "Hint: You are currently not seeing messages from other users and the system." Units choose the identity of the service with `User=`/`Group=` (or `DynamicUser=yes`).' },
    { q: 'How does it start at boot?', a: 'Firmware → boot loader → kernel + initramfs (which runs its own systemd on most distributions) → root filesystem mounted → `/sbin/init` (a symlink to systemd) becomes PID 1 → generators run → systemd starts `default.target` (a symlink, normally to `multi-user.target` on servers or `graphical.target` on desktops) and everything it wants: `sysinit.target` (mounts, swap, udev, journald, tmpfiles, sysctl, nftables on Debian) → `basic.target` → `network.target` / `network-online.target` → services enabled in `multi-user.target.wants/`. `systemd-analyze` and `systemd-analyze blame` show how long it took.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If PID 1 dies the kernel panics, so systemd is designed not to: on an internal error it freezes rather than exits. Services are different: when a service\'s main process exits, systemd records the exit code and applies `Restart=` (no, on-failure, always ...). After `StartLimitBurst` (default 5) restarts within `StartLimitIntervalSec` (default 10 s) it gives up: "Start request repeated too quickly", and the unit stays failed until `systemctl reset-failed` or a manual start. If **journald** crashes, systemd restarts it; messages written while it was down may be lost.' },
  ],
  ports: [
    { port: 'none', proto: '—', purpose: 'systemd and journald use local Unix sockets and D-Bus, not network ports' },
    { port: 'per .socket unit', proto: 'TCP/UDP', purpose: 'Socket activation: systemd listens on a service\'s port (e.g. ssh.socket on TCP 22, Ubuntu 22.10+)' },
    { port: '514', proto: 'UDP/TCP', purpose: 'Classic syslog forwarding when rsyslog is configured to send or receive (optional)' },
    { port: '19532', proto: 'TCP', purpose: 'systemd-journal-remote (HTTP) when journal shipping is set up (optional)' },
  ],
  processes: [
    { name: 'systemd (PID 1)', platform: 'Linux', role: 'Service manager and init: unit graph, jobs, cgroups, restarts, timers, sockets' },
    { name: 'systemd-journald', platform: 'Linux', role: 'Collects kernel, service stdout/stderr and syslog messages into the journal (`/run/log/journal` or `/var/log/journal`)' },
    { name: 'systemd-logind', platform: 'Linux', role: 'Tracks user sessions (the "New session 17 of user alice" lines), seats, idle and power keys' },
    { name: 'systemd-udevd', platform: 'Linux', role: 'Device events, interface naming (eth0 vs ens18 vs enp1s0)' },
    { name: 'rsyslogd', platform: 'RHEL; Debian/Ubuntu when installed', role: 'Writes text logs such as `/var/log/syslog`, `/var/log/auth.log` (Debian) or `/var/log/messages`, `/var/log/secure` (RHEL) and forwards to remote syslog servers' },
    { name: 'services.exe (Service Control Manager)', platform: 'Windows Server 2019/2022, Windows 10/11', role: 'The Windows equivalent of systemd for services: starts, stops, recovers services; logs to the System event log' },
  ],
  dependencies: {
    title: 'From power-on to a running service (each row needs the rows below)',
    caption: 'A service unit only starts when its target is reached and its own Requires/Wants are satisfied. Ordering (After=) and requirement (Requires=/Wants=) are separate settings.',
    rows: [
      { label: 'Service', nodes: [{ id: 'svc', label: 'ssh.service', sub: 'ExecStartPre sshd -t', kind: 'service' }, { id: 'web', label: 'nginx.service', sub: 'WantedBy multi-user', kind: 'service' }] },
      { label: 'Targets', nodes: [{ id: 'multi', label: 'multi-user.target', sub: 'default.target', kind: 'os' }, { id: 'net', label: 'network.target', sub: 'networking.service', kind: 'network' }] },
      { label: 'Early boot', nodes: [{ id: 'basic', label: 'basic.target', sub: 'sockets, timers', kind: 'os' }, { id: 'sysinit', label: 'sysinit.target', sub: 'mounts, nftables', kind: 'os' }, { id: 'journal', label: 'journald', sub: 'logging socket', kind: 'service' }] },
      { label: 'Manager', nodes: [{ id: 'pid1', label: 'systemd (PID 1)', sub: 'unit files, cgroups', kind: 'os' }, { id: 'units', label: 'Unit files', sub: '/etc > /run > /lib', kind: 'data' }] },
      { label: 'Kernel', nodes: [{ id: 'kernel', label: 'Kernel + initramfs', sub: 'root fs mounted', kind: 'os' }] },
    ],
    edges: [
      ['svc', 'multi'], ['web', 'multi'], ['svc', 'net', 'After='], ['multi', 'basic'], ['net', 'sysinit'], ['basic', 'sysinit'],
      ['sysinit', 'journal'], ['sysinit', 'pid1'], ['journal', 'pid1'], ['pid1', 'units'], ['pid1', 'kernel'],
    ],
  },
  sequence: {
    title: 'systemctl restart ssh with a broken config (srv01)',
    lanes: [{ id: 'a', label: 'admin', sub: 'systemctl' }, { id: 'p', label: 'systemd', sub: 'PID 1' }, { id: 's', label: 'sshd', sub: 'ssh.service' }, { id: 'j', label: 'journald' }],
    steps: [
      { from: 'a', to: 'p', label: 'D-Bus: RestartUnit ssh.service' },
      { from: 'p', to: 's', label: 'SIGTERM to main PID', note: 'KillMode=process: only the listener is stopped; existing SSH sessions survive.' },
      { from: 'p', to: 'j', label: 'Stopped ssh.service' },
      { from: 'p', to: 's', label: 'ExecStartPre=/usr/sbin/sshd -t' },
      { from: 's', to: 'j', label: 'Bad configuration option', note: 'The program\'s own error goes to the journal, not to your terminal.', fail: true },
      { from: 's', to: 'p', label: 'exit status 255', fail: true },
      { from: 'p', to: 'j', label: 'Failed with result exit-code', note: 'RestartPreventExitStatus=255: systemd does not retry.' },
      { from: 'p', to: 'a', label: 'Job for ssh.service failed', note: 'systemctl tells you to read systemctl status and journalctl -xeu ssh.service.', fail: true },
    ],
  },
  files: [
    { path: '/lib/systemd/system/ (= /usr/lib/systemd/system/)', platform: 'Debian 12 (merged /usr), Ubuntu; RHEL uses /usr/lib/systemd/system', kind: 'unit', perms: 'root:root 0644, owned by packages', contains: 'Vendor unit files installed by packages: `ssh.service`, `nginx.service`, `nftables.service`, `networking.service`. On merged-/usr systems `/lib` is a symlink to `/usr/lib`, so both paths are the same directory.', accessed: 'At boot and on every `systemctl daemon-reload`.', problems: 'Never edit these: the next package upgrade silently overwrites your change. Use a drop-in (`systemctl edit`) or a full copy in /etc/systemd/system.' },
    { path: '/etc/systemd/system/', platform: 'All systemd distributions', kind: 'unit', perms: 'root:root 0755 (files 0644)', contains: 'Administrator units and overrides: complete unit files (highest precedence), `<unit>.d/*.conf` drop-ins, and the `*.wants/` directories of symlinks created by `systemctl enable`. Also `default.target` (symlink) and mask symlinks to `/dev/null`.', accessed: 'At boot and on `daemon-reload`.', problems: 'A forgotten full copy of a vendor unit here hides every later vendor fix. A symlink to /dev/null means the unit is **masked**. Check with `systemctl cat <unit>` (shows the file actually used) and `systemd-delta` (lists overridden, extended and masked units).' },
    { path: '/etc/systemd/system/<unit>.d/override.conf', platform: 'All systemd distributions', kind: 'unit', perms: 'root:root 0644', contains: 'Drop-in fragments that change only some settings of a unit, e.g. `[Service]` `Restart=always`. Created by `systemctl edit <unit>`.', accessed: 'Merged with the main unit at `daemon-reload`.', problems: 'List-type settings accumulate: to replace `ExecStart=` you must first clear it with an empty `ExecStart=` line, otherwise the start fails with "Service has more than one ExecStart= setting". Files created by hand need `systemctl daemon-reload` ("Warning: The unit file, source configuration file or drop-ins of X changed on disk").' },
    { path: '/run/systemd/system/, /run/systemd/generator*/', platform: 'All systemd distributions', kind: 'runtime', perms: 'root, tmpfs', contains: 'Runtime units (lost at reboot): transient units from `systemd-run`, and units written by generators. On ns1, `/run/systemd/generator.late/isc-dhcp-server.service` is generated from `/etc/init.d/isc-dhcp-server`.', accessed: 'Rebuilt at every boot and every `daemon-reload`.', problems: 'Editing a generated file is pointless: it is regenerated. Change the source (the init script, `/etc/fstab`) or put a real unit or drop-in in /etc/systemd/system.' },
    { path: '/etc/systemd/system.conf, journald.conf, *.conf.d/', platform: 'All systemd distributions', kind: 'config', perms: 'root:root 0644', contains: 'Manager defaults (`DefaultTimeoutStartSec=90s`, `DefaultLimitNOFILE`) and journald settings (`Storage=`, `SystemMaxUse=`, `ForwardToSyslog=`). Put changes in `/etc/systemd/journald.conf.d/*.conf`.', accessed: 'system.conf at boot or `systemctl daemon-reexec`; journald.conf when journald restarts.', problems: '`systemd-analyze cat-config systemd/journald.conf` shows the merged result. A too-small `SystemMaxUse` silently rotates away the logs you need.' },
    { path: '/var/log/journal/<machine-id>/ (persistent), /run/log/journal/ (volatile)', platform: 'Persistent by default on Debian 11+ and Ubuntu; check RHEL', kind: 'log', perms: 'root:systemd-journal 2755 directory, files 0640', contains: 'Binary, indexed, checksummed journal files (`system.journal`, `user-1000.journal`, archived `*@*.journal`).', accessed: 'Written continuously by journald; read by journalctl.', problems: 'With `Storage=auto` the journal is persistent only if `/var/log/journal` exists; otherwise it lives in /run and **is lost at reboot**, so `journalctl -b -1` shows "Specifying boot ID or boot offset has no effect, no persistent journal was found." Fix: `mkdir -p /var/log/journal && systemctl restart systemd-journald`.' },
    { path: '/var/log/syslog, auth.log (Debian/Ubuntu); messages, secure (RHEL)', platform: 'When rsyslog is installed', kind: 'log', perms: 'Debian syslog:adm 0640; RHEL root:root 0600', contains: 'Text copies of journal messages sorted by facility: authentication (sshd, sudo, PAM) in auth.log/secure, everything else in syslog/messages. Rotated by logrotate.', accessed: 'Continuously by rsyslog.', problems: 'Debian 12 does not install rsyslog by default (the journal is persistent instead), so these files may simply not exist: use journalctl. RHEL 9 installs rsyslog.' },
    { path: '/etc/init.d/ and /etc/default/', platform: 'Debian/Ubuntu', kind: 'startup', perms: 'root:root, scripts 0755', contains: 'Legacy SysV/LSB init scripts (wrapped by systemd-sysv-generator) and shell-variable files read by units and scripts, e.g. `/etc/default/isc-dhcp-server` (`INTERFACESv4="eth0"`).', accessed: 'When the corresponding unit starts (`EnvironmentFile=` or sourced by the script).', problems: 'A wrong value in /etc/default breaks the service as surely as an error in its main config (the dhcp-interface ticket). There is no `ExecStartPre` syntax check for these files.' },
    { path: '/etc/fstab', platform: 'Linux', kind: 'config', perms: 'root:root 0644', contains: 'Filesystems to mount at boot; `systemd-fstab-generator` turns each line into a `.mount` unit (e.g. `var-lib-data.mount`).', accessed: 'At boot and on daemon-reload.', problems: 'A wrong UUID or an unavailable network share makes boot wait ("A start job is running for /dev/disk/by-uuid/...", 1min 30s) and can drop to emergency mode. Use `nofail` for non-essential mounts and test with `mount -a` and `findmnt --verify` before rebooting.' },
    { path: '/run/systemd/notify, /run/systemd/private, /run/systemd/journal/', platform: 'Linux', kind: 'runtime', contains: 'Sockets for readiness notification, systemctl, and log input.', accessed: 'Constantly.', problems: 'A full or read-only /run (rare) breaks logging and service start. `df -h /run` checks it.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>', platform: 'Windows Server 2019/2022, Windows 10/11', kind: 'registry', contains: 'The Windows equivalent of a unit file: `ImagePath`, `Start` (2 = automatic, 3 = manual, 4 = disabled), `DependOnService`, `ObjectName` (account), `FailureActions`.', accessed: 'By the Service Control Manager at boot and on service start.', problems: 'Edit with `sc.exe config` or `Set-Service`, not regedit. Service failures are logged in the System event log by source Service Control Manager (event IDs 7000, 7009, 7031, 7034).' },
  ],
  management: [
    {
      platform: 'Debian / Ubuntu',
      tasks: [
        { task: 'Is it running? Why not?', command: 'systemctl status ssh', explain: 'First line: unit name and description (`ssh.service`, even if you typed `sshd`, because of `Alias=sshd.service`). **Loaded:** file used, `enabled`/`disabled` (next boot), vendor preset. **Active:** `active (running)` (daemon up), `active (exited)` (oneshot finished, e.g. nftables, networking), `inactive (dead)` (stopped), `failed (Result: exit-code)`. **Process:** lines show helper commands with their exit status (e.g. `ExecStartPre=/usr/sbin/sshd -t (code=exited, status=255/EXCEPTION)`). The last 10 journal lines usually contain the real reason.', sim: true },
        { task: 'Start / stop', command: 'sudo systemctl start nginx\nsudo systemctl stop nginx', explain: 'Starts or stops now; does not change what happens at boot. Silent on success. Stop sends SIGTERM to the cgroup (or runs ExecStop), then SIGKILL after TimeoutStopSec (90 s default).', risk: '`systemctl stop nftables` runs `nft flush ruleset`: the host is left with no firewall at all. Stopping ssh on a remote host blocks new logins.', sim: true },
        { task: 'Restart', command: 'sudo systemctl restart nginx', explain: 'Stop + start. Needed after changing listen ports, binaries, environment files or unit settings. If the start fails, the service is left **down**.', risk: 'Always validate the program\'s config first (`nginx -t`, `sshd -t`, `named-checkconf`, `dhcpd -t`).', sim: true },
        { task: 'Reload configuration', command: 'sudo systemctl reload ssh\nsudo systemctl reload-or-restart nginx', explain: 'Runs the unit\'s `ExecReload=` (for ssh: `sshd -t`, then `kill -HUP $MAINPID`). The process keeps its PID and open connections. A unit without ExecReload answers "Job type reload is not applicable for unit".', risk: 'Lowest risk; a failed reload of ssh or nginx leaves the old process running with the old config.', sim: true },
        { task: 'Enable / disable at boot', command: 'sudo systemctl enable --now nginx\nsudo systemctl disable nginx\nsystemctl is-enabled nginx', explain: '`enable` creates the symlink named in `[Install] WantedBy=` (`/etc/systemd/system/multi-user.target.wants/nginx.service`); `--now` also starts it. `disable` removes the symlink but does **not** stop the running service. On Debian, enabling a unit that also has an init script prints "Synchronizing state of nginx.service with SysV service script".', sim: true },
        { task: 'Mask / unmask', command: 'sudo systemctl mask isc-dhcp-server\nsudo systemctl unmask isc-dhcp-server', explain: 'Mask links the unit to /dev/null so nothing can start it, not even as a dependency: "Failed to start X: Unit X is masked." Use it for services that must never run on this host (e.g. a second DHCP server).', risk: 'A forgotten mask looks like a broken service. `systemctl status` shows `Loaded: masked (Reason: Unit isc-dhcp-server.service is masked.)`. Not modelled in the simulator.' },
        { task: 'List failed units', command: 'systemctl --failed\nsudo systemctl reset-failed', explain: 'Every unit in the failed state, with LOAD/ACTIVE/SUB columns. `reset-failed` clears the state (and the start-limit counter) after you have fixed the cause. The simulator lists only the lab\'s modelled services.', sim: true },
        { task: 'Dependencies', command: 'systemctl list-dependencies ssh\nsystemctl show ssh -p Requires,Wants,After,Before,WantedBy', explain: 'The tree of units this unit pulls in (green/red dots show their state). `show -p` prints the exact dependency properties. On real systems `systemctl list-dependencies --reverse network-online.target` answers "what needs this?" (not modelled in the simulator).', sim: true },
        { task: 'Recent logs', command: 'journalctl -u ssh -b\njournalctl -u ssh -n 20\nsudo journalctl -fu ssh\njournalctl -b -p err', explain: '`-u` one unit (aliases work), `-b` this boot (`-b -1` previous boot), `-n` last N lines, `-f` follow, `-p err` priority err and worse (emerg, alert, crit, err), `-x` adds explanation text, `-e` jumps to the end, `--since "10 min ago"`, `-g PATTERN` grep.', sim: true },
        { task: 'Why did it fail to start?', command: 'systemctl status nginx\njournalctl -xeu nginx\nsystemctl show nginx -p Result,ExecMainStatus,NRestarts', explain: 'Read the `Process:` exit status and the program\'s last message. `status=203/EXEC` = binary missing or not executable; `217/USER` = User= does not exist; `200/CHDIR` = WorkingDirectory missing; `255/EXCEPTION` or `1/FAILURE` = the program itself reported an error (read its message).', sim: true },
        { task: 'Inspect and override a unit', command: 'systemctl cat ssh\nsudo systemctl edit ssh\nsudo systemctl revert ssh', explain: '`cat` prints the unit file actually loaded plus every drop-in, each preceded by its path. `edit` opens an editor on `/etc/systemd/system/ssh.service.d/override.conf` and reloads systemd when you save. `revert` deletes your overrides and returns to the vendor unit.', risk: '`systemctl edit --full` copies the entire vendor unit to /etc: later package fixes to the unit are then ignored. Prefer drop-ins.' },
        { task: 'After editing unit files by hand', command: 'sudo systemctl daemon-reload', explain: 'Re-reads all unit files and re-runs generators. Without it systemd keeps using the old definition and warns "The unit file ... changed on disk. Run \'systemctl daemon-reload\' to reload units."', risk: 'Does not restart services. The new settings apply at the next start/restart of each unit.', sim: true },
        { task: 'Restoring after a config error', command: 'sudo sshd -t   # or nginx -t, dhcpd -t, named-checkconf\nsudo cp /root/backup/10-hardening.conf /etc/ssh/sshd_config.d/\nsudo systemctl restart ssh && systemctl is-active ssh', explain: 'Find the file and line from the journal, fix or restore the backup, validate, then start. If the service hit the start limit, `systemctl reset-failed <unit>` first. (In the simulator there is no /root/backup: fix the line with an editor or sed instead.)' },
      ],
    },
    {
      platform: 'RHEL / Rocky / Alma 9',
      tasks: [
        { task: 'Same systemctl and journalctl', command: 'systemctl status sshd\njournalctl -u sshd -b\nsystemctl --failed', explain: 'Identical commands, different unit names: `sshd.service` (no `ssh` alias), `httpd.service` instead of apache2, `named.service`, `dhcpd.service`, `firewalld.service`, `NetworkManager.service`. Vendor units live in `/usr/lib/systemd/system`.' },
        { task: 'SELinux blocks a service', command: 'sudo ausearch -m AVC -ts recent\nsudo restorecon -Rv /opt/inventory-api\nsudo semanage port -a -t http_port_t -p tcp 8081', explain: 'A service that works when run by hand but fails under systemd ("Permission denied", status=203/EXEC) is often an SELinux denial: the binary or files have the wrong label, or the port is not labelled for that domain.', risk: 'Do not "fix" it with `setenforce 0`; that removes protection for the whole host.' },
        { task: 'Persistent journal and text logs', command: 'ls -ld /var/log/journal\njournalctl --list-boots\nsudo tail /var/log/messages /var/log/secure', explain: 'Check whether the journal survives reboots on your build (`--list-boots` shows more than one boot). rsyslog keeps `/var/log/messages` (general) and `/var/log/secure` (authentication) regardless.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      tasks: [
        { task: 'Status / start / stop / restart', command: 'Get-Service sshd, W32Time\nStart-Service W32Time\nStop-Service W32Time\nRestart-Service W32Time', explain: 'The Service Control Manager (services.exe) plays the role of systemd. There is no generic "reload": a service either supports a control code (e.g. `sc.exe control <svc> paramchange`) or must be restarted. See the **windows-rdp** lesson for TermService (RDP).' },
        { task: 'Enable / disable at boot', command: 'Set-Service W32Time -StartupType Automatic\nsc.exe config W32Time start= delayed-auto', explain: 'StartupType Automatic, Automatic (Delayed Start), Manual, Disabled correspond to enabled / enabled-late / not enabled / masked. Note the space after `start=` in sc.exe syntax.' },
        { task: 'Dependencies and recovery', command: 'sc.exe qc W32Time\nGet-Service W32Time -DependentServices\nsc.exe qfailure W32Time', explain: '`DEPENDENCIES` is the equivalent of Requires=; `qfailure` shows recovery actions (restart after N ms), the equivalent of Restart= and RestartSec=.' },
        { task: 'Why did it fail?', command: 'Get-WinEvent -FilterHashtable @{LogName=\'System\'; ProviderName=\'Service Control Manager\'} -MaxEvents 20', explain: 'Event 7000 "The X service failed to start due to the following error", 7009 timeout, 7031/7034 "terminated unexpectedly", 7036 state changes, 7045 a new service was installed.' },
      ],
    },
    {
      platform: 'Docker',
      tasks: [
        { task: 'The daemon is a systemd unit', command: 'systemctl status docker containerd\njournalctl -u docker -b', explain: 'dockerd (`docker.service`, plus `docker.socket`) and containerd are ordinary systemd services on the host. Containers are **not** units: systemd does not start, stop or restart them.' },
        { task: 'Containers have their own restart policy', command: 'docker inspect -f \'{{.HostConfig.RestartPolicy.Name}}\' web\ndocker update --restart unless-stopped web\ndocker logs --tail 50 web', explain: 'Restart policies `no`, `on-failure[:N]`, `always`, `unless-stopped` are applied by dockerd, the counterpart of Restart=. Logs come from `docker logs` (or the journal if the journald logging driver is configured).', risk: '`systemctl restart docker` stops every container on the host (unless `live-restore` is enabled in /etc/docker/daemon.json). See the docker lesson.' },
      ],
    },
  ],
  actions: [
    { action: 'systemctl reload <unit>', when: 'The program\'s configuration changed and the unit has ExecReload (ssh, nginx, named via rndc, nftables).', effect: 'Runs ExecReload: the main process re-reads its config and keeps its PID and connections.', risk: 'Lowest. Some settings (listen port, user) need a restart anyway. Not every unit supports reload.' },
    { action: 'systemctl restart <unit>', when: 'Unit settings, binaries, ports or environment changed; the service is hung or failed.', effect: 'Stops all processes of the unit (cgroup), then starts it again with the current files.', risk: 'Brief outage of that service; if the new config is invalid it stays down. Validate first.' },
    { action: 'systemctl daemon-reload', when: 'You added or edited unit files or drop-ins by hand, or changed /etc/fstab.', effect: 'systemd re-reads unit files and re-runs generators. Running services are not touched.', risk: 'None by itself, but it does not apply anything to running services: restart them afterwards.' },
    { action: 'systemctl restart systemd-journald', when: 'After changing journald.conf or creating /var/log/journal.', effect: 'journald restarts; services keep running (their stdout stream is reconnected).', risk: 'Very low; a few messages can be lost during the restart.' },
    { action: 'systemctl restart networking / NetworkManager (interface restart)', when: 'Only when network configuration changed. Never to fix a single service.', effect: 'Takes interfaces down and up again: addresses and routes are removed and re-added.', risk: 'Drops every session over those interfaces, including your SSH session. See the netops lesson for safe procedures.' },
    { action: 'systemctl daemon-reexec', when: 'After upgrading systemd itself or changing /etc/systemd/system.conf.', effect: 'PID 1 re-executes itself, keeping state; services continue.', risk: 'Rarely needed; package upgrades do it for you.' },
    { action: 'reboot', when: 'Kernel updates, or to prove that a service and its configuration come back by themselves.', effect: 'Everything restarts from disk: only **enabled** units start, runtime-only changes are lost, a volatile journal is lost.', risk: 'Longest outage. A disabled or masked unit, a broken /etc/fstab line or a network-online wait can leave the host unreachable or stuck at boot. Have console access.' },
  ],
  workflow: [
    { question: '1. What state is the unit in, and is it the unit you think?', command: 'systemctl status nginx', healthy: '● nginx.service - A high performance web server and a reverse proxy server\n     Loaded: loaded (/lib/systemd/system/nginx.service; enabled; preset: enabled)\n     Active: active (running) since Mon 2026-10-19 07:58:05 UTC; 35min ago\n   Main PID: 414 (nginx)', broken: '"Unit nginx.service could not be found." → wrong name (ssh vs sshd, httpd vs apache2) or package not installed. `failed (Result: exit-code)` → the program exited with an error. `inactive (dead)` with `disabled` → someone stopped it and it is not enabled at boot. `Loaded: masked` → deliberately blocked.', next: 'Failed → step 2. Inactive → step 4 (enablement). Not found → `systemctl list-units --all \'*nginx*\'`, `dpkg -l nginx`.', sim: true },
    { question: '2. What did the program say?', command: 'journalctl -u ssh -b -n 20\njournalctl -b -p err', healthy: 'Oct 19 07:58:05 srv01 sshd[407]: Server listening on 0.0.0.0 port 22.\nOct 19 07:58:05 srv01 systemd[1]: Started ssh.service - OpenBSD Secure Shell server.', broken: 'sshd[424]: /etc/ssh/sshd_config.d/10-hardening.conf line 6: Bad configuration option: PubkeyAuthentcation\nsystemd[1]: ssh.service: Control process exited, code=exited, status=255/EXCEPTION\nsystemd[1]: Failed to start ssh.service - OpenBSD Secure Shell server.\nThe lines from the program (sshd, dhcpd, nginx) name the file and line; the systemd lines tell you which step failed.', next: 'A config error → validate with the program\'s own checker (step 3). "No entries" with `-b -1` → the journal is volatile (step 6).', sim: true },
    { question: '3. Does the program\'s configuration validate?', command: 'sudo sshd -t\nsudo nginx -t\nsudo dhcpd -t -cf /etc/dhcp/dhcpd.conf', healthy: '(sshd -t prints nothing)\nnginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful', broken: 'The checker repeats the error with file and line. Fix that line (or restore your backup) and run the checker until it is clean.', next: 'Clean → `systemctl restart <unit>` → step 1 again.', sim: true },
    { question: '4. Will it start at boot?', command: 'systemctl is-enabled ssh nginx nftables', healthy: 'enabled\nenabled\nenabled', broken: '`disabled` → it runs only until the next reboot (the ssh-monday-reboot ticket). `masked` → cannot start at all. `static` → no [Install] section; started only as a dependency (normal for many helper units). `generated` → created from an init script or fstab.', next: '`sudo systemctl enable --now <unit>`; for masked units `unmask` first.', sim: true },
    { question: '5. What does it depend on, and did those start?', command: 'systemctl list-dependencies ssh\nsystemctl cat isc-dhcp-server', healthy: 'ssh.service\n● ├─-.mount\n● ├─sysinit.target\n● │ ├─nftables.service\n...', broken: 'A red ● or "Dependency failed for X" in the journal means a required unit (mount, network-online, another service) failed first: fix **that** unit. Remember `After=` alone does not pull anything in.', next: 'Work down to the first failed dependency and repeat steps 1–3 for it.', sim: true },
    { question: '6. Are the logs complete and persistent?', command: 'journalctl --list-boots\nls -ld /var/log/journal', healthy: 'IDX BOOT ID                          FIRST ENTRY                 LAST ENTRY\n -1 5c1e... Sun 2026-10-18 06:00:01 UTC Mon 2026-10-19 07:57:40 UTC\n  0 9a7f... Mon 2026-10-19 07:58:05 UTC Mon 2026-10-19 08:33:28 UTC\n(Debian 12 real system)', broken: 'Only boot 0, and /var/log/journal missing → volatile journal: evidence from before the reboot is gone. As a non-admin user: "Hint: You are currently not seeing messages from other users and the system" → use sudo or join group adm/systemd-journal.', next: 'Create /var/log/journal and restart journald so the next incident leaves evidence.' },
    { question: '7. Is it actually serving?', command: 'sudo ss -tlnp\ncurl -I http://127.0.0.1/', healthy: 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=424,fd=3))\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=414,fd=6))', broken: '"active (running)" but no listener on the expected port → it bound elsewhere (check its config) or the port belongs to a .socket unit (owner shown as systemd).', next: 'Listening locally but unreachable remotely → firewall and network (SSH and nftables guides).', sim: true },
  ],
  failures: [
    { symptom: 'Job for X.service failed because the control process exited with error code.', causes: ['Program configuration error (detected by ExecStartPre or at start)', 'Port already in use', 'Missing file referenced by the config (certificate, directory)'], diagnose: ['systemctl status X', 'journalctl -xeu X', 'the program\'s checker: sshd -t, nginx -t, dhcpd -t, named-checkconf'], fix: 'Fix the line the program reports, validate, then `systemctl restart X`.', verify: 'systemctl is-active X && journalctl -u X -n 5' },
    { symptom: 'Unit X.service could not be found. / Failed to start X.service: Unit X.service not found.', causes: ['Wrong unit name for this distribution (sshd vs ssh, httpd vs apache2)', 'Package not installed', 'Unit file added but daemon-reload not run'], diagnose: ['systemctl list-unit-files \'*ssh*\'', 'dpkg -S ssh.service / rpm -qf /usr/lib/systemd/system/sshd.service', 'ls /etc/systemd/system'], fix: 'Use the correct name, install the package, or run `systemctl daemon-reload` after adding the file.', verify: 'systemctl status X' },
    { symptom: 'Failed to start X.service: Unit X.service is masked.', causes: ['Masked on purpose (conflicting service) or by a hardening script'], diagnose: ['systemctl status X (Loaded: masked)', 'ls -l /etc/systemd/system/X.service (→ /dev/null)'], fix: 'Confirm why it was masked; if it should run: `systemctl unmask X && systemctl enable --now X`.', verify: 'systemctl is-enabled X' },
    { symptom: 'X.service: Start request repeated too quickly.', causes: ['Restart= loop: the service crashes at every start (bad config, missing dependency)', 'StartLimitBurst (5) reached within StartLimitIntervalSec (10 s)'], diagnose: ['journalctl -u X -b (the first error before the loop)', 'systemctl show X -p NRestarts,Restart,RestartUSec'], fix: 'Fix the underlying error, then `systemctl reset-failed X` and start it. Do not raise the limits to hide a crash loop.', verify: 'systemctl status X shows active and NRestarts stops increasing' },
    { symptom: 'Dependency failed for X.', causes: ['A unit listed in Requires= or BindsTo= failed (often a .mount from /etc/fstab or network-online.target)'], diagnose: ['journalctl -b -p err', 'systemctl list-dependencies X', 'systemctl --failed'], fix: 'Fix the failed dependency first; X starts afterwards. If the dependency is not really required, change Requires= to Wants= in a drop-in.', verify: 'systemctl --failed shows 0 loaded units' },
    { symptom: 'status=203/EXEC or status=217/USER in systemctl status', causes: ['203: ExecStart path wrong, binary not executable, wrong interpreter (#!), or SELinux denies execution', '217: the account in User= does not exist'], diagnose: ['systemctl cat X', 'ls -l <ExecStart binary>', 'getent passwd <User>', 'RHEL: ausearch -m AVC -ts recent'], fix: 'Correct the path or permissions (`chmod 755`), create the system user (`useradd --system`), or relabel (`restorecon`). Then daemon-reload if you edited the unit.', verify: 'systemctl restart X && systemctl is-active X' },
    { symptom: 'Boot hangs: "A start job is running for ... (1min 30s / ...)"', causes: ['/etc/fstab entry for a missing disk or unreachable share', 'network-online.target waiting for an interface that never comes up (systemd-networkd-wait-online, NetworkManager-wait-online, ifupdown with a missing NIC)'], diagnose: ['systemd-analyze blame', 'systemd-analyze critical-chain', 'journalctl -b -p warning'], fix: 'Add `nofail` (and `x-systemd.device-timeout=10s`) to non-critical fstab lines; fix or remove the interface that never comes up; only use network-online.target for services that really need it.', verify: 'Reboot in a maintenance window and compare systemd-analyze times' },
    { symptom: 'Logs from before the reboot are missing', causes: ['Volatile journal (no /var/log/journal)', 'SystemMaxUse too small, logs rotated away'], diagnose: ['journalctl --list-boots', 'journalctl --disk-usage', 'systemd-analyze cat-config systemd/journald.conf'], fix: '`mkdir -p /var/log/journal && systemctl restart systemd-journald`; set `SystemMaxUse=` in a journald.conf.d drop-in.', verify: 'After the next reboot, journalctl -b -1 shows the previous boot' },
  ],
  verification: [
    { check: 'Unit active now', command: 'systemctl is-active ssh nginx', expect: 'active\nactive' },
    { check: 'Unit starts at boot', command: 'systemctl is-enabled ssh nginx nftables', expect: 'enabled (three times)' },
    { check: 'Nothing failed', command: 'systemctl --failed', expect: '0 loaded units listed.' },
    { check: 'No errors this boot', command: 'journalctl -b -p err', expect: '-- No entries -- (or only understood, harmless lines)' },
    { check: 'The unit file used is the one you expect', command: 'systemctl cat ssh | grep "^# "', expect: '# /lib/systemd/system/ssh.service (plus your drop-in path, if any)' },
    { check: 'Journal is persistent', command: 'journalctl --list-boots | wc -l', expect: 'More than 1 after the first reboot' },
    { check: 'Survives a reboot', command: 'sudo reboot  # then: systemctl --failed; systemctl is-active <units>', expect: 'Same states as before the reboot' },
  ],
  refIds: ['systemctl', 'journalctl', 'ss', 'file:lib-systemd-system', 'file:etc-systemd-system', 'file:journal', 'file:var-log', 'file:etc', 'file:run', 'file:var-lib', 'file:fstab', 'proc:systemd-unit-failed', 'proc:safe-config-change', 'proc:rollback', 'sc', 'get-service', 'restart-service', 'get-winevent', 'docker'],
};

// ---------------------------------------------------------------------------
// Lesson
// ---------------------------------------------------------------------------

export const SYSTEMD_LESSON: Lesson = {
  id: 'systemd',
  moduleId: 'F',
  title: 'Linux service administration: systemd, logs and the filesystem',
  level: 'beginner',
  summary: 'How Linux starts and supervises services, where every configuration and log file lives, and how to find out why a service will not start.',
  concepts: ['svc.systemd', 'logs.journal', 'linux.fs', 'svc.listening', 'linux.permissions', 'ops.recovery'],
  mode: 'simulated',
  guide: SYSTEMD_GUIDE,
  caseStudyIds: ['ssh-refused', 'shared-dependency'],
  objectives: ['N10-009:3.2', 'N10-009:5.3', '200-301:4.5'],

  what: `
**systemd** is the init system and service manager of Debian, Ubuntu, RHEL, Rocky, Alma, SUSE and Fedora. The kernel starts it as **process 1** (\`/sbin/init\` is a symlink to it), and from then on it starts, supervises and stops everything else. Every service you administer in this lab (sshd, nginx, named, isc-dhcp-server, nftables, networking) is started by systemd, logs through systemd's journal, and is controlled with \`systemctl\`.

### Problems it solves
- **Ordered, parallel boot.** Services declare what they need and in which order; systemd starts independent services in parallel.
- **Supervision.** systemd knows every process of a service (through cgroups), notices when it dies, records the exit code and can restart it.
- **One way to manage everything.** Start, stop, enable at boot and read logs the same way for every service.
- **Central logging.** journald stores messages from the kernel, from systemd and from every service with metadata (unit, PID, priority, boot ID), so \`journalctl -u ssh -b\` finds exactly the lines you need.

### Units: what systemd manages
A **unit** is anything systemd manages, described by a small INI-style file. The suffix is the type:
- \`.service\`: a process or a one-shot command (\`ssh.service\`, \`nftables.service\`).
- \`.socket\`: a listening socket that starts a service on the first connection (**socket activation**; Ubuntu 22.10+ ships \`ssh.socket\`, so the port is held by systemd until someone connects).
- \`.target\`: a named group of units, used as a synchronisation point (\`multi-user.target\`, \`network-online.target\`). Targets replace SysV runlevels.
- \`.timer\`: runs a service on a schedule (the systemd answer to cron: \`apt-daily.timer\`, \`logrotate.timer\`).
- \`.mount\`: a mounted filesystem, usually generated from \`/etc/fstab\`.
- \`.path\`: starts a service when a file or directory changes.

### Processes vs units, and cgroups
A unit is a *definition*; when it runs it has one or more *processes*. systemd puts all processes of a service in one **control group** (e.g. \`/system.slice/ssh.service\`, shown on the \`CGroup:\` line of \`systemctl status\`). That is how systemd can stop a service completely even if it forked many children, and why \`KillMode=process\` on ssh.service matters: it tells systemd to kill only the listener, so your existing SSH sessions survive a restart.

### Targets and the boot sequence
At boot systemd activates \`default.target\`, a symlink to \`multi-user.target\` on servers (\`graphical.target\` on desktops). That target *wants* everything enabled for it, which in turn needs:
- \`sysinit.target\`: early system setup: mounts, swap, udev, journald, kernel parameters (systemd-sysctl), and on Debian also \`nftables.service\` (its unit says \`WantedBy=sysinit.target\`), so the firewall is up before any interface.
- \`basic.target\`: sockets, timers, paths and everything basic is ready.
- \`network.target\`: the network management service has been **started**. It says nothing about addresses being configured. Services that only need to bind to 0.0.0.0 use \`After=network.target\` (sshd does).
- \`network-online.target\`: a *wait-online* service has confirmed that the network is **configured** (an address and route exist). Only units that must reach another host at start (NFS mounts, a DHCP server that must bind to a configured address, a service connecting to a remote database) should use \`Wants=\` + \`After=network-online.target\`, because it can delay the boot.

### Dependencies: requirement and ordering are different
- **Requirement** says *what else must be started*: \`Wants=\` (start it too, but continue if it fails), \`Requires=\` (start it too, and fail/stop if it fails), \`BindsTo=\` (like Requires, and also stop when the other unit stops, e.g. a device disappears).
- **Ordering** says *in which order*: \`After=\` and \`Before=\`. They do not start anything.
- You almost always need both: \`Wants=network-online.target\` *and* \`After=network-online.target\`. With only \`After=\`, the target might not be part of the boot at all; with only \`Wants=\`, both start in parallel.
- \`[Install] WantedBy=multi-user.target\` is not a dependency at runtime: it tells \`systemctl enable\` where to create the symlink.

### enable vs start, and masks
- \`start\` / \`stop\`: affects **now**.
- \`enable\` / \`disable\`: affects the **next boot** (creates or removes the \`WantedBy\` symlink). \`enable --now\` does both.
- A service can be running but disabled (it will not come back after a reboot: the ssh-monday-reboot ticket) or enabled but failed.
- \`mask\` makes a unit impossible to start (symlink to \`/dev/null\`); \`unmask\` removes that.

### The journal
\`systemd-journald\` collects kernel messages, the stdout/stderr of every service, and anything sent to syslog. Each entry carries the unit, PID, priority (0 emerg … 3 err … 4 warning … 6 info … 7 debug, the syslog severities) and boot ID, which is what makes \`journalctl -u ssh -b -p err\` possible. **rsyslog**, when installed, copies messages into the classic text files in \`/var/log\`.

> The lab hosts are Debian 12 (systemd 252). The simulator models \`systemctl\` (status, start, stop, restart, reload, enable, disable, is-active, is-enabled, is-failed, list-units, --failed, cat, list-dependencies, show, daemon-reload, mask, unmask) and \`journalctl\` for the lab's services. \`systemctl edit\` and \`get-default\` are explained here but not simulated.

`,

  internals: `
### Where unit files come from (search path and precedence)
systemd looks for a unit in several directories; **the first one found wins**, and drop-ins from all of them are merged:
1. \`/etc/systemd/system/\`: the administrator's units and overrides (highest precedence).
2. \`/run/systemd/system/\`: runtime units, lost at reboot (transient units from \`systemd-run\`).
3. \`/lib/systemd/system/\` = \`/usr/lib/systemd/system/\`: vendor units installed by packages. On **merged-/usr** systems (Debian 12 new installs, Ubuntu, RHEL) \`/lib\` is a symlink to \`/usr/lib\`, so these are one directory. Debian 12 packages still install into \`/lib/systemd/system\`, which is why the lab shows \`Loaded: loaded (/lib/systemd/system/ssh.service; ...)\`; RHEL shows \`/usr/lib/systemd/system/sshd.service\`.
4. \`/run/systemd/generator.late/\`: units created by generators, lowest precedence, so a real unit file always beats a generated one.

\`systemctl cat <unit>\` prints the winning file with its path as a comment, and \`systemd-delta\` lists every overridden, extended and masked unit on the system.

### Drop-ins
To change a few settings of a vendor unit without copying it, create a **drop-in**:
\`\`\`
sudo systemctl edit nginx
# opens /etc/systemd/system/nginx.service.d/override.conf
[Service]
Restart=on-failure
RestartSec=5s
\`\`\`
\`systemctl edit\` runs \`daemon-reload\` for you when you save; if you write \`/etc/systemd/system/<unit>.d/*.conf\` by hand you must run \`sudo systemctl daemon-reload\` yourself, then restart the service. Settings that can appear several times (\`ExecStart=\`, \`ExecStartPre=\`, \`After=\`) **accumulate**; to replace \`ExecStart\`, first clear it with an empty \`ExecStart=\` line.

### Generators
Generators are small programs systemd runs at boot and at every \`daemon-reload\` to translate other configuration into units:
- \`systemd-fstab-generator\`: each \`/etc/fstab\` line → a \`.mount\` unit.
- \`systemd-sysv-generator\`: each \`/etc/init.d\` script without a native unit → a \`.service\` unit in \`/run/systemd/generator.late\`. In the lab, ns1's **isc-dhcp-server** (Debian 12 ships only an init script for it) is such a unit:
\`\`\`
ns1# systemctl cat isc-dhcp-server
# /run/systemd/generator.late/isc-dhcp-server.service
# Automatically generated by systemd-sysv-generator

[Unit]
Documentation=man:systemd-sysv-generator(8)
SourcePath=/etc/init.d/isc-dhcp-server
Description=LSB: DHCP server
Before=multi-user.target
...
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
Restart=no
TimeoutSec=5min
...
RemainAfterExit=yes
SuccessExitStatus=5 6
ExecStart=/etc/init.d/isc-dhcp-server start
ExecStop=/etc/init.d/isc-dhcp-server stop
\`\`\`
Note \`Restart=no\`: if dhcpd dies, nothing restarts it. \`systemctl status\` shows \`Loaded: loaded (/etc/init.d/isc-dhcp-server; generated)\`.

### Reading real units from the lab
**ssh.service** (srv01, \`systemctl cat ssh\`):
\`\`\`
[Unit]
Description=OpenBSD Secure Shell server
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=sshd.service
\`\`\`
- \`ExecStartPre=/usr/sbin/sshd -t\`: the config test runs before every start. If it fails (exit 255), the start fails.
- \`ExecReload\` has two lines: test, then SIGHUP. A failed test aborts the reload and the old daemon keeps running.
- \`Restart=on-failure\` + \`RestartPreventExitStatus=255\`: a crash is restarted, but a config error (exit 255) is not, because restarting cannot fix it.
- \`EnvironmentFile=-/etc/default/ssh\`: the leading \`-\` means "ignore if missing".
- \`Type=notify\`: systemd waits until sshd reports "ready" through sd_notify.

**nftables.service** (\`systemctl cat nftables\`): \`Type=oneshot\` + \`RemainAfterExit=yes\` (runs \`nft -f /etc/nftables.conf\` once, then shows \`active (exited)\`), \`DefaultDependencies=no\`, \`Before=network-pre.target\`, \`WantedBy=sysinit.target\`, \`ExecReload=/usr/sbin/nft -f /etc/nftables.conf\` and \`ExecStop=/usr/sbin/nft flush ruleset\`. So \`systemctl stop nftables\` **removes the whole firewall**.

### Type=: when is a service "started"?
| Type | systemd considers it started when ... | Lab / typical example |
|---|---|---|
| \`simple\` (default) | the process has been forked (immediately) | most custom services |
| \`exec\` | the binary has been executed successfully | custom services; catches 203/EXEC at start |
| \`forking\` | the started process exits and leaves a daemon child (PIDFile helps) | named, LSB scripts (isc-dhcp-server) |
| \`notify\` | the service sends READY=1 via sd_notify | sshd on Debian 12, systemd-networkd |
| \`oneshot\` | the command has **finished**; with \`RemainAfterExit=yes\` the unit then stays "active (exited)" | nftables, networking |

### Restart policy and start limits
\`Restart=\` (no, on-success, on-failure, on-abnormal, on-abort, always) decides whether systemd restarts a service after its main process ends; \`RestartSec=\` waits in between (default 100 ms). To stop endless loops, \`StartLimitIntervalSec=10s\` and \`StartLimitBurst=5\` (defaults) make systemd give up: "Start request repeated too quickly", unit \`failed\`, until \`systemctl reset-failed\`.

### Exit codes you will see in systemctl status
- \`status=0/SUCCESS\`; \`status=1/FAILURE\` and \`status=255/EXCEPTION\`: the program itself exited with that code (read its message).
- \`status=203/EXEC\`: systemd could not execute ExecStart (wrong path, not executable, missing interpreter, SELinux).
- \`status=217/USER\`: \`User=\` does not exist. \`status=200/CHDIR\`: \`WorkingDirectory=\` is missing.
- \`code=killed, signal=KILL\` / \`signal=SEGV\`: killed (OOM killer, timeout) or crashed.

### journald: where logs live and how to query them
- **Volatile** journal: \`/run/log/journal\` (tmpfs, lost at reboot). **Persistent**: \`/var/log/journal\`. With the default \`Storage=auto\`, journald uses /var/log/journal **only if that directory exists**. Debian 11+ and Ubuntu create it (persistent by default; Debian 12 therefore no longer installs rsyslog). On RHEL check \`ls /var/log/journal\` and \`journalctl --list-boots\`; RHEL also keeps text logs through rsyslog.
- Priorities are syslog severities: 0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5 notice, 6 info, 7 debug. \`-p err\` shows 0–3.
- Useful options: \`-u UNIT\`, \`-b\` (this boot; \`-b -1\` previous), \`-p err\`, \`-f\` (follow), \`-x\` (add explanations), \`-e\` (jump to end), \`-n 50\`, \`--since "2026-10-19 07:00"\` / \`"10 min ago"\`, \`-k\` (kernel only), \`-t sshd\` (by syslog identifier), \`-g PATTERN\`, \`-o json-pretty\` (all fields).
- **rsyslog** reads from the journal (imjournal on RHEL, \`/dev/log\` forwarding on Debian) and writes \`/var/log/syslog\` + \`/var/log/auth.log\` (Debian/Ubuntu) or \`/var/log/messages\` + \`/var/log/secure\` (RHEL). Use it for text files and remote syslog forwarding.

### What \`systemctl restart\` actually does (failure path)
Use the sequence diagram below: systemctl asks PID 1 over D-Bus; PID 1 stops the main process, runs ExecStartPre, records the exit code, logs "Failed with result 'exit-code'", and tells systemctl "Job for ssh.service failed". The program's own error message goes to the **journal**, never to your terminal. That is why the first reflex after any failed systemctl command is \`systemctl status\` and \`journalctl -xeu <unit>\`.
`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu 24.04',
      summary: 'Inspect the existing units in the lab, then write, enable and override a unit for a small custom service (inventory-api) on a real VM. Steps marked simulated also work in the sandbox terminal; the custom unit steps need a real system.',
      prerequisites: ['A Debian 12 or Ubuntu 24.04 VM with sudo rights and console access.', 'A program to run as a service, e.g. a Python web API in /opt/inventory-api listening on TCP 8080.'],
      steps: [
        { title: 'Read a vendor unit before writing your own', command: 'systemctl cat ssh', what: 'Prints the unit file systemd actually uses, with its path, plus any drop-ins.', why: 'Vendor units are the best examples of correct ExecStartPre, ExecReload, Restart and Install settings.', expected: '# /lib/systemd/system/ssh.service\n[Unit]\nDescription=OpenBSD Secure Shell server\nAfter=network.target auditd.service\n...\n[Install]\nWantedBy=multi-user.target\nAlias=sshd.service', simulated: true },
        { title: 'See where a unit sits in the boot', command: 'systemctl list-dependencies ssh\nsystemctl show ssh -p WantedBy,After,Type,Restart', what: 'Shows what the unit pulls in and the parsed dependency properties.', why: 'Your service will be ordered the same way: after the network is started, wanted by multi-user.target.', expected: 'WantedBy=multi-user.target\nAfter=network.target auditd.service\nType=notify\nRestart=on-failure', simulated: true },
        { title: 'Create a dedicated system account', command: 'sudo useradd --system --home-dir /opt/inventory-api --shell /usr/sbin/nologin inventory\nsudo chown -R inventory:inventory /opt/inventory-api', what: 'Creates an unprivileged account with no login shell for the service.', why: 'A service running as root turns any bug into a full compromise. `User=` must refer to an existing account, or the start fails with status=217/USER.', expected: '(no output)' },
        { title: 'Write the unit file', command: 'sudo tee /etc/systemd/system/inventory-api.service <<\'EOF\'\n[Unit]\nDescription=Inventory API\nDocumentation=https://intranet.corp.lab/inventory\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=exec\nUser=inventory\nGroup=inventory\nWorkingDirectory=/opt/inventory-api\nEnvironmentFile=-/etc/default/inventory-api\nExecStart=/opt/inventory-api/venv/bin/python -m inventory_api --port 8080\nRestart=on-failure\nRestartSec=5s\nNoNewPrivileges=yes\nProtectSystem=full\n\n[Install]\nWantedBy=multi-user.target\nEOF', what: 'Administrator units belong in /etc/systemd/system. `Type=exec` reports a missing binary at start time; `Restart=on-failure` restarts crashes; `[Install]` says which target enables it.', why: 'It connects to a database on another host at start, so it needs a configured network: Wants= + After=network-online.target (both). A service that only binds a local port would use After=network.target instead.', expected: '' },
        { title: 'Check the unit for mistakes', command: 'sudo systemd-analyze verify /etc/systemd/system/inventory-api.service', what: 'Parses the unit and reports unknown keys, missing executables and bad dependencies.', why: 'Typos in unit files are logged as warnings and the line is ignored, so the service may start with an unexpected configuration.', expected: '(no output when the unit is valid)' },
        { title: 'Tell systemd about the new file', command: 'sudo systemctl daemon-reload', what: 'Re-reads all unit files.', why: 'Without it: "Unit inventory-api.service could not be found." (new file) or a warning that the unit changed on disk (edited file).', expected: '(no output)', simulated: true },
        { title: 'Enable and start in one step', command: 'sudo systemctl enable --now inventory-api', what: 'Creates the multi-user.target.wants symlink and starts the service.', why: 'Running now and starting after a reboot are separate states; forgetting enable is a classic "worked until the reboot" fault.', expected: 'Created symlink /etc/systemd/system/multi-user.target.wants/inventory-api.service → /etc/systemd/system/inventory-api.service.' },
        { title: 'Verify state, logs and listener', command: 'systemctl status inventory-api\njournalctl -u inventory-api -b\nsudo ss -tlnp | grep 8080', what: 'Confirms active (running), the program\'s startup messages, and that it listens on the port.', why: '"active (running)" with Type=exec only proves the process started; the listener proves it is serving.', expected: '● inventory-api.service - Inventory API\n     Loaded: loaded (/etc/systemd/system/inventory-api.service; enabled; preset: enabled)\n     Active: active (running) since ...\nLISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python",pid=2210,fd=3))' },
        { title: 'Change a vendor unit with a drop-in', command: 'sudo systemctl edit nginx\n# in the editor:\n[Service]\nRestart=on-failure\nRestartSec=5s', what: 'Writes /etc/systemd/system/nginx.service.d/override.conf and reloads systemd.', why: 'The vendor file in /lib/systemd/system is replaced at every package upgrade; your drop-in is not. `systemctl cat nginx` now shows both files.', expected: '# /lib/systemd/system/nginx.service\n...\n# /etc/systemd/system/nginx.service.d/override.conf\n[Service]\nRestart=on-failure\nRestartSec=5s' },
        { title: 'Apply the override and check it', command: 'sudo systemctl restart nginx\nsystemctl show nginx -p Restart,DropInPaths', what: 'Restarts so the new setting is used; `show` confirms the drop-in was loaded.', why: 'daemon-reload makes systemd read the change; the running service only picks it up at its next start.', expected: 'Restart=on-failure\nDropInPaths=/etc/systemd/system/nginx.service.d/override.conf' },
        { title: 'Make the journal persistent (if it is not)', command: 'ls -ld /var/log/journal || { sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald; }\njournalctl --list-boots', what: 'Ensures logs survive reboots.', why: 'Without persistence the evidence for "it failed during the night and rebooted" is gone.', expected: 'drwxr-sr-x+ 3 root systemd-journal 4096 ... /var/log/journal' },
        { title: 'Ubuntu: socket-activated SSH', command: 'systemctl status ssh.socket ssh.service\nsudo ss -tlnp | grep :22', what: 'On Ubuntu 22.10+ the listening port belongs to ssh.socket; sshd starts on the first connection.', why: 'ss shows `users:(("systemd",pid=1,...))` on port 22, and ssh.service may be "inactive" while SSH works. Port changes need daemon-reload + `systemctl restart ssh.socket`.', expected: '(Ubuntu 24.04, before the first connection)\nLISTEN 0 4096 *:22 *:* users:(("systemd",pid=1,fd=...))' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky Linux 9 / AlmaLinux 9',
      summary: 'The same systemd, with different unit names and paths, SELinux enforcing, and rsyslog text logs. Run on a real VM.',
      prerequisites: ['RHEL-compatible 9.x VM with sudo rights and console access.'],
      steps: [
        { title: 'Know the names', command: 'systemctl status sshd\nsystemctl cat sshd | head -3', what: 'The SSH unit is sshd.service in /usr/lib/systemd/system.', why: 'RHEL has no ssh.service alias; scripts copied from Debian fail with "Unit ssh.service could not be found."', expected: '# /usr/lib/systemd/system/sshd.service\n[Unit]\nDescription=OpenSSH server daemon' },
        { title: 'Install the custom unit', command: 'sudo install -m 0644 inventory-api.service /etc/systemd/system/\nsudo systemctl daemon-reload\nsudo systemctl enable --now inventory-api', what: 'Same unit file as on Debian.', why: 'systemd behaves identically; differences are around it.', expected: 'Created symlink /etc/systemd/system/multi-user.target.wants/inventory-api.service → /etc/systemd/system/inventory-api.service.' },
        { title: 'If it fails with 203/EXEC or Permission denied: SELinux', command: 'sudo ausearch -m AVC -ts recent\nls -Z /opt/inventory-api/venv/bin/python\nsudo restorecon -Rv /opt/inventory-api', what: 'Shows SELinux denials and restores default labels.', why: 'Programs copied from a home directory keep the `user_home_t` label, which services (init_t) may not execute. Binaries under /usr/local/bin or /opt with correct labels work.', expected: 'Relabeled /opt/inventory-api/... from unconfined_u:object_r:user_home_t:s0 to unconfined_u:object_r:usr_t:s0' },
        { title: 'Open the port in firewalld', command: 'sudo firewall-cmd --permanent --add-port=8080/tcp\nsudo firewall-cmd --reload', what: 'Allows the service through the host firewall.', why: 'A running service behind a closed firewall times out for clients.', expected: 'success\nsuccess' },
        { title: 'Logs', command: 'journalctl -u inventory-api -b\nsudo tail /var/log/messages\njournalctl --list-boots', what: 'Journal for the unit; rsyslog\'s general log; check whether the journal is persistent on this build.', why: 'Know where long-term logs are kept before you need them.', expected: 'IDX BOOT ID ... FIRST ENTRY ... LAST ENTRY' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server 2019 / 2022',
      summary: 'Windows has no systemd. The **Service Control Manager** (services.exe) starts services by their registry definition, and services.msc, `sc.exe` and PowerShell manage them. Elevated PowerShell on a real Windows VM. See the windows-rdp lesson for administering TermService.',
      prerequisites: ['Windows Server 2019/2022 with local Administrator rights.', 'A program written as a Windows service (a normal console program needs a wrapper such as NSSM, or run it as a scheduled task).'],
      steps: [
        { title: 'Register the service', command: 'New-Service -Name InventoryApi -BinaryPathName \'"C:\\Program Files\\InventoryApi\\inventory-api.exe" --port 8080\' -DisplayName "Inventory API" -StartupType Automatic', what: 'Creates HKLM\\SYSTEM\\CurrentControlSet\\Services\\InventoryApi (the "unit file"). sc.exe equivalent: `sc.exe create InventoryApi binPath= "C:\\Program Files\\InventoryApi\\inventory-api.exe" start= auto` (space after each `=`).', why: 'StartupType Automatic is the equivalent of systemctl enable.', expected: 'Status   Name               DisplayName\n------   ----               -----------\nStopped  InventoryApi       Inventory API' },
        { title: 'Run it as a low-privilege account', command: 'sc.exe config InventoryApi obj= "NT AUTHORITY\\LocalService" password= ""', what: 'Equivalent of User= in a unit.', why: 'New services run as LocalSystem by default, which is more powerful than root-equivalent Administrator.', expected: '[SC] ChangeServiceConfig SUCCESS' },
        { title: 'Configure restart on failure', command: 'sc.exe failure InventoryApi reset= 86400 actions= restart/5000/restart/5000/restart/30000', what: 'Restart after 5 s on the first and second failure and after 30 s on later failures; reset the failure counter after a day (86400 s).', why: 'Equivalent of Restart=on-failure, RestartSec=5s and a start limit.', expected: '[SC] ChangeServiceConfig2 SUCCESS' },
        { title: 'Start and check', command: 'Start-Service InventoryApi\nGet-Service InventoryApi\nGet-WinEvent -FilterHashtable @{LogName=\'System\'; ProviderName=\'Service Control Manager\'} -MaxEvents 5', what: 'Starts the service and reads SCM events (7036 "entered the running state", 7000/7009 failures).', why: 'Like journalctl -u, the System log says why a start failed.', expected: 'Status   Name               DisplayName\n------   ----               -----------\nRunning  InventoryApi       Inventory API' },
      ],
    },
    {
      id: 'docker',
      platform: 'Docker Engine 27 on Debian/Ubuntu',
      summary: 'The Docker daemon is a systemd service; containers are not. Use this to decide whether to run a service as a unit or as a container. See the docker lesson.',
      prerequisites: ['Docker Engine installed from the Docker apt repository.'],
      steps: [
        { title: 'The daemon is managed by systemd', command: 'systemctl status docker\nsystemctl is-enabled docker containerd', what: 'docker.service (with docker.socket) and containerd.service are units, enabled at boot.', why: 'If dockerd does not start at boot, no container starts, whatever its restart policy.', expected: '● docker.service - Docker Application Container Engine\n     Loaded: loaded (/lib/systemd/system/docker.service; enabled; preset: enabled)\n     Active: active (running) since ...' },
        { title: 'Containers restart through their own policy', command: 'docker run -d --name inventory --restart unless-stopped -p 8080:8080 inventory-api:1.4', what: 'dockerd restarts the container when it exits and starts it again when the daemon starts.', why: 'Do not wrap containers in systemd units with Restart= as well: two supervisors fight. Use one or the other.', expected: '(a container ID)' },
        { title: 'Logs', command: 'docker logs --tail 50 inventory\njournalctl -u docker -b', what: 'Container output vs daemon messages.', why: 'journalctl -u docker shows daemon problems (storage, networking, iptables), not the application\'s output unless the journald logging driver is configured.', expected: '' },
      ],
    },
  ],

  configIntro: `
### Linux filesystem reference: where things live
| Path | What lives there | Notes |
|---|---|---|
| \`/etc/\` | Host-specific configuration, edited by administrators | Back it up; keep it in version control. Package defaults you changed are kept on upgrade (dpkg asks). |
| \`/var/log/\` | Text logs (rsyslog, nginx, apt) and \`/var/log/journal\` | Rotated by logrotate; fills disks if a service logs in a loop. |
| \`/var/lib/\` | Persistent service state: \`/var/lib/dhcp/dhcpd.leases\`, \`/var/lib/docker\`, \`/var/lib/bind\` | Not configuration: do not edit while the service runs. |
| \`/run/\` | Runtime state on tmpfs: PID files, sockets, generated units, \`/run/systemd/resolve/\` | Recreated at every boot; never put configuration here. |
| \`/usr/lib/systemd/system/\` (= \`/lib/systemd/system/\`) | Vendor unit files from packages | Do not edit; overridden by /etc. |
| \`/etc/systemd/system/\` | Your units, drop-ins (\`<unit>.d/\`), enablement symlinks (\`*.wants/\`) | Highest precedence. |
| \`/etc/network/interfaces\` | ifupdown network configuration (Debian, **the lab**) | Applied by networking.service (\`ifup -a\`). |
| \`/etc/NetworkManager/\` | NetworkManager config; profiles in \`system-connections/*.nmconnection\` (RHEL 9, Ubuntu desktop) | Manage with nmcli; files must be 0600 root. |
| \`/etc/netplan/*.yaml\` | Netplan (Ubuntu): generates networkd or NetworkManager config in /run | Apply with \`netplan try\`/\`apply\`. |
| \`/etc/ssh/\` | sshd_config, sshd_config.d/, host keys, ssh_config | Validate with \`sshd -t\`. |
| \`/etc/resolv.conf\` | DNS servers and search domains for the resolver | Often a **generated file or symlink**: see below. |
| \`/etc/hosts\` | Static name-to-address entries, checked before DNS | A stale line overrides DNS silently (net-hosts-override ticket). |
| \`/etc/nsswitch.conf\` | Order of name sources: \`hosts: files dns\` | Decides whether /etc/hosts or DNS wins. |
| \`/etc/pam.d/\` | PAM stacks per service (sshd, sudo, login) | A broken line can block every login. |
| \`/etc/fstab\` | Filesystems mounted at boot (turned into .mount units) | A bad line can stop the boot: test with \`findmnt --verify\`. |
| \`/etc/sudoers\`, \`/etc/sudoers.d/\` | Who may run what with sudo | Edit only with \`visudo\` / \`visudo -f\`; a syntax error disables sudo. |

### How to tell which file is authoritative
Many files in /etc are **generated** by another program, and editing them directly is undone at the next DHCP renewal, network restart or reboot. Before editing, ask "who writes this file?":
- \`ls -l /etc/resolv.conf\`: a **symlink** to \`../run/systemd/resolve/stub-resolv.conf\` means systemd-resolved owns it; to \`/run/NetworkManager/resolv.conf\` means NetworkManager. A regular file may still be rewritten by dhclient (DHCP hosts) or resolvconf.
- **Read the header comment**: \`# Generated by NetworkManager\`, \`# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8). Do not edit.\`, \`# This file is generated from information provided by the datasource. Changes to it will not persist across an instance reboot.\` (cloud-init).
- \`resolvectl status\` (systemd-resolved) and \`nmcli device show\` (NetworkManager) show the DNS servers actually in use; change them where they come from (netplan YAML, the NM connection profile, the DHCP server).
- \`systemctl cat <unit>\` shows which unit file and drop-ins are in effect; \`systemd-delta\` lists overrides; \`systemd-analyze cat-config systemd/journald.conf\` shows a merged systemd config.
- \`sshd -T\` shows sshd's effective settings after includes; \`nginx -T\` the same for nginx.
- \`dpkg -S /lib/systemd/system/ssh.service\` (Debian/Ubuntu) or \`rpm -qf /usr/lib/systemd/system/sshd.service\` (RHEL) names the package that owns a file; a file owned by no package was created locally or by a script.
- \`nmcli\`, \`networkctl\` and \`netplan get\` tell you which network manager is in charge (netops lesson).

> **Why editing /etc/resolv.conf can be undone.** On Ubuntu, /etc/resolv.conf is a symlink to a file systemd-resolved writes in /run, so your edit either fails or is replaced within seconds. On RHEL/desktop systems NetworkManager rewrites it whenever a connection comes up. On a Debian DHCP client (ws02 in the lab) dhclient rewrites it at every lease renewal. Only on a host with a static, unmanaged regular file (ws01, srv01 in the lab) is editing it directly the correct fix.

### Unit file directives
The table below explains the directives you will read and write most often in \`[Unit]\`, \`[Service]\` and \`[Install]\`. "Compiled default" is systemd's built-in value when the directive is absent.
`,

  configFiles: [
    {
      platform: 'Linux (Debian/Ubuntu; RHEL uses /usr/lib paths and sshd.service)',
      items: [
        { path: '/lib/systemd/system/*.service', purpose: 'Vendor units installed by packages (= /usr/lib/systemd/system on merged /usr). Read-only for you.' },
        { path: '/etc/systemd/system/*.service', purpose: 'Your own units (e.g. inventory-api.service); a file here with the same name replaces the vendor unit.' },
        { path: '/etc/systemd/system/<unit>.d/override.conf', purpose: 'Drop-in overrides created by systemctl edit.' },
        { path: '/etc/systemd/system/multi-user.target.wants/', purpose: 'Symlinks created by systemctl enable.' },
        { path: '/run/systemd/generator.late/', purpose: 'Units generated from /etc/init.d scripts (isc-dhcp-server on ns1).' },
        { path: '/etc/default/<service>', purpose: 'Environment/options read by units and init scripts (INTERFACESv4 for isc-dhcp-server).' },
        { path: '/etc/systemd/journald.conf(.d/)', purpose: 'Journal storage, size limits, forwarding to syslog.' },
        { path: '/var/log/journal/', purpose: 'Persistent journal (volatile in /run/log/journal if absent).' },
        { path: '/etc/rsyslog.conf, /etc/rsyslog.d/', purpose: 'Text log routing (/var/log/syslog, auth.log; RHEL messages, secure) and remote forwarding.' },
        { path: '/etc/fstab', purpose: 'Mounts; converted to .mount units by systemd-fstab-generator.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022',
      items: [
        { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>', purpose: 'Service definition: ImagePath, Start, DependOnService, ObjectName, FailureActions.' },
        { path: 'services.msc', purpose: 'GUI for startup type, account, recovery actions and dependencies.' },
        { path: 'Event Viewer → Windows Logs → System (source Service Control Manager)', purpose: 'Service start/stop/failure events 7000, 7009, 7031, 7034, 7036, 7045.' },
      ],
    },
  ],

  directives: [
    { name: 'Description=', compiledDefault: '(unit name)', recommended: 'A short human name', explanation: 'Shown in `systemctl status` and in every "Starting/Started/Failed to start X - Description" journal line.', security: 'None.' },
    { name: 'Wants= / Requires=', compiledDefault: '(none)', recommended: 'Wants= unless the service truly cannot run without the other unit', explanation: 'Requirement dependencies: start the listed units too. With Requires=, if the listed unit fails to start, this unit fails as well ("Dependency failed for ..."), and stopping it stops this unit.', security: 'Requires= on a fragile unit spreads one failure to many services; prefer Wants=.' },
    { name: 'After= / Before=', compiledDefault: '(none; DefaultDependencies add After=basic.target etc.)', recommended: 'After=network.target for servers that bind locally; After=network-online.target (with Wants=) for services that connect out at start', explanation: 'Ordering only: when both units are started in the same transaction, start this one after/before the other. Does **not** cause the other unit to start.', security: 'Wrong ordering causes race conditions at boot (service starts before its address exists and binds to nothing).' },
    { name: 'BindsTo=', compiledDefault: '(none)', recommended: 'Only for units tied to a device or another unit\'s lifetime', explanation: 'Like Requires=, and additionally stops this unit when the other one stops or disappears (e.g. a service bound to `sys-subsystem-net-devices-eth1.device`).', security: 'None specific.' },
    { name: 'Type=', compiledDefault: 'simple', recommended: 'exec for new services; notify if the program supports sd_notify; oneshot + RemainAfterExit=yes for "apply a config" units', explanation: 'Defines when the start is considered complete (see the Type table in Internals). With forking, systemd tracks the daemon child (PIDFile= helps).', security: 'A wrong Type (forking for a program that does not fork) makes systemd kill the service after the start timeout or think it exited.' },
    { name: 'ExecStart=', compiledDefault: '(required, except oneshot)', recommended: 'Absolute path, program in the foreground', explanation: 'The command that runs the service. In a drop-in, clear it with an empty `ExecStart=` before setting a new one.', security: 'The binary and its directory must not be writable by the service account, or the service can replace its own code.' },
    { name: 'ExecStartPre= / ExecReload=', compiledDefault: '(none)', recommended: 'ExecStartPre= with the program\'s config test (sshd -t, nginx -t); ExecReload= that tests then signals', explanation: 'Commands run before the start / on `systemctl reload`. A failing ExecStartPre aborts the start (ssh-config-typo). A `-` prefix (`ExecStartPre=-/bin/cmd`) ignores its failure.', security: 'Validating before start/reload prevents a bad config from taking a running service down.' },
    { name: 'Restart=', compiledDefault: 'no', recommended: 'on-failure for long-running daemons', explanation: 'When to restart after the main process ends: no, on-success, on-failure, on-abnormal, on-abort, on-watchdog, always. Does not apply to `systemctl stop`.', security: 'Restarting a crashing service hides the crash; monitor NRestarts. `always` also restarts after a clean exit.' },
    { name: 'RestartSec=', compiledDefault: '100ms', recommended: '2–10s', explanation: 'Delay before a restart. Combined with StartLimitIntervalSec=10s / StartLimitBurst=5 (defaults), a crash at start with 100 ms delay hits "Start request repeated too quickly" in under a second.', security: 'A delay gives dependencies time to recover and keeps logs readable.' },
    { name: 'RestartPreventExitStatus=', compiledDefault: '(none)', distroDefault: '255 in Debian\'s ssh.service', recommended: 'The exit code the program uses for configuration errors', explanation: 'Exit codes that should never trigger Restart=, because a restart cannot fix them.', security: 'Avoids restart loops that flood the journal.' },
    { name: 'User= / Group=', compiledDefault: 'root', recommended: 'A dedicated system account (or DynamicUser=yes)', explanation: 'Identity of the service processes. The account must exist (otherwise status=217/USER).', security: 'The single most effective hardening for custom services.' },
    { name: 'EnvironmentFile=', compiledDefault: '(none)', recommended: '`-/etc/default/<name>` (leading - = optional)', explanation: 'Reads VAR=value lines and makes them available to Exec lines as $VAR (ssh.service uses $SSHD_OPTS).', security: 'Files with secrets must be 0600 root; they are readable through /proc by the service user.' },
    { name: 'KillMode=', compiledDefault: 'control-group', distroDefault: 'process in ssh.service', recommended: 'Default unless child processes must survive a restart', explanation: 'Which processes are signalled on stop: the whole cgroup, only the main process, or mixed.', security: 'ssh uses `process` so that user sessions survive restarts of the listener.' },
    { name: 'WantedBy= ([Install])', compiledDefault: '(none: unit is "static")', recommended: 'multi-user.target for server daemons', explanation: 'Read only by `systemctl enable`/`disable`: creates /etc/systemd/system/<target>.wants/<unit>. A unit without [Install] cannot be enabled and shows `static`.', security: 'Enabling only what is needed reduces attack surface after a reboot.' },
    { name: 'NoNewPrivileges= / ProtectSystem= / ProtectHome=', compiledDefault: 'no / no / no', recommended: 'yes / full or strict / yes for custom services', explanation: 'Sandboxing: forbids setuid privilege gain, mounts /usr and /etc (full) or the whole tree (strict) read-only, hides /home. nftables.service uses ProtectSystem=full and ProtectHome=true.', security: '`systemd-analyze security <unit>` rates a unit\'s exposure.' },
  ],

  operateIntro: `
### Unit names differ between distributions
On Debian/Ubuntu the unit is \`ssh.service\`, with \`Alias=sshd.service\`, so \`systemctl status sshd\` also works there and shows "ssh.service". On RHEL it is \`sshd.service\` and \`ssh\` does not exist ("Unit ssh.service could not be found."). The same trap exists for apache2/httpd, bind9/named, isc-dhcp-server/dhcpd.
`,
  troubleshootingIntro: `
### A method for "the service does not work"
1. **Name the unit correctly** (ssh vs sshd, apache2 vs httpd) and run \`systemctl status <unit>\`. Read Loaded (which file, enabled?) and Active (running, exited, dead, failed).
2. **Read the program's own message**: \`journalctl -u <unit> -b\` or \`journalctl -xeu <unit>\`. systemd's lines tell you *which step* failed (ExecStartPre, main process, dependency); the program's lines tell you *why* (file, line, port).
3. **Validate the configuration with the program's checker** (\`sshd -t\`, \`nginx -t\`, \`dhcpd -t\`, \`named-checkconf\`) before restarting.
4. **Check dependencies and boot state**: \`systemctl list-dependencies\`, \`systemctl is-enabled\`, \`systemctl --failed\`, \`journalctl -b -p err\`.
5. **Check that it serves**: \`ss -tlnp\`, then test from a client. "active (running)" is not the same as "reachable".
6. **Fix in the persistent place** (the config file, a drop-in, \`enable\`), not with a runtime workaround, and prove it survives a reboot.

The tickets below exercise this on the lab: a config typo that makes ExecStartPre fail, a service that was disabled and did not come back after a reboot, a stopped nginx, an isc-dhcp-server whose /etc/default file names a non-existent interface, and a DNS zone error that takes named down.
`,

  errorMap: [
    { message: 'Job for X.service failed because the control process exited with error code.', layer: 'Service start', meaning: 'ExecStartPre or ExecStart exited non-zero. systemd only reports the fact; the reason is in the journal.', firstCheck: 'systemctl status X; journalctl -xeu X' },
    { message: 'Unit X.service could not be found.', layer: 'Unit lookup', meaning: 'No unit with that name: wrong distro name (ssh/sshd), package not installed, or new unit file without daemon-reload.', firstCheck: 'systemctl list-unit-files \'*X*\'; daemon-reload' },
    { message: 'Failed to start X.service: Unit X.service is masked.', layer: 'Unit state', meaning: 'The unit is linked to /dev/null on purpose; nothing can start it.', firstCheck: 'systemctl status X (Loaded: masked); ask why before unmask' },
    { message: 'X.service: Start request repeated too quickly.', layer: 'Restart policy', meaning: 'Restart= restarted a crashing service 5 times in 10 s; systemd gave up.', firstCheck: 'journalctl -u X -b (first error); fix, then systemctl reset-failed X' },
    { message: 'Dependency failed for X.', layer: 'Dependencies', meaning: 'A unit X Requires= (often a mount or network-online.target) failed, so X was not started.', firstCheck: 'journalctl -b -p err; systemctl --failed' },
    { message: 'Main process exited, code=exited, status=203/EXEC', layer: 'Unit definition', meaning: 'ExecStart could not be executed: wrong path, not executable, bad #! line, SELinux label.', firstCheck: 'systemctl cat X; ls -l <binary>; ausearch -m AVC (RHEL)' },
    { message: 'Failed to determine user credentials: No such process / status=217/USER', layer: 'Unit definition', meaning: 'The account in User= does not exist on this host.', firstCheck: 'getent passwd <user>' },
    { message: 'Control process exited, code=exited, status=255/EXCEPTION (ExecStartPre=/usr/sbin/sshd -t)', layer: 'Program configuration', meaning: 'The config test failed; on ssh RestartPreventExitStatus=255 stops retries.', firstCheck: 'sshd -t; journalctl -u ssh -n 10' },
    { message: 'A start job is running for ... (1min 30s / no limit)', layer: 'Boot', meaning: 'A unit is waiting: a missing fstab device (90 s default timeout), or network-online.target waiting for an interface that never gets configured.', firstCheck: 'systemd-analyze blame; systemd-analyze critical-chain; journalctl -b -p warning' },
    { message: 'Warning: The unit file, source configuration file or drop-ins of X.service changed on disk. Run \'systemctl daemon-reload\' to reload units.', layer: 'Unit definition', meaning: 'You edited a unit by hand; systemd still uses the old version.', firstCheck: 'systemctl daemon-reload, then restart X' },
    { message: 'Hint: You are currently not seeing messages from other users and the system.', layer: 'Permissions', meaning: 'journalctl run without privileges shows only your own messages.', firstCheck: 'sudo journalctl ...; or add the user to group adm / systemd-journal' },
    { message: 'Specifying boot ID or boot offset has no effect, no persistent journal was found.', layer: 'Logging', meaning: 'The journal is volatile; previous boots are gone.', firstCheck: 'ls -ld /var/log/journal; create it and restart systemd-journald' },
  ],

  scenarioIds: ['ssh-config-typo', 'ssh-monday-reboot', 'fw-nginx-stopped', 'dhcp-interface', 'ssh-dns-zone-error'],
  assessmentId: 'systemd',
  references: [
    { title: 'systemd.unit(5): unit configuration, search paths, dependencies', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html' },
    { title: 'systemd.service(5): Type=, ExecStart=, Restart=', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html' },
    { title: 'systemd.exec(5): User=, EnvironmentFile=, sandboxing; exit codes', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html' },
    { title: 'systemd.special(7): default.target, network.target, network-online.target', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html' },
    { title: 'systemd: Running Services After the Network Is Up', url: 'https://systemd.io/NETWORK_ONLINE/' },
    { title: 'systemctl(1)', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemctl.html' },
    { title: 'journalctl(1) and journald.conf(5)', url: 'https://www.freedesktop.org/software/systemd/man/latest/journalctl.html' },
    { title: 'systemd-sysv-generator(8)', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd-sysv-generator.html' },
    { title: 'Filesystem Hierarchy Standard 3.0', url: 'https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html' },
    { title: 'Debian Reference: system initialization', url: 'https://www.debian.org/doc/manuals/debian-reference/ch03.en.html' },
    { title: 'Red Hat: Managing systemd (RHEL 9)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_systemd_unit_files_to_customize_and_optimize_your_system/index' },
    { title: 'Microsoft Learn: sc.exe create', url: 'https://learn.microsoft.com/windows-server/administration/windows-commands/sc-create' },
  ],
};

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

export const SYSTEMD_ASSESSMENT: Assessment = {
  id: 'systemd',
  title: 'systemd, logs and the filesystem: knowledge check',
  questions: [
    {
      id: 'systemd-q-enable-vs-start',
      kind: 'single',
      level: 'beginner',
      prompt: 'On Monday after a reboot, sshd on srv01 is not running. Which output explains why it was running last week but not after the reboot?',
      exhibit: 'root@srv01:~# systemctl status ssh\n○ ssh.service - OpenBSD Secure Shell server\n     Loaded: loaded (/lib/systemd/system/ssh.service; disabled; preset: enabled)\n     Active: inactive (dead) since Mon 2026-10-19 07:58:05 UTC; 98h 41min ago',
      options: [
        { text: 'The unit is disabled, so nothing started it at boot.', correct: true },
        { text: 'sshd crashed and Restart= was not set.', misconception: 'A crash shows "failed" with an exit status or signal. "inactive (dead)" and no start at this boot means it was never started.' },
        { text: 'The preset is enabled, so the unit file is broken.', misconception: 'The vendor preset is only the distribution\'s recommended default; the actual state is "disabled".' },
        { text: 'The configuration file has a syntax error.', misconception: 'A config error would show "failed (Result: exit-code)" with ExecStartPre status=255.' },
      ],
      concepts: ['svc.systemd'],
      explanation: '`enable` and `start` are independent. A unit can run (started by hand) while disabled; after the next reboot it stays down. Fix: `systemctl enable --now ssh`.',
    },
    {
      id: 'systemd-q-failed-exhibit',
      kind: 'single',
      level: 'beginner',
      prompt: 'After `systemctl restart ssh` you see this. What is the next command that best finds the cause?',
      exhibit: '× ssh.service - OpenBSD Secure Shell server\n     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; preset: enabled)\n     Active: failed (Result: exit-code) since Mon 2026-10-19 08:34:26 UTC; 20min ago\n    Process: 498 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=255/EXCEPTION)',
      options: [
        { text: 'sudo sshd -t', correct: true },
        { text: 'sudo systemctl restart ssh again', misconception: 'The config test will fail again; restarting repeats the failure. Find the error first.' },
        { text: 'sudo systemctl daemon-reload', misconception: 'daemon-reload re-reads unit files; the unit file is fine. The failing step is sshd\'s own config test.' },
        { text: 'sudo systemctl enable ssh', misconception: 'It is already enabled; enablement only affects boot.' },
      ],
      concepts: ['svc.systemd', 'logs.journal', 'ssh.config'],
      explanation: 'ExecStartPre=/usr/sbin/sshd -t exited 255: the configuration test failed. Running `sshd -t` (or reading `journalctl -u ssh -n 10`) prints the file and line, e.g. "/etc/ssh/sshd_config.d/10-hardening.conf line 6: Bad configuration option: PubkeyAuthentcation".',
    },
    {
      id: 'systemd-q-after-wants',
      kind: 'single',
      level: 'intermediate',
      prompt: 'A custom unit contains only `After=network-online.target`. At boot the service starts before the network is configured. Why?',
      options: [
        { text: 'After= only orders units that are being started anyway; nothing pulls network-online.target into the boot, so there is nothing to wait for.', correct: true },
        { text: 'After= is ignored for targets.', misconception: 'Ordering works for targets; the problem is that the target is not part of the transaction.' },
        { text: 'It needs Before=network-online.target instead.', misconception: 'That would order it before the network is online, the opposite of the intent.' },
        { text: 'network-online.target only exists on RHEL.', misconception: 'It is a standard systemd target on all distributions.' },
      ],
      concepts: ['svc.systemd'],
      explanation: 'Requirement (Wants=/Requires=) and ordering (After=/Before=) are separate. Use both: `Wants=network-online.target` and `After=network-online.target`.',
    },
    {
      id: 'systemd-q-precedence',
      kind: 'order',
      level: 'intermediate',
      prompt: 'A unit named `nginx.service` exists in all of these places. Order them from **highest** precedence (the one systemd uses) to lowest.',
      items: [
        '/etc/systemd/system/nginx.service',
        '/run/systemd/system/nginx.service',
        '/lib/systemd/system/nginx.service (= /usr/lib/systemd/system)',
        '/run/systemd/generator.late/nginx.service',
      ],
      concepts: ['svc.systemd', 'linux.fs'],
      explanation: 'Administrator files in /etc win over runtime units in /run, which win over vendor units from packages; units generated from SysV scripts have the lowest precedence, so a native unit always replaces a generated one. Drop-ins (`nginx.service.d/*.conf`) from all directories are merged on top.',
    },
    {
      id: 'systemd-q-dropin',
      kind: 'multi',
      level: 'intermediate',
      prompt: 'You want nginx to restart automatically after a crash, without your change being lost at the next package upgrade. Which steps are correct? (Select all that apply.)',
      options: [
        { text: 'sudo systemctl edit nginx and add [Service] Restart=on-failure', correct: true },
        { text: 'Restart nginx afterwards so the running service uses the new setting', correct: true },
        { text: 'Edit /lib/systemd/system/nginx.service directly', misconception: 'Vendor units are replaced by package upgrades; your change would disappear silently.' },
        { text: 'Write /etc/systemd/system/nginx.service.d/override.conf by hand and run systemctl daemon-reload', correct: true },
        { text: 'Add Restart=on-failure to /etc/nginx/nginx.conf', misconception: 'That is nginx\'s own configuration; systemd directives belong in unit files.' },
      ],
      concepts: ['svc.systemd', 'linux.fs'],
      explanation: '`systemctl edit` creates the drop-in and reloads systemd for you; a hand-written drop-in needs `daemon-reload`. In both cases the new setting applies at the next start, so restart the service.',
    },
    {
      id: 'systemd-q-oneshot',
      kind: 'single',
      level: 'intermediate',
      prompt: '`systemctl status nftables` shows `Active: active (exited)`. What does that mean?',
      options: [
        { text: 'It is a Type=oneshot unit with RemainAfterExit=yes: nft loaded the ruleset and exited, and the unit stays active.', correct: true },
        { text: 'The firewall crashed after starting.', misconception: 'A crash would show "failed". "exited" with "active" is the normal state of a oneshot unit.' },
        { text: 'The ruleset is not loaded; only the service is active.', misconception: 'The rules live in the kernel; no process is needed after nft -f finishes.' },
      ],
      concepts: ['svc.systemd', 'fw.persistence'],
      explanation: 'nftables.service runs `nft -f /etc/nftables.conf` once. Note its `ExecStop=/usr/sbin/nft flush ruleset`: stopping the unit removes the firewall.',
    },
    {
      id: 'systemd-q-journal-flags',
      kind: 'text',
      level: 'beginner',
      prompt: 'Write the journalctl command that shows only messages of priority **err or worse** from the **current boot** (any unit).',
      accept: [/^(sudo\s+)?journalctl\s+(-b\s+-p\s*(err|3)|-p\s*(err|3)\s+-b)$/i, /^(sudo\s+)?journalctl\s+(--boot\s+--priority[= ](err|3)|--priority[= ](err|3)\s+--boot)$/i],
      placeholder: 'journalctl ...',
      concepts: ['logs.journal'],
      explanation: '`journalctl -b -p err` (`-p 3` is equivalent). `-p err` includes emerg, alert, crit and err; add `-u <unit>` to narrow to one service.',
    },
    {
      id: 'systemd-q-resolvconf',
      kind: 'single',
      level: 'intermediate',
      prompt: 'On an Ubuntu 24.04 server you change the nameserver line in /etc/resolv.conf, but a minute later your change is gone. What do you check first?',
      exhibit: '$ ls -l /etc/resolv.conf\nlrwxrwxrwx 1 root root 39 Apr 23 09:12 /etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf',
      options: [
        { text: 'It is a symlink managed by systemd-resolved: check `resolvectl status` and change the DNS servers in the netplan YAML (or the DHCP server).', correct: true },
        { text: 'Make the file immutable with chattr +i.', misconception: 'That fights the resolver manager instead of configuring it, and breaks DNS updates from DHCP/netplan.' },
        { text: 'Restart rsyslog.', misconception: 'rsyslog has nothing to do with name resolution.' },
        { text: 'Edit /etc/hosts instead.', misconception: '/etc/hosts is for static names, not for choosing DNS servers.' },
      ],
      concepts: ['linux.fs', 'dns.resolution'],
      explanation: 'Before editing a file, find out who generates it: `ls -l` for symlinks, the header comment, and the manager\'s own tool (`resolvectl status`, `nmcli device show`). Change the source of truth.',
    },
    {
      id: 'systemd-q-exit-codes',
      kind: 'multi',
      level: 'advanced',
      prompt: 'A new custom unit fails. Match the evidence to its cause: which statements are correct? (Select all that apply.)',
      options: [
        { text: '`status=203/EXEC` means systemd could not execute the ExecStart binary (path, permissions, interpreter, or SELinux label).', correct: true },
        { text: '`status=217/USER` means the account named in User= does not exist.', correct: true },
        { text: '`Start request repeated too quickly` means the service is healthy but busy.', misconception: 'It means Restart= restarted a failing service 5 times within 10 s and systemd gave up.' },
        { text: '`Unit inventory-api.service could not be found` right after creating the file usually means daemon-reload was not run.', correct: true },
      ],
      concepts: ['svc.systemd'],
      explanation: '203/217/200 are systemd\'s own exit codes for setup failures before the program even runs; other codes come from the program. A new or edited unit file is only seen after `daemon-reload`.',
    },
    {
      id: 'systemd-q-generated',
      kind: 'single',
      level: 'advanced',
      prompt: 'On ns1, dhcpd crashed during the night and was not restarted. Based on this unit, why?',
      exhibit: '# /run/systemd/generator.late/isc-dhcp-server.service\n# Automatically generated by systemd-sysv-generator\n[Service]\nType=forking\nRestart=no\nRemainAfterExit=yes\nExecStart=/etc/init.d/isc-dhcp-server start',
      options: [
        { text: 'It is generated from an LSB init script with Restart=no, so systemd never restarts it; add a drop-in with Restart=on-failure (or monitor it).', correct: true },
        { text: 'Edit /run/systemd/generator.late/isc-dhcp-server.service and set Restart=always.', misconception: 'Generated files are rewritten at every boot and daemon-reload; put the change in /etc/systemd/system/isc-dhcp-server.service.d/.' },
        { text: 'Forking services can never be restarted.', misconception: 'Restart= works for forking services too; this unit simply sets Restart=no.' },
      ],
      concepts: ['svc.systemd', 'linux.fs', 'net.dhcp'],
      explanation: 'systemd-sysv-generator wraps /etc/init.d scripts with conservative settings. Note also `RemainAfterExit=yes`: with LSB units the state can show "active" after the daemon has died, so also check the process (`ss -ulnp | grep :67`).',
    },
  ],
};
