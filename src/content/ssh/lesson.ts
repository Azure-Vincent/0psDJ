import type { Lesson } from '../types';

export const SSH_LESSON: Lesson = {
  id: 'ssh',
  moduleId: 'B',
  title: 'SSH: Secure Shell',
  level: 'beginner',
  summary: 'How an SSH login really works, from the hostname you type to an authenticated shell, and how to prove which layer failed when it does not.',
  concepts: ['dns.resolution', 'net.routing', 'net.arp', 'tcp.handshake', 'fw.stateful', 'svc.systemd', 'svc.listening', 'ssh.kex', 'ssh.hostkeys', 'ssh.userauth', 'ssh.authorized-keys', 'linux.permissions', 'ssh.config', 'ssh.authz', 'logs.journal'],

  what: `
**SSH** (Secure Shell, RFC 4251–4254) lets you open a terminal on another computer over a network, as if you were sitting at its keyboard. Everything you type and everything it prints travels **encrypted**, and both sides prove who they are before anything else happens. It is the standard way to administer Linux and Unix servers, network devices and, more and more, Windows servers. It is also the transport underneath tools such as \`scp\`, \`sftp\`, \`rsync\`, Git over SSH and Ansible.

On the server, a background program called **sshd** (the SSH daemon) listens for incoming connections on **TCP port 22**. A "daemon" is simply a program that runs in the background without a user attached, waiting to do its job. On the client, you run the \`ssh\` command.

### What SSH builds on
An SSH connection uses almost everything from module A: the server's name has to resolve ([Transport and DNS](#/lesson/transport/what)), packets need a route there and back ([IP networking](#/lesson/ipnet/what)), a TCP connection to port 22 has to succeed, and every firewall on the way has to allow it. Only then does SSH itself start. That is why SSH problems are often not SSH problems at all, and why this lesson teaches you to read the exact error message to find the layer that failed.

:::practice
Q: List, in order, what must work before sshd itself is even involved in a connection.
A: Name resolution, a route there **and back**, every firewall on the path, and a TCP connection to port 22 that the server's kernel completes because something listens.
Q: \`ssh srv01\` fails with "Connection timed out". Is that most likely an SSH configuration problem?
A: **No.** SSH never started: the TCP connection got no answer. Look at the network and firewalls first.
:::

### Problems it solves
- **Privacy and integrity.** Older tools (Telnet, rlogin, rsh) sent passwords and keystrokes as plain text that anyone on the path could read. Everything SSH sends after its key exchange is encrypted and protected against tampering.
- **Proving the server's identity.** The client checks a cryptographic **host key** that belongs to the server. If the key changes, the client notices: you may be talking to a rebuilt server, the wrong machine because of a bad DNS record, or an attacker in the middle.
- **Proving the user's identity.** Passwords are only ever sent inside the encrypted channel, and **public-key authentication** avoids sending a reusable secret at all.
- **Several things over one connection.** A single connection can carry an interactive shell, remote commands, file transfer (the SFTP subsystem) and port forwarding, each as a separate **channel**.

:::practice
Q: Why is Telnet unacceptable for administering a server across a shared network?
A: It sends the password and every keystroke as **plain text**, readable by anyone on the path. SSH encrypts everything after its key exchange.
Q: A user copies files with sftp and has a shell open, both to the same server over one SSH connection. What makes that possible?
A: **Channels**: one SSH connection carries several independent channels (a shell, the SFTP subsystem, port forwards).
:::

### Where you meet it
- Administrators connecting from a workstation, or through a **bastion** (jump host), to servers: \`ssh -J bastion srv01\`.
- Automation (Ansible, CI/CD deployment jobs, backups) using key-based logins that need no human.
- Network devices (switches, routers, firewalls such as pfSense) and hypervisors.
- Windows Server 2019/2022, which includes an optional **OpenSSH Server** feature.

### The pieces
- Programs: \`ssh\` (the client), \`sshd\` (the server), \`ssh-keygen\` (creates keys), \`ssh-agent\` (holds your unlocked keys in memory), \`ssh-copy-id\` (installs your public key on a server), \`ssh-keyscan\` (fetches a server's host key).
- The server's identity: **host key pairs** in \`/etc/ssh/ssh_host_*_key\`.
- Your identity: **user key pairs** in \`~/.ssh/id_*\` on your computer. The public half of each is authorised on the server in \`~/.ssh/authorized_keys\`.
- Your client's record of known servers: \`~/.ssh/known_hosts\`.

> This lesson uses OpenSSH 9.2 on Debian 12, both as server and client. The simulator reproduces this version's messages and log lines; other versions differ in details (for example, Ubuntu 22.10 and later start sshd through systemd socket activation).

:::practice
Q: Which file on your workstation holds the host keys of servers you have trusted before, and which file on a server lists the public keys allowed to log in as a user?
A: Your **~/.ssh/known_hosts**; the user's **~/.ssh/authorized_keys** on the server.
Q: Which tool installs your public key into a server account's authorized_keys?
A: \`ssh-copy-id user@server\`.
:::

`,
  internals: `
### Three protocol layers (RFC 4251)
SSH itself is built in three layers, each running inside the one before it:
- **Transport layer (RFC 4253)**: version exchange, algorithm negotiation, key exchange, server authentication by host key, then encryption + integrity for everything that follows.
- **User authentication protocol (RFC 4252)**: runs *inside* the encrypted transport; the client proves who the user is (publickey, password, keyboard-interactive, GSSAPI/Kerberos, hostbased).
- **Connection protocol (RFC 4254)**: multiplexes channels (session/shell, exec, subsystem sftp, direct-tcpip and forwarded-tcpip for port forwarding) over the single transport.

:::practice
Q: In which layer does the password or key check happen, and is it encrypted?
A: In the **user authentication** layer, which runs **inside** the already encrypted transport.
Q: \`scp\` and \`sftp\` transfers and \`ssh -L\` port forwards all travel over one SSH connection. Which layer makes that possible?
A: The **connection protocol**: it multiplexes several channels (session, sftp subsystem, forwarded TCP) over the single transport.
:::

### Everything that happens for \`ssh srv01.corp.lab\`
Here is the whole journey of one connection, in order. Each step depends on the previous one, so when SSH fails, the error message tells you which step it reached.

1. **Configuration.** The client merges command-line options, \`~/.ssh/config\` and \`/etc/ssh/ssh_config\`. The first value obtained for each option wins.
2. **Name resolution.** \`getaddrinfo()\` consults NSS: \`/etc/hosts\` first, then DNS servers in \`/etc/resolv.conf\` (with search domains for short names). No answer → "Could not resolve hostname".
3. **Routing and ARP.** The kernel looks up the destination in the routing table (longest prefix match), chooses the source address and next hop (the default gateway for remote networks), and resolves the next hop's MAC address with ARP.
4. **TCP three-way handshake** to port 22: SYN, SYN-ACK, ACK. The server's kernel completes this *before* sshd is involved, as long as a socket is listening. Firewalls along the way (and on the server) must allow the SYN and the replies (stateful rules track the connection).
5. **Identification strings.** Both sides send \`SSH-2.0-<software>\` in clear text.
6. **KEXINIT (key exchange initialisation).** Each side lists the encryption and signing algorithms it supports, in order of preference. For each category, they use the first algorithm on the client's list that the server also supports. If there is none, the connection stops here.
7. **Key exchange** (for example \`sntrup761x25519-sha512@openssh.com\` or \`curve25519-sha256\`). Both sides send each other temporary ("ephemeral") public values. From them, each side calculates the same shared secret *K* and a fingerprint of the conversation so far, the exchange hash *H*, without the secret ever crossing the network. The server signs *H* with its **host key** to prove its identity.
8. **Host key verification.** The client checks the signature, then compares the host key with its \`known_hosts\` file. If it matches, it continues. If the server is unknown, it asks you whether to trust it ("trust on first use"). If the key is different from last time, it refuses with "REMOTE HOST IDENTIFICATION HAS CHANGED". Two very different things produce that warning: a server that was legitimately rebuilt or got new keys, and someone intercepting the connection (a man-in-the-middle). The warning cannot tell them apart, so **do not just delete the old line**. First compare the fingerprint in the warning with one from a channel you trust: the server's console (\`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub\`), the change record, or published fingerprints. Only if they match, remove the old entry (\`ssh-keygen -R srv01\`) and connect again.
9. **NEWKEYS.** From now on every packet is encrypted and authenticated with keys derived from *K* and *H*.
10. **User authentication (ssh-userauth).** The client asks which login methods are allowed (by trying the method "none"), then tries them. For **publickey**, it first asks whether a particular key would be accepted, then proves it holds the private key by signing data that includes this session's identifier. The private key itself never leaves the client.
11. **Authorization and account checks** on the server: account exists, not excluded by \`AllowUsers\`/\`DenyUsers\`/\`AllowGroups\`, valid shell, PAM account rules, \`PermitRootLogin\`.
12. **Session.** sshd opens a PAM session (logind session, MOTD, environment), allocates a pseudo-terminal and starts the user's shell. Channels carry the terminal data.

:::practice
Q: \`ssh srv01\` fails with "Could not resolve hostname". Which steps were never reached?
A: Everything from step 3 on: no route lookup, no TCP connection, no SSH. The failure is **name resolution**; check /etc/hosts, resolv.conf and DNS.
Q: A connection fails with "no matching key exchange method found". At which step did it stop, and had any user credential been sent?
A: At **KEXINIT** (step 6): the two sides share no key exchange algorithm. No credential was sent; user authentication (step 10) was never reached.
:::

### What someone capturing the traffic can see
Steps 1 to 8 happen **before** NEWKEYS, so they travel unencrypted. That is by design: the two sides cannot encrypt until they have agreed how. Someone with a packet capture of an SSH login, but without the session keys, can therefore read:
- the IP addresses and ports of both ends (as for any TCP connection);
- both identification strings, which reveal the software and version (\`SSH-2.0-OpenSSH_9.2p1 Debian-2\`);
- the KEXINIT lists of supported algorithms, and the algorithms both sides chose;
- the server's public host key (it is public: it only proves who the server is).

Everything from NEWKEYS on is encrypted: the user name, the login method, the password or key signature, and every command and its output. The observer still sees the **size and timing** of the encrypted packets. To find out *who* logged in, you need the server's log (\`journalctl -u ssh\`), not the capture.

:::practice
Q: From a capture alone, can you tell which SSH software version the server runs?
A: **Yes.** The identification string (for example \`SSH-2.0-OpenSSH_9.2p1 Debian-2\`) is sent in clear text before encryption starts.
Q: Can a capture tell you whether a login used a password or a key, or which user logged in?
A: **No.** User authentication happens after NEWKEYS, inside the encryption. For that you need the server's log.
:::

### Operating-system components on the server
sshd does not work alone. Several parts of the operating system take part in every login:
- **systemd**, the Linux service manager that starts and supervises background programs, starts \`ssh.service\`, which on Debian first runs \`sshd -t\` (configuration test) and then \`sshd -D\`. A failed test means sshd does not start.
- The main sshd process (the **listener**) accepts each connection and starts a separate **child process** for it. Everything that happens before login runs in an unprivileged, sandboxed process (this is called **privilege separation**), so a bug triggered by an attacker's data does not run as root.
- **PAM** (Pluggable Authentication Modules, configured in \`/etc/pam.d/sshd\`) is the shared login framework of Linux. It handles password verification (\`pam_unix\` against \`/etc/shadow\`), account checks and session setup when \`UsePAM yes\`.
- **The journal** receives sshd's messages (Debian 12 does not install rsyslog by default, so there is no \`/var/log/auth.log\`; use \`journalctl -u ssh\`).
- **The host firewall** (nftables on Debian 12) filters packets before they reach any socket.

:::practice
Q: \`systemctl restart ssh\` fails and sshd is not running afterwards. Which built-in check most likely stopped it?
A: On Debian the unit first runs **\`sshd -t\`** (ExecStartPre). A configuration error makes that test fail, and sshd is not started.
Q: Which component checks a password against /etc/shadow when \`UsePAM yes\` is set?
A: **PAM**, through the \`pam_unix\` module configured in /etc/pam.d/sshd.
:::

### Keys: who proves what
| Key | Lives | Proves | Checked against |
|---|---|---|---|
| Host key (private) | server \`/etc/ssh/ssh_host_*_key\` | "I am the same server as before" | client \`known_hosts\` |
| User key (private) | client \`~/.ssh/id_*\` | "I am this user" | server \`~/.ssh/authorized_keys\` |
| Session keys | memory only, per connection | confidentiality/integrity | derived from the key exchange |

:::practice
Q: Which file must contain the user's **public** key for a key-based login, and on which machine?
A: \`~/.ssh/authorized_keys\` of the target account, on the **server**.
Q: A server was reinstalled and got new host keys. Which file on the client produces the warning, and why does it matter which key was stored there?
A: \`~/.ssh/known_hosts\`. It holds the host key the client trusted before; a different key could be a rebuild or an attacker, so the client refuses until you verify the new fingerprint.
:::

### Dependencies
SSH works only if *every* layer below it works: name resolution → client route → each router's forwarding and return path → firewalls → a listening sshd with a valid configuration → common algorithms → host-key trust → an existing, authorised account → a usable credential with safe file permissions → a valid shell. Each failure produces a **distinct** symptom, which is why reading the exact error message is the first troubleshooting step. Use the dependency map below to switch dependencies off, predict the result, and see what the simulator computes.

:::practice
Q: A colleague's key login worked yesterday and today gives "Permission denied (publickey)". The server is reachable and other users can log in. Which dependencies are still candidates?
A: Those specific to this user: the key itself (or the client not offering it), \`authorized_keys\` content, **file permissions** of the home directory, ~/.ssh or authorized_keys (StrictModes), and whether the account is allowed (AllowUsers/AllowGroups, locked account). The network, sshd and host keys are fine, because others log in.
Q: Why does reading the exact error message come first when SSH fails?
A: Each failed dependency produces a **different** message (resolve, refused, timed out, host key, permission denied), so the message tells you which layer to investigate.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu 24.04',
      summary: 'Install OpenSSH server, verify it listens, set up key-based login, harden, and confirm through the firewall. Run these on a real VM (VirtualBox, KVM, Hyper-V) or a cloud instance. Commands marked "simulated" also work in the sandbox terminal.',
      prerequisites: ['A Debian 12 or Ubuntu 24.04 VM with network access and console access (in case you lock yourself out).', 'A user account with sudo rights.', 'A client machine with the OpenSSH client (Linux/macOS built in; Windows 10/11 built in as ssh.exe).'],
      steps: [
        { title: 'Install the server package', command: 'sudo apt update && sudo apt install openssh-server', what: 'Installs sshd, the default configuration and a systemd unit. Host keys are generated during installation.', why: 'Minimal and server images may not include the SSH server.', expected: 'Setting up openssh-server (1:9.2p1-2+deb12u3) ...\nCreating SSH2 RSA key; this may take some time ...\nCreating SSH2 ECDSA key; this may take some time ...\nCreating SSH2 ED25519 key; this may take some time ...' },
        { title: 'Check the service', command: 'systemctl status ssh', what: 'Shows whether the unit is enabled (starts at boot) and active, its main PID and the latest log lines.', why: '"enabled" and "active (running)" are two different things: one is about the next boot, the other about now.', expected: '● ssh.service - OpenBSD Secure Shell server\n     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; preset: enabled)\n     Active: active (running) since ...', simulated: true },
        { title: 'Confirm it listens', command: 'sudo ss -tlnp', what: 'Lists listening TCP sockets with the owning process.', why: 'Proves the daemon bound the expected address and port. A service can be "running" but listening somewhere unexpected.', expected: 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=407,fd=3))\nLISTEN 0 128    [::]:22    [::]:* users:(("sshd",pid=407,fd=4))', simulated: true },
        { title: 'Record the host key fingerprints', command: 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub', what: 'Prints the SHA256 fingerprint of the ED25519 host key (repeat for the rsa and ecdsa keys).', why: 'Clients will be asked to confirm one of these on first connection. Distribute them through a trusted channel so users can verify instead of blindly typing "yes".', expected: '256 SHA256:YYUWcycRPwFdoA8Iq2JSp28CvBA67hlB45ITKLNx/oE root@srv01 (ED25519)', simulated: true },
        { title: 'Allow SSH through the host firewall', command: 'sudo nft add rule inet filter input tcp dport 22 accept\n# then persist it in /etc/nftables.conf and: sudo systemctl enable --now nftables', what: 'Adds an allow rule to the input chain. With UFW instead: sudo ufw allow OpenSSH.', why: 'With a default-deny input policy, nothing reaches sshd unless explicitly allowed. Runtime rules are lost at reboot unless saved to /etc/nftables.conf.', expected: '(no output on success)', simulated: true },
        { title: 'Create a key pair on the CLIENT', command: 'ssh-keygen -t ed25519 -C "alice@ws01"', what: 'Generates ~/.ssh/id_ed25519 (private, mode 600) and ~/.ssh/id_ed25519.pub (public). Use a passphrase and ssh-agent.', why: 'Key-based authentication is resistant to password guessing and phishing, and enables automation.', expected: 'Your identification has been saved in /home/alice/.ssh/id_ed25519\nYour public key has been saved in /home/alice/.ssh/id_ed25519.pub\nThe key fingerprint is:\nSHA256:4yQgPFwJgftWQvdxEtpEZvzMfqVBR2pLS4x5kFYF9wY alice@ws01' },
        { title: 'Install the public key on the server', command: 'ssh-copy-id alice@srv01.corp.lab', what: 'Logs in with your password once and appends your public key to ~/.ssh/authorized_keys with correct permissions.', why: 'The server must know which public keys may log in as which user. ssh-copy-id needs a working login method (usually password); if passwords are disabled, an administrator must install the key.', expected: 'Number of key(s) added: 1' },
        { title: 'Test key login BEFORE disabling passwords', command: 'ssh -o PasswordAuthentication=no alice@srv01.corp.lab', what: 'Forces the client to use only keys.', why: 'Proves the key works so you do not lock yourself out in the next step. Keep this session open while you change sshd.', expected: 'Linux srv01 6.1.0-26-amd64 ...\nalice@srv01:~$', simulated: true },
        { title: 'Harden with a drop-in file', command: 'sudo tee /etc/ssh/sshd_config.d/10-hardening.conf <<\'EOF\'\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowGroups ssh-users\nEOF', what: 'Places site settings in a drop-in that is included at the top of sshd_config.', why: 'Drop-ins survive package upgrades of sshd_config. Because the first value obtained wins and the Include is at the top, drop-ins override the main file.', expected: '' },
        { title: 'Validate, then reload', command: 'sudo sshd -t && sudo systemctl reload ssh', what: 'sshd -t parses the full configuration and exits non-zero on errors; reload sends SIGHUP so new connections use the new config while existing sessions continue.', why: 'A syntax error plus "restart" leaves you with no sshd at all. "reload" re-runs the test and keeps the old daemon if it fails.', expected: '(no output from sshd -t when the configuration is valid)', simulated: true },
        { title: 'Verify the effective configuration', command: 'sudo sshd -T | grep -Ei "^(port|passwordauthentication|permitrootlogin|allowgroups)"', what: 'Prints the configuration sshd actually uses after includes, defaults and first-match rules.', why: 'Reading sshd_config is not enough: commented lines, drop-ins and duplicates make the file misleading. sshd -T is the ground truth.', expected: 'port 22\npermitrootlogin no\npasswordauthentication no', simulated: true },
        { title: 'Verify from a client with verbose output', command: 'ssh -v alice@srv01.corp.lab', what: 'Shows each protocol step: resolved address, connection, negotiated algorithms, host key check and authentication methods.', why: 'This is your baseline. When something breaks later, compare the new -v output with a known-good one.', expected: 'debug1: Connecting to srv01.corp.lab [10.0.20.10] port 22.\ndebug1: Connection established.\n...\nAuthenticated to srv01.corp.lab ([10.0.20.10]:22) using "publickey".', simulated: true },
        { title: 'Watch the server log while testing', command: 'sudo journalctl -u ssh -f', what: 'Follows sshd\'s messages live.', why: 'Authorization and permission failures are only explained on the server side. The client deliberately gets a generic "Permission denied".', expected: 'sshd[1423]: Accepted publickey for alice from 10.0.10.25 port 51514 ssh2: ED25519 SHA256:...', simulated: true },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky Linux 9 / AlmaLinux 9',
      summary: 'Same concepts with different packaging, firewall front-end and SELinux. Run on a real VM.',
      prerequisites: ['RHEL-compatible 9.x VM with console access.', 'sudo rights.'],
      steps: [
        { title: 'Install and enable', command: 'sudo dnf install openssh-server\nsudo systemctl enable --now sshd', what: 'Installs and starts the daemon. The unit is called sshd.service on RHEL (ssh.service on Debian).', why: 'Unit names differ between distributions; systemctl status sshd tells you which exists.', expected: 'Created symlink /etc/systemd/system/multi-user.target.wants/sshd.service → /usr/lib/systemd/system/sshd.service.' },
        { title: 'Open the firewall', command: 'sudo firewall-cmd --permanent --add-service=ssh\nsudo firewall-cmd --reload', what: 'firewalld manages nftables underneath. --permanent writes the persistent configuration; --reload applies it.', why: 'Without --permanent the change is lost at reload/reboot; without --reload the permanent change is not active yet.', expected: 'success\nsuccess' },
        { title: 'Changing the port requires SELinux labelling', command: 'sudo semanage port -a -t ssh_port_t -p tcp 2222', what: 'Allows sshd (domain sshd_t) to bind TCP 2222.', why: 'With SELinux enforcing, sshd cannot bind a port that is not labelled ssh_port_t: the journal shows "error: Bind to port 2222 on 0.0.0.0 failed: Permission denied" even as root.', expected: '(no output on success)' },
        { title: 'Crypto policies', command: 'update-crypto-policies --show', what: 'RHEL sets SSH algorithm lists system-wide (DEFAULT, FUTURE, LEGACY) via /etc/crypto-policies.', why: 'KexAlgorithms/Ciphers problems on RHEL are often caused by the system crypto policy rather than sshd_config.', expected: 'DEFAULT' },
        { title: 'Logs', command: 'sudo journalctl -u sshd\nsudo tail /var/log/secure', what: 'RHEL also writes authentication messages to /var/log/secure via rsyslog.', why: 'Know where each distribution logs authentication.', expected: 'sshd[1423]: Accepted publickey for alice from 10.0.10.25 port 51514 ssh2' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server 2019 / 2022',
      summary: 'Windows ships OpenSSH (a Microsoft port of OpenSSH) as an optional capability. Run these in an elevated PowerShell on a real Windows Server VM.',
      prerequisites: ['Windows Server 2019 (1809) or later, or Windows 10/11.', 'Local Administrator rights.'],
      steps: [
        { title: 'Install the server capability', command: 'Get-WindowsCapability -Online -Name OpenSSH*\nAdd-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0', what: 'Lists and installs the OpenSSH Server optional feature.', why: 'It is not installed by default on Server editions.', expected: 'Path          :\nOnline        : True\nRestartNeeded : False' },
        { title: 'Start and enable the service', command: 'Start-Service sshd\nSet-Service -Name sshd -StartupType Automatic\nGet-Service sshd', what: 'Starts the sshd Windows service and makes it start at boot.', why: 'Like systemd enablement on Linux: running now and starting at boot are separate settings.', expected: 'Status   Name               DisplayName\n------   ----               -----------\nRunning  sshd               OpenSSH SSH Server' },
        { title: 'Check the firewall rule', command: 'Get-NetFirewallRule -Name *OpenSSH-Server* | Select-Object Name, Enabled, Direction, Action\nTest-NetConnection srv-win01 -Port 22', what: 'Installation creates the inbound rule "OpenSSH-Server-In-TCP". Test-NetConnection checks TCP reachability from a client.', why: 'If the rule is missing or disabled for the active profile (Domain/Private/Public), connections time out.', expected: 'Name                    Enabled Direction Action\nOpenSSH-Server-In-TCP      True   Inbound  Allow\n...\nTcpTestSucceeded : True' },
        { title: 'Know where things live', command: 'notepad C:\\ProgramData\\ssh\\sshd_config', what: 'Configuration and host keys live in C:\\ProgramData\\ssh\\. Users\' keys go in %USERPROFILE%\\.ssh\\authorized_keys.', why: 'For members of the Administrators group, the default sshd_config uses C:\\ProgramData\\ssh\\administrators_authorized_keys instead (Match Group administrators). Keys placed in the user profile are ignored for admins, a very common surprise.', expected: '' },
        { title: 'Fix permissions on administrators_authorized_keys', command: 'icacls.exe "C:\\ProgramData\\ssh\\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"', what: 'Restricts the file to Administrators and SYSTEM.', why: 'Windows sshd applies a StrictModes-like check: if other principals can write the file, the keys are ignored.', expected: 'processed file: C:\\ProgramData\\ssh\\administrators_authorized_keys\nSuccessfully processed 1 files; Failed processing 0 files' },
        { title: 'Choose the default shell (optional)', command: 'New-ItemProperty -Path "HKLM:\\SOFTWARE\\OpenSSH" -Name DefaultShell -Value "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -PropertyType String -Force', what: 'Sets the registry value that selects the shell for SSH sessions (cmd.exe by default).', why: 'Administrators usually want PowerShell.', expected: 'DefaultShell : C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
        { title: 'Logs', command: 'Get-WinEvent -LogName OpenSSH/Operational -MaxEvents 20', what: 'Windows OpenSSH logs to the OpenSSH/Operational event log (Applications and Services Logs).', why: 'Same role as journalctl -u ssh on Linux.', expected: 'sshd: Accepted publickey for alice from 10.0.10.25 port 51514 ssh2: ED25519 SHA256:...' },
      ],
    },
  ],

  configIntro: `
sshd reads its configuration file, \`/etc/ssh/sshd_config\`, when it starts and when it is told to reload. Four rules explain most surprises:
- **The first value for a setting wins.** If the same keyword appears twice, the second one is ignored. (A few list keywords, such as \`Port\`, \`ListenAddress\`, \`HostKey\` and \`AllowUsers\`, add up instead.) Debian's file starts with \`Include /etc/ssh/sshd_config.d/*.conf\`, so settings in those drop-in files take priority over the main file.
- **Lines starting with # are comments.** In the default file they document the default values; they do not configure anything. \`#PasswordAuthentication yes\` does nothing.
- **Edits only take effect after a reload or restart.** Until then, sshd keeps running with the old configuration. Always test the file with \`sshd -t\` before reloading, and check the result with \`sshd -T\`, which prints the settings sshd would actually use. Add \`-C user=alice,addr=10.0.10.25\` to see how Match blocks apply to one particular connection.
- **A Match block lasts until the next Match line or the end of the file.** Every line after \`Match Address 10.0.30.0/24\` applies only to connections that match, so put global settings first and Match blocks **last**. A narrow exception looks like this: strict global settings, then one block that relaxes a single setting for one network:
\`\`\`
PermitRootLogin no
PasswordAuthentication no
Match Address 192.168.50.0/24
    PasswordAuthentication yes
\`\`\`
Connections from 192.168.50.x may use passwords; everyone else may not. Root logins stay forbidden for everyone, because the Match block does not change that setting. (The indentation is only for people; sshd ignores it.)

The explorer below runs the simulator's sshd parser on whatever you type and shows the effective result, exactly as \`sshd -T\` would.
`,
  configFiles: [
    {
      platform: 'Linux (Debian/Ubuntu)',
      items: [
        { path: '/etc/ssh/sshd_config', purpose: 'Main server configuration (package-managed).' },
        { path: '/etc/ssh/sshd_config.d/*.conf', purpose: 'Drop-in overrides, included at the top of sshd_config.' },
        { path: '/etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key[.pub]', purpose: 'Server host key pairs. Private keys must be 600 root:root or sshd refuses them.' },
        { path: '~/.ssh/authorized_keys', purpose: 'Public keys allowed to log in as that user (one per line, optional options prefix such as from="10.0.10.0/24").' },
        { path: '~/.ssh/known_hosts, /etc/ssh/ssh_known_hosts', purpose: 'Client trust store of host keys.' },
        { path: '~/.ssh/config, /etc/ssh/ssh_config', purpose: 'Client configuration (Host blocks, User, Port, IdentityFile, ProxyJump).' },
        { path: '/etc/pam.d/sshd', purpose: 'PAM stack used when UsePAM yes (auth, account, session).' },
        { path: '/lib/systemd/system/ssh.service', purpose: 'systemd unit: ExecStartPre=/usr/sbin/sshd -t, ExecStart=/usr/sbin/sshd -D.' },
        { path: 'journalctl -u ssh', purpose: 'sshd log messages (Debian 12 has no /var/log/auth.log unless rsyslog is installed).' },
      ],
    },
    {
      platform: 'Windows Server',
      items: [
        { path: 'C:\\ProgramData\\ssh\\sshd_config', purpose: 'Server configuration.' },
        { path: 'C:\\ProgramData\\ssh\\administrators_authorized_keys', purpose: 'Authorized keys for members of Administrators (via Match Group administrators).' },
        { path: '%USERPROFILE%\\.ssh\\authorized_keys', purpose: 'Authorized keys for non-admin users.' },
        { path: 'HKLM\\SOFTWARE\\OpenSSH\\DefaultShell', purpose: 'Registry value selecting the session shell.' },
        { path: 'Services: sshd, ssh-agent', purpose: 'Windows services (Get-Service sshd).' },
        { path: 'Event log: OpenSSH/Operational', purpose: 'sshd log messages.' },
      ],
    },
  ],

  directives: [
    { name: 'Port', compiledDefault: '22', recommended: '22', explanation: 'TCP port(s) sshd listens on. May be given several times.', security: 'Moving the port reduces log noise from scanners but is not a security control. It breaks clients, firewall rules, monitoring and (on RHEL) needs an SELinux port label.' },
    { name: 'ListenAddress', compiledDefault: '0.0.0.0 and ::', recommended: 'Management interface address on multi-homed hosts', explanation: 'Addresses to bind. If the address is not configured on the host, bind fails ("Cannot assign requested address").', security: 'Binding only to a management network reduces exposure. Binding to 127.0.0.1 makes sshd unreachable remotely.' },
    { name: 'PermitRootLogin', compiledDefault: 'prohibit-password', recommended: 'no', explanation: 'Whether root may log in directly: yes, prohibit-password (keys only), forced-commands-only, no.', security: 'Use personal accounts plus sudo for accountability. "no" means the journal shows WHO did something.' },
    { name: 'PasswordAuthentication', compiledDefault: 'yes', recommended: 'no', explanation: 'Allows the "password" method. When no, clients are never asked for a password and see "Permission denied (publickey)".', security: 'Disabling passwords removes the brute-force and credential-stuffing attack surface. Make sure keys work first.' },
    { name: 'KbdInteractiveAuthentication', compiledDefault: 'yes', distroDefault: 'no (Debian)', recommended: 'no (unless used for MFA)', explanation: 'Allows keyboard-interactive (PAM conversation) authentication, often used for OTP/MFA. Replaces the deprecated ChallengeResponseAuthentication.', security: 'With UsePAM yes it can allow password logins even when PasswordAuthentication is no.' },
    { name: 'PubkeyAuthentication', compiledDefault: 'yes', recommended: 'yes', explanation: 'Allows public-key authentication.', security: 'Strongest common method; combine with AuthenticationMethods for MFA if required.' },
    { name: 'AuthorizedKeysFile', compiledDefault: '.ssh/authorized_keys .ssh/authorized_keys2', recommended: '.ssh/authorized_keys', explanation: 'Where to look for a user\'s authorised keys, relative to the home directory (tokens %h, %u).', security: 'Centralising keys (e.g. /etc/ssh/authorized_keys/%u, root-owned) prevents users from adding keys themselves.' },
    { name: 'StrictModes', compiledDefault: 'yes', recommended: 'yes', explanation: 'Before using authorized_keys, sshd checks that the file, ~/.ssh and the home directory are owned by the user or root and not writable by group/others.', security: 'Never disable: a group-writable ~/.ssh would let other users plant keys and log in as you.' },
    { name: 'AllowUsers / AllowGroups / DenyUsers / DenyGroups', compiledDefault: '(none: everyone allowed)', recommended: 'AllowGroups <ssh group>', explanation: 'Access lists checked before authentication. Patterns may include user@host. Multiple directives accumulate.', security: 'A strong control, but every new admin must be added. Group-based lists scale better. Rejections are only logged on the server.' },
    { name: 'MaxAuthTries', compiledDefault: '6', recommended: '3–6', explanation: 'Authentication attempts per connection before disconnect. Each offered key counts.', security: 'Too low breaks users with many keys in their agent ("Too many authentication failures").' },
    { name: 'LogLevel', compiledDefault: 'INFO', recommended: 'VERBOSE', explanation: 'INFO logs accepted/failed passwords and accepted keys. VERBOSE also logs connection attempts and key fingerprints of FAILED publickey attempts.', security: 'VERBOSE gives an audit trail of which key was used. DEBUG levels can log sensitive data and should only be used temporarily.' },
    { name: 'UsePAM', compiledDefault: 'no', distroDefault: 'yes (Debian, RHEL)', recommended: 'yes', explanation: 'Uses PAM for account and session management (and password checks).', security: 'Enables account policies (expiry, pam_access, faillock) and logind sessions.' },
    { name: 'KexAlgorithms / Ciphers / MACs', compiledDefault: 'Modern OpenSSH list', recommended: 'Defaults (adjust with + / - / ^)', explanation: 'Algorithm preference lists. A value without prefix REPLACES the default list; "+x" appends, "-x" removes, "^x" moves to the front.', security: 'Do not replace lists to add one legacy algorithm. Scope legacy exceptions with Match Address.' },
    { name: 'X11Forwarding / AllowTcpForwarding / AllowAgentForwarding', compiledDefault: 'no / yes / yes', distroDefault: 'X11Forwarding yes (Debian)', recommended: 'no unless needed', explanation: 'Channel types users may open.', security: 'Forwarding turns an SSH account into a network pivot. Disable for service accounts.' },
    { name: 'ClientAliveInterval / ClientAliveCountMax', compiledDefault: '0 / 3', recommended: '300 / 2', explanation: 'Server-side keepalives through the encrypted channel; disconnects dead clients.', security: 'Cleans up abandoned sessions; also keeps NAT/firewall state from expiring.' },
    { name: 'Match', compiledDefault: '—', recommended: 'Use for exceptions', explanation: 'Conditional block (User, Group, Address, Host, LocalPort) that overrides settings for matching connections until the next Match.', security: 'Keep global settings strict and make exceptions narrow (e.g. Match Address 10.0.30.5 for a legacy appliance).' },
  ],

  troubleshootingIntro: `
### A method, not a guess
Restarting sshd, or opening the firewall "to see if that helps", often hides the real problem or creates a new one. Work methodically instead:

1. **Read the exact error message on the client.** Each layer fails with its own message (see the table below): "Could not resolve hostname" is DNS, "Connection refused" means nothing listens on port 22, "Connection timed out" means packets are dropped, "Permission denied" means the connection worked but the login was refused. Add \`-v\` to the ssh command to see how far the conversation got.
2. **Work out where it failed.** Before TCP (name resolution), during TCP (network, firewall, or no listener), during the key exchange, or during login?
3. **Collect evidence on both ends.** On the client: \`ssh -v\`, \`getent hosts\` (name), \`ip route get\` (route), \`nc -zv HOST 22\` (TCP). On the server: \`systemctl status ssh\` (is sshd running?), \`ss -tlnp\` (is it listening, and on which address?), \`journalctl -u ssh\` (sshd's log), \`nft list ruleset\` (firewall), \`tcpdump\` (what arrives).
4. **Form one hypothesis and test it** with a command whose result would be different if you were wrong. For example: "sshd only listens on 127.0.0.1" is confirmed or ruled out by one look at \`ss -tlnp\`.
5. **Fix it in the saved configuration**, then check that it works now **and** after a reboot, and that you did not weaken security on the way.

The client is deliberately vague about login failures, so that it does not help attackers guess which part was wrong. The reason (wrong password, user not allowed, bad file permissions) is only written in the **server's log**, so always read it.

:::practice
Q: A login fails with "Permission denied (publickey,password)". The client gives no detail. Where is the reason written?
A: In the **server's log** (\`journalctl -u ssh\`): for example "Failed password", "not allowed because …" or a bad-permissions message.
Q: A colleague suggests restarting sshd "to see if it helps" with a login that is refused. Why is that a poor first step?
A: The login is refused, so sshd is already running and answering. A restart can hide the cause (or, with a broken configuration, stop sshd entirely). Read the error and the server log, and test one hypothesis at a time.
:::

### Scoring engines and other programs (Go's SSH client)
Competition scoring engines (CCDC and similar), monitoring and automation tools are often written in Go and report **Go's** error text, not OpenSSH's. They usually log in with a password, try it **once**, and ignore host keys. Translate the message, then investigate exactly as above:

| Scoring engine / Go message | OpenSSH equivalent | What it tells you | First check on the server |
|---|---|---|---|
| \`dial tcp: lookup NAME on 10.0.10.53:53: no such host\` | Could not resolve hostname | DNS: the engine never connected | \`dig NAME @DNS-SERVER\` |
| Status "Unable to dial the remote host…" + \`dial tcp IP:22: connect: connection refused\` | Connection refused | The host answered with a reset: nothing listens on IP:22 (sshd stopped, disabled, masked, or listening on another address or port) | \`systemctl status ssh\`, \`ss -tlnp\`, \`sshd -T \\| grep -E 'listenaddress\\|port'\` |
| Status "Encountered an unexpected error during the check." + \`check timed out. this is most likely due to services timing out\` | Connection timed out | No answer at all, so the engine's own deadline fired before Go's dial gave up: a firewall DROP, a missing route back to the engine, or the host is down | \`nft list ruleset\`, \`ip route\`, \`tcpdump -ni any port 22\` |
| \`dial tcp IP:22: i/o timeout\` | Connection timed out | Same as the row above, from a tool whose deadline is longer than the dial timeout | \`nft list ruleset\`, \`ip route\` |
| \`ssh: handshake failed: ssh: no common algorithm for key exchange\` | Unable to negotiate … no matching key exchange method | Algorithm lists do not overlap | \`sshd -T \\| grep kexalgorithms\` |
| \`ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain\` | Permission denied (publickey,password) | The server offered password logins and **refused the password**: wrong or changed password, locked password, pam_faillock lockout, AllowUsers/AllowGroups, PermitRootLogin | \`journalctl -u ssh -n 30\`, \`faillock --user U\`, \`passwd -S U\` |
| \`… attempted methods [none], no supported methods remain\` | Permission denied (publickey) | Password logins are **not offered** for this account (PasswordAuthentication no, or a Match block) | \`sshd -T -C user=U,host=H,addr=IP \\| grep passwordauthentication\` |
| \`ssh: handshake failed: EOF\` | Connection closed by IP port 22 | The server dropped the connection: expired account (PAM account check), MaxStartups, sshd crash | \`journalctl -u ssh\`, \`chage -l U\` |
| \`Process exited with status 1\` (check command) | This account is currently not available. | Login worked; the shell or command failed (nologin shell, missing home) | \`getent passwd U\` |

The same Go message ("attempted methods [none password]") covers several unrelated causes: the server log tells them apart ("Failed password", "pam_faillock … temporarily locked", "not allowed because …"). A check that turns from **refused** to **timed out** means two things changed: the service came back but something now drops the packets (a firewall rule added in the meantime) — fix both, and make sure the service starts at boot. A check that fails, passes, then fails again usually means a lockout that expires and is re-triggered, or a password someone keeps changing back. Practise these in the **Scored services** tickets.

:::practice
Q: A scoring engine reports \`ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain\`. Did the TCP connection work?
A: **Yes.** The handshake reached authentication and the server **refused the password** (wrong or changed password, lockout, AllowUsers, …). Read \`journalctl -u ssh\` to see which.
Q: The engine's message changes from "connection refused" to "check timed out" after a teammate's change. What two things changed?
A: sshd came **back** (so no more RST), but something now **drops** the packets, typically a firewall rule added meanwhile. Fix both, and make sure sshd starts at boot.
:::

`,

  errorMap: [
    { message: 'Could not resolve hostname …: Name or service not known', layer: 'Name resolution', meaning: 'DNS answered NXDOMAIN for every search candidate (or /etc/hosts and DNS have no entry).', firstCheck: 'getent hosts NAME; dig NAME; cat /etc/resolv.conf' },
    { message: 'Could not resolve hostname …: Temporary failure in name resolution', layer: 'Name resolution', meaning: 'No usable DNS answer: server unreachable, timed out, or SERVFAIL.', firstCheck: 'dig NAME (status / timeouts); ping the DNS server; check named on the DNS server' },
    { message: 'connect to host … port 22: Network is unreachable', layer: 'Client routing', meaning: 'The client has no route to the destination; no packet was sent.', firstCheck: 'ip route; ip route get DEST' },
    { message: 'connect to host … port 22: No route to host', layer: 'Network path / firewall', meaning: 'ICMP host-unreachable or admin-prohibited came back, or ARP for the next hop failed. A firewall reject with icmp admin-prohibited looks identical.', firstCheck: 'tcpdump -n icmp on the client (who sends the ICMP?); ip neigh on the last router; dig to confirm the address' },
    { message: 'connect to host … port 22: Connection timed out', layer: 'Network path / firewall', meaning: 'Nothing came back: a DROP rule, a missing return route, or a dead host.', firstCheck: 'ping; nc -zv -w 5 HOST 22; tcpdump on the server; nft list ruleset; ip route on the server' },
    { message: 'connect to host … port 22: Connection refused', layer: 'Service', meaning: 'The host answered with RST (nothing listening on that address/port) or a reject-with-tcp-reset rule.', firstCheck: 'ss -tlnp and systemctl status ssh on the server; journalctl -u ssh' },
    { message: 'kex_exchange_identification: Connection closed by remote host', layer: 'Service', meaning: 'TCP worked but the peer closed before sending an SSH banner: not sshd on that port, MaxStartups exceeded, or TCP wrappers/IPS.', firstCheck: 'nc HOST 22 (do you see SSH-2.0-…?); ss -tlnp on the server' },
    { message: 'Unable to negotiate … no matching key exchange method found', layer: 'Transport (algorithms)', meaning: 'No common algorithm. The message lists the other side\'s offer.', firstCheck: 'sshd -T | grep kexalgorithms; ssh -Q kex' },
    { message: 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!', layer: 'Transport (host key)', meaning: 'known_hosts holds a different key for this name. Rebuilt server, wrong IP in DNS, or interception.', firstCheck: 'Compare fingerprints out-of-band (ssh-keygen -lf on the server console); dig NAME' },
    { message: 'Permission denied (publickey)', layer: 'Authentication / authorization', meaning: 'Only publickey is offered and no key was accepted: missing/wrong key, unsafe permissions (StrictModes), account not allowed, or client could not load its key.', firstCheck: 'journalctl -u ssh on the server; ssh -v ("Offering"/"Server accepts key"); ls -ld ~ ~/.ssh' },
    { message: 'Permission denied, please try again.', layer: 'Authentication', meaning: 'A password was rejected (wrong password, invalid/not-allowed user, root login refused).', firstCheck: 'journalctl -u ssh: "Failed password for [invalid user] …"' },
    { message: 'ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain (Go / scoring engine)', layer: 'Authentication / authorization', meaning: 'Go\'s client (scoring engines, monitoring) tried a password the server offered and it was refused. Same as OpenSSH "Permission denied (publickey,password)": wrong or changed password, locked password, pam_faillock lockout, AllowUsers/AllowGroups or PermitRootLogin.', firstCheck: 'journalctl -u ssh -n 30 on the server; faillock --user USER; passwd -S USER' },
    { message: 'ssh: handshake failed: EOF (Go / scoring engine)', layer: 'Account / service', meaning: 'The server closed the connection during the handshake or login: an expired account (PAM account check), MaxStartups throttling, or something that is not sshd on the port.', firstCheck: 'journalctl -u ssh; chage -l USER' },
    { message: 'Your account has expired; please contact your system administrator.', layer: 'Account (PAM)', meaning: 'Authentication succeeded but PAM\'s account phase refused the expired account; sshd logs "fatal: Access denied for user … by PAM account configuration".', firstCheck: 'chage -l USER; chage -E -1 USER to remove the expiry' },
    { message: 'This account is currently not available.', layer: 'Session', meaning: 'Authentication succeeded but the shell is /usr/sbin/nologin.', firstCheck: 'getent passwd USER' },
  ],

  scenarioIds: ['ssh-config-typo', 'ssh-port-moved', 'ssh-firewall-drop', 'ssh-client-key-perms', 'ssh-hostkey-changed', 'ssh-bob-password', 'ssh-firewall-reject', 'ssh-dns-stale', 'ssh-missing-gateway', 'ssh-perms-strictmodes', 'ssh-allowusers', 'ssh-dns-zone-error', 'ssh-kex-legacy', 'ssh-monday-reboot', 'score-password-changed', 'score-faillock', 'score-root-prohibit', 'score-account-expired', 'score-allowgroups', 'score-sshd-masked', 'score-sshd-loopback', 'score-ssh-firewall-drop', 'score-ssh-no-route-back', 'score-refused-then-timeout'],
  assessmentId: 'ssh',
  references: [
    { title: 'RFC 4251: The Secure Shell (SSH) Protocol Architecture', url: 'https://www.rfc-editor.org/rfc/rfc4251' },
    { title: 'RFC 4252: SSH Authentication Protocol', url: 'https://www.rfc-editor.org/rfc/rfc4252' },
    { title: 'RFC 4253: SSH Transport Layer Protocol', url: 'https://www.rfc-editor.org/rfc/rfc4253' },
    { title: 'RFC 4254: SSH Connection Protocol', url: 'https://www.rfc-editor.org/rfc/rfc4254' },
    { title: 'RFC 8308: Extension Negotiation in SSH', url: 'https://www.rfc-editor.org/rfc/rfc8308' },
    { title: 'RFC 8709: Ed25519 and Ed448 Public Key Algorithms for SSH', url: 'https://www.rfc-editor.org/rfc/rfc8709' },
    { title: 'RFC 793 / RFC 9293: Transmission Control Protocol', url: 'https://www.rfc-editor.org/rfc/rfc9293' },
    { title: 'OpenSSH manual pages: sshd(8), sshd_config(5), ssh(1)', url: 'https://www.openssh.com/manual.html' },
    { title: 'Debian Reference: SSH', url: 'https://www.debian.org/doc/manuals/debian-reference/ch06.en.html' },
    { title: 'Microsoft Learn: OpenSSH for Windows', url: 'https://learn.microsoft.com/windows-server/administration/openssh/openssh_overview' },
    { title: 'Red Hat: Using secure communications between two systems with OpenSSH', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/assembly_using-secure-communications-between-two-systems-with-openssh_securing-networks' },
  ],
};
