# Infrastructure Lab

Infrastructure Lab is a free, offline desktop application for learning how to run,
troubleshoot and recover the services that real networks depend on: IP routing,
DNS, DHCP, NAT, VLANs, IPv6, MTU, TLS certificates, SSH, firewalls, Linux
services, Windows/RDP, Active Directory, Docker and pfSense.

## Purpose

Most courses explain what a service is; few teach what to do when it breaks.
Infrastructure Lab is for students and new administrators: teams preparing for
defensive competitions such as CCDC, Network+ and CCNA candidates, and junior
sysadmins. It trains the skill that matters in an outage: **finding the cause
from evidence** instead of guessing, fixing it safely, and proving that the fix
holds.

For every technology it answers the same questions:

- What is it, how does it work, and what does it depend on?
- Where do its configuration and logs live?
- How do you check, start, stop, reload and restart it?
- Why does it typically fail, and which commands tell the causes apart?
- How do you confirm that it is healthy again?

## What's inside

- **19 lessons** on networking, interfaces and virtual switches, TLS, remote
  access, identity (including Kerberos), firewalls, containers, Linux and Windows administration,
  and safe recovery. Each lesson starts in plain language (the short version,
  an everyday analogy, the key ideas each with a concrete example from the lab,
  one case followed step by step, common misconceptions and a quick
  self-check), then explains in depth how the technology works, with
  interactive diagrams, and includes deployment guides (Ubuntu/Debian, RHEL,
  Windows, pfSense, Docker), configuration reference, an **Operate & recover**
  guide (files, logs, service management, diagnostic workflow, common
  failures) and a graded assessment.
- **Three guided labs**: build a freshly installed Debian server into a
  hardened intranet web server (Lab 1), create an Active Directory domain and
  join a member server (Lab 2), and turn a fresh pfSense into the perimeter
  firewall with a DMZ and a published web server (Lab 3). The simulator checks
  each step against the running machines, and the last step reboots everything.
- **An Infrastructure Builder**: draw your own network (workstations, servers,
  routers, VLAN-aware switches), set addresses, gateways, VLANs, firewall
  rules and NAT, then build it. Every device becomes a simulated Debian
  machine configured from the files the design generates. You get terminals
  on each machine and a packet tracer that shows every hop and every firewall
  and NAT decision.
- **75 troubleshooting tickets**, each injecting a realistic fault into the
  lab. You investigate with real commands in terminals, record a diagnosis and
  repair the fault. The app then checks your fix immediately, again after
  rebooting every machine, and against security rules, so "just open the
  firewall" does not count.
- **7 end-to-end case studies**: SSH refused, a server with no Internet, a failed
  domain login, an unreachable Docker app, pfSense blocking traffic, RDP broken
  by a policy change, and several services failing at once.
- **Reference library** of commands, configuration files, logs and recovery
  procedures for Linux, Windows, Docker, pfSense and Cisco IOS.
- **Packet Lab** with Wireshark-style captures (exportable as PCAP), a
  certification objective map for Network+ and CCNA, a glossary, and progress
  tracking.

Everything is stored locally, and the app works without an Internet connection.
The sidebar can be hidden (the « button, or Ctrl+\\) to give lessons, labs and
terminals the full width; the choice is remembered.

### How the lab works

The lab machines are not virtual machines. They are a **simulation** built
into the app: a small network with a switch, a router, a DNS/DHCP server
that is also the Kerberos KDC, a Linux server, a Windows server, an Active
Directory domain controller, a pfSense perimeter firewall with a DMZ web
server, workstations and an "Internet" host. Commands such as `ip`,
`ss`, `systemctl`, `journalctl`, `nft`, `ssh`, `dig`, `curl`, `openssl`,
`kinit` and `tcpdump` behave like their Debian 12 counterparts and all act on one
consistent model: when you change a configuration file, the services, sockets,
firewall decisions, packets and logs all follow from that change. The Windows
server (win01, Windows Server 2022) has a Windows PowerShell 5.1 console:
cmdlets such as `Get-Service`, `Get-NetFirewallRule`, `Test-NetConnection` and
`Get-WinEvent` and programs such as `ipconfig`, `netsh` and `sc.exe` work on the
same model, and the Linux machines connect to it with `xfreerdp`. The domain
controller dc01 runs Active Directory and DNS for ad.corp.lab: members find it
through DNS SRV records, join the domain, and pass domain logons to it over
their secure channel. The firewall fw01 is a simulated pfSense 2.7.2: its
config.xml is compiled into a pf ruleset (interface rules, aliases, port
forwards, outbound NAT, states and the firewall log), and you manage it from
its webConfigurator in a browser on ws01 or with `pfctl` and `easyrule` on its
console. Docker is not simulated; it is taught from documentation and
representative output.

## Installation

The app runs on **Linux, Windows and macOS**. You need:

- **Node.js 20 or newer**: download the LTS version from <https://nodejs.org>.
  On Ubuntu/Debian `sudo apt install nodejs npm` works if your release ships
  version 20+ (Ubuntu 24.04 does).
- **The source code**: `git clone https://github.com/Azure-Vincent/0psDJ.git`,
  or **Code → Download ZIP** on the GitHub page, then extract it.
- **Internet access for the first start only**, to download the dependencies
  (including the Electron runtime; about 600 MB on disk). After that, the app
  works offline.

### Linux

Open a terminal in the project folder and run:

```bash
./launch.sh
```

The first run installs the dependencies and builds the app (one to two
minutes); later runs start immediately. To add **Infrastructure Lab** to your
application menu, run `./launch.sh --add-to-menu` once
(`./launch.sh --remove-from-menu` removes it). If you get "Permission denied",
run `sh launch.sh` instead.

On Ubuntu/Debian you can also build a regular installable package. It installs
into the application menu and needs no Node.js afterwards:

```bash
npm install && npm run dist:linux
sudo apt install ./release/InfrastructureLab-*-linux-amd64.deb
```

Start it from the menu or with `infrastructure-lab`; remove it with
`sudo apt remove infrastructure-lab`. The same command also produces an
AppImage and a `.tar.gz` in `release/` for other distributions.

> **Ubuntu 23.10 and later:** these releases restrict the user namespaces that
> Chromium's sandbox uses. The launcher detects this and starts the app with
> `--no-sandbox` (it prints a notice); the `.deb` instead installs the sandbox
> helper so the sandbox stays on. The app only loads its own offline pages.

### Windows

1. Install Node.js 20+ from <https://nodejs.org> (the LTS installer; keep the default options).
2. Download and extract the source code.
3. Double-click **`launch.cmd`** in the project folder.

The first start installs the dependencies and builds the app; later starts
are quick. Keep the console window open while you use the app. After updating
the source code, run `launch.cmd --rebuild`.

To create a standalone `.exe` you can copy to other Windows PCs without Node.js,
open a terminal in the project folder and run `npm install` then
`npm run dist:win`. This produces `release\InfrastructureLab-<version>-win-x64.exe`
(a portable app) and a `.zip`. They are unsigned, so SmartScreen warns on first
start: choose **More info → Run anyway**.

### macOS

Open Terminal in the project folder and run:

```bash
./launch.sh
```

To create an app bundle instead, run `npm install` then `npm run dist:mac`.
This produces a `.dmg` in `release/`; drag the app to Applications. It is
unsigned, so open it the first time with **right-click → Open**.

### Updating

Download the new source (or `git pull`) and start the app again with
`./launch.sh` (Linux/macOS) or `launch.cmd --rebuild` (Windows). Your progress
is stored separately and is kept; it can also be exported and imported under
**Settings**.

## Using the app

Start with **Curriculum** for the learning path, or open a lesson from the
sidebar. Each lesson has tabs from "What is it?" to "Assessment".
**Guided labs** walks you through building something step by step, with a
**Check step** button, hints and a reference solution for every step.
**Infrastructure Builder** lets you design a network on a canvas: add devices,
press **Connect** and click two devices to cable them, then click a device to
set its addresses and rules. The checks below the canvas list mistakes such as
duplicate addresses or an unreachable gateway. **Build & run** starts the
network. Designs are saved in the browser and can be exported as JSON.
**Troubleshooting lab** lists the tickets. Each ticket opens a workspace with
terminals on the affected machines, a notes area, hints that get more specific
each time you ask, and a **Verify** button. Lesson sandboxes reset with one
click, so experiment freely.

## For developers

```bash
npm install          # dependencies
npm run dev          # development server at http://localhost:5173 (browser)
npm run desktop      # build and open the desktop app
npm test             # test suite (Vitest)
npm run typecheck    # TypeScript checks
```

| Path | Contents |
|---|---|
| `src/engine/` | the simulator: network, services, shell commands, troubleshooting scenarios, guided labs, PCAP |
| `src/content/` | lessons, guides, case studies, reference library, certification map, glossary (plain data) |
| `src/ui/` | the React interface |
| `src/learning/` | grading and progress tracking |
| `electron/`, `build/`, `scripts/` | desktop shell, packaging configuration and Linux launch helpers |
| `tests/` | tests, including a content-integrity suite that checks every cross-link |
| `docs/ARCHITECTURE.md` | design documents and how to add a new service |

## Accuracy

Simulated behaviour follows the relevant RFCs and the behaviour of Debian 12
components (OpenSSH 9.2, BIND 9.18, ISC DHCP 4.4, radvd, ifupdown2, nftables,
systemd 252, nginx 1.22, OpenSSL 3.0, curl 7.88). Where the simulation
simplifies, the app says so next to the feature. Examples: cryptographic values
are synthetic (certificates are readable PEM data without real signatures),
spanning tree and DHCPv6 relays are not simulated, and `tcpdump` shows recent traffic
rather than a live capture.

The Windows server follows Windows Server 2022 and Windows PowerShell 5.1
(output formats, error records, event IDs). The domain has one DC; domain
logons use NTLM pass-through, and Kerberos for Windows logons, Group Policy
objects and replication are not modelled. PowerShell covers the cmdlets and
parameters the lessons, tickets and labs use. The pfSense firewall covers
interfaces, aliases, filter rules, port forwards, outbound NAT, states and the
firewall log; its DHCP and DNS services, VLANs, VPNs, gateway monitoring,
floating rules and packages are not simulated, and the webConfigurator shows
only the pages these features need.
Other output for Windows, Active Directory, Docker, pfSense and Cisco IOS is
representative of the versions named on each page; check the exact wording
against your own systems when it matters. The certification map is a study
aid, not a guarantee of exam readiness: check objectives against the vendors'
current documents.
