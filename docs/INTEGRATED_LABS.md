# Integrated labs

The integrated labs combine several subjects in one realistic situation. They
extend the guided-lab framework (`src/engine/labs/`) rather than replacing it:
an integrated lab is a `GuidedLab` with an `integrated` section
(`IntegratedInfo` in `src/engine/labs/types.ts`), shown by the same page
(`src/ui/pages/GuidedLab.tsx`) and stored in the same progress record.

## The ten labs

| # | Lab | Builds on | Incident (stage 5) |
|---|---|---|---|
| 1 | Build a Functional Small Office Network | IP, DHCP relay, DNS, nftables, NAT (new steps on VLAN 30) | DHCP hands out a wrong router option |
| 2 | Deploy and Secure a Linux Web Server | DNS, nginx, permissions, nftables, SSH keys (new server web03) | An HTTPS listener without a certificate stops nginx |
| 3 | Deploy an Active Directory Environment | Lab 2's steps + an OU and a GPO delivered to win01 | A member's clock drifts (W32Time), Kerberos logons fail |
| 4 | Troubleshoot Cross-Platform Connectivity | Four independent tickets: routing, Windows firewall, PostgreSQL, Samba | A stale /etc/hosts entry |
| 5 | Deploy a Containerized Business Application | Lab 4's steps + publication through the reverse proxy and a data volume | A renamed Compose service breaks the app's database name |
| 6 | Configure Network Segmentation With pfSense | Lab 3's steps framed as a flow matrix | A block rule above the DNS pass rule |
| 7 | Investigate an Enterprise DNS Failure | A firewall with a CIDR mistake on ns1, then the KDC it also hid | The zone loses its Kerberos SRV records |
| 8 | Restore a Multi-Service Outage | Three changes: router forwarding, an unresolvable upstream, a reset listen address | A firewall review drops the established rule |
| 9 | Secure and Maintain an Enterprise Environment | Accounts, sshd drop-ins, rsyslog selectors, a restore test | Hardening on fs01 cuts the monitoring scrape |
| 10 | Complete Infrastructure Deployment | Lab 5's steps + key-only SSH and monitoring for app01 | Two at once: NTP blocked on rtr01 and a wrong proxy_pass port |

Each lab names the scenario, technologies, systems, starting configuration,
tools (with reference-library links), the lessons it builds on, common
mistakes and how completion is verified (`IntegratedInfo`).

## The six stages

1. **Environment**: the story, the systems and the starting configuration;
   the terminals are already running, so the learner can inspect before changing.
2. **Dependencies**: an explanation of how the technologies depend on each
   other and one or more **request paths**. "Probe the path" runs each hop's
   real command on a copy of the lab (`probePath`, `src/engine/labs/integrated.ts`)
   and stops at the first hop that fails; the learner sees the evidence
   (command and output) but not the cause.
3. **Configure**: steps with checks against the running machines, hints, a
   reference solution and, in guided mode, explanations of the important
   commands (what, why, where the configuration lives, what success looks
   like, how to verify).
4. **Verify**: end-to-end checks from the users' side; the final step reboots
   every machine on a copy of the lab and re-runs every check.
5. **Troubleshoot**: once everything is verified, "Start the incident"
   changes the learner's own lab the way the story says (`LabFault.inject`).
   The learner submits a diagnosis (causes from the troubleshooting catalog)
   and verifies the repair (checks now and after a reboot). Several incidents
   reuse existing tickets (`ticketFault`), including the constraints that
   reject the tempting wrong fixes.
6. **Review**: questions about how the systems worked together (choices in a
   fixed per-question order), then feedback: subjects shown or to review, with
   links to lessons, and remarks on the troubleshooting process.

## Learning modes

| Mode | Shown | Not shown |
|---|---|---|
| Guided | Objective, background, tasks, explained commands, hints, reference solution | |
| Assisted | Objective, background, lesson links, hints on request; the detailed tasks on request (counted as a hint); the reference solution after a confirmation | Tasks and command explanations by default |
| Independent | The scenario, step objectives and the checks | Background, tasks, hints, reference solutions (the incident's repair only after it is repaired) |

A lab finished in one mode can be started again in another; the modes
completed are kept (`LabProgress.modesCompleted`).

## What is tracked

`LabProgress` (`src/learning/progress.ts`), saved in local storage with the
rest of the progress: completed and assisted steps, the mode, hints used,
commands typed, the diagnostic tools used, restarts and reboots (and those
typed during the incident before the diagnosis), the incident's diagnosis
attempts and repair, review answers, and the learner's notes.
`classifyCommand` (`integrated.ts`) separates evidence gathering, restarts and
changes; `labFeedback` (`src/learning/labFeedback.ts`) turns the record into
the feedback of stage 6. Completion is based only on checks of the simulated
machines, so any technically correct solution passes.

## Workflow

- The machines live for the browser session; switching stages, opening the
  reference solution or "Do it for me" keeps the terminals and their history.
- After an application restart, "Continue" rebuilds the lab and replays the
  completed steps' reference solutions, then re-injects (and, if it was
  repaired, repairs) the incident (`rebuildLab`). The learner's own commands
  are not replayed: the state is equivalent, not identical.
- Resetting a lab asks for confirmation; notes and completed modes are kept.

## Limitations (and the alternatives used)

- **Everything is simulated.** No command reaches a real machine. Cisco IOS
  commands appear in the tool lists for comparison only; the routers in the
  lab are Linux (rtr01) and pfSense (fw01).
- **Debian ifupdown** is the network configuration method on the Linux hosts.
  NetworkManager, Netplan and systemd-networkd are described in the reference
  library (and their differences in the lessons), not simulated as alternatives
  inside these labs.
- **Lab 6 (segmentation)** separates Internet, DMZ and the internal networks on
  pfSense. A separate guest or management VLAN on pfSense is not modelled; VLAN
  segmentation on the Linux router is practised in Lab 1.
- **Lab 3** uses Windows Server members; a Windows 10/11 workstation is not
  modelled. Group Policy is shown with a firewall rule delivered to an OU.
- **Diagnosis** is a choice of root causes from the catalog, not free text;
  feedback on the process is based on the commands typed, not on their intent.
- **Saved state after a restart** is rebuilt from reference solutions (see
  Workflow).
