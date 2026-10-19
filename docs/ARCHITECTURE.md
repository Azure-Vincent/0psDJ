# Infrastructure Lab: design

This document covers the six design deliverables requested before implementation:
architecture and stack, curriculum dependency map, interface layout, data model,
troubleshooting-engine design, and the phased plan. Status markers show what
exists today (✅ implemented, 🟡 partial, ⏳ planned).

---

## 1. Architecture and technology stack

| Concern | Choice | Why |
|---|---|---|
| Desktop shell | **Electron** (`electron/main.cjs`) | One codebase for Windows, Linux and macOS; ships its own Chromium, so rendering of SVG diagrams and terminals is identical everywhere; fully offline (`loadFile` of the built bundle). Tauri was considered (smaller binaries) but needs a Rust toolchain per platform and WebView differences (WebKitGTK/WebView2/WKWebView) would make diagram and terminal behaviour platform-dependent. |
| UI | **React 18 + TypeScript**, plain CSS with design tokens | Mature, well-known, no UI-kit lock-in. Light/dark themes via CSS custom properties and `prefers-color-scheme`. |
| Build | **Vite** (`base: './'`) | Fast dev server; production bundle loads from `file://` inside Electron. |
| Simulation engine | **Pure TypeScript, no DOM** (`src/engine`) | Deterministic and unit-testable in Node. The same engine drives the terminal, the sequence diagram, the dependency map, the packet lab and the verification of troubleshooting fixes. |
| Tests | **Vitest** (`tests/`) | Engine, scenarios (fault → symptom → fix → verify), grading, PCAP checksums, display filters. |
| Persistence | `localStorage` (Electron stores it in the app's user-data folder) + JSON export/import | No server, no account, no paid API. |

```
┌──────────────────────────── Electron (main process: window, external links) ──────────────────────────┐
│ Renderer (React)                                                                                     │
│  pages/  Dashboard · Curriculum · Lesson (7 sections) · Troubleshooting · Commands · Packet Lab ·     │
│          Glossary · History · Settings · Search                                                       │
│  components/  Terminal · LabTerminals · SequenceDiagram · PacketLayers · DependencyMap ·              │
│               ConfigExplorer · Assessment · Topology · Editor · Markdown                              │
│  learning/  grading (assessments, command exercises) · progress (mastery, history, persistence)      │
│  content/   lessons · assessments · command reference · glossary · curriculum · concepts (data only)  │
│  engine/    deterministic infrastructure simulator (below)                                            │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘

engine/
  net/ip.ts            IPv4 + CIDR math
  config/              parsers that real admins edit: sshd_config, nftables, BIND zones, ifupdown, resolv.conf, hosts
  sim/network.ts       hop-by-hop forwarding: routing (LPM), ARP, TTL, conntrack, nft hooks, ICMP errors, captures
  sim/tcp.ts           3-way handshake, RST, SYN retransmission/backoff, data segments, FIN teardown
  sim/dns.ts           glibc-like stub resolver (hosts → resolv.conf servers, search list) + authoritative answers
  sim/services.ts      systemd-like lifecycle: start/stop/reload/enable, ExecStartPre tests, bind(), boot
  sim/ssh.ts           OpenSSH 9.2 client+server behaviour, journal lines, protocol trace
  sim/trace.ts         event recorder shared by the diagram, dependency map and packet lab
  shell/               simulated bash: tokenizer (quotes, pipes, redirection, && ||), 50+ commands
  scenarios/           cause catalogue, scenario definitions, verification, diagnosis grading
  lab/                 baseline lab, dependency map faults, packet-capture presets
  pcap.ts, filter.ts   libpcap writer with valid checksums; Wireshark display-filter subset
```

**Determinism.** No `Math.random`, no wall-clock use inside the engine: ports, ISNs,
IDs and key material come from seeded functions of world state. Interactive
prompts (host-key confirmation, passwords, sudo) are implemented by *replaying*
a command line with the collected answers on a fresh copy of the world; this is
only correct because the engine is deterministic, and it is tested.

**Honesty about simulation.** The app never claims to run Debian, Windows,
pfSense or Docker. Deployment guides target real VMs and are labelled as such;
the sandbox and scenarios are labelled as simulations, and simplifications are
stated where they matter (see §5.6).

---

## 2. Curriculum dependency map

Modules (✅ / 🟡 / ⏳ per topic are listed in-app under *Curriculum*):

```
            ┌──────────────► B Remote access (SSH ✅, RDP ⏳, WinRM ⏳, VPN ⏳ …) ─┐
A Networking┤──────────────► D Firewalls (nftables 🟡, pfSense ⏳ …) ──────────────┼─► F Enterprise infrastructure
fundamentals├──────────────► E Virtualization & containers (⏳) ─────────────────────┤      (DNS 🟡, Linux admin 🟡, others ⏳)
            └─► C Identity & authentication (PAM 🟡, AD/Kerberos/LDAP ⏳) ◄── B ──────┘
```

Concept-level prerequisites (used for remediation advice on the dashboard;
defined in `src/content/concepts.ts`):

```
net.arp → net.routing → net.icmp
                     └→ tcp.handshake → fw.stateful
                                     └→ svc.listening
                                     └→ ssh.kex → ssh.hostkeys
                                               └→ ssh.userauth → ssh.authorized-keys
                                                              └→ ssh.authz
dns.resolution → dns.zone        svc.systemd → ssh.config        linux.permissions   fw.persistence   logs.journal
```

When a concept is "struggling" (≥ 2 errors, smoothed accuracy < 50 %), the
dashboard recommends it *and* any prerequisite that is not yet proficient.

---

## 3. Interface layout

```
┌──────────────┬─────────────────────────────────────────────────────────────────┐
│ Brand        │ Page                                                            │
│ [ search ]   │                                                                 │
│ Dashboard    │ Lesson: tabs 1 What · 2 How it works (+dependency map) ·        │
│ Curriculum   │   3 Visualize (sequence diagram | inspector) · 4 Deploy         │
│ LEARN        │   (platform guides + sandbox terminals) · 5 Configuration       │
│  SSH lesson  │   (effective-config explorer, directive table) ·                │
│  Troublesh.  │   6 Troubleshooting (error→layer map, tickets) · 7 Assessment   │
│  Commands    │                                                                 │
│  Packet Lab  │ Troubleshooting workspace (3 columns):                          │
│ REFERENCE    │  ticket/briefing/topology/hints │ terminals: ws01 · srv01 ·     │
│  Glossary    │                                 │ ns1 · rtr01 consoles          │
│  History     │                                 │ │ notes · evidence log ·      │
│  Settings    │                                 │ │ diagnosis · verify · RCA    │
│ offline note │                                                                 │
└──────────────┴─────────────────────────────────────────────────────────────────┘
```

Principles: no decorative controls; every button does something; planned
features are labelled "planned" and have no buttons; the answer to a ticket is
never visible until it is solved or explicitly revealed (the topology shows
addresses and roles only, never runtime state).

---

## 4. Data model

All content is plain data (`src/content/types.ts`) so new services are added by
writing data and, where needed, engine modules: not by changing the UI.

```ts
Lesson { id, moduleId, title, level, concepts[], what, internals,            // markdown-lite text
         deployment: DeploymentGuide[] { platform, prerequisites[], steps[] { command, what, why, expected, simulated } },
         configFiles[], directives[] { name, compiledDefault, distroDefault, recommended, explanation, security },
         troubleshootingIntro, errorMap[], scenarioIds[], assessmentId, references[] }

Question = single | multi | order | text | nft-rule | sshd-config            // practical kinds graded by the engine
CommandRef { name, platform, purpose, syntax, args[], example, interpretation, limitations, simulator? }
CommandExercise = choose-command (acceptCommands, mustMatch) | spot-abnormal (output[], abnormal[])
CurriculumModule { id, title, dependsOn[], topics[] { title, level, status, link? } }

Scenario { id, title, difficulty, ticket, briefing[], goals[] { localUser, user, target, method },
           setup(world)  // injects faults by running shell commands
           rootCauses[], acceptable{cause: note}, candidates[], feedback{cause: text},
           hints[3], solution[] { host, user, commands[] }, explanation { rootCause, manifestation, evidence, prevention },
           constraints[] (security/persistence checks), concepts[] }
Cause   { id, title, category, signature (evidence it produces), check (how to test), concept }

World   { hosts{}, segments{}, clock, counter, sessions[] }
Host    { fs{path: {type, mode, owner, group, content}},  users{},            // persistent
          ifaces[], routes[], neighbors[], nft, conntrack[], services{}, ipForward,   // runtime
          journal[], capture[] }

Progress { lessons{visited[]}, concepts{id: {correct, incorrect, misconceptions[]}},
           questions{}, exercises{}, predictions{},
           attempts[] { scenarioId, status, hintsUsed, diagnoses[], verifications[], commands[], notes } ,
           settings { theme } }
```

---

## 5. Stateful troubleshooting engine

### 5.1 One model, many views
A `World` holds hosts with a virtual filesystem (persistent configuration) and
runtime state (addresses, routes, loaded firewall, running services). Every
observation is computed from this state at the moment it is requested:

| The learner runs… | …which is computed from |
|---|---|
| `ssh`, `nc`, `curl`, `ping`, `traceroute`, `dig` | packets routed hop by hop through `transmit()` (routes, ARP, nft input/forward/output, conntrack, TTL), listeners from running services, the *loaded* sshd/BIND configuration |
| `systemctl status`, `journalctl` | service runtime state and the journal entries that operations actually wrote |
| `ss`, `ip`, `nft list`, `conntrack -L`, `tcpdump` | runtime tables and per-interface capture buffers filled by the packets above |
| `cat`, `ls -l`, `stat`, `sshd -T` | the filesystem and the real parsers |

So changing a firewall rule, a route, a file mode or a service state changes the
connection result, the counters, the captures and the logs together, because
they are all consequences of the same computation.

### 5.2 Persistent vs runtime state
`bootHost()` discards runtime state and rebuilds it from files:
`/etc/network/interfaces` → addresses/routes, `/etc/sysctl.d` → forwarding,
`/etc/nftables.conf` (if nftables is enabled) → ruleset, enabled units → started
(running their config tests). This makes "fixed now, broken after reboot"
faults real.

### 5.3 Fault injection
Scenarios inject faults with the same shell commands an administrator would
type (`systemctl restart ssh`, `chmod 777 …`, `rndc reload`, `reboot`), so the
journal contains a coherent history (e.g. the failed restart with the
`sshd -t` error and line number). Faults can be layered (the "Monday" ticket has
two, and fixing one changes the symptom from *timeout* to *refused*).

### 5.4 Verification
`verifyScenario()` checks the goal (a real `ssh` run in `BatchMode`) **now**,
then on a copy where **every host is rebooted**, then evaluates **constraints**
(e.g. firewall still default-deny, `PasswordAuthentication no` still enforced,
modern KEX still offered, other users still able to log in). A fix that opens
the firewall completely or only exists at runtime does not pass.

### 5.5 Diagnosis, hints, misconceptions
The learner records hypotheses from a catalogue of plausible causes. Wrong
choices are answered with *what that cause would look like and how to test it*
(or scenario-specific feedback), never with the answer. Hints are progressive
(method → where to look → nearly the fix). The root cause, manifestation,
identifying evidence, prevention and a reference repair are shown only after
resolution or an explicit, recorded reveal. Wrong causes are recorded as
misconceptions against their concept for mastery tracking.

### 5.6 Fidelity and simplifications
Modelled faithfully: longest-prefix routing, ARP (incl. failure timing), TTL,
ICMP errors and their errno mapping (RST/port-unreachable → refused,
host-unreachable/admin-prohibited → no route, silence → timeout after
6 SYN retransmissions ≈ 127 s), stateful nftables evaluation with counters and
logging, sshd_config first-match/Include/Match semantics and `sshd -t` errors,
OpenSSH 9.2 negotiation and authentication flow and its log lines, StrictModes
path checks, glibc resolver order and search list, BIND zone parsing and SERVFAIL
on load errors, systemd enable/active semantics.

Simplified: IPv4 only; one TCP segment per SSH message, no congestion control or
window dynamics; cryptographic values are synthetic (fingerprints are genuine
SHA-256 of synthetic key blobs); `tcpdump` shows a buffer of recent traffic
instead of live capture (terminals are not concurrent); a subset of each tool's
options is implemented and unsupported options say so.

---

## 6. Phased implementation plan

| Phase | Scope | Status |
|---|---|---|
| 0 | Foundation: Electron/React/Vite app shell, navigation, themes, search, local progress, glossary, curriculum map | ✅ |
| 1 | Engine core: IPv4 forwarding, ARP, ICMP, conntrack, nftables, DNS, systemd services, journal, simulated shell | ✅ |
| 2 | **Vertical slice: SSH**: 7-section lesson, protocol visualisation, deployment guides (Debian/RHEL/Windows) + sandbox, config explorer, 14 stateful troubleshooting tickets with verification, assessment with engine-graded practical questions, command reference & practice, packet lab with PCAP export, dependency map | ✅ |
| 3a | Lesson registry (data-driven lesson pages with per-lesson widgets); **Module D nftables lesson** with hook diagram, CIDR calculator, rule-by-rule packet tester, traced-run visualizer, 5 firewall tickets with HTTP/DNS goals and unsafe-fix constraints; atomic `reload` vs flushing `restart` for nftables.service | ✅ |
| 3b | Module A lessons on the existing engine (TCP/UDP, ARP, routing, DNS, DHCP, NAT, MTU); Lab 1 as a guided multi-step lab | ⏳ |
| 4 | Infrastructure Builder (drag-and-drop topology on top of the same `World` model; packet tracing and firewall decisions already exist in the engine) | ⏳ |
| 5 | Windows/AD track: Windows host model (services, Defender Firewall, event log), DNS SRV, Kerberos AS/TGS exchange visualisation, NTLM, LDAP; RDP lesson; Lab 2 | ⏳ |
| 6 | pfSense model (WAN/LAN/DMZ, NAT, state table, logs); Lab 3 | ⏳ |
| 7 | Containers: image layers, namespaces, bridge networking, port publishing; Docker Compose; Lab 4 | ⏳ |
| 8 | Enterprise services (web/reverse proxy, SMB/NFS, NTP, logging) and Labs 5–6 (multi-system outages, recovery) | ⏳ |

### Adding a new service (checklist)
1. Engine: add a `ServiceDef` in `sim/services.ts` (start/reload/listeners/config parsing) and any protocol simulator under `sim/` that records `TraceEvent`s.
2. Shell: add the service's admin/diagnostic commands under `shell/`.
3. Content: add a `Lesson` and an `Assessment` and register them in `src/content/lessons.ts`; add command references and glossary entries. Optional interactive widgets are wired in `widgetsFor()` in `src/ui/pages/LessonPage.tsx`.
4. Scenarios: add `Scenario` objects (goals: SSH login, HTTP request or name lookup) with `setup`, `solution` and constraints, and register the set in `src/engine/scenarios/index.ts`; the generic scenario test proves each one breaks and is fixable.
5. Curriculum: flip the topic status to `available` with a link.
