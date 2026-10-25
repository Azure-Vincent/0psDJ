// Reference library: Windows, Active Directory, Docker, pfSense and Cisco IOS commands.
// None of these run in the simulator; example output is representative output of the
// platform/version named in `compat`.

import type { CommandRef } from '../types';

const raw = String.raw;

export const PLATFORM_COMMAND_REFS: CommandRef[] = [
  // --- Windows networking ---------------------------------------------------------
  {
    id: 'get-netadapter', name: 'Get-NetAdapter', platform: 'Windows', category: 'Interfaces',
    purpose: 'Lists network adapters with their link status, MAC address and link speed: the Windows equivalent of `ip -br link`.',
    syntax: 'Get-NetAdapter [-Name name] [-Physical] [-IncludeHidden] | Format-List *',
    args: [
      { arg: '-Name "Ethernet0"', meaning: 'One adapter by its alias (wildcards allowed: "Ether*")' },
      { arg: '-Physical', meaning: 'Hide virtual adapters (Hyper-V vEthernet, VPN, loopback)' },
      { arg: '-IncludeHidden', meaning: 'Also show hidden adapters (e.g. WAN miniports)' },
      { arg: '| Format-List *', meaning: 'All properties: DriverVersion, MediaConnectionState, FullDuplex, VlanID ...' },
    ],
    example: {
      command: 'Get-NetAdapter',
      output: raw`Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
----                      --------------------                    ------- ------       ----------             ---------
Ethernet1                 vmxnet3 Ethernet Adapter #2                   9 Disconnected 00-50-56-A1-4D-5E          0 bps
Ethernet0                 vmxnet3 Ethernet Adapter                      6 Up           00-50-56-A1-2B-3C        10 Gbps`,
    },
    interpretation: 'Read **Status** first: `Up` means link is present (layer 1/2 fine); `Disconnected` means no carrier (cable, switch port, virtual NIC not connected in the hypervisor); `Disabled` means someone disabled it in Windows; `Not Present` means the device is gone (driver or hardware). The **ifIndex** is what Get-NetRoute and Get-NetIPConfiguration refer to. A LinkSpeed of 10 Mbps or 100 Mbps on a gigabit port points at a cabling or negotiation fault, a common cause of slow transfers.',
    limitations: 'Says nothing about IP configuration (use Get-NetIPConfiguration) or whether traffic actually flows (Test-NetConnection). An adapter can be `Up` on the wrong VLAN.',
    errors: [
      { message: "Get-NetAdapter : No MSFT_NetAdapter objects found with property 'Name' equal to 'Ethernet 2'. Verify the value of the property and retry.", meaning: 'Wrong alias. Adapter names are not stable across hardware: list them without `-Name` first (note "Ethernet 2" with a space is a different name from "Ethernet2").' },
    ],
    permissions: 'Any user can read. Changing adapters (Disable-/Enable-/Rename-NetAdapter) needs an elevated session.',
    risks: 'Read-only.',
    compat: 'Windows 8/Server 2012 and later (NetAdapter module); Windows Server 2019/2022, Windows 10/11; PowerShell 5.1 (also works in PowerShell 7 on Windows).',
    services: ['Windows networking', 'Networking'],
    protocols: [],
    symptoms: ['No IP address', 'No Internet access', 'Slow or intermittent connectivity'],
  },
  {
    id: 'get-netipconfiguration', name: 'Get-NetIPConfiguration', platform: 'Windows', category: 'Addressing',
    purpose: 'Summarises, per interface, the IP addresses, default gateway, DNS servers and network profile: the first command to run on a Windows host with a connectivity problem.',
    syntax: 'Get-NetIPConfiguration [-InterfaceAlias alias] [-All] [-Detailed]',
    args: [
      { arg: '-InterfaceAlias "Ethernet0"', meaning: 'Only this interface' },
      { arg: '-All', meaning: 'Include disconnected and hidden interfaces' },
      { arg: '-Detailed', meaning: 'Adds MAC address, adapter status, network category, MTU and whether DHCP is enabled' },
    ],
    example: {
      command: 'Get-NetIPConfiguration -InterfaceAlias Ethernet0',
      output: raw`InterfaceAlias       : Ethernet0
InterfaceIndex       : 6
InterfaceDescription : vmxnet3 Ethernet Adapter
NetProfile.Name      : corp.lab
IPv4Address          : 10.0.20.30
IPv4DefaultGateway   : 10.0.20.1
DNSServer            : 10.0.20.5
                       10.0.20.6`,
    },
    interpretation: 'Check, in order: is there an address, is it in the expected subnet, is there exactly one default gateway, and do the DNS servers point at your internal DNS (for a domain member: the domain controllers, never a public resolver). **NetProfile.Name** shows the network the host identified: the domain name means Network Location Awareness found a DC (Domain profile); `Unidentified network` means it could not, and the Public firewall profile is probably applied, which can block RDP, SMB and WinRM.',
    limitations: 'Does not show the prefix length; use `Get-NetIPAddress -InterfaceAlias Ethernet0 -AddressFamily IPv4` (PrefixLength, PrefixOrigin Dhcp/Manual) or `ipconfig /all`. It shows configuration, not reachability.',
    errors: [
      { message: 'IPv4Address          : 169.254.x.x', meaning: 'APIPA (link-local) address: the adapter is set to DHCP and no DHCP server answered. Check link, VLAN, DHCP scope and relay.' },
      { message: 'NetProfile.Name      : Unidentified network', meaning: 'No gateway or no DC detected: the Public firewall profile may be active. Check gateway and DNS, then `Get-NetConnectionProfile`.' },
      { message: 'IPv4DefaultGateway   :   (empty)', meaning: 'No default route: the local subnet works but nothing beyond it.' },
    ],
    permissions: 'Any user.',
    risks: 'Read-only.',
    compat: 'Windows 8/Server 2012 and later; Windows Server 2019/2022, Windows 10/11; PowerShell 5.1.',
    services: ['Windows networking', 'Networking', 'DNS', 'DHCP'],
    protocols: ['DHCP', 'DNS'],
    symptoms: ['No IP address', 'No Internet access', 'Name resolution fails', 'No route to host'],
  },
  {
    id: 'get-netroute', name: 'Get-NetRoute', platform: 'Windows', category: 'Routing',
    purpose: 'Shows the Windows routing table (IPv4 and IPv6) with metrics and whether a route is active or persistent.',
    syntax: 'Get-NetRoute [-AddressFamily IPv4|IPv6] [-DestinationPrefix prefix] [-InterfaceIndex n] [-PolicyStore ActiveStore|PersistentStore]',
    args: [
      { arg: '-AddressFamily IPv4', meaning: 'Only IPv4 routes' },
      { arg: '-DestinationPrefix 0.0.0.0/0', meaning: 'Only default routes' },
      { arg: '-PolicyStore PersistentStore', meaning: 'Routes that survive a reboot (ActiveStore = what is in use now)' },
      { arg: 'Find-NetRoute -RemoteIPAddress 10.0.10.25', meaning: 'Related cmdlet: which source address and route Windows would pick for a destination' },
    ],
    example: {
      command: 'Get-NetRoute -AddressFamily IPv4 -InterfaceIndex 6',
      output: raw`ifIndex DestinationPrefix NextHop    RouteMetric ifMetric PolicyStore
------- ----------------- -------    ----------- -------- -----------
6       255.255.255.255/32 0.0.0.0           256 15       ActiveStore
6       224.0.0.0/4       0.0.0.0            256 15       ActiveStore
6       10.0.20.255/32    0.0.0.0            256 15       ActiveStore
6       10.0.20.30/32     0.0.0.0            256 15       ActiveStore
6       10.0.20.0/24      0.0.0.0            256 15       ActiveStore
6       0.0.0.0/0         10.0.20.1            0 15       ActiveStore`,
    },
    interpretation: 'NextHop `0.0.0.0` means on-link (directly connected). The effective metric is RouteMetric + ifMetric; with two default routes (two NICs, or a VPN), the lowest sum wins, which explains "Internet works but the LAN does not" (or the reverse) on multi-homed hosts. A route in ActiveStore but not PersistentStore will disappear at reboot.',
    limitations: 'Shows the table, not whether the next hop answers. `route print` gives the same data in classic format. Routes pushed by VPN clients can change while you look.',
    errors: [
      { message: "Get-NetRoute : No matching MSFT_NetRoute objects found by CIM query for instances of the ROOT/StandardCimv2/MSFT_NetRoute class on the  CIM server", meaning: 'No route matches the filter: with `-DestinationPrefix 0.0.0.0/0` this means there is no default gateway.' },
      { message: 'New-NetRoute : Instance MSFT_NetRoute already exists', meaning: 'A route with that prefix and next hop exists already (possibly only in one store). Inspect it, then use Set-NetRoute or Remove-NetRoute.' },
    ],
    permissions: 'Any user can read; New-/Set-/Remove-NetRoute need elevation.',
    risks: 'Read-only. Removing or changing the default route on a remote server disconnects your session if you are not on the same subnet.',
    compat: 'Windows 8/Server 2012 and later; Windows Server 2019/2022, Windows 10/11; PowerShell 5.1.',
    services: ['Windows networking', 'Routing', 'Networking'],
    protocols: ['TCP', 'UDP', 'ICMP'],
    symptoms: ['No route to host', 'No Internet access', 'Connection timed out'],
  },
  {
    id: 'resolve-dnsname', name: 'Resolve-DnsName', platform: 'Windows', category: 'DNS',
    purpose: 'Queries DNS from PowerShell, through the same resolver path the system uses (hosts file, DNS cache, configured servers) or directly against a chosen server.',
    syntax: 'Resolve-DnsName name [-Type A|AAAA|SRV|MX|PTR|...] [-Server ip] [-DnsOnly] [-NoHostsFile] [-CacheOnly]',
    args: [
      { arg: '-Type SRV', meaning: 'Record type; SRV is how clients locate domain controllers (_ldap._tcp.dc._msdcs.<domain>)' },
      { arg: '-Server 10.0.20.5', meaning: 'Ask this DNS server directly, bypassing the client configuration' },
      { arg: '-DnsOnly', meaning: 'DNS only, no LLMNR/NetBIOS fallback' },
      { arg: '-NoHostsFile', meaning: 'Ignore C:\\Windows\\System32\\drivers\\etc\\hosts' },
      { arg: '-CacheOnly', meaning: 'Answer only from the local DNS client cache' },
    ],
    example: {
      command: 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab',
      output: raw`Name                                     Type   TTL   Section    NameTarget                     Priority Weight Port
----                                     ----   ---   -------    ----------                     -------- ------ ----
_ldap._tcp.dc._msdcs.corp.lab            SRV    600   Answer     dc01.corp.lab                  0        100    389

Name       : dc01.corp.lab
QueryType  : A
TTL        : 3600
Section    : Additional
IP4Address : 10.0.20.5`,
    },
    interpretation: 'If the SRV query fails, domain join, logon and Group Policy fail too, because clients cannot find a DC. Compare the normal query with `-Server <dc>`: if the DC answers but the default path does not, the client is using the wrong DNS server. Unlike nslookup, Resolve-DnsName honours the hosts file and cache, so a difference between the two tools points at hosts or a stale cache (`Clear-DnsClientCache`).',
    limitations: 'Windows only. Results may come from the cache; use `-DnsOnly -Server` for an authoritative test. Does not show the DNS suffix search list (Get-DnsClientGlobalSetting).',
    errors: [
      { message: 'Resolve-DnsName : srv99.corp.lab : DNS name does not exist', meaning: 'NXDOMAIN: the server answered authoritatively that the name does not exist (typo, missing record, wrong zone).' },
      { message: 'Resolve-DnsName : srv01.corp.lab : This operation returned because the timeout period expired', meaning: 'No DNS server answered: server down, UDP/TCP 53 blocked, or the configured DNS IP is wrong.' },
      { message: 'Resolve-DnsName : corp.lab : No records found for given DNS query', meaning: 'The name exists but has no record of the requested type.' },
    ],
    permissions: 'Any user.',
    risks: 'Read-only.',
    compat: 'Windows 8/Server 2012 and later; Windows Server 2019/2022, Windows 10/11; PowerShell 5.1.',
    services: ['DNS', 'Active Directory', 'Windows networking'],
    protocols: ['DNS', 'UDP', 'TCP'],
    symptoms: ['Name resolution fails', 'Login fails', 'Trust relationship failed'],
  },
  {
    id: 'restart-netadapter', name: 'Restart-NetAdapter', platform: 'Windows', category: 'Interfaces',
    purpose: 'Disables and re-enables a network adapter, which re-runs DHCP, re-detects the network profile and resets the driver state.',
    syntax: 'Restart-NetAdapter -Name alias [-Confirm:$false]',
    args: [
      { arg: '-Name "Ethernet0"', meaning: 'Adapter alias (from Get-NetAdapter)' },
      { arg: '-Confirm:$false', meaning: 'Do not prompt' },
      { arg: 'Disable-NetAdapter / Enable-NetAdapter', meaning: 'The two halves separately (dangerous remotely: nothing re-enables it for you)' },
    ],
    example: {
      command: 'Restart-NetAdapter -Name Ethernet0; Start-Sleep 10; Get-NetAdapter Ethernet0',
      output: raw`Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
----                      --------------------                    ------- ------       ----------             ---------
Ethernet0                 vmxnet3 Ethernet Adapter                      6 Up           00-50-56-A1-2B-3C        10 Gbps`,
    },
    interpretation: 'Restart-NetAdapter itself prints nothing on success. Check the adapter returns to `Up`, then re-run Get-NetIPConfiguration to confirm the address and profile came back.',
    limitations: 'A workaround, not a fix: if the adapter needed a restart, find out why (driver, DHCP, profile detection). It does not reset the TCP/IP stack (that is `netsh int ip reset`).',
    errors: [
      { message: "Restart-NetAdapter : No MSFT_NetAdapter objects found with property 'Name' equal to 'Ethernet 9'. Verify the value of the property and retry.", meaning: 'Wrong adapter alias.' },
      { message: 'Restart-NetAdapter : Access denied', meaning: 'Not elevated: run PowerShell as Administrator.' },
    ],
    permissions: 'Administrator (elevated session).',
    risks: '**Drops every connection over that adapter, including the RDP or WinRM session you are typing in.** It normally comes back in seconds, but if the address does not return (DHCP failure, static config problem) you lose the server. Run it from the hypervisor/iLO console, or over a different NIC.',
    compat: 'Windows 8/Server 2012 and later; Windows Server 2019/2022, Windows 10/11; PowerShell 5.1.',
    services: ['Windows networking', 'Networking', 'DHCP'],
    protocols: ['DHCP'],
    symptoms: ['No IP address', 'No Internet access', 'Remote session disconnects'],
  },
  // --- Windows services ---------------------------------------------------------
  {
    id: 'restart-service', name: 'Restart-Service', platform: 'Windows', category: 'Services',
    purpose: 'Stops and starts a Windows service. With `-Force` it also stops services that depend on it.',
    syntax: 'Restart-Service [-Name] name [-Force] [-PassThru]',
    args: [
      { arg: '-Name W32Time', meaning: 'Service name (not display name; `-DisplayName` exists for that)' },
      { arg: '-Force', meaning: 'Required when other running services depend on this one; it stops them too' },
      { arg: '-PassThru', meaning: 'Output the service object afterwards (shows the new Status)' },
      { arg: 'Get-Service name -DependentServices', meaning: 'Check first what -Force would also stop' },
    ],
    example: {
      command: 'Restart-Service W32Time -PassThru',
      output: raw`WARNING: Waiting for service 'Windows Time (W32Time)' to stop...

Status   Name               DisplayName
------   ----               -----------
Running  W32Time            Windows Time`,
    },
    interpretation: 'The WARNING lines are progress messages, not errors. Verify with Get-Service and the System log (7036 "entered the running state"). Dependent services stopped by `-Force` are **not always started again**; check them explicitly (`Get-Service TermService -DependentServices`).',
    limitations: 'Cannot restart a service whose StartType is Disabled. Gives no reason when a start fails; read the System log (Service Control Manager 7000/7009/7023/7031) or the application log.',
    errors: [
      { message: "Restart-Service : Cannot stop service 'Remote Desktop Services (TermService)' because it has dependent services. It can only be stopped if the Force flag is set.", meaning: 'Other services depend on it (UmRdpService here). Decide whether stopping them is acceptable, then use `-Force`.' },
      { message: "Restart-Service : Failed to start service 'Netlogon (Netlogon)'.", meaning: 'The stop worked but the start failed: the service is now down. Read the System log immediately.' },
      { message: "Service 'Windows Time (W32Time)' cannot be stopped due to the following error: Cannot open W32Time service on computer '.'.", meaning: 'Not elevated: run as Administrator.' },
    ],
    permissions: 'Administrator (elevated).',
    risks: 'Restarting TermService disconnects every RDP session including yours; restarting Netlogon/NTDS/DNS/KDC on a domain controller affects every client of that DC; restarting a service with -Force can stop services you did not intend to. Know the dependency tree before you run it.',
    compat: 'Windows Server 2019/2022, Windows 10/11; PowerShell 5.1 (and 7.x on Windows).',
    services: ['Windows networking', 'RDP', 'Active Directory', 'Time sync'],
    protocols: [],
    symptoms: ['Service fails to start', 'Remote session disconnects'],
  },
  {
    id: 'sc', name: 'sc.exe', platform: 'Windows', category: 'Services',
    purpose: 'Low-level Service Control Manager client: shows service state, PID, configuration (binary path, account, dependencies, start type) and failure actions, and can change them.',
    syntax: 'sc.exe query|queryex|qc|qfailure|config|start|stop name [option= value]',
    args: [
      { arg: 'queryex name', meaning: 'State plus PID (to find the svchost process)' },
      { arg: 'qc name', meaning: 'Configuration: START_TYPE, BINARY_PATH_NAME, DEPENDENCIES, SERVICE_START_NAME' },
      { arg: 'qfailure name', meaning: 'Recovery actions (restart / run program / reboot) after a crash' },
      { arg: 'config name start= auto', meaning: 'Change start type (auto | delayed-auto | demand | disabled). The space after "=" is mandatory' },
      { arg: '\\\\server', meaning: 'First argument: target a remote computer (sc.exe \\\\srv02 query TermService)' },
    ],
    example: {
      command: 'sc.exe qc TermService',
      output: raw`[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: TermService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k NetworkService
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Remote Desktop Services
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : NT Authority\NetworkService`,
    },
    interpretation: 'DEPENDENCIES lists what must run first: if one of them is disabled or failing, this service cannot start (error 1068). SERVICE_START_NAME is the account: a service running as a domain user breaks when that password changes (error 1069). `queryex` adds the PID; `tasklist /svc /fi "PID eq 1184"` shows whether other services share that svchost process (killing it kills them all).',
    limitations: '**In PowerShell, `sc` is an alias for Set-Content**: always type `sc.exe`. Output is text, not objects. Changes made with `config` persist immediately in the registry.',
    errors: [
      { message: '[SC] OpenService FAILED 1060: The specified service does not exist as an installed service.', meaning: 'Wrong service name (use the short name, e.g. TermService, not "Remote Desktop Services").' },
      { message: '[SC] StartService FAILED 1058: The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.', meaning: 'START_TYPE is DISABLED. Find out who disabled it (GPO? hardening script?) before re-enabling.' },
      { message: '[SC] StartService FAILED 1053: The service did not respond to the start or control request in a timely fashion.', meaning: 'The service process started but hung or crashed during initialisation; read the application/System logs.' },
      { message: '[SC] ControlService FAILED 1051: A stop control has been sent to a service that other running services are dependent on.', meaning: 'Stop the dependants first (or use Restart-Service -Force knowingly).' },
      { message: '[SC] OpenService FAILED 5: Access is denied.', meaning: 'Not elevated, or no rights on the remote computer.' },
    ],
    permissions: 'Query: any user for most services. config/start/stop: Administrator.',
    risks: '`sc.exe config ... start= disabled` on a remote server for TermService, Netlogon or a network service can make the machine unreachable after the next reboot. `sc.exe delete` removes the service registration permanently.',
    compat: 'All supported Windows versions; Windows Server 2019/2022, Windows 10/11.',
    services: ['RDP', 'Active Directory', 'Windows networking', 'WinRM'],
    protocols: [],
    symptoms: ['Service fails to start'],
  },
  {
    id: 'qwinsta', name: 'qwinsta (query session)', platform: 'Windows', category: 'Remote access',
    purpose: 'Lists Remote Desktop sessions and listeners on a host: who is connected, which sessions are disconnected, and whether the RDP listener exists.',
    syntax: 'qwinsta [/server:name] | quser [/server:name] | rwinsta id [/server:name]',
    args: [
      { arg: '/server:srv02', meaning: 'Query a remote host (uses RPC/SMB; needs rights there)' },
      { arg: 'quser', meaning: 'User-oriented view with idle time and logon time' },
      { arg: 'rwinsta <id>  /  logoff <id>', meaning: 'Reset (log off) a session, e.g. a stale disconnected one' },
    ],
    example: {
      command: 'qwinsta /server:srv02',
      output: raw` SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
 console           Administrator             1  Active
 rdp-tcp#3         alice                     2  Active
                   bob                       3  Disc
 rdp-tcp                                 65536  Listen`,
    },
    interpretation: 'The `rdp-tcp ... Listen` line is the RDP listener: if it is missing, TermService is not listening (RDP disabled, listener broken, or certificate problem) and clients get a connection failure even though the server is up. `Disc` sessions still hold their programs and count towards the two administrative sessions allowed without RDS licensing; a full set produces "The number of connections to this computer is limited..." on the client.',
    limitations: 'Shows sessions, not firewall or network state. Querying remotely needs RPC (TCP 445/135) open and admin rights on the target.',
    errors: [
      { message: 'Error 5 getting sessionnames', meaning: 'Access denied on the remote host (not an administrator there, or UAC remote restrictions for local accounts).' },
      { message: 'Error 1722 getting sessionnames', meaning: 'RPC server unavailable: host down, name resolves to the wrong IP, or firewall blocks RPC/SMB.' },
      { message: 'The number of connections to this computer is limited and all connections are in use right now.', meaning: 'Client-side message: both administrative sessions are taken. Log off a disconnected session with `rwinsta`/`logoff`, or use `mstsc /admin` only if the console session is free.' },
    ],
    permissions: 'Local: any user sees sessions; resetting others needs Administrator. Remote: Administrator on the target.',
    risks: '`rwinsta`/`logoff` ends the session and its programs without saving: confirm with the user first.',
    compat: 'Windows Server 2019/2022, Windows 10/11 (Pro/Enterprise; Home has no RDP server).',
    services: ['RDP'],
    protocols: ['RDP', 'SMB'],
    symptoms: ['Remote session disconnects', 'Login fails', 'Connection refused'],
  },
  {
    id: 'get-netfirewallrule', name: 'Get-NetFirewallRule', platform: 'Windows', category: 'Firewall',
    purpose: 'Lists Windows Defender Firewall rules, their state, profile and action; piped into the filter cmdlets it shows ports and addresses.',
    syntax: 'Get-NetFirewallRule [-DisplayName name] [-DisplayGroup group] [-Enabled True] [-Direction Inbound] [-PolicyStore ActiveStore] | Get-NetFirewallPortFilter',
    args: [
      { arg: '-DisplayGroup "Remote Desktop"', meaning: 'Built-in rule group (localized on non-English systems: use -Group "@FirewallAPI.dll,-28752" instead)' },
      { arg: '-PolicyStore ActiveStore', meaning: 'The effective rules, including those pushed by Group Policy' },
      { arg: '| Get-NetFirewallPortFilter', meaning: 'Protocol and local/remote ports of each rule' },
      { arg: '| Get-NetFirewallAddressFilter', meaning: 'Remote address scope (e.g. LocalSubnet only)' },
      { arg: 'Get-NetFirewallProfile', meaning: 'Related: which profiles are enabled and their default inbound action' },
    ],
    example: {
      command: 'Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table DisplayName, Enabled, Profile, Direction, Action',
      output: raw`DisplayName                           Enabled Profile Direction Action
-----------                           ------- ------- --------- ------
Remote Desktop - User Mode (TCP-In)      True     Any   Inbound  Allow
Remote Desktop - User Mode (UDP-In)      True     Any   Inbound  Allow
Remote Desktop - Shadow (TCP-In)        False     Any   Inbound  Allow`,
    },
    interpretation: 'A rule only applies if it is Enabled **and** its Profile matches the active profile (`Get-NetConnectionProfile`). A server that suddenly classifies its network as Public (no DC found at boot) stops matching Domain-only rules. Check the address filter too: rules created by the GUI often allow only "LocalSubnet". Block rules win over allow rules.',
    limitations: 'Does not log anything: to see what was dropped, enable the firewall log (pfirewall.log). Third-party firewalls/EDR products are not shown. Filtering by port requires the pipeline through Get-NetFirewallPortFilter, which is slow on large rule sets.',
    errors: [
      { message: "Get-NetFirewallRule : No MSFT_NetFirewallRule objects found with property 'DisplayName' equal to 'RDP'. Verify the value of the property and retry.", meaning: 'No rule with that exact display name; search with wildcards (`-DisplayName "*Remote Desktop*"`).' },
    ],
    permissions: 'Reading: any user. Enable-/Set-/New-NetFirewallRule: Administrator. Rules from GPO cannot be changed locally.',
    risks: 'Read-only. Changing or disabling rules remotely can cut your own session; Group Policy may overwrite local changes at the next refresh.',
    compat: 'Windows 8/Server 2012 and later; Windows Server 2019/2022, Windows 10/11; PowerShell 5.1.',
    services: ['Firewall', 'RDP', 'WinRM', 'Windows networking'],
    protocols: ['TCP', 'UDP', 'RDP', 'SMB'],
    symptoms: ['Traffic blocked by firewall', 'Connection timed out', 'Port not reachable'],
  },
  {
    id: 'reg-query', name: 'reg query', platform: 'Windows', category: 'Configuration',
    purpose: 'Reads registry keys and values from the command line, locally or on a remote computer. Many service settings (RDP, time, services) live in the registry.',
    syntax: 'reg query KEY [/v value | /ve] [/s] [/f data]',
    args: [
      { arg: '/v fDenyTSConnections', meaning: 'One named value' },
      { arg: '/s', meaning: 'Recurse into subkeys' },
      { arg: '/f text', meaning: 'Search for text in names and data' },
      { arg: '\\\\srv02\\HKLM\\...', meaning: 'Remote registry (needs the RemoteRegistry service and admin rights)' },
      { arg: 'Get-ItemProperty HKLM:\\...', meaning: 'PowerShell equivalent' },
    ],
    example: {
      command: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections',
      output: raw`
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server
    fDenyTSConnections    REG_DWORD    0x0
`,
    },
    interpretation: 'DWORD values are shown in hex: `0x0` here means RDP connections are allowed; `0x1` means denied. Remember that Group Policy values under `HKLM\\SOFTWARE\\Policies` override the "local" value, so query both locations before concluding.',
    limitations: 'Shows the stored value, not whether the service has picked it up (many services read their settings only at start). Remote queries fail when RemoteRegistry is stopped (default on client Windows).',
    errors: [
      { message: 'ERROR: The system was unable to find the specified registry key or value.', meaning: 'Key or value does not exist (typo, or the setting is at its default because nobody created it).' },
      { message: 'ERROR: Access is denied.', meaning: 'Not elevated, or the key ACL denies you (e.g. parts of HKLM\\SECURITY).' },
      { message: 'ERROR: The network path was not found.', meaning: 'Remote host unreachable or RemoteRegistry/SMB blocked.' },
    ],
    permissions: 'Most of HKLM readable by users; writes (`reg add`, `reg delete`) need Administrator.',
    risks: 'Read-only. `reg add`/`reg delete` take effect without any validation or undo: export the key first (`reg export KEY backup.reg`).',
    compat: 'All supported Windows versions; Windows Server 2019/2022, Windows 10/11.',
    services: ['RDP', 'Time sync', 'Windows networking'],
    protocols: [],
    symptoms: ['Connection refused', 'Service fails to start'],
  },
  // --- Active Directory ----------------------------------------------------------
  {
    id: 'nltest', name: 'nltest', platform: 'Windows', category: 'Identity',
    purpose: 'Tests the Netlogon side of domain membership: which DC the machine finds (DC locator), and whether its secure channel (machine account trust) to the domain works.',
    syntax: 'nltest /dsgetdc:DOMAIN [/force] [/pdc] [/kdc] | /sc_query:DOMAIN | /sc_verify:DOMAIN | /sc_reset:DOMAIN[\\DC] | /dclist:DOMAIN | /dbflag:0x2080ffff',
    args: [
      { arg: '/dsgetdc:corp.lab', meaning: 'Run the DC locator (DNS SRV lookup + LDAP ping) and show the DC chosen; /force skips the cache' },
      { arg: '/sc_query:corp.lab', meaning: 'Show the current secure channel and its status' },
      { arg: '/sc_verify:corp.lab', meaning: 'Actively verify the machine account password with a DC (Server 2008 R2/Windows 7 and later)' },
      { arg: '/sc_reset:corp.lab\\dc01', meaning: 'Re-establish the secure channel (optionally to a specific DC)' },
      { arg: '/dbflag:0x2080ffff', meaning: 'Enable verbose %SystemRoot%\\debug\\netlogon.log (0x0 to disable)' },
    ],
    example: {
      command: 'nltest /dsgetdc:corp.lab',
      output: raw`           DC: \\dc01.corp.lab
      Address: \\10.0.20.5
     Dom Guid: 6f1c2a9e-3b7d-4c11-9a0e-2d5b8e7f4a10
     Dom Name: corp.lab
  Forest Name: corp.lab
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10
The command completed successfully`,
    },
    interpretation: '/dsgetdc success proves DNS SRV records and LDAP to a DC work. The Flags say which roles that DC has (PDC = PDC emulator, KDC, TIMESERV, GC). `CLOSE_SITE` missing means the client is not in the DC\'s site (subnet not mapped to a site: slow logons). For trust problems, `/sc_verify` should end with `Trust Verification Status = 0 0x0 NERR_Success`; any other status means the machine account password no longer matches.',
    limitations: 'Tests Netlogon/secure channel only, not Kerberos tickets for users (klist) or Group Policy (gpresult). /sc_reset needs a working DC reachable and does not fix a password mismatch on its own (use Test-ComputerSecureChannel -Repair).',
    errors: [
      { message: 'Getting DC name failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN', meaning: 'The DC locator found no DC: almost always DNS (client points at a public resolver, or SRV records missing). Test with `Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab`.' },
      { message: 'Trusted DC Connection Status Status = 1311 0x51f ERROR_NO_LOGON_SERVERS', meaning: 'No secure channel: no DC reachable (network, firewall, DNS) at the time of the attempt.' },
      { message: 'Trust Verification Status = 5 0x5 ERROR_ACCESS_DENIED', meaning: 'The DC rejected the machine password: broken trust (VM snapshot revert, account reset, duplicate computer name). Repair the secure channel.' },
      { message: 'I_NetLogonControl failed: Status = 5 0x5 ERROR_ACCESS_DENIED', meaning: 'You ran /sc_verify or /sc_reset without elevation.' },
    ],
    permissions: '/dsgetdc and /sc_query: any user. /sc_verify, /sc_reset, /dbflag: Administrator.',
    risks: '/sc_reset briefly drops the secure channel: pass-through authentication on that machine may fail for a moment. Leaving /dbflag on fills the debug log (it rotates to netlogon.bak).',
    compat: 'Windows Server 2019/2022, Windows 10/11 (built in; on clients /sc_verify is available since Windows 7).',
    services: ['Active Directory', 'Kerberos', 'DNS'],
    protocols: ['DNS', 'LDAP', 'Kerberos', 'SMB'],
    symptoms: ['Trust relationship failed', 'Login fails', 'Name resolution fails'],
  },
  {
    id: 'setspn', name: 'setspn', platform: 'Windows', category: 'Identity',
    purpose: 'Reads and manages Service Principal Names on AD accounts. Kerberos uses the SPN to find which account (and key) a service ticket must be encrypted for.',
    syntax: 'setspn -L account | -Q spn | -X [-F] | -S spn account | -D spn account',
    args: [
      { arg: '-L CORP\\svc-web', meaning: 'List SPNs registered on an account' },
      { arg: '-Q HTTP/web01.corp.lab', meaning: 'Find which account holds an SPN (wildcards allowed: */web01*)' },
      { arg: '-X', meaning: 'Search for duplicate SPNs (add -F for the whole forest)' },
      { arg: '-S spn account', meaning: 'Add an SPN after checking for duplicates (use instead of -A, which does not check)' },
      { arg: '-D spn account', meaning: 'Delete an SPN from an account' },
    ],
    example: {
      command: 'setspn -X',
      output: raw`Checking domain DC=corp,DC=lab
Processing entry 0
HTTP/web01.corp.lab is registered on these accounts:
        CN=WEB01,CN=Computers,DC=corp,DC=lab
        CN=svc-web,OU=Service Accounts,DC=corp,DC=lab

found 1 group of duplicate SPNs.`,
    },
    interpretation: 'A duplicate SPN means the KDC cannot know which account\'s key to use; clients may get tickets the service cannot decrypt (System log on the client: Security-Kerberos event 4, `KRB_AP_ERR_MODIFIED`) and authentication falls back to NTLM or fails. The SPN must sit on the account the service actually runs as: the computer account for services running as SYSTEM/NetworkService, the service account otherwise.',
    limitations: 'Only shows registrations; it cannot tell which name a client requests. Check that with `klist` on the client after accessing the service. Changes need AD replication to reach every DC.',
    errors: [
      { message: 'No such SPN found.', meaning: '-Q found nothing: Kerberos to that name will fail (KDC_ERR_S_PRINCIPAL_UNKNOWN) and clients fall back to NTLM.' },
      { message: 'Duplicate SPN found, aborting operation!', meaning: '-S refused because another account holds the SPN; remove it there first (-D).' },
      { message: "Failed to assign SPN on account 'CN=svc-web,OU=Service Accounts,DC=corp,DC=lab', error 0x2098/8344 -> Insufficient access rights to perform the operation.", meaning: 'You lack write rights to servicePrincipalName on that object (Domain Admins or delegated rights required).' },
    ],
    permissions: 'Reading: any domain user. Writing: Domain Admins or delegated "Write servicePrincipalName".',
    risks: 'Removing or moving an SPN immediately affects every client authenticating to that service (after their cached tickets expire, or immediately after `klist purge`).',
    compat: 'Windows Server 2019/2022, Windows 10/11 with RSAT (setspn ships with the AD DS tools).',
    services: ['Active Directory', 'Kerberos', 'Web server'],
    protocols: ['Kerberos', 'LDAP'],
    symptoms: ['Login fails'],
  },
  {
    id: 'gpupdate', name: 'gpupdate', platform: 'Windows', category: 'Identity',
    purpose: 'Triggers a Group Policy refresh now instead of waiting for the background interval (90 minutes plus a random offset of up to 30 minutes on members).',
    syntax: 'gpupdate [/target:computer|user] [/force] [/wait:seconds] [/logoff] [/boot]',
    args: [
      { arg: '/force', meaning: 'Reapply all settings, not just changed GPOs' },
      { arg: '/target:computer', meaning: 'Only computer policy' },
      { arg: '/boot  /logoff', meaning: 'Reboot or log off automatically if a setting needs it (e.g. software installation, folder redirection)' },
      { arg: 'Invoke-GPUpdate -Computer ws01', meaning: 'Remote refresh from a management host (GroupPolicy module; needs remote scheduled task/firewall rules)' },
    ],
    example: {
      command: 'gpupdate /force',
      output: raw`Updating policy...

Computer policy could not be updated successfully. The following errors were encountered:

The processing of Group Policy failed. Windows attempted to read the file \\corp.lab\SysVol\corp.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini from a domain controller and was not successful. Group Policy settings may not be applied until this event is resolved. This issue may be transient and could be caused by one or more of the following:
a) Name Resolution/Network Connectivity to the current domain controller.
b) File Replication Service Latency (a file created on another domain controller has not replicated to the current domain controller).
c) The Distributed File System (DFS) client has been disabled.
User Policy update has completed successfully.`,
    },
    interpretation: 'Success prints "Computer Policy update has completed successfully." for each scope. The gpt.ini error (System event 1058) means the client found the GPO in AD (LDAP) but could not read it from SYSVOL (SMB): DNS for the domain name, DC reachability on 445, or SYSVOL replication. The GUID {31B2F340-...} is always the Default Domain Policy.',
    limitations: 'Refreshes, it does not diagnose: use `gpresult /h` for what applied and the GroupPolicy Operational log for why. Some settings only apply at boot or logon.',
    errors: [
      { message: 'The processing of Group Policy failed because of lack of network connectivity to a domain controller.', meaning: 'Event 1129: no DC reachable when policy ran (network, DNS, or the NIC came up late at boot).' },
      { message: 'Certain Computer policies are enabled that can only run during startup. OK to restart? (Y/N)', meaning: 'A pending setting needs a reboot. Answering Y reboots immediately: answer N on production servers and schedule it.' },
      { message: 'Certain User policies are enabled that can only run during logon. OK to log off? (Y/N)', meaning: 'Same for user settings; logging off ends your session.' },
    ],
    permissions: 'Any user can refresh their own user policy; computer policy refresh requires elevation to be meaningful (it runs as SYSTEM in the Group Policy service).',
    risks: '/boot and /logoff reboot or log off without further confirmation. A /force refresh reapplies everything, including security settings and firewall rules from GPO.',
    compat: 'Windows Server 2019/2022, Windows 10/11 (domain members).',
    services: ['Group Policy', 'Active Directory'],
    protocols: ['LDAP', 'SMB', 'Kerberos', 'DNS'],
    symptoms: ['Login fails', 'Name resolution fails'],
  },
  {
    id: 'w32tm', name: 'w32tm', platform: 'Windows', category: 'Time',
    purpose: 'Shows and configures the Windows Time service. Kerberos rejects tickets when client and DC clocks differ by more than 5 minutes (default policy), so time is an authentication dependency.',
    syntax: 'w32tm /query /status|/source|/configuration|/peers | /resync [/rediscover] | /stripchart /computer:host [/samples:n] [/dataonly] | /config ... /update',
    args: [
      { arg: '/query /status', meaning: 'Stratum, last successful sync, current source' },
      { arg: '/query /source', meaning: 'Just the source; "Local CMOS Clock" means not syncing from anywhere' },
      { arg: '/stripchart /computer:dc01 /samples:5 /dataonly', meaning: 'Measure the offset to another host (works without changing anything)' },
      { arg: '/resync [/rediscover]', meaning: 'Sync now (rediscover the source first)' },
      { arg: '/config /syncfromflags:domhier /update', meaning: 'Members and non-PDC DCs: follow the domain hierarchy' },
      { arg: '/config /manualpeerlist:"0.pool.ntp.org,0x8" /syncfromflags:manual /reliable:yes /update', meaning: 'PDC emulator of the forest root: sync from external NTP' },
    ],
    example: {
      command: 'w32tm /query /status',
      output: raw`Leap Indicator: 0(no warning)
Stratum: 3 (secondary reference - syncd by (S)NTP)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0312500s
Root Dispersion: 7.8128312s
ReferenceId: 0x0A001405 (source IP:  10.0.20.5)
Last Successful Sync Time: 10/21/2026 9:14:02 AM
Source: dc01.corp.lab
Poll Interval: 10 (1024s)`,
    },
    interpretation: 'Healthy: Source is a DC (or external NTP for the PDC emulator) and Last Successful Sync Time is recent. Broken: `Source: Local CMOS Clock` with `Leap Indicator: 3(not synchronized)` (free-running), or `VM IC Time Synchronization Provider` on a virtual DC (the hypervisor overrides domain time). Use /stripchart against a DC to measure the actual offset.',
    limitations: 'Shows the time service view, not whether Kerberos has already failed (check Security event 4771 on DCs, or KRB_AP_ERR_SKEW errors). /resync refuses corrections larger than MaxPos/NegPhaseCorrection.',
    errors: [
      { message: 'The following error occurred: The service has not been started. (0x80070426)', meaning: 'W32Time is stopped (it is trigger-start on non-domain machines). `Start-Service W32Time`.' },
      { message: 'The computer did not resync because no time data was available.', meaning: 'No reachable time source: UDP 123 blocked, or the configured peer does not answer. Check /query /peers.' },
      { message: '09:20:11, error: 0x800705B4', meaning: '/stripchart timed out: the target is not answering NTP on UDP 123.' },
      { message: 'KRB_AP_ERR_SKEW', meaning: 'Kerberos clock skew too great (seen in Kerberos event logs and klist/application errors): fix time first, then `klist purge`.' },
    ],
    permissions: '/query and /stripchart: any user (some queries need elevation). /config and /resync: Administrator.',
    risks: 'Configuring a member or non-PDC DC with a manual peer list breaks the domain hierarchy. A large forward/backward time jump can expire tickets and certificates and confuse applications.',
    compat: 'Windows Server 2016/2019/2022, Windows 10/11 (high-accuracy time and /stripchart /dataonly available on all).',
    services: ['Time sync', 'Kerberos', 'Active Directory'],
    protocols: ['NTP', 'UDP', 'Kerberos'],
    symptoms: ['Clock skew', 'Login fails'],
  },
  {
    id: 'test-wsman', name: 'Test-WSMan', platform: 'Windows', category: 'Remote access',
    purpose: 'Checks that the WinRM (WS-Management) listener on a remote computer answers: the prerequisite for PowerShell remoting (Enter-PSSession, Invoke-Command) and many admin tools.',
    syntax: 'Test-WSMan [-ComputerName host] [-Port 5985|5986] [-UseSSL] [-Authentication Default -Credential cred]',
    args: [
      { arg: '-ComputerName srv02', meaning: 'Target (use the FQDN for Kerberos)' },
      { arg: '-UseSSL', meaning: 'Test the HTTPS listener on 5986' },
      { arg: '-Authentication Default', meaning: 'Authenticate; without it the test is anonymous and does not prove your credentials work' },
    ],
    example: {
      command: 'Test-WSMan -ComputerName srv02.corp.lab',
      output: raw`wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0`,
    },
    interpretation: 'Any answer proves name resolution, TCP 5985 and the WinRM listener. `OS: 0.0.0` is normal for an anonymous test; with `-Authentication Default` you see the real OS version (e.g. `OS: 10.0.20348` for Server 2022). If this works and Enter-PSSession fails, the problem is authentication or authorization (Remote Management Users group, TrustedHosts for non-domain targets).',
    limitations: 'Tests the listener, not session configuration or JEA endpoints. Server 2012+ enables WinRM by default; Windows 10/11 clients do not (Enable-PSRemoting).',
    errors: [
      { message: 'Test-WSMan : WinRM cannot complete the operation. Verify that the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception for the WinRM service is enabled and allows access from this computer. By default, the WinRM firewall exception for public profiles limits access to remote computers within the same local subnet.', meaning: 'TCP 5985 not reachable: host down, WinRM not enabled, or firewall (note the Public-profile rule only allows the local subnet).' },
      { message: 'The WinRM client cannot process the request. Default authentication may be used with an IP address under the following conditions: the transport is HTTPS or the destination is in the TrustedHosts list, and explicit credentials are provided.', meaning: 'You used an IP address or a non-domain host: Kerberos needs a name. Use the FQDN, or HTTPS, or add the host to TrustedHosts (understanding the security trade-off).' },
    ],
    permissions: 'Anonymous test: any user. Remoting itself: Administrators or Remote Management Users on the target.',
    risks: 'Read-only.',
    compat: 'Windows Server 2019/2022, Windows 10/11; PowerShell 5.1 (WinRM 3.0).',
    services: ['WinRM'],
    protocols: ['HTTP', 'TLS', 'Kerberos', 'TCP'],
    symptoms: ['Connection refused', 'Connection timed out', 'Port not reachable', 'Login fails'],
  },
  // --- Docker -------------------------------------------------------------------
  {
    id: 'docker-compose', name: 'docker compose', platform: 'Docker', category: 'Containers', simulator: 'docker',
    purpose: 'Manages a multi-container application defined in compose.yaml: create/recreate containers, networks and volumes, show their state and logs.',
    syntax: 'docker compose [-f file] [-p project] up -d | down | ps | logs [-f] [svc] | config | restart svc | pull',
    args: [
      { arg: 'up -d', meaning: 'Create or recreate containers whose configuration changed, in the background' },
      { arg: 'up -d --force-recreate svc', meaning: 'Recreate even if nothing changed' },
      { arg: 'ps [-a]', meaning: 'Containers of this project, their status and published ports' },
      { arg: 'config [--quiet]', meaning: 'Validate and print the final model after variable interpolation' },
      { arg: 'down [-v]', meaning: 'Remove containers and networks; **-v also deletes named volumes (data)**' },
      { arg: 'restart svc', meaning: 'Restart existing containers; does NOT apply changes to compose.yaml' },
    ],
    example: {
      command: 'docker compose ps',
      output: raw`NAME        IMAGE         COMMAND                  SERVICE   CREATED         STATUS                         PORTS
web-app-1   nginx:1.27    "/docker-entrypoint.…"   app       2 minutes ago   Up 2 minutes                   0.0.0.0:8080->80/tcp, [::]:8080->80/tcp
web-db-1    postgres:16   "docker-entrypoint.s…"   db        2 minutes ago   Restarting (1) 5 seconds ago`,
    },
    interpretation: '`Restarting (1)` means the main process exits with code 1 and the restart policy keeps starting it: read `docker compose logs db`. A service with no PORTS entry is reachable only from other containers on the same network. `0.0.0.0:8080->80/tcp` means host port 8080 forwards to container port 80 on all host addresses; `127.0.0.1:8080->80/tcp` would be local-only.',
    limitations: 'Operates on one project (directory or -p name). `restart` does not pick up compose.yaml or .env changes; `up -d` does. `ps` hides stopped containers unless -a.',
    errors: [
      { message: 'Error response from daemon: driver failed programming external connectivity on endpoint web-app-1 (3c1f...): Bind for 0.0.0.0:8080 failed: port is already allocated', meaning: 'Another container (or a host process) already publishes that host port. Find it with `docker ps --filter publish=8080` or `ss -tlnp`.' },
      { message: 'dependency failed to start: container web-db-1 is unhealthy', meaning: 'depends_on with condition: service_healthy, and the dependency\'s healthcheck failed. Inspect the dependency first.' },
      { message: 'no configuration file provided: not found', meaning: 'No compose.yaml/docker-compose.yml in the current directory: cd to the project or pass -f.' },
      { message: 'WARN[0000] /srv/web/compose.yaml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion', meaning: 'Harmless warning in Compose v2: delete the `version:` line.' },
      { message: "docker: 'compose' is not a docker command.", meaning: 'The Compose v2 plugin is not installed (package docker-compose-plugin); the old standalone `docker-compose` v1 is end-of-life.' },
    ],
    permissions: 'root, or membership of the `docker` group (which is root-equivalent).',
    risks: '`down -v` destroys named volumes. `up -d` after editing recreates containers: a short outage, and anything written inside the container (not in a volume) is lost.',
    compat: 'Docker Engine 27, Compose v2 (2.2x+). The legacy `docker-compose` (v1, Python) uses underscores in names (web_app_1).',
    services: ['Docker'],
    protocols: ['TCP', 'HTTP'],
    symptoms: ['Container exits immediately', 'Port not reachable', 'Service fails to start'],
  },
  {
    id: 'docker-inspect', name: 'docker inspect', platform: 'Docker', category: 'Containers', simulator: 'docker',
    purpose: 'Prints the full low-level configuration and state of a container (or image, volume, network) as JSON; with --format you extract exactly the field you need.',
    syntax: "docker inspect [--format '{{template}}'] name|id",
    args: [
      { arg: "--format '{{json .NetworkSettings.Ports}}'", meaning: 'Published port mappings' },
      { arg: "--format '{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}'", meaning: 'Why a container stopped (exit code, killed by the OOM killer)' },
      { arg: "--format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'", meaning: 'Container IP address on each network' },
      { arg: "--format '{{json .Mounts}}'", meaning: 'Volumes and bind mounts (where the data lives)' },
      { arg: "--format '{{.HostConfig.RestartPolicy.Name}}'", meaning: 'Restart policy (no, always, unless-stopped, on-failure)' },
    ],
    example: {
      command: "docker inspect --format '{{json .NetworkSettings.Ports}}' web-app-1",
      output: '{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"}]}',
    },
    interpretation: 'Each container port maps to a list of host bindings. `"80/tcp":null` means the port is exposed (EXPOSE in the image) but **not published**: unreachable from outside the host. `{}` means nothing is exposed at all. HostIp `127.0.0.1` means only the host itself can connect. Exit code 137 = killed by SIGKILL (often OOM: check OOMKilled), 143 = SIGTERM, 1 = application error, 127 = command not found in the image.',
    limitations: 'Shows configuration, not whether the application inside actually listens on that port (check with `docker exec` or logs). The JSON includes environment variables, so secrets can leak if you paste it into a ticket.',
    errors: [
      { message: 'Error: No such object: web', meaning: 'No container/image/volume with that name: use the full container name from `docker ps -a` (Compose names are project-service-N).' },
      { message: 'template parsing error: template: :1: function "jsn" not defined', meaning: 'Typo in the Go template.' },
    ],
    permissions: 'root or `docker` group.',
    risks: 'Read-only, but output may contain passwords from environment variables.',
    compat: 'Docker Engine 27 (the format templates are stable across 20.10-27).',
    services: ['Docker', 'Networking'],
    protocols: ['TCP', 'UDP'],
    symptoms: ['Port not reachable', 'Container exits immediately', 'Connection refused'],
  },
  {
    id: 'docker-logs', name: 'docker logs', platform: 'Docker', category: 'Logs', simulator: 'docker',
    purpose: 'Shows what a container\'s main process wrote to stdout/stderr: the first place to look when a container exits immediately or keeps restarting.',
    syntax: 'docker logs [-f] [--tail N] [--since 10m] [-t] container   |   docker compose logs [-f] [svc]',
    args: [
      { arg: '--tail 50', meaning: 'Only the last 50 lines' },
      { arg: '-f', meaning: 'Follow new output' },
      { arg: '--since 10m / --until', meaning: 'Time window (relative or RFC 3339)' },
      { arg: '-t', meaning: 'Prefix each line with its timestamp' },
    ],
    example: {
      command: 'docker logs --tail 20 -t web-db-1',
      output: raw`2026-10-21T09:12:03.418225717Z Error: Database is uninitialized and superuser password is not specified.
2026-10-21T09:12:03.418253125Z        You must specify POSTGRES_PASSWORD to a non-empty value for the
2026-10-21T09:12:03.418258432Z        superuser. For example, "-e POSTGRES_PASSWORD=password" on "docker run".`,
    },
    interpretation: 'Read the last lines before the exit: here the image\'s entrypoint refuses to start because a required environment variable is missing, so the fix is in compose.yaml/.env followed by `docker compose up -d` (a restart would not apply it). Logs survive container restarts but are deleted when the container is removed.',
    limitations: 'Only stdout/stderr of the main process: applications that log to files inside the container show nothing here. Works with the json-file and local drivers, and for other drivers only while Docker\'s dual logging cache is enabled.',
    errors: [
      { message: 'Error response from daemon: No such container: web', meaning: 'Wrong name; list with `docker ps -a`.' },
      { message: 'Error response from daemon: configured logging driver does not support reading', meaning: 'The container logs to syslog/journald/gelf etc. and dual logging is disabled: read logs at that destination (e.g. `journalctl CONTAINER_NAME=web`).' },
    ],
    permissions: 'root or `docker` group.',
    risks: 'Read-only. Logs may contain secrets or personal data.',
    compat: 'Docker Engine 27 (dual logging since 20.10); Compose v2 for `docker compose logs`.',
    services: ['Docker'],
    protocols: [],
    symptoms: ['Container exits immediately', 'Service fails to start'],
  },
  {
    id: 'docker-network', name: 'docker network', platform: 'Docker', category: 'Networking', simulator: 'docker',
    purpose: 'Lists, inspects, creates and connects Docker networks. Containers on the same user-defined network can reach each other by name through Docker\'s embedded DNS (127.0.0.11).',
    syntax: 'docker network ls | inspect NET | create [--subnet CIDR] NET | connect NET CONTAINER | disconnect NET CONTAINER | rm NET',
    args: [
      { arg: 'ls', meaning: 'All networks with driver (bridge, host, null, overlay, macvlan)' },
      { arg: 'inspect web_default', meaning: 'Subnet, gateway and attached containers with their IPs' },
      { arg: 'create --subnet 172.30.0.0/24 appnet', meaning: 'User-defined bridge with a chosen subnet' },
      { arg: 'connect appnet web-app-1', meaning: 'Attach a running container to another network' },
    ],
    example: {
      command: "docker network inspect web_default --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{\"\\n\"}}{{end}}'",
      output: raw`web-app-1 172.18.0.3/16
web-db-1 172.18.0.2/16`,
    },
    interpretation: 'Compose creates `<project>_default` and attaches every service, so `app` reaches the database as `db:5432`. Containers on different networks cannot talk to each other. On the legacy default `bridge` network there is no name resolution between containers. If a Docker subnet overlaps a real LAN (e.g. 172.18.0.0/16 used by an office), the host routes that LAN into the bridge and those users lose access: set `default-address-pools` in daemon.json.',
    limitations: 'Shows Docker\'s view; the actual forwarding and NAT are iptables/nftables rules on the host (`iptables -t nat -L DOCKER -n`), which a host firewall reload can remove.',
    errors: [
      { message: 'Error response from daemon: Pool overlaps with other one on this address space', meaning: 'The requested subnet overlaps an existing Docker network (or a Compose network that was not cleaned up).' },
      { message: 'Error response from daemon: network web_default not found', meaning: 'Wrong name: Compose prefixes the project name.' },
      { message: 'Error response from daemon: error while removing network: network web_default id 7e6d5c4b3a29 has active endpoints', meaning: 'Containers are still attached; stop/disconnect them (or `docker compose down`).' },
    ],
    permissions: 'root or `docker` group.',
    risks: 'Disconnecting a container cuts its traffic on that network immediately. `docker network prune` removes all unused networks.',
    compat: 'Docker Engine 27, Compose v2.',
    services: ['Docker', 'Networking', 'DNS', 'NAT'],
    protocols: ['TCP', 'UDP', 'DNS'],
    symptoms: ['Name resolution fails', 'Port not reachable', 'Connection refused', 'No route to host'],
  },
  // --- pfSense ------------------------------------------------------------------
  {
    id: 'pfctl', name: 'pfctl', platform: 'pfSense', category: 'Firewall',
    purpose: 'Controls the pf packet filter underneath pfSense: show the loaded ruleset, states, NAT and counters; enable/disable filtering in an emergency.',
    syntax: 'pfctl -s rules|nat|states|info|Tables [-v[v]] | -d | -e | -nf FILE | -f FILE | -t TABLE -T show | -k HOST',
    args: [
      { arg: '-sr  (-vvsr)', meaning: 'Loaded filter rules (with rule numbers and counters)' },
      { arg: '-sn', meaning: 'NAT and port-forward (rdr) rules' },
      { arg: '-ss', meaning: 'State table (current connections)' },
      { arg: '-si', meaning: 'Status: enabled/disabled, state and counter statistics' },
      { arg: '-d  /  -e', meaning: 'Disable / enable pf entirely (emergency only)' },
      { arg: '-nf /tmp/rules.debug', meaning: 'Parse a ruleset without loading it' },
      { arg: '-k 10.0.10.25', meaning: 'Kill states from a host (so a new block rule takes effect on existing connections)' },
      { arg: '-t bogons -T show', meaning: 'Show the contents of a table (aliases are tables)' },
    ],
    example: {
      command: "pfctl -sr | grep -E 'anti-lockout|USER_RULE|Default deny'",
      output: raw`block drop in log inet all label "Default deny rule IPv4" ridentifier 1000000103
block drop out log inet all label "Default deny rule IPv4" ridentifier 1000000103
pass in quick on vtnet1 proto tcp from any to (vtnet1) port = ssh flags S/SA keep state label "anti-lockout rule" ridentifier 10000
pass in quick on vtnet1 proto tcp from any to (vtnet1) port = http flags S/SA keep state label "anti-lockout rule" ridentifier 10000
pass in quick on vtnet1 proto tcp from any to (vtnet1) port = https flags S/SA keep state label "anti-lockout rule" ridentifier 10000
pass in quick on vtnet1 inet from 10.0.10.0/24 to any flags S/SA keep state label "USER_RULE: Default allow LAN to any rule" ridentifier 1770000101`,
    },
    interpretation: 'This is the ruleset pf actually enforces, generated from config.xml (representative excerpt; exact numbers differ). The ridentifier is the tracker ID shown in the firewall log, so you can map a logged block to its rule. Rules with `quick` stop evaluation at the first match; pfSense evaluates interface rules top to bottom on the **inbound** interface. If a rule is in the GUI but not here, the filter reload failed (check the notices).',
    limitations: 'Do not edit rules with pfctl on pfSense: the next filter reload (any rule save, interface event, WAN DHCP renewal) regenerates and reloads /tmp/rules.debug and discards your change. Existing states are not affected by new rules until they expire or are killed.',
    errors: [
      { message: 'pfctl: Syntax error in config file: pf rules not loaded', meaning: 'The ruleset failed to parse; the previous ruleset stays active. Run `pfctl -nf /tmp/rules.debug` to see the failing line; on pfSense the GUI shows "There were error(s) loading the rules".' },
      { message: 'pf disabled', meaning: 'Output of `pfctl -d`: filtering **and NAT** are off. LAN clients lose Internet (no outbound NAT) and every port on every interface is exposed.' },
      { message: 'pfctl: pf already enabled', meaning: 'Harmless: `pfctl -e` when pf is already on.' },
    ],
    permissions: 'root (console option 8, or SSH as admin/root).',
    risks: '**`pfctl -d` removes all protection and NAT** until the next filter reload or `pfctl -e`. `pfctl -F all` flushes rules, NAT and states (drops all connections). Killing states drops live connections.',
    compat: 'pfSense CE 2.7.x (FreeBSD 14) / pfSense Plus 23.x-24.x; output wording is FreeBSD pf. OPNsense also uses pf but generates different labels.',
    services: ['pfSense', 'Firewall', 'NAT'],
    protocols: ['TCP', 'UDP', 'ICMP'],
    symptoms: ['Traffic blocked by firewall', 'Port not reachable', 'Connection timed out', 'No Internet access'],
  },
  {
    id: 'pfsense-console', name: 'pfSense console menu', platform: 'pfSense', category: 'Recovery',
    purpose: 'The text menu on the pfSense console (VGA/serial/hypervisor console, or SSH): the recovery path when the web GUI is unreachable or a rule change locked you out.',
    syntax: 'Enter an option: <number>',
    args: [
      { arg: '1) Assign Interfaces', meaning: 'Map WAN/LAN/OPTx to NICs and VLANs (fixes interface mismatch after hardware change)' },
      { arg: '2) Set interface(s) IP address', meaning: 'Change an interface IP/DHCP server; offers to revert the GUI to HTTP' },
      { arg: '3) Reset webConfigurator password', meaning: 'Reset admin password (and re-enable the account)' },
      { arg: '8) Shell', meaning: 'Root shell (pfctl, easyrule, viconfig, pfSsh.php)' },
      { arg: '10) Filter Logs', meaning: 'Live firewall log' },
      { arg: '11) Restart webConfigurator', meaning: 'Restart the GUI web server' },
      { arg: '15) Restore recent configuration', meaning: 'Pick one of the automatic config backups' },
      { arg: '16) Restart PHP-FPM', meaning: 'Fixes a GUI that answers 502 Bad Gateway' },
      { arg: '4) Reset to factory defaults', meaning: 'Erases the configuration: last resort' },
    ],
    example: {
      command: '(console after boot)',
      output: raw`*** Welcome to pfSense 2.7.2-RELEASE (amd64) on fw01 ***

 WAN (wan)       -> vtnet0     -> v4/DHCP4: 203.0.113.2/24
 LAN (lan)       -> vtnet1     -> v4: 10.0.10.1/24

 0) Logout (SSH only)                  9) pfTop
 1) Assign Interfaces                 10) Filter Logs
 2) Set interface(s) IP address       11) Restart webConfigurator
 3) Reset webConfigurator password    12) PHP shell + pfSense tools
 4) Reset to factory defaults         13) Update from console
 5) Reboot system                     14) Enable Secure Shell (sshd)
 6) Halt system                       15) Restore recent configuration
 7) Ping host                         16) Restart PHP-FPM
 8) Shell

Enter an option:`,
    },
    interpretation: 'The banner shows each interface, its NIC and address: check first that LAN/WAN are on the NICs you expect and have the expected IPs (a wrong assignment looks like "everything is blocked"). From LAN, the anti-lockout rule normally keeps the GUI reachable on the LAN address; if not, use 2 to fix the address, 11/16 for a hung GUI, or 8 for the shell.',
    limitations: 'Needs console or SSH access (SSH is off by default; enable with 14 from the console). The menu cannot edit firewall rules directly: use `easyrule` in the shell or restore a configuration.',
    errors: [
      { message: 'Potential DNS Rebind attack detected, see https://en.wikipedia.org/wiki/DNS_rebinding', meaning: 'GUI error: you reached the GUI by a hostname pfSense does not know. Use the IP address or add the name under System > Advanced > Admin Access (Alternate Hostnames).' },
      { message: 'An HTTP_REFERER was detected other than what is defined in System > Advanced (https://...). If not needed, this check can be disabled in System > Advanced > Admin Access.', meaning: 'GUI error: the browser came from a link/proxy with a foreign Referer. Open the GUI URL directly.' },
      { message: '502 Bad Gateway', meaning: 'nginx is up but PHP-FPM is not answering: console option 16.' },
    ],
    permissions: 'Physical/console access, or SSH as admin (root equivalent).',
    risks: 'Option 4 erases the configuration; 5/6 reboot/halt the firewall (outage for every network behind it); 15 replaces the running configuration; 1 can swap WAN and LAN.',
    compat: 'pfSense CE 2.7.x (FreeBSD 14); menu numbering identical in pfSense Plus 23.x-24.x.',
    services: ['pfSense', 'Firewall'],
    protocols: ['HTTP', 'TLS', 'SSH'],
    symptoms: ['Traffic blocked by firewall', 'Connection timed out', 'Login fails', 'No Internet access'],
  },
  // --- Cisco IOS ----------------------------------------------------------------
  {
    id: 'ios-show-ip-int-brief', name: 'show ip interface brief', platform: 'Cisco IOS', category: 'Interfaces',
    purpose: 'One line per interface with its IPv4 address and the two status columns (line status and line protocol): the IOS equivalent of `ip -br addr`.',
    syntax: 'show ip interface brief [| include up|exclude unassigned]',
    args: [
      { arg: '| exclude unassigned', meaning: 'Hide interfaces without an address' },
      { arg: 'show interfaces status', meaning: 'Switches: port VLAN, duplex, speed, err-disabled' },
      { arg: 'show interfaces Gi1', meaning: 'Full counters: input errors, CRC, drops' },
    ],
    example: {
      command: 'show ip interface brief',
      output: raw`Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       203.0.113.10    YES manual up                    up
GigabitEthernet2       10.0.10.2       YES manual up                    up
GigabitEthernet3       unassigned      YES unset  administratively down down
GigabitEthernet4       10.0.12.1       YES manual down                  down
Loopback0              10.255.0.1      YES manual up                    up`,
    },
    interpretation: '`up/up` is working. `administratively down/down` means the interface is shut down in config (`no shutdown` fixes it). `down/down` is layer 1: no cable, peer down, wrong port. `up/down` means the physical layer is fine but the line protocol is not (encapsulation or keepalive mismatch, err-disabled peer). Method shows how the address was set (manual, DHCP, NVRAM, unset).',
    limitations: 'IPv4 only (use `show ipv6 interface brief`). Says nothing about VLAN membership, errors or duplex mismatch (`show interfaces`).',
    errors: [
      { message: "% Invalid input detected at '^' marker.", meaning: 'Typo, or you are in the wrong mode (e.g. inside `configure terminal`: prefix with `do`).' },
      { message: '% Ambiguous command:  "show ip int b"', meaning: 'Abbreviation matches more than one keyword; type more letters.' },
    ],
    permissions: 'User EXEC (level 1) is enough.',
    risks: 'Read-only.',
    compat: 'Cisco IOS 15.x and IOS XE 16.x/17.x (router naming GigabitEthernet1 on CSR/Catalyst 8000V; switches use GigabitEthernet1/0/1 and Vlan10 SVIs).',
    services: ['Cisco IOS', 'Networking', 'Routing'],
    protocols: ['ARP'],
    symptoms: ['No route to host', 'Connection timed out', 'No Internet access'],
  },
  {
    id: 'ios-show-ip-route', name: 'show ip route', platform: 'Cisco IOS', category: 'Routing',
    purpose: 'Shows the IPv4 routing table with the source of each route, administrative distance/metric, next hop and outgoing interface.',
    syntax: 'show ip route [A.B.C.D | connected | static | ospf] [vrf NAME]',
    args: [
      { arg: '10.0.20.10', meaning: 'Which route is used for this destination (longest match, with details)' },
      { arg: 'ospf / static / connected', meaning: 'Only routes from one source' },
      { arg: 'vrf NAME', meaning: 'Routing table of a VRF' },
      { arg: 'show ipv6 route', meaning: 'IPv6 equivalent' },
    ],
    example: {
      command: 'show ip route',
      output: raw`Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       ...
Gateway of last resort is 203.0.113.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 203.0.113.1
      10.0.0.0/8 is variably subnetted, 6 subnets, 3 masks
C        10.0.10.0/24 is directly connected, GigabitEthernet2
L        10.0.10.2/32 is directly connected, GigabitEthernet2
O        10.0.20.0/24 [110/2] via 10.0.10.1, 00:12:44, GigabitEthernet2
O IA     10.0.30.0/24 [110/3] via 10.0.10.1, 00:12:44, GigabitEthernet2
C        10.255.0.1/32 is directly connected, Loopback0
      203.0.113.0/24 is variably subnetted, 2 subnets, 2 masks
C        203.0.113.0/24 is directly connected, GigabitEthernet1
L        203.0.113.10/32 is directly connected, GigabitEthernet1`,
    },
    interpretation: '`[110/2]` is [administrative distance/metric]: when two sources offer the same prefix, the lower AD wins (connected 0, static 1, eBGP 20, EIGRP 90, OSPF 110). The most specific prefix wins before AD is even considered. `Gateway of last resort is not set` means unknown destinations are dropped. A missing OSPF route usually means a missing neighbor (check `show ip ospf neighbor`).',
    limitations: 'Shows the router\'s own routing decision only; the return path is decided on other devices. Policy-based routing and NAT are not shown.',
    errors: [
      { message: '% Network not in table', meaning: 'No route covers that destination (and no default route): traffic to it is dropped here.' },
      { message: '% Subnet not in table', meaning: 'The major network is known but not this specific subnet.' },
    ],
    permissions: 'User EXEC (level 1).',
    risks: 'Read-only.',
    compat: 'Cisco IOS 15.x and IOS XE 16.x/17.x (codes list abbreviated above; newer releases add more codes).',
    services: ['Cisco IOS', 'Routing', 'OSPF'],
    protocols: ['OSPF', 'ICMP'],
    symptoms: ['No route to host', 'No Internet access', 'Connection timed out'],
  },
  {
    id: 'ios-show-vlan', name: 'show vlan brief', platform: 'Cisco IOS', category: 'Switching',
    purpose: 'Lists the VLANs that exist on a switch and which access ports belong to each. Trunk ports are shown separately with `show interfaces trunk`.',
    syntax: 'show vlan brief | show vlan id N | show interfaces trunk | show interfaces Gi1/0/1 switchport',
    args: [
      { arg: 'show vlan id 30', meaning: 'One VLAN with its ports' },
      { arg: 'show interfaces trunk', meaning: 'Trunk ports, native VLAN, allowed and active VLANs' },
      { arg: 'show interfaces Gi1/0/4 switchport', meaning: 'Mode (access/trunk), access VLAN, voice VLAN of one port' },
    ],
    example: {
      command: 'show vlan brief',
      output: raw`VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/5, Gi1/0/6, Gi1/0/7, Gi1/0/8
10   OFFICE                           active    Gi1/0/1, Gi1/0/2
20   SERVERS                          active    Gi1/0/3
30   DEV                              active    Gi1/0/4
1002 fddi-default                     act/unsup
1003 token-ring-default               act/unsup
1004 fddinet-default                  act/unsup
1005 trnet-default                    act/unsup`,
    },
    interpretation: 'An access port in the wrong VLAN (or still in VLAN 1) puts the host in the wrong subnet: DHCP from the wrong scope, or no address at all. A VLAN missing from the list does not exist on this switch, so its ports are inactive. Trunks do not appear here: run `show interfaces trunk` and check the "Vlans allowed and active" line; a VLAN missing there is pruned from the trunk and cannot cross to the next switch or router.',
    limitations: 'Static view; it does not show MAC learning (`show mac address-table vlan 30`) or spanning-tree blocking (`show spanning-tree vlan 30`).',
    errors: [
      { message: 'VLAN id 40 not found in current VLAN database', meaning: '`show vlan id 40`: the VLAN was never created (or VTP removed it).' },
      { message: "% Invalid input detected at '^' marker.", meaning: 'The device is a router without a VLAN database (use `show interfaces` for subinterfaces) or a typo.' },
    ],
    permissions: 'User EXEC (level 1).',
    risks: 'Read-only.',
    compat: 'Cisco Catalyst IOS 15.x and IOS XE 16.x/17.x (Catalyst 9000); port names Gi1/0/x.',
    services: ['Cisco IOS', 'VLAN'],
    protocols: ['802.1Q'],
    symptoms: ['No IP address', 'No route to host', 'Connection timed out'],
  },
  {
    id: 'ios-show-run', name: 'show running-config', platform: 'Cisco IOS', category: 'Configuration',
    purpose: 'Displays the active configuration in RAM. Changes made in configure mode apply immediately but are lost on reload unless saved to startup-config.',
    syntax: 'show running-config [interface IF] [| section KEYWORD | include TEXT]',
    args: [
      { arg: 'interface Gi1/0/24', meaning: 'Only one interface' },
      { arg: '| section router ospf', meaning: 'A configuration block with its sub-commands' },
      { arg: '| include ip route', meaning: 'Matching lines only' },
      { arg: 'show startup-config', meaning: 'What will load at the next boot' },
      { arg: 'copy running-config startup-config', meaning: 'Save (same as `write memory`)' },
    ],
    example: {
      command: 'show running-config interface GigabitEthernet1/0/24',
      output: raw`Building configuration...

Current configuration : 141 bytes
!
interface GigabitEthernet1/0/24
 description uplink to rtr01
 switchport trunk allowed vlan 10,20
 switchport mode trunk
end`,
    },
    interpretation: 'Here the uplink trunk only allows VLANs 10 and 20: VLAN 30 traffic cannot leave the switch. Defaults are not shown (a missing `shutdown` line means the interface is enabled). Comparing running with startup config tells you whether a problem appeared after an unsaved change, or will appear at the next reload.',
    limitations: 'Shows configuration, not operational state (an interface can be configured and still down). Passwords appear as type 7 (reversibly encoded) or hashes: redact before sharing.',
    errors: [
      { message: "% Invalid input detected at '^' marker.", meaning: 'You are in user EXEC (prompt ends with >): run `enable` first; inside config mode prefix with `do`.' },
    ],
    permissions: 'Privileged EXEC (level 15, `enable`).',
    risks: 'Read-only. When changing a remote device, schedule `reload in 10` before risky changes and `reload cancel` once you have confirmed access: an unsaved mistake is undone by the reload.',
    compat: 'Cisco IOS 15.x and IOS XE 16.x/17.x.',
    services: ['Cisco IOS', 'VLAN', 'Routing', 'OSPF'],
    protocols: ['802.1Q', 'OSPF'],
    symptoms: ['No route to host', 'Connection timed out'],
  },
  {
    id: 'ios-show-ip-ospf-neighbor', name: 'show ip ospf neighbor', platform: 'Cisco IOS', category: 'Routing',
    purpose: 'Lists OSPF adjacencies and their state. Routes are only exchanged with neighbors in FULL state (or 2WAY between DROTHERs).',
    syntax: 'show ip ospf neighbor [detail] | show ip ospf interface brief',
    args: [
      { arg: 'detail', meaning: 'Area, DR/BDR, uptime and options per neighbor' },
      { arg: 'show ip ospf interface brief', meaning: 'Which interfaces run OSPF, area, cost, state, neighbor count' },
      { arg: 'debug ip ospf adj', meaning: 'Shows why an adjacency fails (area/hello/auth/MTU mismatch); use with care' },
    ],
    example: {
      command: 'show ip ospf neighbor',
      output: raw`Neighbor ID     Pri   State           Dead Time   Address         Interface
10.255.0.2        1   FULL/DR         00:00:36    10.0.10.1       GigabitEthernet2
10.255.0.3        1   FULL/BDR        00:00:33    10.0.10.3       GigabitEthernet2
10.255.0.4        0   FULL/  -        00:00:38    10.0.12.2       GigabitEthernet4`,
    },
    interpretation: 'FULL is a working adjacency (`FULL/  -` on point-to-point links, where there is no DR). A neighbor stuck in INIT sees no hellos back (one-way: ACL or multicast problem); stuck in EXSTART/EXCHANGE is the classic MTU mismatch; a neighbor missing completely means hellos are not accepted (different subnet, area, hello/dead timers, authentication, or a passive interface). Dead Time counting down past ~30 s repeatedly suggests lost hellos.',
    limitations: 'Lists neighbors only, not which routes they advertise (`show ip ospf database`, `show ip route ospf`).',
    errors: [
      { message: '%OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.2 on GigabitEthernet2 from FULL to DOWN, Neighbor Down: Dead timer expired', meaning: 'Log message: no hello received within the dead interval (link, interface errors, CPU, or hello blocked).' },
      { message: '%OSPF-4-DUP_RTRID_NBR: OSPF detected duplicate router-id 10.255.0.2 from 10.0.10.9 on interface GigabitEthernet2', meaning: 'Two routers use the same router ID (often a cloned config): set unique `router-id` values.' },
    ],
    permissions: 'User EXEC (level 1); debug needs level 15.',
    risks: 'Read-only. `debug` on a busy router can overload the CPU: prefer `terminal monitor` with a narrow debug and `undebug all` afterwards.',
    compat: 'Cisco IOS 15.x and IOS XE 16.x/17.x (OSPFv2; for OSPFv3 use `show ospfv3 neighbor`).',
    services: ['Cisco IOS', 'OSPF', 'Routing'],
    protocols: ['OSPF'],
    symptoms: ['No route to host', 'Slow or intermittent connectivity'],
  },
];
