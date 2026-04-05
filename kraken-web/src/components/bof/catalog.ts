// BOF Catalog - Comprehensive library of Beacon Object Files
// Based on popular BOF collections: CS-Situational-Awareness-BOF, trustedsec/CS-Remote-OPs-BOF, etc.

import type { BOFManifest } from './types';

export const BOF_CATALOG: BOFManifest[] = [
  // ============================================
  // RECONNAISSANCE
  // ============================================
  {
    id: 'whoami',
    name: 'whoami',
    version: '1.2.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Get current user context and group memberships',
    longDescription: `Retrieves the current user's identity including:
- Username and domain
- Security identifier (SID)
- Local and domain group memberships
- Privilege information

Safe to run - uses standard Windows APIs.`,
    category: 'recon',
    tags: ['identity', 'user', 'groups', 'privileges'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/whoami.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/whoami.x86.o' },
    ],
    arguments: [],
    repoUrl: 'https://github.com/trustedsec/CS-Situational-Awareness-BOF',
    opsecNotes: 'Low risk. Uses GetUserName, GetTokenInformation APIs.',
  },
  {
    id: 'netstat',
    name: 'netstat',
    version: '1.1.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Display active network connections',
    longDescription: `Lists all active TCP/UDP connections including:
- Local and remote addresses/ports
- Connection state (ESTABLISHED, LISTENING, etc.)
- Process ID owning the connection

No arguments required - shows all connections.`,
    category: 'recon',
    tags: ['network', 'connections', 'tcp', 'udp', 'ports'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/netstat.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/netstat.x86.o' },
    ],
    arguments: [],
    repoUrl: 'https://github.com/trustedsec/CS-Situational-Awareness-BOF',
    opsecNotes: 'Low risk. Uses GetTcpTable2/GetUdpTable APIs.',
  },
  {
    id: 'dir',
    name: 'dir',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'List directory contents with timestamps',
    longDescription: `Directory listing showing:
- File and folder names
- File sizes
- Creation/modification timestamps
- File attributes (hidden, system, etc.)

Supports wildcards (e.g., *.exe, *.dll).`,
    category: 'recon',
    tags: ['filesystem', 'files', 'directories', 'listing'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/dir.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/dir.x86.o' },
    ],
    arguments: [
      {
        name: 'path',
        type: 'wstring',
        description: 'Directory path or wildcard pattern',
        optional: false,
        defaultValue: 'C:\\*',
      },
    ],
    repoUrl: 'https://github.com/trustedsec/CS-Situational-Awareness-BOF',
    opsecNotes: 'Low risk. Uses FindFirstFile/FindNextFile APIs.',
  },
  {
    id: 'reg_query',
    name: 'reg_query',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Query Windows registry keys and values',
    longDescription: `Query registry for keys and values:
- Enumerate subkeys
- Read REG_SZ, REG_DWORD, REG_BINARY values
- Support for HKLM, HKCU, HKU hives

Useful for configuration discovery and persistence checks.`,
    category: 'recon',
    tags: ['registry', 'configuration', 'enumeration'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/reg_query.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/reg_query.x86.o' },
    ],
    arguments: [
      {
        name: 'key',
        type: 'wstring',
        description: 'Registry key path (e.g., HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)',
        optional: false,
      },
    ],
    repoUrl: 'https://github.com/trustedsec/CS-Situational-Awareness-BOF',
    opsecNotes: 'Low risk. Uses RegOpenKeyEx/RegQueryValueEx APIs.',
  },
  {
    id: 'arp',
    name: 'arp',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Display ARP cache table',
    longDescription: `Shows the ARP (Address Resolution Protocol) cache:
- IP addresses and their MAC addresses
- Interface information
- Entry types (dynamic, static)

Useful for network discovery and identifying local hosts.`,
    category: 'recon',
    tags: ['network', 'arp', 'mac', 'discovery'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/arp.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/arp.x86.o' },
    ],
    arguments: [],
    repoUrl: 'https://github.com/trustedsec/CS-Situational-Awareness-BOF',
    opsecNotes: 'Low risk. Uses GetIpNetTable API.',
  },
  {
    id: 'ipconfig',
    name: 'ipconfig',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Display network adapter configuration',
    longDescription: `Shows network adapter information:
- IP addresses (IPv4/IPv6)
- Subnet masks
- Default gateways
- DNS servers
- DHCP configuration`,
    category: 'recon',
    tags: ['network', 'ip', 'dns', 'adapter'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/ipconfig.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/ipconfig.x86.o' },
    ],
    arguments: [],
    repoUrl: 'https://github.com/trustedsec/CS-Situational-Awareness-BOF',
    opsecNotes: 'Low risk. Uses GetAdaptersInfo API.',
  },
  {
    id: 'env',
    name: 'env',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Display environment variables',
    longDescription: `Lists all environment variables:
- System and user variables
- PATH, TEMP, USERNAME, etc.
- Custom application variables`,
    category: 'recon',
    tags: ['environment', 'variables', 'system'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/env.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/env.x86.o' },
    ],
    arguments: [],
    opsecNotes: 'Low risk. Uses GetEnvironmentStrings API.',
  },
  {
    id: 'tasklist',
    name: 'tasklist',
    version: '1.1.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'List running processes with details',
    longDescription: `Lists all running processes:
- Process ID (PID) and parent PID
- Process name and path
- Memory usage
- Owner/user context
- Session ID

Optionally filter by process name.`,
    category: 'recon',
    tags: ['processes', 'tasks', 'enumeration'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/tasklist.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/tasklist.x86.o' },
    ],
    arguments: [
      {
        name: 'filter',
        type: 'string',
        description: 'Optional process name filter',
        optional: true,
      },
    ],
    opsecNotes: 'Low risk. Uses CreateToolhelp32Snapshot API.',
  },
  {
    id: 'schtasks_enum',
    name: 'schtasks_enum',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Enumerate scheduled tasks',
    longDescription: `Lists scheduled tasks:
- Task name and path
- Triggers (time-based, event-based)
- Actions (command, script)
- Run level and user context
- Last run time and result

Useful for persistence discovery.`,
    category: 'recon',
    tags: ['scheduled', 'tasks', 'persistence', 'enumeration'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/schtasks_enum.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/schtasks_enum.x86.o' },
    ],
    arguments: [
      {
        name: 'folder',
        type: 'wstring',
        description: 'Task folder path (default: \\)',
        optional: true,
        defaultValue: '\\',
      },
    ],
    opsecNotes: 'Low risk. Uses Task Scheduler COM interfaces.',
  },
  {
    id: 'services_enum',
    name: 'services_enum',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Enumerate Windows services',
    longDescription: `Lists Windows services:
- Service name and display name
- Status (running, stopped, etc.)
- Start type (auto, manual, disabled)
- Service account
- Binary path`,
    category: 'recon',
    tags: ['services', 'enumeration', 'persistence'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/services_enum.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/services_enum.x86.o' },
    ],
    arguments: [],
    opsecNotes: 'Low risk. Uses OpenSCManager/EnumServicesStatusEx APIs.',
  },
  {
    id: 'ldap_query',
    name: 'ldap_query',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'trustedsec',
    description: 'Query Active Directory via LDAP',
    longDescription: `Execute LDAP queries against Active Directory:
- User enumeration
- Group membership
- Computer objects
- Custom LDAP filters

Returns attributes specified in the query.`,
    category: 'recon',
    tags: ['ldap', 'ad', 'domain', 'enumeration'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/recon/ldap_query.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/recon/ldap_query.x86.o' },
    ],
    arguments: [
      {
        name: 'filter',
        type: 'string',
        description: 'LDAP filter (e.g., (objectClass=user))',
        optional: false,
      },
      {
        name: 'attributes',
        type: 'string',
        description: 'Comma-separated attributes to return',
        optional: true,
        defaultValue: 'cn,distinguishedName',
      },
    ],
    opsecNotes: 'Medium risk. Generates LDAP traffic. May trigger SIEM alerts.',
  },

  // ============================================
  // CREDENTIALS
  // ============================================
  {
    id: 'nanodump',
    name: 'nanodump',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'helpsystems',
    description: 'Dump LSASS process memory (stealthy)',
    longDescription: `Creates a minidump of the LSASS process using direct syscalls.

Features:
- Avoids API hooks via syscalls
- Invalid signature to avoid AV detection
- Forked process dumping option
- Can dump to memory instead of disk

Output can be processed with mimikatz/pypykatz offline.`,
    category: 'creds',
    tags: ['lsass', 'dump', 'credentials', 'mimikatz'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/creds/nanodump.x64.o' },
    ],
    arguments: [
      {
        name: 'pid',
        type: 'int',
        description: 'LSASS PID (0 for auto-detect)',
        optional: true,
        defaultValue: 0,
      },
      {
        name: 'output',
        type: 'wstring',
        description: 'Output file path',
        optional: true,
        defaultValue: 'C:\\Windows\\Temp\\debug.dmp',
      },
    ],
    repoUrl: 'https://github.com/helpsystems/nanodump',
    opsecNotes: 'HIGH RISK. LSASS access is heavily monitored. Consider fork dumping.',
  },
  {
    id: 'sam_dump',
    name: 'sam_dump',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Dump SAM database hashes',
    longDescription: `Extracts password hashes from the SAM database:
- Local user NTLM hashes
- Cached domain credentials (if available)

Requires SYSTEM privileges.`,
    category: 'creds',
    tags: ['sam', 'hashes', 'ntlm', 'credentials'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/creds/sam_dump.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/creds/sam_dump.x86.o' },
    ],
    arguments: [],
    opsecNotes: 'HIGH RISK. Registry access to SAM/SECURITY hives is monitored.',
  },
  {
    id: 'kerberoast',
    name: 'kerberoast',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'GhostPack',
    description: 'Request TGS tickets for offline cracking',
    longDescription: `Performs Kerberoasting attack:
- Enumerates SPNs in Active Directory
- Requests TGS tickets for service accounts
- Outputs tickets in hashcat/john format

Tickets can be cracked offline to recover service account passwords.`,
    category: 'creds',
    tags: ['kerberos', 'spn', 'tickets', 'cracking', 'ad'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/creds/kerberoast.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/creds/kerberoast.x86.o' },
    ],
    arguments: [
      {
        name: 'spn',
        type: 'string',
        description: 'Specific SPN to target (empty for all)',
        optional: true,
      },
      {
        name: 'format',
        type: 'string',
        description: 'Output format: hashcat or john',
        optional: true,
        defaultValue: 'hashcat',
      },
    ],
    opsecNotes: 'Medium risk. Multiple TGS requests may trigger detection.',
  },
  {
    id: 'dcsync',
    name: 'dcsync',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'gentilkiwi',
    description: 'DCSync - replicate AD credentials',
    longDescription: `Simulates domain controller replication to extract credentials:
- Requires Replicating Directory Changes permissions
- Can target specific users or all users
- Extracts NTLM hashes and Kerberos keys

Typically requires Domain Admin or equivalent privileges.`,
    category: 'creds',
    tags: ['dcsync', 'ad', 'domain', 'replication', 'krbtgt'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/creds/dcsync.x64.o' },
    ],
    arguments: [
      {
        name: 'user',
        type: 'string',
        description: 'Target user (e.g., krbtgt, Administrator)',
        optional: false,
      },
      {
        name: 'domain',
        type: 'string',
        description: 'Target domain FQDN',
        optional: true,
      },
    ],
    opsecNotes: 'HIGH RISK. DRS replication is logged. Requires high privileges.',
  },

  // ============================================
  // LATERAL MOVEMENT
  // ============================================
  {
    id: 'wmi_exec',
    name: 'wmi_exec',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Execute commands via WMI',
    longDescription: `Executes commands on remote systems via WMI:
- Uses Win32_Process.Create
- Supports credential specification
- Semi-interactive command execution`,
    category: 'lateral',
    tags: ['wmi', 'remote', 'execution', 'lateral'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/lateral/wmi_exec.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/lateral/wmi_exec.x86.o' },
    ],
    arguments: [
      {
        name: 'target',
        type: 'string',
        description: 'Target hostname or IP',
        optional: false,
      },
      {
        name: 'command',
        type: 'wstring',
        description: 'Command to execute',
        optional: false,
      },
    ],
    opsecNotes: 'Medium risk. WMI process creation is commonly logged.',
  },
  {
    id: 'psexec',
    name: 'psexec',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Execute via service creation (PsExec-style)',
    longDescription: `Executes commands on remote systems by creating a service:
- Connects to remote SCM
- Creates and starts a temporary service
- Deletes service after execution

Requires local admin on target.`,
    category: 'lateral',
    tags: ['psexec', 'service', 'remote', 'execution'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/lateral/psexec.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/lateral/psexec.x86.o' },
    ],
    arguments: [
      {
        name: 'target',
        type: 'string',
        description: 'Target hostname or IP',
        optional: false,
      },
      {
        name: 'service_name',
        type: 'string',
        description: 'Service name to create',
        optional: true,
        defaultValue: 'YOURSERVICE',
      },
      {
        name: 'command',
        type: 'wstring',
        description: 'Command/binary to execute',
        optional: false,
      },
    ],
    opsecNotes: 'HIGH RISK. Service creation is heavily monitored. Leaves artifacts.',
  },
  {
    id: 'scshell',
    name: 'scshell',
    version: '1.0.0',
    author: 'Kraken Team',
    originalAuthor: 'Mr-Un1k0d3r',
    description: 'Fileless lateral movement via service modification',
    longDescription: `Modifies existing service to execute payload:
- Changes service binary path
- Starts service to trigger execution
- Restores original configuration

More stealthy than creating new services.`,
    category: 'lateral',
    tags: ['service', 'fileless', 'lateral', 'modification'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/lateral/scshell.x64.o' },
    ],
    arguments: [
      {
        name: 'target',
        type: 'string',
        description: 'Target hostname',
        optional: false,
      },
      {
        name: 'service',
        type: 'string',
        description: 'Service name to modify',
        optional: false,
      },
      {
        name: 'payload',
        type: 'wstring',
        description: 'Command to execute',
        optional: false,
      },
    ],
    repoUrl: 'https://github.com/Mr-Un1k0d3r/SCShell',
    opsecNotes: 'Medium risk. Service config changes are logged.',
  },

  // ============================================
  // PRIVILEGE ESCALATION
  // ============================================
  {
    id: 'getsystem',
    name: 'getsystem',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Elevate to SYSTEM via named pipe impersonation',
    longDescription: `Attempts to elevate to SYSTEM privileges using:
- Named pipe impersonation technique
- Creates service to connect to pipe
- Impersonates SYSTEM token

Requires local administrator privileges.`,
    category: 'privesc',
    tags: ['system', 'elevation', 'impersonation', 'token'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/privesc/getsystem.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/privesc/getsystem.x86.o' },
    ],
    arguments: [],
    opsecNotes: 'Medium risk. Named pipe creation and service manipulation.',
  },
  {
    id: 'token_steal',
    name: 'token_steal',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Steal and impersonate process token',
    longDescription: `Steals access token from another process:
- Opens target process
- Duplicates primary token
- Impersonates token in current thread

Useful for context switching without credentials.`,
    category: 'privesc',
    tags: ['token', 'impersonation', 'steal', 'privilege'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/privesc/token_steal.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/privesc/token_steal.x86.o' },
    ],
    arguments: [
      {
        name: 'pid',
        type: 'int',
        description: 'Target process ID',
        optional: false,
      },
    ],
    opsecNotes: 'Medium risk. Opening process handles is logged.',
  },
  {
    id: 'uac_bypass',
    name: 'uac_bypass',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Bypass UAC to get elevated privileges',
    longDescription: `Bypasses User Account Control:
- Multiple techniques (fodhelper, eventvwr, etc.)
- No GUI interaction required
- Spawns elevated process

Only works if current user is in Administrators group.`,
    category: 'privesc',
    tags: ['uac', 'bypass', 'elevation', 'admin'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/privesc/uac_bypass.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/privesc/uac_bypass.x86.o' },
    ],
    arguments: [
      {
        name: 'technique',
        type: 'string',
        description: 'Bypass technique: fodhelper, eventvwr, computerdefaults',
        optional: true,
        defaultValue: 'fodhelper',
      },
      {
        name: 'command',
        type: 'wstring',
        description: 'Command to run elevated',
        optional: false,
      },
    ],
    opsecNotes: 'Medium risk. Registry modifications and process spawning.',
  },

  // ============================================
  // EVASION
  // ============================================
  {
    id: 'unhook_ntdll',
    name: 'unhook_ntdll',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Unhook ntdll.dll to bypass EDR',
    longDescription: `Removes EDR hooks from ntdll.dll:
- Maps fresh copy of ntdll from disk
- Compares .text sections
- Overwrites hooked functions with clean versions

Helps bypass EDR function hooking.`,
    category: 'evasion',
    tags: ['unhook', 'edr', 'bypass', 'ntdll'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/evasion/unhook_ntdll.x64.o' },
    ],
    arguments: [],
    opsecNotes: 'Medium risk. Memory writes to ntdll may trigger alerts.',
  },
  {
    id: 'etw_patch',
    name: 'etw_patch',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Patch ETW to disable logging',
    longDescription: `Disables Event Tracing for Windows in current process:
- Patches EtwEventWrite to return early
- Prevents .NET/PowerShell logging
- Survives until process termination`,
    category: 'evasion',
    tags: ['etw', 'logging', 'bypass', 'patch'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/evasion/etw_patch.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/evasion/etw_patch.x86.o' },
    ],
    arguments: [],
    opsecNotes: 'Medium risk. Memory patching may trigger AV.',
  },
  {
    id: 'amsi_patch',
    name: 'amsi_patch',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Patch AMSI to bypass script scanning',
    longDescription: `Disables Antimalware Scan Interface:
- Patches AmsiScanBuffer to return clean
- Allows execution of detected scripts
- Process-specific patch`,
    category: 'evasion',
    tags: ['amsi', 'bypass', 'antivirus', 'patch'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/evasion/amsi_patch.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/evasion/amsi_patch.x86.o' },
    ],
    arguments: [],
    opsecNotes: 'Medium risk. AMSI bypass attempts are often detected.',
  },

  // ============================================
  // PERSISTENCE
  // ============================================
  {
    id: 'schtask_create',
    name: 'schtask_create',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Create scheduled task for persistence',
    longDescription: `Creates a scheduled task:
- Supports various triggers (logon, daily, etc.)
- Can run as SYSTEM or specific user
- Survives reboots`,
    category: 'persistence',
    tags: ['scheduled', 'task', 'persistence', 'startup'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/persistence/schtask_create.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/persistence/schtask_create.x86.o' },
    ],
    arguments: [
      {
        name: 'name',
        type: 'wstring',
        description: 'Task name',
        optional: false,
      },
      {
        name: 'trigger',
        type: 'string',
        description: 'Trigger type: logon, daily, startup',
        optional: true,
        defaultValue: 'logon',
      },
      {
        name: 'command',
        type: 'wstring',
        description: 'Command to execute',
        optional: false,
      },
    ],
    opsecNotes: 'HIGH RISK. Task creation is heavily logged and monitored.',
  },
  {
    id: 'reg_persist',
    name: 'reg_persist',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Add registry Run key persistence',
    longDescription: `Creates registry Run key for persistence:
- Supports HKCU or HKLM
- Executes on user logon
- Simple but effective persistence`,
    category: 'persistence',
    tags: ['registry', 'run', 'persistence', 'startup'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/persistence/reg_persist.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/persistence/reg_persist.x86.o' },
    ],
    arguments: [
      {
        name: 'name',
        type: 'wstring',
        description: 'Value name',
        optional: false,
      },
      {
        name: 'command',
        type: 'wstring',
        description: 'Command to execute',
        optional: false,
      },
      {
        name: 'hive',
        type: 'string',
        description: 'Registry hive: hkcu or hklm',
        optional: true,
        defaultValue: 'hkcu',
      },
    ],
    opsecNotes: 'HIGH RISK. Run key modifications are heavily monitored.',
  },

  // ============================================
  // UTILITIES
  // ============================================
  {
    id: 'timestomp',
    name: 'timestomp',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Modify file timestamps',
    longDescription: `Modifies file timestamps to blend in:
- Creation time
- Modified time
- Accessed time
- Can copy timestamps from another file`,
    category: 'util',
    tags: ['timestamp', 'forensics', 'antiforensics'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/util/timestomp.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/util/timestomp.x86.o' },
    ],
    arguments: [
      {
        name: 'target',
        type: 'wstring',
        description: 'Target file path',
        optional: false,
      },
      {
        name: 'reference',
        type: 'wstring',
        description: 'Reference file (copy timestamps from)',
        optional: true,
      },
    ],
    opsecNotes: 'Low risk. SetFileTime API calls.',
  },
  {
    id: 'screenshot',
    name: 'screenshot',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Capture screenshot of desktop',
    longDescription: `Captures a screenshot of the desktop:
- Captures all monitors
- Returns JPEG compressed image
- Configurable quality`,
    category: 'util',
    tags: ['screenshot', 'capture', 'desktop'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/util/screenshot.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/util/screenshot.x86.o' },
    ],
    arguments: [
      {
        name: 'quality',
        type: 'int',
        description: 'JPEG quality (1-100)',
        optional: true,
        defaultValue: 80,
      },
    ],
    opsecNotes: 'Medium risk. Screen capture APIs may trigger DLP.',
  },
  {
    id: 'clipboard',
    name: 'clipboard',
    version: '1.0.0',
    author: 'Kraken Team',
    description: 'Read clipboard contents',
    longDescription: `Reads the current clipboard contents:
- Text data
- File paths (if files copied)
- Can also set clipboard data`,
    category: 'util',
    tags: ['clipboard', 'data', 'capture'],
    entrypoint: 'go',
    platforms: [
      { os: 'windows', arch: 'x64', path: 'bofs/util/clipboard.x64.o' },
      { os: 'windows', arch: 'x86', path: 'bofs/util/clipboard.x86.o' },
    ],
    arguments: [],
    opsecNotes: 'Low risk. Standard clipboard APIs.',
  },
];

// Group BOFs by category for quick access
export const BOF_BY_CATEGORY = BOF_CATALOG.reduce((acc, bof) => {
  if (!acc[bof.category]) {
    acc[bof.category] = [];
  }
  acc[bof.category].push(bof);
  return acc;
}, {} as Record<string, BOFManifest[]>);

// Search BOFs by name, description, or tags
export function searchBOFs(query: string): BOFManifest[] {
  const lowerQuery = query.toLowerCase();
  return BOF_CATALOG.filter(
    (bof) =>
      bof.name.toLowerCase().includes(lowerQuery) ||
      bof.description.toLowerCase().includes(lowerQuery) ||
      bof.tags.some((tag) => tag.toLowerCase().includes(lowerQuery))
  );
}

// Get BOF by ID
export function getBOFById(id: string): BOFManifest | undefined {
  return BOF_CATALOG.find((bof) => bof.id === id);
}

export default BOF_CATALOG;
