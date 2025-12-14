// constants.ts

export const INITIAL_CONTENT = `
# VOLATILITY 3 CHEAT SHEET

Welcome, Investigator. 

Select a plugin from the **PLUGINS_DIR** on the left to initialize analysis modules.

## ARCHITECTURE
Volatility 3 uses a new plugin-based architecture. 
Commands follow the syntax: 
\`vol -f [image] [os].[plugin]\`

## SHORTCUTS
- **CTRL+F**: Search command history
- **TAB**: Autocomplete plugin names
`;

export interface PluginDef {
  name: string;
  command: string;
  category: string;
}

// --- PART 1: THE PLUGIN LIST (SIDEBAR) ---
export const PLUGINS: PluginDef[] = [
  // 3.1 Memory, Pools, and Paging
  { category: "Memory & Pools", name: "BigPools", command: "windows.bigpools.BigPools" },
  { category: "Memory & Pools", name: "Memmap", command: "windows.memmap.Memmap" },
  { category: "Memory & Pools", name: "PoolScanner", command: "windows.poolscanner.PoolScanner" },
  { category: "Memory & Pools", name: "VadInfo", command: "windows.vadinfo.VadInfo" },
  { category: "Memory & Pools", name: "VadWalk", command: "windows.vadwalk.VadWalk" },
  { category: "Memory & Pools", name: "VadYaraScan", command: "windows.vadyarascan.VadYaraScan" },
  { category: "Memory & Pools", name: "VirtMap", command: "windows.virtmap.VirtMap" },

  // 3.2 Registry & Persistence
  { category: "Registry Analysis", name: "HiveList", command: "windows.registry.hivelist.HiveList" },
  { category: "Registry Analysis", name: "HiveScan", command: "windows.registry.hivescan.HiveScan" },
  { category: "Registry Analysis", name: "PrintKey", command: "windows.registry.printkey.PrintKey" },
  { category: "Registry Analysis", name: "UserAssist", command: "windows.registry.userassist.UserAssist" },
  { category: "Registry Analysis", name: "Certificates", command: "windows.registry.certificates.Certificates" },
  { category: "Registry Analysis", name: "AmCache", command: "windows.registry.amcache.AmCache" },
  { category: "Registry Analysis", name: "ShimCache", command: "windows.registry.shimcache.ShimCache" },

  // 3.3 Processes & Threads
  { category: "Process Analysis", name: "PsList", command: "windows.pslist.PsList" },
  { category: "Process Analysis", name: "PsTree", command: "windows.pstree.PsTree" },
  { category: "Process Analysis", name: "PsScan", command: "windows.psscan.PsScan" },
  { category: "Process Analysis", name: "ThrdScan", command: "windows.thrdscan.ThrdScan" },
  { category: "Process Analysis", name: "Sessions", command: "windows.sessions.Sessions" },

  // 3.4 DLLs, Modules, Drivers
  { category: "DLLs & Drivers", name: "DllList", command: "windows.dlllist.DllList" },
  { category: "DLLs & Drivers", name: "Modules", command: "windows.modules.Modules" },
  { category: "DLLs & Drivers", name: "ModScan", command: "windows.modscan.ModScan" },
  { category: "DLLs & Drivers", name: "DriverScan", command: "windows.driverscan.DriverScan" },
  { category: "DLLs & Drivers", name: "DriverModule", command: "windows.drivermodule.DriverModule" },
  { category: "DLLs & Drivers", name: "DriverIrp", command: "windows.driverirp.DriverIrp" },
  { category: "DLLs & Drivers", name: "IAT", command: "windows.iat.IAT" },
  { category: "DLLs & Drivers", name: "VerInfo", command: "windows.verinfo.VerInfo" },

  // 3.5 Malware Analysis
  { category: "Malware Analysis", name: "Malfind", command: "windows.malfind.Malfind" },
  { category: "Malware Analysis", name: "YaraScan", command: "yarascan.YaraScan" },
  { category: "Malware Analysis", name: "MFTScan", command: "windows.mftscan.MFTScan" },
  { category: "Malware Analysis", name: "ADS", command: "windows.mftscan.ADS" },
  { category: "Malware Analysis", name: "Skeleton Key Check", command: "windows.skeleton_key_check.Skeleton_Key_Check" },
  { category: "Malware Analysis", name: "TrueCrypt Passphrase", command: "windows.truecrypt.Passphrase" },

  // 3.6 User Accounts & Creds
  { category: "Users & Creds", name: "Hashdump", command: "windows.hashdump.Hashdump" },
  { category: "Users & Creds", name: "Cachedump", command: "windows.cachedump.Cachedump" },
  { category: "Users & Creds", name: "Lsadump", command: "windows.lsadump.Lsadump" },
  { category: "Users & Creds", name: "GetSIDs", command: "windows.getsids.GetSIDs" },
  { category: "Users & Creds", name: "Privileges", command: "windows.privileges.Privs" },

  // 3.7 File System
  { category: "File System", name: "FileScan", command: "windows.filescan.FileScan" },
  { category: "File System", name: "DumpFiles", command: "windows.dumpfiles.DumpFiles" },
  { category: "File System", name: "Strings", command: "windows.strings.Strings" },
  { category: "File System", name: "SymlinkScan", command: "windows.symlinkscan.SymlinkScan" },

  // 3.8 Networking
  { category: "Networking", name: "NetScan", command: "windows.netscan.NetScan" },
  { category: "Networking", name: "NetStat", command: "windows.netstat.NetStat" },

  // 3.9 System Info & Misc
  { category: "System Info", name: "Info", command: "windows.info.Info" },
  { category: "System Info", name: "CmdLine", command: "windows.cmdline.CmdLine" },
  { category: "System Info", name: "Envars", command: "windows.envars.Envars" },
  { category: "System Info", name: "SvcScan", command: "windows.svcscan.SvcScan" },
  { category: "System Info", name: "Callbacks", command: "windows.callbacks.Callbacks" },
  { category: "System Info", name: "Handles", command: "windows.handles.Handles" },
  { category: "System Info", name: "SSDT", command: "windows.ssdt.SSDT" },
];

// --- PART 2: THE CONTENT DESCRIPTIONS (MAIN VIEW) ---
export const PREDEFINED_PLUGIN_CONTENT: Record<string, string> = {
  
  // --- SYSTEM INFO ---
  "Info": `
# Windows.Info.Info

**Purpose:** Establishes the OS, architecture, and Kernel Base Address.

### Syntax
\`vol.py -f <image> windows.info.Info\`

### Malware Detection Focus (Triage)
- **Context Validation:** Essential for verifying the image profile.
- **Kernel Base Address:** Defines the legitimate memory space (\`ntoskrnl.exe\`) against which all kernel pointers (SSDT/Callbacks) are measured for anomaly (hooking).
- **Critical Check:** Confirms successful loading of the **NT Symbol Table**. Failure may indicate anti-forensic measures or an inability to run core kernel plugins.
`,

  "CmdLine": `
# Windows.CmdLine.CmdLine

**Purpose:** Lists the full Command Line Arguments used to launch processes (PID, Name, Args).

### Syntax
\`vol.py -f <image> windows.cmdline.CmdLine\`

### Malware Detection Focus (Triage)
- **Primary Tool:** Essential for post-exploitation analysis.
- **LOLBins:** Watch for misuse of legitimate binaries (\`powershell.exe\`, \`wmic.exe\`).
- **Base64 Encoding:** Look for long, unreadable strings and flags like \`-EncodedCommand\`.
- **Obfuscation:** Excessive or meaningless tokens designed to bypass simple detection.
- **Action:** Immediately decode Base64 strings to reveal the true payload/C2 URL.
`,

  "Envars": `
# Windows.Envars.Envars

**Purpose:** Lists Environment Variables (Name and Value) for all running processes.

### Syntax
\`vol.py -f <image> windows.envars.Envars\`

### Malware Detection Focus (Triage)
- **Persistence:** Finds stealthy, low-footprint persistence.
- **DLL Search Order Hijacking (DLL SOH):** Check for manipulation of the \`PATH\` variable to prepend a malicious directory.
- **Indicator:** Variables containing C2 IPs, specific file paths for payloads, or decryption keys.
`,

  "SvcScan": `
# Windows.SvcScan.SvcScan

**Purpose:** Enumerates all registered Windows Services.

### Syntax
\`vol.py -f <image> windows.svcscan.SvcScan\`

### Malware Detection Focus (Triage)
- **Mechanism:** Highly favored malware persistence mechanism.
- **Binary Path Validation:** Ensure path points to standard, protected directories (e.g., \`C:\\Windows\\System32\`).
- **Shared Service Abuse:** If Service Type is \`SERVICE_WIN32_SHARE_PROCESS\` hosted by \`svchost.exe\`, check the Registry for a malicious \`ServiceDll\` (requires follow-up with \`windows.registry.printkey\`).
- **Indicators:** Services in a **Stopped** state but configured for **Automatic** start (staged payload), and suspicious names/misspellings.
`,

  "Handles": `
# Windows.Handles.Handles

**Purpose:** Lists all Kernel Object Handles held by processes (Type, Name, Granted Access).

### Syntax
\`vol.py -f <image> windows.handles.Handles\`

### Malware Detection Focus (Triage)
- **Insight:** Reveals Inter-Process Communication (IPC) and permission manipulation (precursors to injection).
- **Injection Precursors:** Low-privilege process holding a handle of type \`Process\` pointing to a system process (e.g., \`lsass.exe\`).
- **Suspicious Access Masks:** Look for \`PROCESS_ALL_ACCESS\` (often \`0x1F0FFF\`) on Process handles, indicating the capability to perform injection/hollowing.
- **Indicators:** \`Mutant\`/\`Event\` handles with unique, non-system strings, signaling C2 or single-instance execution.
`,

  "SSDT": `
# Windows.SSDT.SSDT

**Purpose:** Inspects the System Service Descriptor Table (SSDT).

### Syntax
\`vol.py -f <image> windows.ssdt.SSDT\`

### Malware Detection Focus (Triage)
- **Mechanism:** Detects classic, high-impact rootkit techniques (Ring 0 compromise).
- **Rootkit Hooking:** Check for an Address pointing to a memory location **outside** the expected range of the legitimate kernel module (\`ntoskrnl.exe\`), defined by the Kernel Base Address.
- **Target Functions:** Hooks on functions like \`NtQuerySystemInformation\` or \`NtQueryDirectoryFile\` are used to hide processes, files, or registry keys.
`,

  "Callbacks": `
# Windows.Callbacks.Callbacks

**Purpose:** Lists legitimate Driver Notification Routines registered for system events.

### Syntax
\`vol.py -f <image> windows.callbacks.Callbacks\`

### Malware Detection Focus (Triage)
- **Mechanism:** Detects modern, stealthy rootkit persistence (post-PatchGuard era).
- **Notification Hook:** A Callback Address pointing to a function within an **unknown driver** or **unbacked memory**.
- **Target Types:** 
    1. **Process/Thread Callbacks:** Used to hide creation.
    2. **Image Load Callbacks:** Used for userland API unhooking and anti-forensics.
`,

  // --- PROCESS ANALYSIS ---
  "PsList": `
# Windows.PsList.PsList (The Official View)

**Purpose:** Lists active processes by walking the doubly-linked list of \`EPROCESS\` structures. This is the list the operating system uses.

### Syntax
\`vol.py -f <dump> windows.pslist\`

### The Baseline Test
Used to establish the known-good state. It's the fastest way to spot simple "typo-squatting" (e.g., \`scvhost.exe\` instead of \`svchost.exe\`). Any process missing from this list is considered hidden.
`,

  "PsScan": `
# Windows.PsScan.PsScan (The Deep Scan)

**Purpose:** Scans the raw kernel memory for \`EPROCESS\` objects using specific pool tags. It does not rely on the official OS list.

### Syntax
\`vol.py -f <dump> windows.psscan\`

### High-Confidence Confirmation (The "Invisible Man" Test)
**DKOM (Direct Kernel Object Manipulation):** A process that appears in \`psscan\` but is **MISSING** from \`pslist\` is a definitive indicator of a rootkit. The malware is physically in memory but has "cut the rope" (unlinked itself) from the official list to achieve invisibility.
`,

  "PsTree": `
# Windows.PsTree.PsTree (The Family Tree)

**Purpose:** Formats the process list into a parent-child hierarchy based on the Process ID (PID) and Parent Process ID (PPID).

### Syntax
\`vol.py -f <dump> windows.pstree\`

### High-Confidence Confirmation (The Orphan Test / PPID Spoofing)
Look for illogical parent-child relationships. If a web browser (\`chrome.exe\`) is spawned by a critical system process like \`lsass.exe\` (which should never happen), it confirms **PPID Spoofing**—malicious exploit behavior designed to hide the origin of the payload.
`,

  "ThrdScan": `
# Windows.ThrdScan.ThrdScan (The Pulse Check)

**Purpose:** Scans memory for \`ETHREAD\` structures. Since every process must have at least one thread to execute code, this finds the "heartbeat" of active code.

### Syntax
\`vol.py -f <dump> windows.thrdscan\`

### High-Confidence Confirmation (Process Hollowing Test)
**Ghost Processes:** If \`thrdscan\` finds threads belonging to a PID that is **MISSING** from both \`pslist\` and \`psscan\`, you have found a "ghost" process. This is often the result of **Process Hollowing**, where an attacker injects code into a legitimate process's memory space and executes it via a new thread.
`,

  "Sessions": `
# Windows.Sessions.Sessions (The Login Auditor)

**Purpose:** Lists active login sessions, the user/IP, and the associated processes.

### Syntax
\`vol.py -f <dump> windows.sessions\`

### High-Confidence Confirmation (Lateral Movement Test)
**Rogue Remote Session:** Look for a new session (e.g., Session 2) created from a remote IP address that is running a command shell (\`cmd.exe\` or \`powershell.exe\`). This is definitive proof of an attacker successfully logging in via RDP or WinRM and actively moving laterally within the network.
`,

  "Malfind": "# Windows.Malfind\n\nFinds hidden or injected code/DLLs in user mode memory. It scans for VAD tags that have `PAGE_EXECUTE_READWRITE` protection.\n\n### Usage\n`vol -f mem.raw windows.malfind`\n\n### Analysis Tips\nLook for memory sections that are executable but not backed by a file on disk.",
  
  // --- NETWORK ANALYSIS ---
  "NetScan": `
# Windows.NetScan.NetScan

**Purpose:** Scans for network connections and sockets.

### Syntax
\`vol.py -f <dump> windows.netscan\`

### Technical Advantage: Pool Scanning
This plugin **bypasses malware stealth** by not querying the kernel's easily-hooked network lists. Instead, it performs a deep scan of the entire kernel memory pools (specifically looking for \`_TCP_ENDPOINT\` and \`_UDP_ENDPOINT\` structures).

### Result
It finds "unlinked" or covert socket objects that rootkits leave behind, making it the most reliable method for discovering hidden C2 communication.

### Malware Triage (Correlation)
1. **State:** Look for connections in the **ESTABLISHED** state (active beaconing).
2. **Foreign Endpoint:** Triage the \`ForeignAddr\` and \`ForeignPort\`. Look for non-standard ports (4444, 4342) or known malicious IPs.
3. **Crucial Pivot:** Note the **PID**. This is the critical step to confirm the process context of the suspicious connection.
`,

  "NetStat": `
# Windows.NetStat.NetStat

**Purpose:** Verifies the integrity of standard network tracking structures.

### Syntax
\`vol.py -f <dump> windows.netstat\`

### The Contradiction Test
While \`netscan\` performs a deep memory sweep (Pool Scanning), \`netstat\` checks the official OS lists. Comparing them is key.

### High-Confidence Confirmation
**Rootkit Compromise:** A malicious connection will appear in the **NetScan** output but will be **ABSENT** or corrupted in the **NetStat** output.

**Conclusion:** This contradiction is definitive proof of a kernel-level anti-forensic maneuver. The rootkit successfully unlinked the socket to achieve invisibility, but the raw memory object remains, confirming Ring 0 compromise.
`,

  "Methodology": `
# Integrated Forensic Methodology
## The Full Confirmation Chain

The highest confidence in a finding is achieved when plugins align to show the full attack chain.

### 1. Discovery (NetScan)
**Action:** Identify an **ESTABLISHED** C2 connection.
**Key Artifact:** The suspicious **PID** associated with the socket.

### 2. Stealth Validation (The Contradiction)
**Action:** Run \`windows.netstat\`.
**Check:** Is the connection **Missing**?
**Result:** If missing in Netstat but present in Netscan, this confirms **Kernel-Level Anti-Forensics**.

### 3. Context Attribution (CmdLine)
**Action:** Run \`windows.cmdline\`.
**Check:** Did the PID launch with suspicious flags (e.g., \`-EncodedCommand\`) or from a temp path?

### 4. Final Confirmation (Malfind)
**Action:** Run \`windows.malfind\` on the PID.
**Result:** The PID confirmed to host the C2 connection (Netscan) is the same process containing the injected payload (Malfind). 

**Verdict:** Irrefutable evidence of a fileless or injected C2 channel.
`,

  // --- FILE SYSTEM ---
  "FileScan": `
# Windows.FileScan.FileScan

**Purpose:** Scans for file objects present in memory.

### Syntax
\`vol.py -f <dump> windows.filescan\`

### Malware Triage (Confirmation)
- **Anomalous Paths:** Look for file object paths pointing to non-standard executable locations, such as temporary directories (\`%TEMP%\`) or user profile subdirectories.
- **Unlinked File Objects:** Files executed and immediately deleted will often appear here as objects without an existing disk reference. This provides the **only proof** that the file was ever executed.
- **Crucial Output:** This plugin yields the memory **Offset** of the file object, which is required for extraction via \`dumpfiles\`.
`,

  "DumpFiles": `
# Windows.DumpFiles.DumpFiles

**Purpose:** Extracts binary files (EXE/DLL) from memory to disk for analysis.

### Syntax (Extracting File Object)
\`vol.py -f <dump> -o <output_dir> windows.dumpfiles --virtaddr <Offset>\`
*(Use the Offset obtained from windows.filescan)*

### Syntax (Extracting Process Image)
\`vol.py -f <dump> -o <output_dir> windows.dumpfiles --pid <PID>\`

### High-Confidence Attribution
- **Evidence:** The output is a raw binary file.
- **Next Steps:** The extracted payload is the core evidence needed for **Signature Verification** against YARA rulesets and in-depth **Static Analysis** (strings, disassembly) to confirm family attribution (e.g., Meterpreter, Ransomware).
`,

  "Strings": `
# Windows.Strings.Strings

**Purpose:** Maps textual data found in memory back to its process context (PID, Process, String).

### Syntax
\`vol.py -f <dump> windows.strings\`

### Malware Triage (Operational Intent)
- **C2 Parameters:** Reveals hardcoded C2 IP addresses, domain names, base URLs, or unique HTTP user-agent strings.
- **Execution Artifacts:** Exposes internal malware commands (e.g., \`GET /beacon.php?id=\`), mutex names, or internal file paths used during decryption routines.
- **Decrypted Data:** Can capture plaintext configuration blocks, ransomware file extension lists, or registry keys that were only decrypted in memory.
`,

  "SymlinkScan": `
# Windows.SymlinkScan.SymlinkScan

**Purpose:** Scans for symbolic links (\`_OBJECT_SYMBOLIC_LINK\`) that can redirect object resolution.

### Syntax
\`vol.py -f <dump> windows.symlinkscan\`

### Malware Triage (Advanced Stealth)
- **Persistence via Redirection:** A malicious link can redirect a legitimate system path (\`LinkName\`) to a location controlled by the malware (\`TargetName\`), effectively tricking the OS into executing a malicious file.
- **High-Confidence Finding:** The presence of a symbolic link pointing to a suspicious or non-canonical directory confirms a persistence mechanism that actively masks the malware’s true location or identity.
`,

  // --- CREDENTIALS & PRIVILEGES ---
  "Hashdump": `
# Windows.Hashdump.Hashdump (Local Accounts)

**Purpose:** Extracts NTLM and LM password hashes from the SAM and SYSTEM hives stored in memory.

### Syntax
\`vol.py -f <dump> windows.hashdump\`

### The Persistence Test
- **Shadow Accounts:** Seeing a user (e.g., \`Support_Acc\`) that is not in the official user directory confirms an attacker-created backdoor account.
- **Hash Extraction:** A "Live" hash for a user who hasn't logged in recently indicates a **Pass-the-Hash** attack or a persistence mechanism.
`,

  "Cachedump": `
# Windows.Cachedump.Cachedump (Domain Accounts)

**Purpose:** Retrieves cached domain credentials (MSCASH/MSCASH2) used when a Domain Controller is unavailable.

### Syntax
\`vol.py -f <dump> windows.cachedump\`

### The Lateral Movement Test
- **High-Confidence Confirmation:** If the cache contains credentials for a **Domain Admin** found on a low-privilege workstation, it is a high-priority indicator of lateral movement and privilege escalation targeting these caches (often via tools like Mimikatz).
`,

  "Lsadump": `
# Windows.Lsadump.Lsadump (LSA Secrets)

**Purpose:** Dumps LSA (Local Security Authority) secrets, which can include service account passwords, DPAPI keys, and clear-text passwords.

### Syntax
\`vol.py -f <dump> windows.lsadump\`

### The "Crown Jewels" Test
- **Plaintext Exposure:** Finding a populated \`DefaultPassword\` field is definitive proof of poor security hygiene or a specialized configuration that malware abuses to maintain access after a reboot.
`,

  "GetSIDs": `
# Windows.GetSIDs.GetSIDs (Process Ownership)

**Purpose:** Maps every running process (PID) to the Security Identifier (SID) of the user who owns it.

### Syntax
\`vol.py -f <dump> windows.getsids\`

### The Impersonation Test
- **Standard:** System processes (\`svchost.exe\`, \`lsass.exe\`) must run under system SIDs (e.g., \`S-1-5-18\` for LocalSystem).
- **User-Land Injection:** If a critical system process (e.g., \`svchost.exe\` or \`lsass.exe\`) is shown as being owned by a standard user SID (e.g., \`S-1-5-21...-1001\`), the process has likely been hollowed or injected by malware to masquerade as a system service.
`,

  "Privileges": `
# Windows.Privileges.Privs (Process Rights)

**Purpose:** Displays the specific Rights (Privileges) assigned to a process token (e.g., ability to debug, load drivers).

### Syntax
\`vol.py -f <dump> windows.privileges\`

### The Escalation Test
- **Standard:** Standard applications (like Notepad) should only have basic privileges.
- **Privilege Escalation (Smoking Gun):** A non-system process showing \`SeDebugPrivilege\` or \`SeLoadDriverPrivilege\` as **Enabled** is a definitive indicator. The malware has successfully bypassed UAC or exploited a vulnerability to gain the rights needed to inject code into other processes or install a rootkit.
`
};