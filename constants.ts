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

  // 3.3 Processes & Threads
  { category: "Process Analysis", name: "PsList", command: "windows.pslist.PsList" },
  { category: "Process Analysis", name: "PsTree", command: "windows.pstree.PsTree" },
  { category: "Process Analysis", name: "PsScan", command: "windows.psscan.PsScan" },
  { category: "Process Analysis", name: "ThrdScan", command: "windows.thrdscan.ThrdScan" },
  { category: "Process Analysis", name: "Sessions", command: "windows.sessions.Sessions" },

  // 3.4 DLLs, Modules, Drivers
  { category: "DLLs & Drivers", name: "DllList", command: "windows.dlllist.DllList" },
  { category: "DLLs & Drivers", name: "LdrModules", command: "windows.ldrmodules.LdrModules" },
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

### Identifying Suspicious Flags (Red Flags)
**Common Suspicious Flags:**
- **-NoProfile:** Tells PowerShell to skip loading user profiles to avoid detection or logging.
- **-ExecutionPolicy Bypass:** Allows scripts to bypass the execution policy to run without restriction.
- **-WindowStyle Hidden:** Hides the window of the PowerShell or CMD process from the user.

### Example Suspicious Combination
\`powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Invoke-WebRequest ..."\`

**Analysis:** This command attempts to execute PowerShell with minimal user interaction and bypass security settings. This is typical behavior for malicious scripts like **downloaders**, **droppers**, or **webshells**.
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

  // --- REGISTRY ANALYSIS (Matched Images) ---
  "HiveList": `
# Windows.Registry.HiveList & HiveScan

**Purpose:** 
- **HiveList:** Identifies and lists the registry hives currently loaded in memory (Virtual/Physical addresses).
- **HiveScan:** Performs a raw scan for hive structures that might not be actively linked.

### Syntax
\`vol.py -f <dump> windows.registry.hivelist\`
\`vol.py -f <dump> windows.registry.hivescan\`

![HiveList Output](/registry.hivelist.png)

### The "Stealth Persistence" Test
Rootkits may hide registry hives containing their configuration data.

**High-Confidence Confirmation:** A hive found by **HiveScan** but **missing from HiveList** indicates a hidden registry-based configuration or "Registry-only" malware.
`,
  
  "HiveScan": `
# Windows.Registry.HiveList & HiveScan
*See HiveList for details.*

![HiveScan Output](/registry.hivelist.png)
`,

  "PrintKey": `
# Windows.Registry.PrintKey

**Purpose:** Displays the subkeys and values of a specific registry key without needing to extract the entire hive.

### Syntax
\`vol.py -f <dump> windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"\`

![PrintKey Output](/printkey.png)

### High-Confidence Confirmation
- **Persistence:** Checking the **Run** and **RunOnce** keys is the most common way to find malware that survives reboots.
- **Suspicious Locations:** Look for executables running from temporary folders like \`\\AppData\\Local\\\` instead of standard paths like \`\\Program Files\\\`.
`,

  "UserAssist": `
# Windows.Registry.UserAssist

**Purpose:** Extracts and decodes (ROT13) a registry key that tracks the execution of GUI-based applications.

### Syntax
\`vol.py -f <dump> windows.registry.userassist\`

### Example Output
| Application | Run Count | Last Used |
| :--- | :--- | :--- |
| cmd.exe | 15 | 2025-12-14 |
| mimikatz.exe | 1 | 2025-12-15 |

### The Evidence of Execution Test
**Timeline Reconstruction:** Even if an attacker deletes their tools, the UserAssist record often remains. Finding a credential dumper like \`mimikatz.exe\` with a "Run Count" of **1** is definitive proof of an interactive compromise.
`,

  "Certificates": `
# Windows.Registry.Certificates

**Purpose:** Lists certificates installed in the Certificate Store (Registry).

### Syntax
\`vol.py -f <dump> windows.registry.certificates.Certificates\`

### The "Man-in-the-Middle" Test
**Root Trust Poisoning:** Malware often installs a rogue **Root CA** to intercept HTTPS traffic without triggering browser warnings. Look for self-signed certificates or unknown authorities in the \`Root\` store.
`,

  // --- MEMORY & POOLS (Matched Images) ---
  "BigPools": `
# Windows.BigPools.BigPools

**Purpose:** Scans the PoolBigPageTable for "Big Page" allocations (typically >4KB).

### Syntax
\`vol.py -f <dump> windows.bigpools.BigPools\`

### The "Staging" Test
Malware often uses big pool allocations to stage large encrypted payloads or shellcode in kernel memory.

**High-Confidence Confirmation:** Look for large allocations (e.g., \`0x100000\` bytes) with suspicious or non-standard tags (like \`Leak\`, \`Frag\`, or unprintable characters).
`,

  "PoolScanner": `
# Windows.PoolScanner.PoolScanner

**Purpose:** Performs a raw scan for \`_POOL_HEADER\` structures to identify kernel objects unlinked from official system lists.

### Syntax
\`vol.py -f <dump> windows.poolscanner.PoolScanner\`

### The "Zombie" Test (DKOM)
This plugin finds "orphan" objects that \`pslist\` cannot see.

**High-Confidence Confirmation:** If PoolScanner finds a process object that does not appear in \`pslist\`, it is definitive proof of **Direct Kernel Object Manipulation (DKOM)** used by rootkits to achieve invisibility.
`,

  "VadInfo": `
# Windows.VadInfo / VadWalk / VadYaraScan

**Purpose:** 
- **VadInfo:** Lists Virtual Address Descriptors (VAD) showing memory ranges and permissions.
- **VadWalk:** Traverses the VAD tree to verify structural integrity.

### Syntax
\`vol.py -f <dump> windows.vadinfo.VadInfo --pid <PID>\`

![VadInfo Output](/vadinfo.png)

### The "RWX" Test
Legitimate applications rarely require memory that is simultaneously Writable and Executable.

**High-Confidence Confirmation:** A VAD range marked as **PAGE_EXECUTE_READWRITE (RWX)** in a system process is a primary indicator of code injection or a reflective DLL.
`,
  "VadWalk": `
# Windows.VadInfo / VadWalk / VadYaraScan
*See VadInfo for full details.*
`,
  "VadYaraScan": `
# Windows.VadInfo / VadWalk / VadYaraScan

**Purpose:** Scans specific VAD memory ranges for YARA signatures.

### Syntax
\`vol.py -f <dump> windows.vadyarascan.VadYaraScan --yara-rules "rule_name"\`

### The "Signature" Test
The most flexible tool for finding specific malware families in RAM.

**High-Confidence Confirmation:** A YARA hit on a private memory region (VAD) within a legitimate process confirms that malicious code is currently resident and active.
`,

  "Memmap": `
# Windows.Memmap & VirtMap

**Purpose:** \`Memmap\` prints the memory map. \`VirtMap\` maps the virtual address space layers.

### Syntax
\`vol.py -f <dump> windows.memmap.Memmap --pid <PID> --dump\`

### How to Spot Malware
- **Orphaned Memory:** Identify memory regions not backed by any file on disk but marked as executable.
- **Memory Extraction:** Use \`--dump\` to extract these suspicious regions for offline analysis with \`strings\` or a debugger.
`,
  "VirtMap": `
# Windows.Memmap & VirtMap
*See Memmap for full details.*
`,

  // --- SPECIALIZED MALWARE HUNTING ---
  "MFTScan": `
# Windows.MFTScan.MFTScan & ADS

**Purpose:** 
- **MFTScan:** Scans for Master File Table (MFT) record objects in memory.
- **ADS:** specifically looks for Alternate Data Streams.

### Syntax
\`vol.py -f <dump> windows.mftscan.MFTScan\`

### Malware Spotting
Threat actors often hide malicious payloads in **Alternate Data Streams** (e.g., \`legit.exe:hidden.exe\`) because standard file explorers do not show them. Finding unexpected ADSs is a high-confidence indicator of hidden tools.
`,
  "ADS": `
# Windows.MFTScan.MFTScan & ADS
*See MFTScan for full details.*
`,

  "Skeleton Key Check": `
# Windows.Skeleton_Key_Check

**Purpose:** Specifically looks for signs of the "Skeleton Key" malware, which backdoors Active Directory domain controllers.

### Syntax
\`vol.py -f <dump> windows.skeleton_key_check.SkeletonKeyCheck\`

### High-Confidence Confirmation
The plugin checks for specific hooks in the \`lsass.exe\` process. Any positive result means the entire domain’s authentication has been compromised.
`,

  "YaraScan": `
# Windows.YaraScan.YaraScan

**Purpose:** Scans the entire memory image (process or kernel space) for patterns defined in YARA rules.

### Syntax
\`vol.py -f <dump> windows.yarascan.YaraScan --yara-rules "rule_name"\`

### The "Signature" Test
This is the most flexible tool for finding specific malware families in RAM.

**High-Confidence Confirmation:** A YARA hit on a private memory region (VAD) within a legitimate process confirms that malicious code is currently resident and active in that process.
`,

  "TrueCrypt Passphrase": `
# Windows.TrueCrypt.Passphrase

**Purpose:** Attempts to find cached TrueCrypt or VeraCrypt passphrases within the kernel module's memory.

### Syntax
\`vol.py -f <dump> windows.truecrypt.Passphrase\`

### Malware Spotting
If an attacker has encrypted their exfiltrated data or local tools, this plugin may recover the key needed to decrypt the evidence.
`,

  // --- PROCESS ANALYSIS (Matched Images) ---
  "PsList": `
# Windows.PsList.PsList (The Official View)

**Purpose:** Lists active processes by walking the doubly-linked list of \`EPROCESS\` structures. This is the list the operating system uses.

### Syntax
\`vol.py -f <dump> windows.pslist\`

![PsList Output](/pslist.png)

### The Baseline Test
Used to establish the known-good state. It's the fastest way to spot simple "typo-squatting" (e.g., \`scvhost.exe\` instead of \`svchost.exe\`). Any process missing from this list is considered hidden.
`,

  "PsScan": `
# Windows.PsScan.PsScan (The Deep Scan)

**Purpose:** Scans the raw kernel memory for \`EPROCESS\` objects using specific pool tags.

### Syntax
\`vol.py -f <dump> windows.psscan\`

![PsScan Output](/psscan.png)

### High-Confidence Confirmation (The "Invisible Man" Test)
**DKOM:** A process that appears in \`psscan\` but is **MISSING** from \`pslist\` is a definitive indicator of a rootkit. The malware is physically in memory but has "cut the rope" (unlinked itself) from the official list.
`,

  "PsTree": `
# Windows.PsTree.PsTree (The Family Tree)

**Purpose:** Formats the process list into a parent-child hierarchy based on PID and PPID.

### Syntax
\`vol.py -f <dump> windows.pstree\`

![PsTree Output](/pstree.png)

### High-Confidence Confirmation (PPID Spoofing)
Look for illogical parent-child relationships. If a web browser (\`chrome.exe\`) is spawned by a critical system process like \`lsass.exe\` (which should never happen), it confirms **PPID Spoofing**—malicious exploit behavior.
`,

  "ThrdScan": `
# Windows.ThrdScan.ThrdScan (The Pulse Check)

**Purpose:** Scans memory for \`ETHREAD\` structures. Finds the "heartbeat" of active code.

### Syntax
\`vol.py -f <dump> windows.thrdscan\`

### High-Confidence Confirmation (Process Hollowing)
**Ghost Processes:** If \`thrdscan\` finds threads belonging to a PID that is **MISSING** from both \`pslist\` and \`psscan\`, you have found a "ghost" process. This is often the result of **Process Hollowing**.
`,

  "Sessions": `
# Windows.Sessions.Sessions (The Login Auditor)

**Purpose:** Lists active login sessions, the user/IP, and the associated processes.

### Syntax
\`vol.py -f <dump> windows.sessions\`

### High-Confidence Confirmation (Lateral Movement)
**Rogue Remote Session:** Look for a new session (e.g., Session 2) created from a remote IP address that is running a command shell (\`cmd.exe\` or \`powershell.exe\`). This is definitive proof of an attacker successfully logging in via RDP or WinRM.
`,

  // --- MALWARE & MODULES (Matched Images) ---
  "Malfind": `
# Windows.Malfind.Malfind

**Purpose:** Detects memory regions with signs of code injection (like VAD tags with RWX permissions).

### Syntax
\`vol.py -f <dump> windows.malfind\`

![Malfind Output](/malfind.png)

### The "MZ" Anomaly (Analysis Tip)
To quickly identify injected PE files (Executables/DLLs), pipe the output to grep:
\`vol.py -f <dump> windows.malfind | grep -C 5 'MZ'\`

### The Permissions Test (RWX)
**PAGE_EXECUTE_READWRITE:** In memory, only code sections should be executable, while data should be Read/Write. If a region is **Writable AND Executable**, it suggests code injection or self-modifying code.

### Troubleshooting (Offline/MobaXterm)
**Symbol Tables:** If you see errors regarding symbols, Volatility 3 cannot download the required JSON files due to lack of internet. Unlike Volatility 2, Vol 3 **requires** these symbols to resolve kernel structures.
`,

  "LdrModules": `
# Windows.LdrModules.LdrModules

**Purpose:** Detects unlinked or hidden DLLs by comparing the three internal lists the Windows Loader uses to track modules.

### Syntax
\`vol.py -f <dump> windows.ldrmodules\`

![LdrModules Output](/ldrmodules.png)

### The Unlinked DLL Test
Volatility checks three lists:
1. **InLoadOrder**
2. **InInitOrder**
3. **InMemOrder**

**Suspicious:** If a module shows:
- **InLoadOrder:** False
- **InInitOrder:** False
- **InMemOrder:** True

This means the DLL is present in memory but has been **unlinked** from the official lists to hide from standard monitoring tools.

### Forensic Workflow
1. **Identify:** Find PID with unlinked modules.
2. **Dump:** \`vol.py -f <dump> -o dump/ windows.dlldump --pid <PID>\`
3. **Verify:** Calculate hash (\`md5sum <file>\`) and submit to VirusTotal.
`,
  "DllList": `
# Windows.DllList.DllList

**Purpose:** Lists loaded modules for a specific process.

### Syntax
\`vol.py -f <dump> windows.dlllist --pid <PID>\`

![DllList Output](/dlllist.png)

### Analysis
Use this to cross-reference with **LdrModules**. If a DLL appears here, it is "officially" recognized. If it is missing here but found in memory scans, it is suspicious.
`,

  // --- KERNEL & DRIVERS (Matched Images) ---
  "Modules": `
# Windows.Modules.Modules

**Purpose:** Lists loaded kernel modules (drivers, .sys files) utilizing the standard doubly-linked list.

### Syntax
\`vol.py -f <dump> windows.modules.Modules\`

![Modules Output](/modules.png)

### Analysis
The "Official" list of loaded drivers. Compare this against **ModScan** or **DriverScan** to find hidden rootkits.
`,

  "ModScan": `
# Windows.ModScan.ModScan

**Purpose:** Scans kernel memory pools for \`_LDR_DATA_TABLE_ENTRY\` structures (Kernel Modules).

### Syntax
\`vol.py -f <dump> windows.modscan.ModScan\`

### The "Hidden Driver" Test
**DKOM:** If a driver appears in **ModScan** but is missing from **Modules**, it has unlinked itself to hide. This is standard behavior for kernel-mode rootkits.
`,

  "DriverScan": `
# Windows.DriverScan.DriverScan

**Purpose:** Scans memory for \`_DRIVER_OBJECT\` structures.

### Syntax
\`vol.py -f <dump> windows.driverscan.DriverScan\`

### Malware Triage
**Unbacked Code:** Look for driver objects that do not map to a file on disk or have invalid names. This suggests a driver was loaded directly from memory (Reflective Loading).
`,

  "DriverIrp": `
# Windows.DriverIrp.DriverIrp

**Purpose:** Checks the I/O Request Packet (IRP) function tables for drivers.

### Syntax
\`vol.py -f <dump> windows.driverirp.DriverIrp\`

### The "IRP Hooking" Test
**Rootkit Detection:** Drivers process system requests via IRP handlers. Rootkits hook these handlers to intercept data (e.g., keyloggers hooking the Keyboard Driver).
- **Red Flag:** An IRP function pointing to a memory address outside the legitimate driver's module range.
`,

  "DriverModule": `
# Windows.DriverModule.DriverModule

**Purpose:** Associates driver objects with their corresponding kernel modules.

### Syntax
\`vol.py -f <dump> windows.drivermodule.DriverModule\`

### Analysis
Helps attribute a specific suspicious driver object found in \`DriverScan\` to the specific \`.sys\` file (or lack thereof) responsible for it.
`,

  // --- PE & CODE ANALYSIS ---
  "IAT": `
# Windows.IAT.IAT (Import Address Table)

**Purpose:** Scans the Import Address Table of a process to detect hooking.

### Syntax
\`vol.py -f <dump> windows.iat.IAT --pid <PID>\`

### The "API Hooking" Test
**Userland Rootkits:** Malware modifies the IAT to redirect API calls (like \`WriteFile\` or \`ConnectSocket\`) to malicious code.
- **Detection:** Volatility checks if the IAT pointers resolve to the correct system DLLs or if they point to private/unknown memory regions.
`,

  "VerInfo": `
# Windows.VerInfo.VerInfo

**Purpose:** Extracts Version Information resources from PE files in memory.

### Syntax
\`vol.py -f <dump> windows.verinfo.VerInfo\`

### The "Masquerading" Test
**Fake System Files:** An attacker may name their malware \`svchost.exe\`. Use \`VerInfo\` to check the internal metadata (Company Name, Product Version).
- **Mismatch:** A file named \`svchost.exe\` but with "Company Name: RandomHacker" or missing a Microsoft digital signature block is confirmed malware.
`,

  // --- NETWORK ANALYSIS ---
  "NetScan": `
# Windows.NetScan.NetScan

**Purpose:** Scans for network connections and sockets using Pool Scanning.

### Syntax
\`vol.py -f <dump> windows.netscan\`

### Technical Advantage
Bypasses malware stealth by scanning kernel pools for \`_TCP_ENDPOINT\` structures rather than linked lists.

### Malware Triage
1. **State:** Look for **ESTABLISHED** connections.
2. **Pivot:** Note the **PID** to confirm the process context.
`,

  "NetStat": `
# Windows.NetStat.NetStat

**Purpose:** Verifies standard network tracking structures.

### Syntax
\`vol.py -f <dump> windows.netstat\`

### The Contradiction Test
**Rootkit Compromise:** A malicious connection present in **NetScan** but **ABSENT** in **NetStat** confirms kernel-level anti-forensics.
`,

  "Methodology": `
# Integrated Forensic Methodology
## The Full Confirmation Chain

### 1. Discovery (NetScan)
**Action:** Identify an **ESTABLISHED** C2 connection and PID.

### 2. Stealth Validation (The Contradiction)
**Action:** Run \`windows.netstat\`.
**Check:** Is the connection **Missing**? (Confirms Rootkit).

### 3. Context Attribution (CmdLine)
**Action:** Run \`windows.cmdline\`.
**Check:** Suspicious flags or temp paths?

### 4. Final Confirmation (Malfind)
**Action:** Run \`windows.malfind\` on the PID.
**Result:** PID hosting C2 also contains injected payload (RWX memory).
`,

  // --- FILE SYSTEM ---
  "FileScan": `
# Windows.FileScan.FileScan

**Purpose:** Scans for file objects present in memory.

### Syntax
\`vol.py -f <dump> windows.filescan\`

### Malware Triage
- **Unlinked File Objects:** Files executed and deleted will appear here as objects without a disk reference. This is often the **only proof** of execution.
- **Offset:** Yields the memory address needed for \`dumpfiles\`.
`,

  "DumpFiles": `
# Windows.DumpFiles.DumpFiles

**Purpose:** Extracts binary files (EXE/DLL) from memory to disk for analysis.

### Syntax
\`vol.py -f <dump> -o <output_dir> windows.dumpfiles --virtaddr <Offset>\`

### High-Confidence Attribution
The extracted payload is the core evidence needed for **Signature Verification** against YARA rulesets and in-depth **Static Analysis** (strings, disassembly) to confirm family attribution (e.g., Meterpreter, Ransomware).
`,

  "Strings": `
# Windows.Strings.Strings

**Purpose:** Maps textual data found in memory back to its process context (PID, Process, String).

### Syntax
\`vol.py -f <dump> windows.strings\`

### Malware Triage
- **C2 Parameters:** Reveals hardcoded C2 IP addresses, domain names, base URLs, or unique HTTP user-agent strings.
- **Execution Artifacts:** Exposes internal malware commands (e.g., \`GET /beacon.php?id=\`), mutex names, or internal file paths used during decryption routines.
- **Decrypted Data:** Can capture plaintext configuration blocks, ransomware file extension lists, or registry keys that were only decrypted in memory.
`,

  "SymlinkScan": `
# Windows.SymlinkScan.SymlinkScan

**Purpose:** Scans for symbolic links (\`_OBJECT_SYMBOLIC_LINK\`) that can redirect object resolution.

### Syntax
\`vol.py -f <dump> windows.symlinkscan\`

### Malware Triage
**Persistence via Redirection:** A malicious link can redirect a legitimate system path (\`LinkName\`) to a location controlled by the malware (\`TargetName\`), effectively tricking the OS into executing a malicious file.
`,

  // --- CREDENTIALS & PRIVILEGES ---
  "Hashdump": `
# Windows.Hashdump.Hashdump (Local Accounts)

**Purpose:** Extracts NTLM and LM password hashes from the SAM and SYSTEM hives stored in memory.

### Syntax
\`vol.py -f <dump> windows.hashdump\`

### Persistence Test
- **Shadow Accounts:** Seeing a user (e.g., \`Support_Acc\`) that is not in the official user directory confirms an attacker-created backdoor account.
- **Hash Extraction:** A "Live" hash for a user who hasn't logged in recently indicates a **Pass-the-Hash** attack or a persistence mechanism.
`,

  "Cachedump": `
# Windows.Cachedump.Cachedump (Domain Accounts)

**Purpose:** Retrieves cached domain credentials (MSCASH/MSCASH2) used when a Domain Controller is unavailable.

### Syntax
\`vol.py -f <dump> windows.cachedump\`

### Lateral Movement Test
Finding **Domain Admin** credentials on a low-privilege workstation is a high-priority indicator of lateral movement targeting caches.
`,

  "Lsadump": `
# Windows.Lsadump.Lsadump (LSA Secrets)

**Purpose:** Dumps LSA (Local Security Authority) secrets, which can include service account passwords, DPAPI keys, and clear-text passwords.

### Syntax
\`vol.py -f <dump> windows.lsadump\`

### The "Crown Jewels" Test
**Plaintext Exposure:** Finding a populated \`DefaultPassword\` field is definitive proof of poor security hygiene or a specialized configuration that malware abuses to maintain access after a reboot.
`,

  "GetSIDs": `
# Windows.GetSIDs.GetSIDs (Process Ownership)

**Purpose:** Maps every running process (PID) to the Security Identifier (SID) of the user who owns it.

### Syntax
\`vol.py -f <dump> windows.getsids\`

### How It Works
SIDs are unique identifiers for users, groups, or security principals. Each process is associated with a SID. This plugin allows you to verify if processes are executing under the **correct** or **expected** user accounts.

### Commonly Suspicious Indicators
1.  **Unexpected SID Changes:** A process changing its SID over time is a sign of **Privilege Escalation**.
2.  **Mismatch of User and Process:** If a critical system process (e.g., \`lsass.exe\`) is running under a standard user SID (e.g., \`S-1-5-21...\`) instead of System, it is a high-confidence indicator of **Process Hollowing** or malicious activity.
3.  **Unauthorized SIDs:** Any process running with a SID that doesn't belong to a known user should be flagged.

### How to Investigate Further
Once identified, check the **Process Hierarchy** (\`pstree\`). Often, malicious processes with strange SIDs are launched by legitimate processes (e.g., a Browser spawning a System-level shell).
`,

  "Privileges": `
# Windows.Privileges.Privs (Process Rights)

**Purpose:** Displays the specific Rights (Privileges) assigned to a process token (e.g., ability to debug, load drivers).

### Syntax
\`vol.py -f <dump> windows.privileges\`

### The Escalation Test
**Smoking Gun:** A non-system process showing \`SeDebugPrivilege\` or \`SeLoadDriverPrivilege\` as **Enabled** is a definitive indicator. The malware has successfully bypassed UAC or exploited a vulnerability to gain the rights needed to inject code into other processes or install a rootkit.
`
};