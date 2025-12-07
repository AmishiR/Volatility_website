import { PluginInfo } from './types';

export const INITIAL_CONTENT = `
## Volatility Framework
**Volatility** is a tool used for extraction of digital artifacts from volatile memory (RAM) samples. Volatility uses a set of plugins that can be used to extract these artifacts in a time efficient and quick manner.

## Featured Plugin: ldrmodules
**ldrmodules** – a volatility plugin that is used to detect unlinked DLLs.

From an incident response perspective, the volatile data residing inside the system's memory contains rich information such as passwords, credentials, network connections, malware intrusions, registry hives, and etc. that can be a valuable source of evidence and is not typically stored on the local hard disk. This is one of the investigator's favorite data sources to perform digital forensics on, and knowing the right tool to dump memory is a must.
`;

// ------------------------------------------------------------------
// MANUAL CONTENT OVERRIDES
// ------------------------------------------------------------------
// This is where you add your custom descriptions.
// 1. Find the plugin name in the list below (e.g., 'netscan', 'malfind').
// 2. Add a new key to this object with the EXACT plugin name.
// 3. Write your description in Markdown format inside backticks (`).
//
// If you leave a plugin out of this list, the app will automatically
// ask Gemini AI to generate the description for you.
// ------------------------------------------------------------------
export const PREDEFINED_PLUGIN_CONTENT: Record<string, string> = {
  // EXAMPLE 1: Manual content for 'ldrmodules'
  ldrmodules: `
# Plugin: ldrmodules

**Overview**: Detects unlinked DLLs and modules that are not present in the process loader lists.

**Usage**: Malware often unlinks itself from the doubly-linked lists (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList) in the PEB to hide from standard monitoring tools. \`ldrmodules\` cross-references these lists with the VAD (Virtual Address Descriptor) tree to find discrepancies.

**Syntax**: 
\`\`\`bash
vol.py -f image.mem --profile=Win10x64 ldrmodules --pid=1234
\`\`\`

**Output Analysis**:
- **InLoad**, **InInit**, **InMem**: Boolean columns indicating presence in the respective PEB lists.
- **MappedPath**: The path to the file on disk.
- **False** entries in the PEB columns for a mapped file often indicate hidden code injection or rootkit activity.
`,

  // EXAMPLE 2: Manual content for 'pslist'
  pslist: `
# Plugin: pslist

**Overview**: Lists the processes of a system by walking the doubly-linked list pointed to by \`PsActiveProcessHead\`.

**Usage**: This is the standard "Task Manager" view of memory. It is used to identify running processes, their PIDs, parent PIDs, and start times. Note that advanced rootkits can unlink themselves from this list (DKOM), making them invisible to \`pslist\`.

**Syntax**:
\`\`\`bash
vol.py -f image.mem --profile=Win10x64 pslist
\`\`\`
  `,

  // --- ADD YOUR NEW PLUGINS HERE ---
  
  // Example for netscan (uncomment and edit):
  /*
  netscan: `
# Plugin: netscan
**Overview**: Scans for connections and sockets.
**Usage**: Finding malware C2 connections.
  `,
  */
  
};

export const PLUGINS: PluginInfo[] = [
  { name: 'apihooks', category: 'malware' },
  { name: 'malfind', category: 'malware' },
  { name: 'callbacks', category: 'system' },
  { name: 'mftparser', category: 'system' },
  { name: 'cmdline', category: 'process' },
  { name: 'moddump', category: 'malware' },
  { name: 'cmdscan', category: 'process' },
  { name: 'modules', category: 'system' },
  { name: 'connections', category: 'network' },
  { name: 'netscan', category: 'network' },
  { name: 'consoles', category: 'process' },
  { name: 'printkey', category: 'system' },
  { name: 'dlllist', category: 'process' },
  { name: 'privs', category: 'process' },
  { name: 'dlldump', category: 'process' },
  { name: 'pslist', category: 'process' },
  { name: 'dumpregistry', category: 'system' },
  { name: 'pstree', category: 'process' },
  { name: 'filescan', category: 'system' },
  { name: 'psxview', category: 'process' },
  { name: 'getsids', category: 'process' },
  { name: 'symlinkscan', category: 'system' },
  { name: 'handles', category: 'process' },
  { name: 'vaddump', category: 'process' },
  { name: 'hivelist', category: 'system' },
  { name: 'vadinfo', category: 'process' },
  { name: 'imageinfo', category: 'misc' },
  { name: 'yarascan', category: 'malware' },
  { name: 'ldrmodules', category: 'malware' },
  { name: 'auditpol', category: 'system' },
  { name: 'dumpfiles', category: 'system' },
  { name: 'deskscan', category: 'system' },
  { name: 'strings', category: 'misc' },
  { name: 'wndscan', category: 'system' },
  { name: 'volshell', category: 'misc' },
];