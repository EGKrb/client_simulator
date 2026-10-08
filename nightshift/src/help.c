#include "nightshift.h"

void ns_print_version(void) {
    printf("NightShift v%s - Microsoft Dynamics GP CLI + DLL Internal Commands\n", NS_VERSION);
}

void ns_print_help(void) {
    ns_print_version();
    printf("\nUsage: nightshift.exe [command] [options]\n\n");

    printf("=== GP Commands ===\n");
    printf("  login <user> <pass> [company]   Log in as specified user\n");
    printf("  login <alias>                   Log in using alias from aliases.txt\n");
    printf("  sql \"<query>\"                   Execute SQL query\n");
    printf("  batch <file>                    Process batch file\n");
    printf("  reset                           Reset current session\n");
    printf("  aliases                         List configured aliases\n");
    printf("  terminate                       Exit Dynamics GP\n");

    printf("\n=== DLL Commands ===\n");
    printf("  load <path>                     Load a DLL into memory\n");
    printf("  mapload <path>                  Map DLL without running DllMain (bypasses anti-tamper)\n");
    printf("  map <file>                      Load symbol map (Ghidra dump) for calladdr/inspect\n");
    printf("  unload                          Unload the current DLL\n");
    printf("  symbols [filter]                List DLL exports (optional filter)\n");
    printf("  call <func> [arg1] [arg2] [arg3] Call exported function\n");
    printf("  calladdr <sym|0xADDR> [a1..a3]   Call function at address (name or hex)\n");
    printf("  inspect <symbol|0xADDR>         Read memory/value at address\n");
    printf("  peinfo                          Show PE header info\n");
    printf("  sections                        Show PE section table\n");
    printf("  resource [offset] [length]      Dump embedded resource data\n");
    printf("  hexdump <sym|0xADDR|.section> [length]  Hex dump memory (name, hex, section)\n");
    printf("  dumpsec <.section> <file>       Extract a whole section to a binary file\n");

    printf("\n=== System ===\n");
    printf("  version                         Show version\n");
    printf("  help                            Show this help\n");

    printf("\nBatch File Format:\n");
    printf("  SQL:<query>                     Execute SQL\n");
    printf("  LOGIN:<alias>                   Switch user\n");
    printf("  CMD:<command>                   Execute command\n");
    printf("  #<comment>                      Comment line (ignored)\n");
    printf("  WAIT:<ms>                       Pause execution\n");

    printf("\nAlias File (aliases.txt) Format:\n");
    printf("  alias_name|username|password|company\n");

    printf("\nDLL Usage Examples:\n");
    printf("  load My_dll.dll                 Load the decompiled DLL\n");
    printf("  symbols                         List all exports\n");
    printf("  symbols Func                    Filter exports by name\n");
    printf("  call FuncName 0x1 0x2 0x3       Call with 3 args\n");
    printf("  calladdr 0x180CBBDC8            Call at specific address\n");
    printf("  inspect glDispatchTable         Read integrity table\n");
    printf("  inspect 0x181422750             Read address value\n");
    printf("  hexdump 0 128                   Dump first 128 bytes of DLL\n");
}
