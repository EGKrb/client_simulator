#ifndef INTERNAL_CMDS_H
#define INTERNAL_CMDS_H

#include "nightshift.h"
#include "dll_loader.h"

int ns_cmd_load(NSDllHandle *dll, const char *path);
int ns_cmd_unload(NSDllHandle *dll);
int ns_cmd_mapload(NSDllHandle *dll, const char *path);
int ns_cmd_map(NSDllHandle *dll, const char *mapfile);
int ns_cmd_call(NSDllHandle *dll, const char *func_name, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3);
int ns_cmd_call_addr(NSDllHandle *dll, DWORD_PTR address, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3);
DWORD_PTR ns_resolve_arg(NSDllHandle *dll, const char *arg);
int ns_cmd_inspect(NSDllHandle *dll, const char *symbol_name);
int ns_cmd_peinfo(NSDllHandle *dll);
int ns_cmd_sections(NSDllHandle *dll);
int ns_cmd_resource(NSDllHandle *dll, int offset, int length);
int ns_cmd_hexdump(NSDllHandle *dll, DWORD_PTR address, int length);
int ns_cmd_dumpsec(NSDllHandle *dll, const char *name, const char *path);
int ns_cmd_symbols(NSDllHandle *dll, const char *filter);

#endif
