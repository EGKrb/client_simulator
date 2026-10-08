#ifndef DLL_LOADER_H
#define DLL_LOADER_H

#include "nightshift.h"

#define NS_MAX_SYMBOLS 8192
#define NS_MAX_SYM_NAME 128

typedef struct {
    char name[NS_MAX_SYM_NAME];
    DWORD_PTR addr;   /* absolute VA as recorded in the map */
} NSSymbol;

typedef struct NSDllHandle {
    HMODULE module;
    DWORD_PTR base_address;
    DWORD size;
    char path[NS_MAX_PATH_LEN];
    int loaded;
    int mapped;       /* 1 if loaded via mapload (no DllMain) */
    NSSymbol symbols[NS_MAX_SYMBOLS];
    int sym_count;
} NSDllHandle;

typedef struct {
    DWORD magic;
    WORD machine;
    WORD num_sections;
    DWORD timestamp;
    DWORD symbol_table;
    DWORD num_symbols;
    WORD size_optional;
    WORD characteristics;
} NSPeHeader;

typedef struct {
    char name[8];
    DWORD virtual_size;
    DWORD virtual_address;
    DWORD raw_size;
    DWORD raw_offset;
    DWORD characteristics;
} NSPeSection;

int ns_dll_load(NSDllHandle *handle, const char *path);
int ns_dll_unload(NSDllHandle *handle);
int ns_dll_mapload(NSDllHandle *handle, const char *path);
int ns_sym_load(NSDllHandle *handle, const char *mapfile);
DWORD_PTR ns_sym_resolve(NSDllHandle *handle, const char *name);
FARPROC ns_dll_resolve(NSDllHandle *handle, const char *func_name);
FARPROC ns_dll_resolve_ordinal(NSDllHandle *handle, WORD ordinal);
FARPROC ns_dll_resolve_addr(NSDllHandle *handle, DWORD_PTR address);
int ns_pe_get_header(NSDllHandle *handle, NSPeHeader *header);
int ns_pe_get_sections(NSDllHandle *handle, NSPeSection sections[], int max_sections);
int ns_pe_find_section(NSDllHandle *handle, const char *name, NSPeSection *section);

#endif
