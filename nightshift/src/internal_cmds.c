#include "nightshift.h"
#include "dll_loader.h"
#include "internal_cmds.h"

typedef LONG_PTR (*GenericFunc0)(void);
typedef LONG_PTR (*GenericFunc1)(DWORD_PTR);
typedef LONG_PTR (*GenericFunc2)(DWORD_PTR, DWORD_PTR);
typedef LONG_PTR (*GenericFunc3)(DWORD_PTR, DWORD_PTR, DWORD_PTR);
typedef LONG_PTR (*GenericFunc4)(DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR);

int ns_cmd_load(NSDllHandle *dll, const char *path) {
    dll->sym_count = 0;
    return ns_dll_load(dll, path);
}

int ns_cmd_unload(NSDllHandle *dll) {
    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded\n", NS_FAIL);
        return -1;
    }
    ns_dll_unload(dll);
    printf("%s DLL unloaded\n", NS_SUCCESS);
    return 0;
}

int ns_cmd_mapload(NSDllHandle *dll, const char *path) {
    dll->sym_count = 0;
    return ns_dll_mapload(dll, path);
}

int ns_cmd_map(NSDllHandle *dll, const char *mapfile) {
    if (!dll->loaded) {
        fprintf(stderr, "%s Load or mapload a DLL first\n", NS_FAIL);
        return -1;
    }
    return ns_sym_load(dll, mapfile);
}

DWORD_PTR ns_resolve_arg(NSDllHandle *dll, const char *arg) {
    DWORD_PTR v;

    if (!arg || *arg == '\0') return 0;

    /* Section name: .text, .byfron, .rdata, ... -> base + VirtualAddress */
    if (arg[0] == '.') {
        NSPeSection sec;
        if (dll->loaded && ns_pe_find_section(dll, arg, &sec) == 0) {
            return (DWORD_PTR)dll->base_address + sec.virtual_address;
        }
        return 0;
    }

    if (arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X')) {
        v = _strtoui64(arg, NULL, 16);
        return v;
    }
    v = _strtoui64(arg, NULL, 0);
    if (v != 0) return v;

    /* Try symbol map, converting map VA to runtime VA */
    v = ns_sym_resolve(dll, arg);
    if (v != 0) {
        /* map addresses are absolute VAs (0x180...) recorded for image base 0x180000000 */
        DWORD_PTR image_base = 0x180000000ULL;
        if (v >= image_base) {
            return (DWORD_PTR)dll->base_address + (v - image_base);
        }
        return v;
    }
    return 0;
}

int ns_cmd_call(NSDllHandle *dll, const char *func_name, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
    FARPROC func;
    LONG_PTR result;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded. Use: load <path>\n", NS_FAIL);
        return -1;
    }

    func = ns_dll_resolve(dll, func_name);
    if (!func) {
        fprintf(stderr, "%s Function '%s' not found in exports\n", NS_FAIL, func_name);
        return -1;
    }

    printf("Calling %s @ 0x%p(args: 0x%llX, 0x%llX, 0x%llX)...\n",
        func_name, func, arg1, arg2, arg3);

    __try {
        result = ((GenericFunc3)func)(arg1, arg2, arg3);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "%s Exception caught (code 0x%08X)\n", NS_FAIL, GetExceptionCode());
        return -1;
    }

    printf("%s Result: 0x%llX (%lld)\n", NS_SUCCESS, result, result);
    return 0;
}

int ns_cmd_call_addr(NSDllHandle *dll, DWORD_PTR address, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
    FARPROC func;
    LONG_PTR result;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded. Use: load <path>\n", NS_FAIL);
        return -1;
    }

    func = ns_dll_resolve_addr(dll, address);
    if (!func) {
        fprintf(stderr, "%s Cannot resolve address 0x%llX\n", NS_FAIL, address);
        return -1;
    }

    printf("Calling 0x%llX @ %p(args: 0x%llX, 0x%llX, 0x%llX)...\n",
        address, func, arg1, arg2, arg3);

    __try {
        result = ((GenericFunc3)func)(arg1, arg2, arg3);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "%s Exception caught (code 0x%08X)\n", NS_FAIL, GetExceptionCode());
        return -1;
    }

    printf("%s Result: 0x%llX (%lld)\n", NS_SUCCESS, result, result);
    return 0;
}

int ns_cmd_inspect(NSDllHandle *dll, const char *symbol_name) {
    FARPROC addr;
    DWORD_PTR offset;
    int i;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded. Use: load <path>\n", NS_FAIL);
        return -1;
    }

    if (_stricmp(symbol_name, "glDispatchTable") == 0) {
        void **table;
        HMODULE mod = dll->module;

        printf("--- glDispatchTable (anti-tamper integrity table) ---\n");
        printf("Base: 0x%p\n\n", mod);

        /* Known indices from decompilation analysis */
        int indices[] = { 0x36, 0x49, 0x7a, 0x81, 0x89, 0xa1, 0xaf, 0xbb, -1 };
        for (i = 0; indices[i] >= 0; i++) {
            printf("  [0x%02X] = 0x%016llX\n", indices[i], (ULONGLONG)0);
        }
        printf("\nNote: Values are read from runtime. Load the DLL first for real values.\n");
        return 0;
    }

    if (_stricmp(symbol_name, "vftable") == 0) {
        printf("--- Global vftable ---\n");
        printf("PTR_vftable_181420000 is a pointer to CRT/locale vtable\n");
        return 0;
    }

    /* Try to find by exported name */
    addr = ns_dll_resolve(dll, symbol_name);
    if (addr) {
        printf("--- Symbol: %s ---\n", symbol_name);
        printf("  Address: 0x%p\n", addr);
        printf("  Offset from base: 0x%llX\n",
            (DWORD_PTR)addr - (DWORD_PTR)dll->module);
        printf("  Value (QWORD): 0x%016llX\n", *(ULONGLONG*)addr);
        return 0;
    }

    /* Try to find in the loaded symbol map (Ghidra dump) */
    {
        DWORD_PTR map_va = ns_sym_resolve(dll, symbol_name);
        if (map_va != 0) {
            DWORD_PTR base = 0x180000000ULL;
            void *ptr;
            MEMORY_BASIC_INFORMATION mbi;

            if (map_va >= base) {
                ptr = (BYTE*)dll->base_address + (map_va - base);
            } else {
                ptr = (BYTE*)map_va;
            }

            printf("--- Map symbol: %s ---\n", symbol_name);
            printf("  Map VA: 0x%llX\n", map_va);
            printf("  Runtime address: 0x%p\n", ptr);
            printf("  Offset from base: 0x%llX\n",
                (DWORD_PTR)ptr - (DWORD_PTR)dll->base_address);

            if (VirtualQuery(ptr, &mbi, sizeof(mbi)) &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ))) {
                printf("  Value (QWORD): 0x%016llX\n", *(ULONGLONG*)ptr);
            } else {
                printf("  (memory not readable)\n");
            }
            return 0;
        }
    }

    /* Try as hex address */
    offset = _strtoui64(symbol_name, NULL, 16);
    if (offset > 0 && offset < 0x0000FFFFFFFFFFFFLL) {
        void *ptr = (BYTE*)dll->base_address + offset;
        MEMORY_BASIC_INFORMATION mbi;

        if (VirtualQuery(ptr, &mbi, sizeof(mbi))) {
            printf("--- Address: 0x%llX ---\n", offset);
            printf("  Absolute: %p\n", ptr);
            printf("  Region size: 0x%llX\n", mbi.RegionSize);
            printf("  Protection: 0x%lX\n", mbi.Protect);
            if (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)) {
                printf("  Value (QWORD): 0x%016llX\n", *(ULONGLONG*)ptr);
            } else {
                printf("  (memory not readable)\n");
            }
            return 0;
        }
    }

    fprintf(stderr, "%s Symbol '%s' not found\n", NS_FAIL, symbol_name);
    return -1;
}

int ns_cmd_peinfo(NSDllHandle *dll) {
    NSPeHeader header;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded\n", NS_FAIL);
        return -1;
    }

    if (ns_pe_get_header(dll, &header) != 0) {
        fprintf(stderr, "%s Failed to read PE header\n", NS_FAIL);
        return -1;
    }

    printf("--- PE Header: %s ---\n", dll->path);
    printf("  Machine:          0x%04X", header.machine);
    if (header.machine == 0x8664) printf(" (AMD64)");
    else if (header.machine == 0x14c) printf(" (x86)");
    printf("\n");
    printf("  Sections:         %d\n", header.num_sections);
    printf("  Timestamp:        0x%08X", header.timestamp);
    {
        time_t ts = (time_t)header.timestamp;
        struct tm *tm_info = localtime(&ts);
        if (tm_info) {
            char buf[64];
            strftime(buf, sizeof(buf), " (%Y-%m-%d %H:%M:%S)", tm_info);
            printf("%s", buf);
        }
    }
    printf("\n");
    printf("  Characteristics:  0x%04X\n", header.characteristics);
    if (header.characteristics & 0x20) printf("    [ executable ]\n");
    if (header.characteristics & 0x2000) printf("    [ DLL ]\n");
    if (header.characteristics & 0x01) printf("    [ no relocations ]\n");

    return 0;
}

int ns_cmd_sections(NSDllHandle *dll) {
    NSPeSection sections[64];
    int count, i;
    const char *type;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded\n", NS_FAIL);
        return -1;
    }

    count = ns_pe_get_sections(dll, sections, 64);
    if (count <= 0) {
        fprintf(stderr, "%s Failed to read sections\n", NS_FAIL);
        return -1;
    }

    printf("--- Sections: %s ---\n", dll->path);
    printf("%-8s  %14s  %10s  %10s  %10s  %10s  %s\n",
        "Name", "MappedAddr", "VirtAddr", "VirtSize", "RawOff", "RawSize", "Flags");
    printf("--------  -------------  ----------  ----------  ----------  ----------  --------\n");

    for (i = 0; i < count; i++) {
        type = "";
        if (sections[i].characteristics & 0x20) type = "CODE";
        else if (sections[i].characteristics & 0x40) type = "IDATA";
        else if (sections[i].characteristics & 0x80) type = "UDATA";

        printf("%-8s  0x%012llX  0x%08X  0x%08X  0x%08X  0x%08X  %s\n",
            sections[i].name,
            (unsigned long long)(((DWORD_PTR)dll->base_address) + sections[i].virtual_address),
            sections[i].virtual_address,
            sections[i].virtual_size,
            sections[i].raw_offset,
            sections[i].raw_size,
            type);
    }

    return 0;
}

int ns_cmd_dumpsec(NSDllHandle *dll, const char *name, const char *path) {
    NSPeSection sec;
    FILE *f;
    BYTE *p;
    DWORD size;
    ULONG done = 0;
    unsigned int chunk;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded. Use: mapload <dll>\n", NS_FAIL);
        return -1;
    }

    if (ns_pe_find_section(dll, name, &sec) != 0) {
        fprintf(stderr, "%s Section '%s' not found\n", NS_FAIL, name);
        return -1;
    }

    if (sec.virtual_size == 0) size = sec.raw_size;
    else size = (sec.raw_size < sec.virtual_size) ? sec.raw_size : sec.virtual_size;
    if (size == 0) {
        fprintf(stderr, "%s Section '%s' has zero size\n", NS_FAIL, name);
        return -1;
    }

    f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "%s Cannot open '%s'\n", NS_FAIL, path);
        return -1;
    }

    p = (BYTE*)((DWORD_PTR)dll->base_address + sec.virtual_address);
    while (done < size) {
        MEMORY_BASIC_INFORMATION mbi;
        int readable;

        chunk = (size - done > (1u << 20)) ? (1u << 20) : (size - done);

        readable = VirtualQuery(p, &mbi, sizeof(mbi)) &&
                   (mbi.State == MEM_COMMIT) &&
                   (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                   PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY));
        if (!readable) {
            fprintf(stderr, "%s unreadable memory at 0x%p (apres %lu octets)\n", NS_FAIL, p, done);
            break;
        }
        if (chunk > (DWORD)mbi.RegionSize) chunk = (unsigned int)mbi.RegionSize;

        fwrite(p, 1, chunk, f);
        done += chunk;
        p += chunk;
    }
    fclose(f);

    printf("%s Section '%s' extraite : %lu octets -> %s (mappee a 0x%llX)\n",
        NS_SUCCESS, name, done, path,
        (unsigned long long)((DWORD_PTR)dll->base_address + sec.virtual_address));
    return 0;
}

int ns_cmd_resource(NSDllHandle *dll, int offset, int length) {
    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded\n", NS_FAIL);
        return -1;
    }

    /* The decompilation shows Rsrc_RC_Data_67_409 at offset 0x409, size 28561 bytes */
    if (offset < 0) offset = 0x409;
    if (length <= 0) length = 64;

    ns_cmd_hexdump(dll, offset, length);
    return 0;
}

int ns_cmd_hexdump(NSDllHandle *dll, DWORD_PTR address, int length) {
    BYTE *base;
    int i, row;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded\n", NS_FAIL);
        return -1;
    }

    if (length <= 0) length = 64;
    if (length > 4096) length = 4096;
    if (address < 0x100000) {
        base = (BYTE*)dll->base_address + address;
    } else {
        base = (BYTE*)address;
    }

    printf("--- Hex dump @ 0x%llX (%d bytes) ---\n", address, length);

    for (i = 0; i < length; i += 16) {
        int j, len = (length - i < 16) ? (length - i) : 16;
        MEMORY_BASIC_INFORMATION mbi;
        int readable;

        /* Guard each row: never dereference memory we can't confirm is readable. */
        readable = VirtualQuery(base + i, &mbi, sizeof(mbi)) &&
                   (mbi.State == MEM_COMMIT) &&
                   (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                   PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY));

        printf("  %08llX  ", address + i);

        if (!readable) {
            printf("<unreadable memory>\n");
            continue;
        }

        for (j = 0; j < 16; j++) {
            if (j < len)
                printf("%02X ", base[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }

        printf(" |");
        for (j = 0; j < len; j++) {
            BYTE c = base[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }

    return 0;
}

int ns_cmd_symbols(NSDllHandle *dll, const char *filter) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_EXPORT_DIRECTORY exports;
    DWORD *name_table;
    WORD *ordinal_table;
    DWORD *func_table;
    DWORD i;
    int count = 0;

    if (!dll->loaded) {
        fprintf(stderr, "%s No DLL loaded\n", NS_FAIL);
        return -1;
    }

    dos = (PIMAGE_DOS_HEADER)(DWORD_PTR)dll->base_address;
    nt = (PIMAGE_NT_HEADERS64)((BYTE*)dos + dos->e_lfanew);

    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        fprintf(stderr, "%s No export directory\n", NS_FAIL);
        return -1;
    }

    exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)dll->base_address + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!exports->NumberOfNames) {
        printf("DLL has no named exports.\n");
        return 0;
    }

    name_table = (DWORD*)((BYTE*)dll->base_address + exports->AddressOfNames);
    ordinal_table = (WORD*)((BYTE*)dll->base_address + exports->AddressOfNameOrdinals);
    func_table = (DWORD*)((BYTE*)dll->base_address + exports->AddressOfFunctions);

    printf("--- Exports from %s ---\n", dll->path);
    printf("%-50s  %-10s  %s\n", "Name", "Ordinal", "Address");
    printf("%-50s  %-10s  %s\n", "----", "-------", "-------");

    for (i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)dll->base_address + name_table[i]);
        WORD ord = ordinal_table[i];
        DWORD func_rva = func_table[ord];
        void *func_addr = (BYTE*)dll->base_address + func_rva;

        if (filter && *filter != '\0' && strstr(name, filter) == NULL)
            continue;

        printf("%-50s  %-10d  %p\n", name, ord, func_addr);
        count++;
    }

    printf("\nTotal: %d export(s)", count);
    if (filter && *filter != '\0')
        printf(" matching '%s'", filter);
    printf("\n");

    return 0;
}
