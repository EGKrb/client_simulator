#include "nightshift.h"
#include "dll_loader.h"

int ns_dll_load(NSDllHandle *handle, const char *path) {
    memset(handle, 0, sizeof(NSDllHandle));

    handle->module = LoadLibraryA(path);
    if (!handle->module) {
        fprintf(stderr, "%s Cannot load DLL: %s (error %lu)\n", NS_FAIL, path, GetLastError());
        return -1;
    }

    handle->base_address = (DWORD_PTR)handle->module;
    strncpy(handle->path, path, NS_MAX_PATH_LEN - 1);
    handle->loaded = 1;

    printf("%s DLL loaded: %s at 0x%p\n", NS_SUCCESS, path, (void*)handle->module);
    return 0;
}

int ns_dll_mapload(NSDllHandle *handle, const char *path) {
    memset(handle, 0, sizeof(NSDllHandle));

    /* Map the image at its section VAs WITHOUT executing DllMain,
       bypassing anti-tamper init of protected DLLs. */
    handle->module = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!handle->module) {
        fprintf(stderr, "%s Cannot mapload DLL: %s (error %lu)\n", NS_FAIL, path, GetLastError());
        return -1;
    }

    /* The returned HMODULE of an image-resource mapping may not point at
       the image headers; locate the real image base from the owning region. */
    {
        MEMORY_BASIC_INFORMATION mbi;
        BYTE *scan = (BYTE*)handle->module;
        BYTE *image_base = NULL;

        if (VirtualQuery(scan, &mbi, sizeof(mbi)) && mbi.BaseAddress) {
            BYTE *region = (BYTE*)mbi.BaseAddress;
            int i;
            for (i = 0; i < 0x100; i++) {
                if (((PIMAGE_DOS_HEADER)(region + i))->e_magic == IMAGE_DOS_SIGNATURE) {
                    image_base = region + i;
                    break;
                }
            }
        }
        if (image_base)
            handle->base_address = (DWORD_PTR)image_base;
        else
            handle->base_address = (DWORD_PTR)handle->module;
    }

    strncpy(handle->path, path, NS_MAX_PATH_LEN - 1);
    handle->mapped = 1;
    handle->loaded = 1;

    printf("%s DLL mapped (no DllMain): %s at 0x%p (headers 0x%p)\n",
        NS_SUCCESS, path, (void*)handle->module, (void*)handle->base_address);
    return 0;
}

int ns_sym_load(NSDllHandle *handle, const char *mapfile) {
    FILE *f;
    char line[512];
    int count = 0;

    handle->sym_count = 0;

    f = fopen(mapfile, "r");
    if (!f) {
        fprintf(stderr, "%s Cannot open map file: %s\n", NS_FAIL, mapfile);
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p = ns_trim(line);
        char *name;
        unsigned long long val;

        if (*p == '\0' || *p == '#')
            continue;

        name = strchr(p, ' ');
        if (!name) name = strchr(p, '\t');
        if (!name) continue;
        *name++ = '\0';
        name = ns_trim(name);

        if (sscanf(p, "0x%llx", &val) != 1)
            continue;
        if (val == 0)
            continue;

        if (handle->sym_count >= NS_MAX_SYMBOLS)
            break;

        strncpy(handle->symbols[handle->sym_count].name, name, NS_MAX_SYM_NAME - 1);
        handle->symbols[handle->sym_count].name[NS_MAX_SYM_NAME - 1] = '\0';
        handle->symbols[handle->sym_count].addr = (DWORD_PTR)val;
        handle->sym_count++;
        count++;
    }

    fclose(f);
    printf("%s Loaded %d symbols from %s\n", NS_SUCCESS, count, mapfile);
    return count > 0 ? 0 : -1;
}

DWORD_PTR ns_sym_resolve(NSDllHandle *handle, const char *name) {
    int i;
    for (i = 0; i < handle->sym_count; i++) {
        if (_stricmp(handle->symbols[i].name, name) == 0)
            return handle->symbols[i].addr;
    }
    return 0;
}

int ns_dll_unload(NSDllHandle *handle) {
    if (!handle->loaded) return 0;

    if (handle->module) {
        if (handle->mapped)
            FreeLibrary(handle->module);  /* image-resource module: just unmap */
        else
            FreeLibrary(handle->module);
        handle->module = NULL;
    }
    handle->loaded = 0;
    handle->mapped = 0;
    return 0;
}

FARPROC ns_dll_resolve(NSDllHandle *handle, const char *func_name) {
    if (!handle->loaded) return NULL;
    return GetProcAddress(handle->module, func_name);
}

FARPROC ns_dll_resolve_ordinal(NSDllHandle *handle, WORD ordinal) {
    if (!handle->loaded) return NULL;
    return GetProcAddress(handle->module, (LPCSTR)(DWORD_PTR)ordinal);
}

FARPROC ns_dll_resolve_addr(NSDllHandle *handle, DWORD_PTR address) {
    DWORD_PTR base = (DWORD_PTR)handle->base_address;

    if (!handle->loaded) return NULL;

    if (address >= base && address < base + 0x10000000) {
        return (FARPROC)(DWORD_PTR)address;
    }

    if (address > 0 && address < 0x100000) {
        return (FARPROC)(DWORD_PTR)(base + address);
    }

    return (FARPROC)(DWORD_PTR)address;
}

int ns_pe_get_header(NSDllHandle *handle, NSPeHeader *header) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;

    if (!handle->loaded) return -1;

    dos = (PIMAGE_DOS_HEADER)(DWORD_PTR)handle->base_address;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;

    nt = (PIMAGE_NT_HEADERS64)((BYTE*)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;

    header->magic = nt->FileHeader.Machine;
    header->machine = nt->FileHeader.Machine;
    header->num_sections = nt->FileHeader.NumberOfSections;
    header->timestamp = nt->FileHeader.TimeDateStamp;
    header->symbol_table = nt->FileHeader.PointerToSymbolTable;
    header->num_symbols = nt->FileHeader.NumberOfSymbols;
    header->size_optional = nt->FileHeader.SizeOfOptionalHeader;
    header->characteristics = nt->FileHeader.Characteristics;

    return 0;
}

int ns_pe_get_sections(NSDllHandle *handle, NSPeSection sections[], int max_sections) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_SECTION_HEADER sec;
    int i, count;

    if (!handle->loaded) return -1;

    dos = (PIMAGE_DOS_HEADER)(DWORD_PTR)handle->base_address;
    nt = (PIMAGE_NT_HEADERS64)((BYTE*)dos + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);

    count = nt->FileHeader.NumberOfSections;
    if (count > max_sections) count = max_sections;

    for (i = 0; i < count; i++) {
        memcpy(sections[i].name, sec[i].Name, 8);
        sections[i].virtual_size = sec[i].Misc.VirtualSize;
        sections[i].virtual_address = sec[i].VirtualAddress;
        sections[i].raw_size = sec[i].SizeOfRawData;
        sections[i].raw_offset = sec[i].PointerToRawData;
        sections[i].characteristics = sec[i].Characteristics;
    }

    return count;
}

int ns_pe_find_section(NSDllHandle *handle, const char *name, NSPeSection *section) {
    NSPeSection sections[64];
    int count, i;

    count = ns_pe_get_sections(handle, sections, 64);
    if (count <= 0) return -1;

    for (i = 0; i < count; i++) {
        if (strncmp(sections[i].name, name, 8) == 0) {
            *section = sections[i];
            return 0;
        }
    }
    return -1;
}
