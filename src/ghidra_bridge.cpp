#include "ghidra_bridge.hpp"

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

// Racine du projet client_simulator = dossier parent du dossier contenant
// l'executable (bin\MonNouvelApp.exe -> C:\client_simulator).
fs::path ProjectRoot() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return fs::path("C:\\client_simulator");
    fs::path exe(buf);
    return exe.parent_path().parent_path();
}

fs::path VenvPython() {
    // 1) Surcharge explicite via la variable d'environnement GHIDRA_RPC_PYTHON.
    wchar_t buf[32768];
    DWORD n = GetEnvironmentVariableW(L"GHIDRA_RPC_PYTHON", buf, 32768);
    if (n > 0 && n < 32768 && fs::exists(buf)) return fs::path(buf);
    // 2) venv cree par build_monnouvelapp.bat.
    fs::path venv = ProjectRoot() / "ghidra-rpc" / ".venv" / "Scripts" / "python.exe";
    if (fs::exists(venv)) return venv;
    return {};
}

bool HasGhidraMarker(const fs::path& dir) {
    return fs::exists(dir / "ghidraRun.bat") || fs::exists(dir / "ghidraRun");
}

std::string DetectGhidraInstall() {
    // 1) Deja defini dans l'environnement.
    {
        char buf[32768];
        DWORD n = GetEnvironmentVariableA("GHIDRA_INSTALL_DIR", buf, 32768);
        if (n > 0 && n < 32768) return std::string(buf);
    }
    // 2) C:\Users\<user>\ghidra\ghidra_*_PUBLIC
    {
        wchar_t profile[32768];
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", profile, 32768);
        if (n > 0 && n < 32768) {
            std::error_code ec;
            fs::path gdir = fs::path(profile) / "ghidra";
            if (fs::exists(gdir)) {
                std::vector<fs::path> hits;
                for (const auto& e : fs::directory_iterator(gdir, ec))
                    if (e.is_directory() && HasGhidraMarker(e.path()))
                        hits.push_back(e.path());
                if (!hits.empty()) {
                    std::sort(hits.begin(), hits.end());
                    return hits.back().string();
                }
            }
        }
    }
    // 3) Program Files\Ghidra\* (auto-extrait au format ghidra_*_PUBLIC).
    {
        const char* pfd = std::getenv("ProgramFiles");
        if (pfd) {
            std::error_code ec;
            fs::path gdir = fs::path(pfd) / "Ghidra";
            if (fs::exists(gdir)) {
                for (const auto& e : fs::directory_iterator(gdir, ec))
                    if (e.is_directory() && HasGhidraMarker(e.path()))
                        return e.path().string();
            }
        }
    }
    return {};
}

// Quote un argument unique pour CreateProcess (CommandLineToArgvW compatible).
std::string QuoteArg(const std::string& a) {
    if (a.find_first_of(" \t\"") == std::string::npos) return a;
    std::string out = "\"";
    for (char c : a) {
        if (c == '"') out += "\\\"";
        else out += c;
    }
    return out + "\"";
}

}  // namespace

void PrintGhidraUsage() {
    std::printf(
        "Mode ghidra-rpc integre : MonNouvelApp.exe --ghidra <sous-commande> [args...]\n"
        "\n"
        "Execute la commande equivalente du CLI ghidra-rpc (package Python 0.2.0\n"
        "vendorise dans C:\\client_simulator\\ghidra-rpc) et affiche le JSON renvoye.\n"
        "Le daemon Ghidra tourne en arriere-plan (PyGhidra + JVM) et reste chaud\n"
        "entre les commandes : chaque projet .gpr possede son propre endpoint.\n"
        "\n"
        "Sous-commandes principales (voir --ghidra --help pour la liste complete) :\n"
        "  MonNouvelApp.exe --ghidra start   --project <fichier.gpr> [--headless|--detach]\n"
        "  MonNouvelApp.exe --ghidra status  --project <fichier.gpr>\n"
        "  MonNouvelApp.exe --ghidra stop    --project <fichier.gpr>\n"
        "  MonNouvelApp.exe --ghidra list-instances\n"
        "  MonNouvelApp.exe --ghidra load    --project <fichier.gpr> <chemin-binaire>\n"
        "  MonNouvelApp.exe --ghidra decompile --project <fichier.gpr> <binaire> <fonction>\n"
        "  MonNouvelApp.exe --ghidra xrefs-to --project <fichier.gpr> <binaire> <symbole>\n"
        "  MonNouvelApp.exe --ghidra strings --project <fichier.gpr> <binaire> [filtre]\n"
        "  MonNouvelApp.exe --ghidra rename-function --project <fichier.gpr> <binaire> <ancien> <nouveau>\n"
        "  MonNouvelApp.exe --ghidra mcp    --project <fichier.gpr>  (serveur MCP stdio)\n"
        "\n"
        "En tout, ~80 commandes ghidra-rpc sont disponibles : decompile, disassemble,\n"
        "basic-blocks, pcode, functions, imports, exports, search-decompiled, find-bytes,\n"
        "read-bytes, write-bytes, set-comment, set-signature, version-track, list-vtable,\n"
        "memory-map, tags, data-types, cancellation (cancel) et batch.\n"
        "\n"
        "Variables d'environnement utiles :\n"
        "  GHIDRA_RPC_PYTHON  -> python.exe alternatif du venv\n"
        "  GHIDRA_INSTALL_DIR -> dossier d'installation Ghidra (detecte auto si absent)\n"
        "  GHIDRA_RPC_PROJECT -> projet .gpr par defaut (si --project omis)\n");
}

int RunGhidraCommand(const std::vector<std::string>& args) {
    fs::path python = VenvPython();
    std::vector<std::string> cmdline;

    if (python.empty()) {
        // Repli : commande `ghidra-rpc` du PATH (si le package a ete installe
        // ailleurs via `uv tool install` ou `pip install`).
        std::printf("[ghidra] venv introuvable (ghidra-rpc\\.venv), bascule sur `ghidra-rpc` du PATH.\n"
                    "        Lancez build_monnouvelapp.bat pour creer le venv dedie.\n");
        cmdline.push_back("ghidra-rpc");
    } else {
        cmdline.push_back(python.string());
        cmdline.push_back("-m");
        cmdline.push_back("ghidra_rpc.cli");
    }
    for (const auto& a : args) cmdline.push_back(a);

    std::string cmd;
    for (size_t i = 0; i < cmdline.size(); ++i) {
        if (i) cmd += ' ';
        cmd += QuoteArg(cmdline[i]);
    }

    // GHIDRA_INSTALL_DIR auto-detection. Positionne AVANT CreateProcess pour
    // que le processus enfant herite de la valeur (sans ecraser un defaut
    // explicite).
    std::string ghidra = DetectGhidraInstall();
    char setVar[32768];
    DWORD cur = GetEnvironmentVariableA("GHIDRA_INSTALL_DIR", setVar, 32768);
    const bool hadInstallDir = (cur > 0 && cur < 32768);
    if (!hadInstallDir && !ghidra.empty())
        SetEnvironmentVariableA("GHIDRA_INSTALL_DIR", ghidra.c_str());

    // Creation du processus (herite stdout/stderr -> JSON sur la console).
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    char* mutableCmd = new char[cmd.size() + 1];
    std::copy(cmd.begin(), cmd.end(), mutableCmd);
    mutableCmd[cmd.size()] = '\0';

    BOOL ok = CreateProcessA(
        nullptr, mutableCmd, nullptr, nullptr, TRUE,
        CREATE_NEW_CONSOLE == 0 ? 0 : CREATE_DEFAULT_ERROR_MODE,
        nullptr, nullptr, &si, &pi);
    if (!ok) {
        DWORD err = GetLastError();
        std::fprintf(stderr, "[ghidra] echec de lancement du CLI ghidra-rpc "
                             "(erreur %lu).\n  Commande : %s\n", err, cmd.c_str());
        delete[] mutableCmd;
        return 1;
    }
    delete[] mutableCmd;

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(exitCode);
}

#endif  // _WIN32