#pragma once

#include <string>
#include <vector>

//  Pont d'integration du CLI ghidra-rpc (Python) dans MonNouvelApp.exe.
//  Le package Python est vendorise dans C:\client_simulator\ghidra-rpc et
//  installe dans un venv dedie (ghidra-rpc\.venv) par build_monnouvelapp.bat.
//
//  - RunGhidraCommand : execute `python -m ghidra_rpc.cli <args...>` en
//    sous-processus, herite stdout/stderr (JSON visible sur la console) et
//    renvoie le code de sortie de la commande ghidra-rpc.
//  - PrintGhidraUsage : aide de la liste des commandes disponibles.
//
//  Comportement :
//    * Le python du venv est cherche en priorite (GHIDRA_RPC_PYTHON, puis
//      <racine>\ghidra-rpc\.venv\Scripts\python.exe).
//    * Repli sur la commande `ghidra-rpc` du PATH si le venv manque.
//    * GHIDRA_INSTALL_DIR est positionne automatiquement (var d'env deja
//      definie, sinon detection depuis C:\Users\<user>\ghidra, sinon
//      Program Files\Ghidra) afin que `--ghidra start` fonctionne sans
//      configuration manuelle.

#ifdef _WIN32

int  RunGhidraCommand(const std::vector<std::string>& args);
void PrintGhidraUsage();

#else
// Hors Windows (build non soutenu), aucune operation.
inline int  RunGhidraCommand(const std::vector<std::string>&) { return 1; }
inline void PrintGhidraUsage() {}
#endif