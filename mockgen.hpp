#pragma once
#include <string>

// Pipeline natif de simulation d'état de possession (portage C++17 de
// C:\qa-automation\proxy-mock\Generate-OwnershipMock.ps1) :
//   Analyze   -> profilage Mutations vs Queries + traffic_profile.csv
//   Capture   -> extraction d'une réponse JSON (ownership_token) depuis un log
//   Configure -> génération de rules.ini (contrat proxy-mock) + payload sérialisé
//   Deploy    -> copie dans le dossier du proxy + marqueur de rechargement
// L'étage All enchaîne les quatre (comme -Stage All du script).
namespace mockgen {

struct Options {
    std::string log_path;             // -LogPath (Capture)
    std::string session_glob = ".\\logs\\sessions\\*.log";  // -SessionLogSearchPath
    std::string url_filter   = "ownership";   // -EndpointUrlFilter
    std::string product_id;           // -ProductId (isolation stricte)
    std::string state_filter;         // -StateFilter (ex. "owned")
    std::string captured_json = ".\\captured\\ownership_sample.json";  // -CapturedJson
    std::string response_out_dir = ".\\responses";                     // -ResponseOutDir
    std::string rules_file = ".\\rules.ini";                           // -RulesFile
    std::string proxy_rules_dir;      // -ProxyRulesDir (requis pour Deploy)
    std::string proxy_service;        // -ProxyServiceName (optionnel)
    std::string reload_marker = ".reload";                            // -ReloadMarker
    bool inject_luau = false;         // --mock-luau : règle Script=mock_success.luau
                                     // (injection du payload via mock.respond, audit "inject")
                                     // au lieu de ResponseFile (audit "mock-file")
};

// Exécute un étage (Analyze | Capture | Configure | Deploy | All).
// Retourne 0 en succès, 1 en échec (message sur stderr).
int RunMockStage(const std::string& stage, const Options& opt);

} // namespace mockgen