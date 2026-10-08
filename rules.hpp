#pragma once
#include "http1.hpp"
#include <vector>
#include <string>

namespace localgate {

enum class Action { kForward, kDrop, kMutateResponse, kMock };

struct Directive {
    Action action = Action::kForward;
    int inject_status = 0;        // forcer 400/401/429/500/503...
    bool strip_body = false;      // vider le corps de réponse
    int latency_ms = 0;           // latence simulée
    std::string mutate_header;    // "Header:valeur"
    std::string mock_script;      // script Luau à exécuter en fallback
    // Contrat proxy-mock (Generate-OwnershipMock.ps1) : répondeur fichier.
    // Si respond_file est non vide, la requête est servie SANS appeler
    // l'upstream avec le contenu du payload (simulation d'état de possession).
    std::string respond_file;         // chemin résolu du payload à injecter
    int         respond_status = 0;   // status à servir (0 -> 200)
    std::string respond_content_type; // content-type (défaut application/json)
    // Note d'audit à émettre quand le script Luau a répondu (ex. "inject").
    // Vide -> "mock" (comportement historique des règles [rule]).
    std::string respond_note;
};

struct Rule {
    std::string host_glob;        // *.monapp.test
    std::string path_regex;       // /api/.*
    std::string method;           // POST / GET / *
    Directive d;
    bool matches(const http1::Request& r) const;
};

// Règle « ownership » au format du contrat proxy-mock (PLAN_ACTION_TECHNIQUE.md §4) :
//   [Rule_<nom>]
//   Enabled=1
//   Priority=200
//   Method=GET
//   Pattern=^https?://api\.example\.com/v1/ownership/status\??([^?&]*&)*product_id=1337...
//   ResponseFile=ownership_pid_1337.json      (OU) Script=mock_success.luau
//   StatusCode=200
//   ContentType=application/json
struct OwnershipRule {
    std::string name;
    bool enabled = true;
    int priority = 0;
    std::string method = "*";       // * = tous verbes
    std::string pattern;            // regex ECMAScript ancrée ^...$ sur l'URL complète
    std::string response_file;      // résolu relativement au dossier de règles du proxy
    // Script= : fichier Luau (ex. mock_success.luau) appelant mock.respond pour
    // injecter le payload capturé. Si présent, remplace ResponseFile et la note
    // d'audit devient "inject".
    std::string script;
    int status_code = 200;
    std::string content_type = "application/json";
};

class RuleEngine {
public:
    void load(const std::string& ini_path);
    Directive evaluate(const http1::Request& req);
    Directive evaluate(const http1::Response& resp, const http1::Request& req);
    size_t ownership_count() const { return ownership_rules_.size(); }
private:
    std::vector<Rule> rules_;
    Directive mock_if_5xx_;
    std::vector<OwnershipRule> ownership_rules_;  // triées par Priority DESC (stable)
    std::string rules_dir_;                       // dossier contenant rules.ini
};

} // namespace localgate