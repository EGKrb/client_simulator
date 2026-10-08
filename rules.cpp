#include "rules.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdio>

namespace localgate {

// ---------- utilitaires ----------
static std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

// host_glob : * = n'importe quelle séquence, ? = un seul caractère (insensible à la casse)
static bool glob_match(const std::string& pat, const std::string& s) {
    std::string p = to_upper(pat);
    std::string str = to_upper(s);

    std::size_t pi = 0, si = 0;
    std::size_t star = std::string::npos, star_at = 0;
    while (si < str.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == str[si])) { ++pi; ++si; }
        else if (pi < p.size() && p[pi] == '*') { star = pi++; star_at = si; }
        else if (star != std::string::npos) { pi = star + 1; si = ++star_at; }
        else return false;
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

// Extrait le chemin d'une requête (forme origin-form ou absolue)
static std::string path_of(const std::string& target) {
    if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) {
        auto slash = target.find('/', target.find("://") + 3);
        return slash == std::string::npos ? "/" : target.substr(slash);
    }
    return target;
}

// ---------- Rule ----------
bool Rule::matches(const http1::Request& r) const {
    if (method != "*" && to_upper(method) != to_upper(r.method)) return false;

    std::string host = r.get("host");
    if (host.empty() || host_glob.empty()) return false;
    if (host[0] != '[') {                          // hôte IPv6 : ne pas découper le port
        auto colon = host.rfind(':');
        if (colon != std::string::npos) host = host.substr(0, colon);
    }
    if (!glob_match(host_glob, host)) return false;

    if (path_regex.empty()) return true;           // règle générique : seul l'hôte compte
    try {
        std::regex re(path_regex, std::regex::ECMAScript);
        return std::regex_match(path_of(r.target), re);
    } catch (const std::regex_error&) {
        return false;                              // regex invalide = règle inapplicable
    }
}

// ---------- helpers contrat proxy-mock ----------
// Reconstruit l'URL complète vue par le client : forme absolue telle quelle,
// forme origin-form (cœur des tunnels CONNECT) reconstruite avec le Host header.
static std::string full_url_of(const http1::Request& r) {
    if (r.target.rfind("http://", 0) == 0 || r.target.rfind("https://", 0) == 0)
        return r.target;
    std::string host = r.get("host");
    if (host.empty()) return r.target;
    return "https://" + host + path_of(r.target);
}

// std::regex (ECMAScript MSVC) ne sait pas compiler (?<nom>...) : on neutralise
// les groupes nommés du Pattern généré (ex. (?<ProductId>...) -> (...)) sans
// toucher aux lookbehind/lookahead (?<=, ?<!).
static std::string strip_named_groups(const std::string& s) {
    std::string out = s;
    for (size_t i = 0; i + 3 < out.size(); ) {
        if (out[i] != '(' || out[i + 1] != '?' || out[i + 2] != '<') { ++i; continue; }
        unsigned char c = static_cast<unsigned char>(out[i + 3]);
        if (!(std::isalnum(c) || c == '_')) { ++i; continue; }
        size_t close = out.find('>', i + 3);
        if (close == std::string::npos || close == i + 3) { ++i; continue; }
        out.erase(i + 1, close - i);   // retire "?<Nom>" en gardant "("
    }
    return out;
}

// Résout ResponseFile relativement au dossier du rules.ini qui l'a déclaré.
static std::string dir_of(const std::string& p) {
    std::string::size_type pos = p.find_last_of("/\\");
    return pos == std::string::npos ? "." : p.substr(0, pos);
}

// ---------- RuleEngine ----------
void RuleEngine::load(const std::string& ini_path) {
    rules_dir_ = dir_of(ini_path);
    if (rules_dir_.empty()) rules_dir_ = ".";

    std::ifstream in(ini_path);
    if (!in) {
        fprintf(stderr, "[rules] Echec d'ouverture de %s\n", ini_path.c_str());
        return;
    }

    mock_if_5xx_ = Directive{};
    mock_if_5xx_.mock_script = "fallback.luau";    // robustesse par défaut : bascule Luau

    enum class Sect { kNone, kRule, kMock, kOwnership };
    Sect cur_sect = Sect::kNone;
    Rule cur;
    OwnershipRule cur_own;

    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        if (t[0] == '[' && t.back() == ']') {
            if (cur_sect == Sect::kRule) rules_.push_back(cur);
            if (cur_sect == Sect::kOwnership && !cur_own.pattern.empty()) ownership_rules_.push_back(cur_own);
            cur = Rule{};
            cur_own = OwnershipRule{};
            std::string name = trim(t.substr(1, t.size() - 2));
            if (name == "rule") cur_sect = Sect::kRule;
            else if (name == "mock_if_5xx") cur_sect = Sect::kMock;
            else if (name.rfind("Rule_", 0) == 0) { cur_own.name = name; cur_sect = Sect::kOwnership; }
            else cur_sect = Sect::kNone;
            continue;
        }

        auto eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(t.substr(0, eq));
        std::string val = trim(t.substr(eq + 1));

        if (cur_sect == Sect::kMock) {
            if (key == "mock_script") mock_if_5xx_.mock_script = val;
            else if (key == "strip_body") mock_if_5xx_.strip_body = (val == "true" || val == "1");
            else if (key == "latency_ms") mock_if_5xx_.latency_ms = atoi(val.c_str());
            continue;
        }
        if (cur_sect == Sect::kOwnership) {
            if (key == "Enabled") cur_own.enabled = (val == "1" || val == "true");
            else if (key == "Priority") cur_own.priority = atoi(val.c_str());
            else if (key == "Method") cur_own.method = to_upper(val);
            else if (key == "Pattern") cur_own.pattern = val;
            else if (key == "ResponseFile") cur_own.response_file = val;
            else if (key == "Script") cur_own.script = val;
            else if (key == "StatusCode") cur_own.status_code = atoi(val.c_str());
            else if (key == "ContentType") cur_own.content_type = val;
            continue;
        }
        if (cur_sect != Sect::kRule) continue;

        if (key == "host") cur.host_glob = val;
        else if (key == "path") cur.path_regex = val;
        else if (key == "method") cur.method = to_upper(val);
        else if (key == "inject_status") cur.d.inject_status = atoi(val.c_str());
        else if (key == "strip_body") cur.d.strip_body = (val == "true" || val == "1");
        else if (key == "latency_ms") cur.d.latency_ms = atoi(val.c_str());
        else if (key == "mutate_header") cur.d.mutate_header = val;
        else if (key == "mock_script") cur.d.mock_script = val;
        else if (key == "action") {
            if (val == "drop") cur.d.action = Action::kDrop;
        }
    }
    if (cur_sect == Sect::kRule) rules_.push_back(cur);
    if (cur_sect == Sect::kOwnership && !cur_own.pattern.empty()) ownership_rules_.push_back(cur_own);

    // Priorité forte d'abord (stable : à égalité, l'ordre du fichier est conservé).
    std::stable_sort(ownership_rules_.begin(), ownership_rules_.end(),
        [](const OwnershipRule& a, const OwnershipRule& b) { return a.priority > b.priority; });

    fprintf(stderr, "[rules] %u regle(s) + %u regle(s) ownership chargee(s) depuis %s\n",
            (unsigned)rules_.size(), (unsigned)ownership_rules_.size(), ini_path.c_str());
}

namespace {
Directive match_ownership(const std::vector<OwnershipRule>& rules, const std::string& rules_dir,
                          const http1::Request& req) {
    for (const auto& r : rules) {
        if (!r.enabled) continue;
        if (r.method != "*" && r.method != to_upper(req.method)) continue;
        if (r.pattern.empty()) continue;
        try {
            std::regex re(strip_named_groups(r.pattern), std::regex::ECMAScript);
            if (!std::regex_match(full_url_of(req), re)) continue;
        } catch (const std::regex_error&) {
            continue;
        }
        Directive d;
        if (!r.script.empty()) {
            // Injection Luau : mock_success.luau joué via mock.respond, la note
            // d'audit de la passerelle devient "inject" (rejet si script absent).
            d.mock_script = rules_dir == "." ? r.script
                                             : rules_dir + "\\" + r.script;
            d.respond_note = "inject";
        } else {
            d.respond_file = rules_dir == "." ? r.response_file
                                              : rules_dir + "\\" + r.response_file;
        }
        d.respond_status = r.status_code;
        d.respond_content_type = r.content_type;
        return d;
    }
    return Directive{};
}
} // namespace

Directive RuleEngine::evaluate(const http1::Request& req) {
    Directive d = match_ownership(ownership_rules_, rules_dir_, req);
    if (!d.respond_file.empty() || !d.mock_script.empty()) return d;
    for (const auto& r : rules_) {
        if (r.matches(req)) return r.d;
    }
    return Directive{};
}

Directive RuleEngine::evaluate(const http1::Response& resp, const http1::Request& req) {
    Directive d = match_ownership(ownership_rules_, rules_dir_, req);
    if (!d.respond_file.empty() || !d.mock_script.empty()) return d;
    for (const auto& r : rules_) {
        if (r.matches(req)) return r.d;
    }
    // pas de règle explicite : le backend a répondu 5xx -> bascule en mock
    if (resp.code >= 500) return mock_if_5xx_;
    return Directive{};
}

} // namespace localgate