#include "mockgen.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace mockgen {

static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

static bool contains_ci(const std::string& hay, const std::string& needle) {
    return to_lower(hay).find(to_lower(needle)) != std::string::npos;
}

static std::string dir_of(const std::string& p) {
    std::string::size_type pos = p.find_last_of("/\\");
    return pos == std::string::npos ? "." : p.substr(0, pos);
}

static std::string base_name(const std::string& p) {
    std::string::size_type pos = p.find_last_of("/\\");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

static std::string iso_now() {
    SYSTEMTIME st, utc;
    GetLocalTime(&st);
    GetSystemTime(&utc);
    __int64 lf = 0, uf = 0;
    SystemTimeToFileTime(&st, (FILETIME*)&lf);
    SystemTimeToFileTime(&utc, (FILETIME*)&uf);
    long offMin = (long)((lf - uf) / 10000000LL / 60);
    long absOff = offMin < 0 ? -offMin : offMin;
    char tz[16];
    _snprintf_s(tz, _TRUNCATE, "%c%02ld:%02ld", offMin < 0 ? '-' : '+', absOff / 60, absOff % 60);
    char buf[80];
    _snprintf_s(buf, _TRUNCATE, "%04d-%02d-%02dT%02d:%02d:%02d.%07ld%s",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                (long)st.wMilliseconds * 10000L, tz);
    return buf;
}

static std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (data.size() >= 3 && (unsigned char)data[0] == 0xEF &&
        (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF)
        data.erase(0, 3);
    return data;
}

static bool write_file(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(data.data(), (std::streamsize)data.size());
    return out.good();
}

static bool ensure_dirs(const std::string& dir) {
    if (dir.empty() || dir == "." || dir == "\\" || dir == "/") return true;
    std::string seg;
    for (size_t i = 0; i <= dir.size(); ++i) {
        if (i == dir.size() || dir[i] == '\\' || dir[i] == '/') {
            if (!seg.empty() && seg.back() != ':' &&
                !CreateDirectoryA(seg.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
                return false;
            if (i < dir.size()) seg.push_back(dir[i]);
        } else {
            seg.push_back(dir[i]);
        }
    }
    return true;
}

static bool ensure_parent_dirs(const std::string& path) {
    std::string parent = dir_of(path);
    if (parent.empty() || parent == "." || parent == "\\" || parent == "/") return true;
    return ensure_dirs(parent);
}

static std::vector<std::string> list_files(const std::string& pathOrGlob) {
    std::vector<std::string> out;
    size_t sep = pathOrGlob.find_last_of("/\\");
    std::string dir = sep == std::string::npos ? "." : pathOrGlob.substr(0, sep);
    std::string pat = sep == std::string::npos ? pathOrGlob : pathOrGlob.substr(sep + 1);
    if (dir.empty()) dir = ".";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + "\\" + pat).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return out;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            out.push_back((dir == ".") ? fd.cFileName : dir + "\\" + fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    std::sort(out.begin(), out.end());
    return out;
}

static std::vector<std::string> glob_files(const std::string& glob) {
    if (glob.find('*') == std::string::npos && glob.find('?') == std::string::npos) {
        if (GetFileAttributesA(glob.c_str()) != INVALID_FILE_ATTRIBUTES) return { glob };
        return {};
    }
    return list_files(glob);
}

static std::string regex_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        switch (c) {
            case '\\': case '*': case '+': case '?': case '|':
            case '{': case '[': case '(': case ')': case '^': case '$':
            case '.': case '#':
                out.push_back('\\');
                out.push_back((char)c);
                break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case ' ': out += "\\ "; break;
            default:
                out.push_back((char)c);
        }
    }
    return out;
}

static bool matches_filter(const std::string& text, const std::string& filter) {
    if (filter.empty()) return true;
    try {
        std::regex re(filter, std::regex::ECMAScript | std::regex::icase);
        return std::regex_search(text, re);
    } catch (const std::regex_error&) {
        return contains_ci(text, filter);
    }
}

static std::string json_str(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) {
                    char b[8];
                    _snprintf_s(b, _TRUNCATE, "\\u%04x", c);
                    out += b;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    out += "\"";
    return out;
}

// Echappe une chaîne en littéral Lua/Luau double-quote (UTF-8 conservé tel quel).
static std::string luau_str(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char b[8];
                    _snprintf_s(b, _TRUNCATE, "\\%03d", (int)c);
                    out += b;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    out += "\"";
    return out;
}

namespace json {

struct Value {
    enum class Kind { kNull, kBool, kNum, kStr, kArr, kObj };
    Kind k = Kind::kNull;
    bool b = false;
    double n = 0;
    std::string s;
    std::vector<Value> a;
    std::vector<std::pair<std::string, Value>> o;
    const Value* get(const std::string& key) const {
        if (k != Kind::kObj) return nullptr;
        for (const auto& kv : o) if (kv.first == key) return &kv.second;
        return nullptr;
    }
};

class Parser {
public:
    explicit Parser(const std::string& src) : src_(src) {}
    bool run(Value& root) {
        ws();
        if (!parse_value(root)) return false;
        ws();
        return i_ == src_.size();
    }
    const std::string& error() const { return err_; }
private:
    const std::string& src_;
    size_t i_ = 0;
    std::string err_;

    void ws() { while (i_ < src_.size() && (src_[i_] == ' ' || src_[i_] == '\t' || src_[i_] == '\r' || src_[i_] == '\n')) ++i_; }

    bool fail(const std::string& m) { if (err_.empty()) err_ = m; return false; }

    bool parse_value(Value& v) {
        if (i_ >= src_.size()) return fail("json: unexpected eof");
        char c = src_[i_];
        if (c == '{') return parse_obj(v);
        if (c == '[') return parse_arr(v);
        if (c == '"') { std::string s; if (!parse_string(s)) return false; v.k = Value::Kind::kStr; v.s = s; return true; }
        if (c == 't' || c == 'f') {
            std::string w = src_.compare(i_, 5, "true") == 0 ? "true" : src_.compare(i_, 6, "false") == 0 ? "false" : "";
            if (w.empty()) return fail("json: bad literal");
            i_ += (w == "true") ? 4 : 5;
            v.k = Value::Kind::kBool; v.b = (w == "true"); return true;
        }
        if (c == 'n') {
            if (src_.compare(i_, 4, "null") != 0) return fail("json: bad null");
            i_ += 4; v.k = Value::Kind::kNull; return true;
        }
        return parse_num(v);
    }

    bool parse_num(Value& v) {
        size_t start = i_;
        if (i_ < src_.size() && src_[i_] == '-') ++i_;
        size_t digits = 0;
        while (i_ < src_.size() && src_[i_] >= '0' && src_[i_] <= '9') { ++i_; ++digits; }
        if (digits == 0) return fail("json: bad number");
        if (i_ < src_.size() && src_[i_] == '.') {
            ++i_;
            size_t d2 = 0;
            while (i_ < src_.size() && src_[i_] >= '0' && src_[i_] <= '9') { ++i_; ++d2; }
            if (d2 == 0) return fail("json: bad fraction");
        }
        if (i_ < src_.size() && (src_[i_] == 'e' || src_[i_] == 'E')) {
            ++i_;
            if (i_ < src_.size() && (src_[i_] == '+' || src_[i_] == '-')) ++i_;
            size_t d3 = 0;
            while (i_ < src_.size() && src_[i_] >= '0' && src_[i_] <= '9') { ++i_; ++d3; }
            if (d3 == 0) return fail("json: bad exponent");
        }
        v.k = Value::Kind::kNum;
        v.n = std::atof(src_.substr(start, i_ - start).c_str());
        return true;
    }

    bool parse_string(std::string& out) {
        if (i_ >= src_.size() || src_[i_] != '"') return fail("json: expected string");
        ++i_;
        while (i_ < src_.size()) {
            unsigned char c = (unsigned char)src_[i_];
            if (c == '"') { ++i_; return true; }
            if (c == '\\') {
                if (++i_ >= src_.size()) return fail("json: bad escape");
                char e = src_[i_++];
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
                        if (i_ + 4 > src_.size()) return fail("json: bad \\u");
                        unsigned cp = 0;
                        for (int k = 0; k < 4; ++k) {
                            char h = src_[i_++];
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                            else return fail("json: bad hex");
                        }
                        if (cp < 0x80) out.push_back((char)cp);
                        else if (cp < 0x800) {
                            out.push_back((char)(0xC0 | (cp >> 6)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back((char)(0xE0 | (cp >> 12)));
                            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: return fail("json: unknown escape");
                }
                continue;
            }
            if (c < 0x20) return fail("json: control char in string");
            out.push_back((char)c);
            ++i_;
        }
        return fail("json: unterminated string");
    }

    bool parse_obj(Value& v) {
        ++i_;
        v.k = Value::Kind::kObj;
        ws();
        if (i_ < src_.size() && src_[i_] == '}') { ++i_; return true; }
        while (true) {
            ws();
            if (i_ >= src_.size() || src_[i_] != '"') return fail("json: expected key");
            std::string key;
            if (!parse_string(key)) return false;
            ws();
            if (i_ >= src_.size() || src_[i_] != ':') return fail("json: expected ':'");
            ++i_;
            ws();
            Value val;
            if (!parse_value(val)) return false;
            v.o.emplace_back(std::move(key), std::move(val));
            ws();
            if (i_ >= src_.size()) return fail("json: obj eof");
            char c = src_[i_];
            if (c == ',') { ++i_; continue; }
            if (c == '}') { ++i_; return true; }
            return fail("json: expected ',' or '}'");
        }
    }

    bool parse_arr(Value& v) {
        ++i_;
        v.k = Value::Kind::kArr;
        ws();
        if (i_ < src_.size() && src_[i_] == ']') { ++i_; return true; }
        while (true) {
            ws();
            Value val;
            if (!parse_value(val)) return false;
            v.a.push_back(std::move(val));
            ws();
            if (i_ >= src_.size()) return fail("json: arr eof");
            char c = src_[i_];
            if (c == ',') { ++i_; continue; }
            if (c == ']') { ++i_; return true; }
            return fail("json: expected ',' or ']'");
        }
    }
};

static bool parse(const std::string& text, Value& root) {
    Parser p(text);
    return p.run(root);
}

} // namespace json

struct LogEntry {
    std::string raw;
    std::string method;
    std::string url;
    std::string status;
    std::string body;
};

static void split_parts(const std::string& ls, std::vector<std::string>& parts) {
    size_t pos = 0;
    while (pos < ls.size()) {
        size_t n = ls.find('|', pos);
        if (n == std::string::npos) { parts.push_back(ls.substr(pos)); break; }
        parts.push_back(ls.substr(pos, n - pos));
        pos = n + 1;
    }
}

static std::string url_path(const std::string& url) {
    size_t q = url.find('?');
    return q == std::string::npos ? url : url.substr(0, q);
}

static std::vector<std::string> split_keyval(const std::string& query) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos < query.size()) {
        size_t n = query.find('&', pos);
        if (n == std::string::npos) { out.push_back(query.substr(pos)); break; }
        out.push_back(query.substr(pos, n - pos));
        pos = n + 1;
    }
    return out;
}

static std::string url_decode(std::string s) {
    if (s.find('%') == std::string::npos) return s;
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hexv = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hexv(s[i + 1]), lo = hexv(s[i + 2]);
            if (hi >= 0 && lo >= 0) { out.push_back((char)((hi << 4) | lo)); i += 2; continue; }
        }
        out.push_back(s[i]);
    }
    return out;
}

static std::string query_param(const std::string& query, const std::string& key) {
    for (const std::string& kv : split_keyval(query)) {
        if (kv.compare(0, key.size(), key) == 0) {
            if (kv.size() == key.size()) return "";
            if (kv[key.size()] == '=') return url_decode(kv.substr(key.size() + 1));
        }
    }
    return "";
}

struct CapturedHit {
    bool has_token = false;
    int status = 0;
    int state_rank = -1;
    bool ownership = false;
    std::string ownership_state;
    std::string body;
};

enum class ReqClass { kUnclassified, kQuery, kMutation };

static const char* const kQueryKw[] = { "ownership", "verify", "check", "status", "validate", "balance", "profile", "list", "get" };
static const char* const kMutationKw[] = { "purchase", "buy", "order", "pay", "payment", "transfer", "create", "update", "delete", "add", "remove", "cancel", "charge" };
static const char* const kQueryVerbs[] = { "GET", "HEAD", "OPTIONS" };
static const char* const kMutationVerbs[] = { "POST", "PUT", "PATCH", "DELETE" };

static ReqClass classify(const std::string& verb, const std::string& url) {
    for (const char* v : kQueryVerbs) if (verb == v) return ReqClass::kQuery;
    for (const char* v : kMutationVerbs) if (verb == v) return ReqClass::kMutation;
    if (verb.empty()) return ReqClass::kUnclassified;
    std::string path = to_lower(url_path(url));
    bool has_mut = false;
    for (const char* kw : kMutationKw) if (path.find(kw) != std::string::npos) has_mut = true;
    if (has_mut) {
        for (const char* kw : kQueryKw)
            if (path.find(kw) != std::string::npos && !has_mut) return ReqClass::kQuery;
        return ReqClass::kMutation;
    }
    for (const char* kw : kQueryKw) if (path.find(kw) != std::string::npos) return ReqClass::kQuery;
    return ReqClass::kUnclassified;
}

// Découpe une ligne de log en entrée typée (défauts : corps vide/status 0 si absents).
static LogEntry parse_log_line(const std::string& line) {
    std::string ls = trim(line);
    if (ls.empty()) return LogEntry{};
    LogEntry e;
    e.raw = ls;
    size_t p1 = ls.find('|');
    size_t p2 = p1 == std::string::npos ? std::string::npos : ls.find('|', p1 + 1);
    size_t p3 = p2 == std::string::npos ? std::string::npos : ls.find('|', p2 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) return LogEntry{};
    e.method = trim(ls.substr(p1 + 1, p2 - p1 - 1));
    e.url = trim(ls.substr(p2 + 1, p3 - p2 - 1));
    e.status = trim(ls.substr(p3 + 1));
    return e;
}

static LogEntry body_from_line(const std::string& line) {
    LogEntry e = parse_log_line(line);
    if (e.method.empty()) return e;
    return e;
}

static const char* const kCapturedDir  = ".\\captured";
static const char* const kResponsesDir = ".\\responses";
static const char* const kSourceTxt    = ".\\captured\\ownership_source.txt";
static const char* const kSampleJson   = ".\\captured\\ownership_sample.json";
static const char* const kPidJson      = ".\\captured\\ownership_pid.json";
static const char* const kTokenHints[] = { "ownership_token", "ownership-token", "possession_token", "possession-token" };

static bool has_token(const std::string& body) {
    if (body.empty()) return false;
    for (const char* h : kTokenHints) if (contains_ci(body, h)) return true;
    return false;
}

static bool within_ownership_service(const LogEntry& e) {
    if (!contains_ci(e.url, "ownership")) return false;
    std::string last = to_lower(url_path(e.url));
    while (!last.empty() && last.back() == '/') last.pop_back();
    const char* ends[] = { "/status", "/verify", "/check", "/checks", "/v1/ownership" };
    for (const char* s : ends) {
        size_t n = strlen(s);
        if (last.size() >= n && last.compare(last.size() - n, n, s) == 0) return true;
    }
    return false;
}

static std::string query_of(const std::string& url) {
    size_t q = url.find('?');
    return q == std::string::npos ? "" : url.substr(q + 1);
}

static bool is_ownership_hit(const LogEntry& e) {
    if (classify(e.method, e.url) != ReqClass::kQuery) return false;
    if (!within_ownership_service(e)) return false;
    return !query_param(query_of(e.url), "product_id").empty();
}

static std::string line_body(const std::string& line) {
    size_t p3 = std::string::npos;
    int bars = 0;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '|') {
            ++bars;
            if (bars == 4) { p3 = i; break; }
        }
    }
    if (p3 == std::string::npos) return "";
    return line.substr(p3 + 1);
}

static std::vector<std::string> split_lines(const std::string& data) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos < data.size()) {
        size_t n = data.find('\n', pos);
        if (n == std::string::npos) { out.push_back(data.substr(pos)); break; }
        out.push_back(data.substr(pos, n - pos));
        pos = n + 1;
    }
    return out;
}

// Etape Analyze : identifie la source de verite (session log) et ecrit sa copie.
static int stage_analyze(const Options& opt) {
    printf("[Analyse] Recherche de la source de verite des sessions ownership...\n");
    std::string source = opt.log_path;
    std::string chosen;
    int scanned = 0, hits = 0;
    if (!source.empty()) {
        if (GetFileAttributesA(source.c_str()) == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "[Analyse] ERREUR: log '%s' introuvable\n", source.c_str());
            return 1;
        }
        std::vector<std::string> lines = split_lines(read_file(source));
        int cnt = 0;
        for (const std::string& l : lines) {
            LogEntry e = parse_log_line(l);
            if (!e.method.empty() && is_ownership_hit(e)) ++cnt;
        }
        if (cnt == 0) {
            fprintf(stderr, "[Analyse] ERREUR: aucun hit ownership dans '%s'\n", source.c_str());
            return 1;
        }
        chosen = source;
        hits = cnt;
        scanned = 1;
    } else {
        std::vector<std::string> logs = glob_files(opt.session_glob);
        printf("[Analyse] Balayage %zu session(s) via '%s'...\n", logs.size(), opt.session_glob.c_str());
        for (const std::string& f : logs) {
            scanned++;
            std::vector<std::string> lines = split_lines(read_file(f));
            int cnt = 0;
            for (const std::string& l : lines) {
                LogEntry e = parse_log_line(l);
                if (!e.method.empty() && is_ownership_hit(e)) ++cnt;
            }
            if (cnt > 0) {
                chosen = f;
                hits = cnt;
                break;
            }
        }
        if (chosen.empty()) {
            fprintf(stderr, "[Analyse] ERREUR: aucune session ne contient de hit ownership; " 
                            "fournissez --mock-log <chemin>\n");
            return 1;
        }
    }
    if (!ensure_parent_dirs(kSourceTxt)) {
        fprintf(stderr, "[Analyse] ERREUR: impossible de creer .\\captured\n");
        return 1;
    }
    if (!write_file(kSourceTxt, chosen + "\n")) {
        fprintf(stderr, "[Analyse] ERREUR: impossible d'ecrire %s\n", kSourceTxt);
        return 1;
    }
    printf("[Analyse] OK - source: %s\n", chosen.c_str());
    printf("[Analyse]   sessions examinees : %d\n", scanned);
    printf("[Analyse]   lignes de hit ownership detectees : %d\n", hits);
    printf("[Analyse]   copie : %s\n", kSourceTxt);
    return 0;
}

static std::string detect_ownership_state(const std::string& body) {
    std::string b = body;
    static const char* pats[] = {
        "<ownership_state>([^<\\s]+)", "<possession_state>([^<\\s]+)",
        "\"ownership[_]?state\"\\s*[:=]\\s*\"([^\"]+)\"",
        "\"ownership[_]?state\"\\s*[:=]\\s*([A-Za-z][A-Za-z0-9_]*)",
        "\"state\"\\s*[:=]\\s*\"(OK|K0|NoToken|NotOwned|Unknown)\""
    };
    for (const char* p : pats) {
        try {
            std::regex re(p, std::regex::ECMAScript | std::regex::icase);
            std::smatch m;
            if (std::regex_search(b, m, re) && m.size() > 1) return to_upper(m[1].str());
        } catch (const std::regex_error&) {}
    }
    std::string ls = to_lower(b);
    static const char* states[] = { "STATE=OK", "OWNERSHIP_STATE=OK" };
    for (const char* s : states) if (ls.find(s) != std::string::npos) return "OK";
    return "";
}

static int status_int(const std::string& s) {
    if (s.empty()) return 0;
    int v = std::atoi(s.c_str());
    return v > 0 ? v : 0;
}

// Etape Capture : choisit la meilleure occurrence et ecrit le JSON d'echantillon.
static int stage_capture(const Options& opt) {
    printf("[Capture] Extraction de l'echantillon depuis la source...\n");
    std::string source = opt.log_path;
    if (source.empty()) source = trim(read_file(kSourceTxt));
    if (source.empty()) {
        fprintf(stderr, "[Capture] ERREUR: aucune source (aucun session log) - lancez d'abord --mock-analyze\n");
        return 1;
    }
    std::vector<std::string> lines = split_lines(read_file(source));
    std::string chosen_url, chosen_method;
    int chosen_status = 0, chosen_has_token = 0, chosen_rank = 99;
    std::string chosen_body, chosen_state;
    int total_query = 0;
    for (const std::string& l : lines) {
        LogEntry e = parse_log_line(l);
        if (e.method.empty()) continue;
        if (classify(e.method, e.url) != ReqClass::kQuery) continue;
        if (!within_ownership_service(e)) continue;
        // Isolation produit (--mock-product) : ne retenir que les hits de l'ID cible.
        if (!opt.product_id.empty() &&
            query_param(query_of(e.url), "product_id") != opt.product_id) continue;
        total_query++;
        std::string body = line_body(l);
        CapturedHit hit;
        hit.has_token = has_token(body);
        hit.status = status_int(e.status);
hit.ownership_state = detect_ownership_state(body);

        int rank = 4;
        if (hit.has_token && !hit.ownership_state.empty()) rank = 1;
        else if (hit.ownership_state == "OK" && hit.status == 200) rank = 2;
        else if (hit.has_token && hit.status == 200) rank = 3;
        if (rank < chosen_rank) {
            chosen_rank = rank;
            chosen_url = e.url;
            chosen_method = e.method;
            chosen_status = hit.status;
            chosen_has_token = hit.has_token ? 1 : 0;
            chosen_body = body;
            chosen_state = hit.ownership_state;
            if (rank == 1) break;
        }
    }
    if (chosen_rank == 99) {
        fprintf(stderr, "[Capture] ERREUR: aucune occurrence ownership exploitable dans '%s'\n", source.c_str());
        return 1;
    }
    std::string out = "{\n";
    out += "  \"CapturedAt\": " + json_str(iso_now()) + ",\n";
    out += "  \"SourceLog\": " + json_str(source) + ",\n";
    out += "  \"Method\": " + json_str(chosen_method) + ",\n";
    out += "  \"Url\": " + json_str(chosen_url) + ",\n";
    out += "  \"Status\": " + std::to_string(chosen_status) + ",\n";
    out += "  \"ContentType\": \"application/json\",\n";
    out += "  \"Body\": " + json_str(chosen_body) + ",\n";
    out += "  \"HasOwnershipToken\": " + std::to_string(chosen_has_token) + "\n";
    out += "}\n";
    if (!ensure_parent_dirs(opt.captured_json)) {
        fprintf(stderr, "[Capture] ERREUR: impossible de creer le dossier capture\n");
        return 1;
    }
    if (!write_file(opt.captured_json, out)) {
        fprintf(stderr, "[Capture] ERREUR: impossible d'ecrire %s\n", opt.captured_json.c_str());
        return 1;
    }
    printf("[Capture] OK - echantillon ecrit : %s\n", opt.captured_json.c_str());
    printf("[Capture]   source           : %s\n", source.c_str());
    printf("[Capture]   lignes scrutées  : %zu\n", lines.size());
    printf("[Capture]   hits ownership   : %d\n", total_query);
    printf("[Capture]   retenu           : %s %s\n", chosen_method.c_str(), chosen_url.c_str());
    printf("[Capture]   status           : %d\n", chosen_status);
    printf("[Capture]   jeton possedé    : %s\n", chosen_has_token ? "oui" : "non");
    printf("[Capture]   etat possédé     : %s\n", chosen_state.empty() ? "non detecte" : (chosen_state == "OK" ? "OK" : chosen_state.c_str()));
    return 0;
}

static bool parse_authority_path(const std::string& url, std::string& authority,
                                 std::string& path, std::string& query) {
    size_t p = url.find("://");
    if (p == std::string::npos) return false;
    size_t s = p + 3;
    size_t slash = url.find('/', s);
    size_t qmark = url.find('?', s);
    size_t endAuth;
    if (slash != std::string::npos && qmark != std::string::npos) endAuth = (std::min)(slash, qmark);
    else if (slash != std::string::npos) endAuth = slash;
    else if (qmark != std::string::npos) endAuth = qmark;
    else endAuth = url.size();
    authority = url.substr(s, endAuth - s);
    if (slash != std::string::npos) {
        size_t pe = (qmark != std::string::npos && qmark > slash) ? qmark : url.size();
        path = url.substr(slash, pe - slash);
    } else {
        path = "";
    }
    if (qmark != std::string::npos) query = url.substr(qmark + 1);
    return !authority.empty();
}

struct CapturedSample {
    std::string method, url, body, content_type;
    int status = 200;
};

static bool load_captured(const std::string& path, CapturedSample& out) {
    std::string text = read_file(path);
    if (text.empty()) return false;
    json::Value root;
    if (!json::parse(text, root)) return false;
    const json::Value* v;
    if ((v = root.get("Method"))) out.method = v->s;
    if ((v = root.get("Url"))) out.url = v->s;
    if ((v = root.get("Body"))) out.body = v->s;
    if ((v = root.get("ContentType"))) out.content_type = v->s;
    if ((v = root.get("Status")) && v->k == json::Value::Kind::kNum) out.status = (int)v->n;
    return !out.url.empty();
}

static std::string default_payload(const std::string& pid, bool any) {
    std::string body = "{\n";
    body += "  \"state\": \"OK\",\n";
    body += "  \"ownership_token\": \"mock-" + (any ? std::string("any") : pid) + "\",\n";
    body += "  \"product_id\": " + json_str(any ? "" : pid) + ",\n";
    body += "  \"owner\": \"mock-user\"\n";
    body += "}\n";
    return body;
}

// Etape Configure : construit les patterns et les fichiers de mock.
static int stage_configure(const Options& opt) {
    printf("[Config] Construction des regles de mock ownership...\n");
    std::string capPath = opt.captured_json;
    std::string text = read_file(capPath);
    if (text.empty()) {
        fprintf(stderr, "[Config] ERREUR: %s introuvable ou vide - lancez d'abord --mock-capture\n", capPath.c_str());
        return 1;
    }
    json::Value root;
    if (!json::parse(text, root)) {
        fprintf(stderr, "[Config] ERREUR: %s n'est pas un JSON valide\n", capPath.c_str());
        return 1;
    }
    const json::Value* v;
    std::string method, url, body, ctype;
    int status = 200;
    if ((v = root.get("Method"))) method = v->s;
    if ((v = root.get("Url"))) url = v->s;
    if ((v = root.get("Body"))) body = v->s;
    if ((v = root.get("ContentType"))) ctype = v->s;
    if ((v = root.get("Status")) && v->k == json::Value::Kind::kNum) status = (int)v->n;
    if (url.empty()) { fprintf(stderr, "[Config] ERREUR: Url absente de l'echantillon\n"); return 1; }
    if (ctype.empty()) ctype = "application/json";

    std::string authority, path, query;
    if (!parse_authority_path(url, authority, path, query)) {
        fprintf(stderr, "[Config] ERREUR: Url non parse : %s\n", url.c_str());
        return 1;
    }
    while (!path.empty() && path.back() == '/') path.pop_back();
    std::string pid = query_param(query, "product_id");
    if (!opt.product_id.empty()) pid = opt.product_id;
    bool hasPid = !pid.empty();

    std::string authEsc = regex_escape(authority);
    std::string pathEsc = regex_escape(path);
    std::string queryPre = "\\??([^?&]*&)*";

    if (body.empty()) body = default_payload(pid, !hasPid);

    std::string responsesDir = opt.response_out_dir;
    std::string pidFile, anyFile;
    if (hasPid) {
        pidFile = responsesDir + "\\ownership_pid_" + pid + ".json";
    } else {
        anyFile = responsesDir + "\\ownership_any.json";
    }
    if (!ensure_dirs(responsesDir)) {
        fprintf(stderr, "[Config] ERREUR: impossible de creer %s\n", responsesDir.c_str());
        return 1;
    }

    std::string ini;
    ini += "; Fichier de regles Mock Ownership genere par MonNouvelApp.exe\n";
    ini += "; Genere le : " + iso_now() + "\n";
    ini += "; Source      : " + capPath + "\n";
    ini += "; Classement  : Priority decroissante (200=strict, 199=any, 198=fallback)\n";
    if (opt.inject_luau)
        ini += "; Mode injection : Script=mock_success.luau (mock.respond, audit \"inject\")\n\n";
    else
        ini += "; Mode réponse fichier : ResponseFile=... (audit \"mock-file\")\n\n";

    // En mode injection, le payload capture est embarque dans mock_success.luau
    // via mock.respond : PAS de fichier JSON a resoudre cote gateway.
    auto write_luau = [&](const std::string& payload) -> bool {
        if (!opt.inject_luau) return true;
        std::string script;
        script += "-- Payload ownership capture (MonNouvelApp.exe --mock-luau)\n";
        script += "-- mock.respond(code, headers, body) : injection exacte du corps capture.\n";
        script += "mock.respond(" + std::to_string(status) + ", {\n";
        script += "  [\"content-type\"] = " + luau_str(ctype) + ",\n";
        script += "  [\"x-ltg-inject\"] = \"ownership-replay\"\n";
        script += "}, " + luau_str(payload) + ")\n";
        std::string luauPath = responsesDir + "\\mock_success.luau";
        if (!write_file(luauPath, script)) {
            fprintf(stderr, "[Config] ERREUR: impossible d'ecrire %s\n", luauPath.c_str());
            return false;
        }
        printf("[Config] Script d'injection Luau ecrit : %s\n", luauPath.c_str());
        return true;
    };

    int ruleCount = 0;
    if (hasPid) {
        if (!write_file(pidFile, body)) {
            fprintf(stderr, "[Config] ERREUR: impossible d'ecrire %s\n", pidFile.c_str());
            return 1;
        }
        if (!write_luau(body)) return 1;
        std::string pat = "^https?://" + authEsc + pathEsc + queryPre +
                          "product_id=" + regex_escape(pid) + "(?![0-9A-Za-z_\\-])(&.*)?$";
        ini += "[Rule_Ownership_Pid_" + pid + "]\n";
        ini += "Enabled=1\n";
        ini += "Priority=200\n";
        ini += "Method=" + method + "\n";
        ini += "Pattern=" + pat + "\n";
        if (opt.inject_luau)
            ini += "Script=mock_success.luau\n";
        else
            ini += "ResponseFile=ownership_pid_" + pid + ".json\n";
        ini += "StatusCode=" + std::to_string(status) + "\n";
        ini += "ContentType=" + ctype + "\n\n";
        ruleCount++;
        (void)anyFile;
    } else {
        if (!write_file(anyFile, body)) {
            fprintf(stderr, "[Config] ERREUR: impossible d'ecrire %s\n", anyFile.c_str());
            return 1;
        }
        if (!write_luau(body)) return 1;
        std::string pat = "^https?://" + authEsc + pathEsc + queryPre +
                          "product_id=(?<ProductId>[0-9A-Za-z_\\-]+)(&.*)?$";
        ini += "[Rule_Ownership_Any_Product]\n";
        ini += "Enabled=1\n";
        ini += "Priority=199\n";
        ini += "Method=" + method + "\n";
        ini += "Pattern=" + pat + "\n";
        if (opt.inject_luau)
            ini += "Script=mock_success.luau\n";
        else
            ini += "ResponseFile=ownership_any.json\n";
        ini += "StatusCode=" + std::to_string(status) + "\n";
        ini += "ContentType=" + ctype + "\n\n";
        ruleCount++;
    }
    std::string patFall = "^https?://" + authEsc + pathEsc + "(\\?.*)?$";
    std::string fallBody = "{\n  \"state\": \"Unknown\",\n  \"message\": \"Pas de regle stricte pour ce produit\"\n}\n";
    std::string fallFile = responsesDir + "\\ownership_fallback.json";
    if (!write_file(fallFile, fallBody)) {
        fprintf(stderr, "[Config] ERREUR: impossible d'ecrire %s\n", fallFile.c_str());
        return 1;
    }
    ini += "[Rule_Ownership_Fallback]\n";
    ini += "Enabled=0\n";
    ini += "Priority=198\n";
    ini += "Method=GET\n";
    ini += "Pattern=" + patFall + "\n";
    ini += "ResponseFile=ownership_fallback.json\n";
    ini += "StatusCode=200\n";
    ini += "ContentType=application/json\n\n";
    ruleCount++;

    if (!write_file(opt.rules_file, ini)) {
        fprintf(stderr, "[Config] ERREUR: impossible d'ecrire %s\n", opt.rules_file.c_str());
        return 1;
    }
    printf("[Config] OK - regles ecrites : %s\n", opt.rules_file.c_str());
    printf("[Config]   cible        : %s%s\n", authority.c_str(), path.c_str());
    printf("[Config]   product_id   : %s\n", hasPid ? pid.c_str() : "(aucun - regle any-product)");
    printf("[Config]   payloads     : %s\n", responsesDir.c_str());
    printf("[Config]   injection    : %s\n", opt.inject_luau ? "Luau mock.respond (audit \"inject\")" : "fichier ResponseFile (audit \"mock-file\")");
    printf("[Config]   regles       : %d (dont fallback desactive)\n", ruleCount);
    return 0;
}

#include <winsvc.h>

static int restart_service(const std::string& name) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "[Deploy] ERREUR: OpenSCManager a echoue (%lu) - administrateur requis\n",
                (unsigned long)GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceA(scm, name.c_str(),
                                 SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        fprintf(stderr, "[Deploy] ERREUR: service '%s' introuvable (%lu)\n",
                name.c_str(), (unsigned long)GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st;
    int rc = 0;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st) && st.dwCurrentState != SERVICE_STOPPED) {
        for (int i = 0; i < 30 && st.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(1000);
            QueryServiceStatus(svc, &st);
        }
    }
    if (st.dwCurrentState != SERVICE_STOPPED) {
        fprintf(stderr, "[Deploy] ERREUR: arret du service '%s' en timeout\n", name.c_str());
        rc = 1;
    } else if (!StartServiceA(svc, 0, nullptr)) {
        fprintf(stderr, "[Deploy] ERREUR: demarrage du service '%s' (%lu)\n",
                name.c_str(), (unsigned long)GetLastError());
        rc = 1;
    } else {
        printf("[Deploy] Service '%s' redemarre.\n", name.c_str());
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}

// Etape Deploy : pousse les regles vers le proxy, marque le rechargement.
static int stage_deploy(const Options& opt) {
    printf("[Deploy] Publication des regles vers le proxy...\n");
    std::string proxyDir = opt.proxy_rules_dir;
    if (proxyDir.empty()) {
        fprintf(stderr, "[Deploy] ERREUR: indiquez le dossier de regles cible via --mock-proxy-dir\n");
        return 1;
    }
    if (!ensure_dirs(proxyDir)) {
        fprintf(stderr, "[Deploy] ERREUR: dossier proxy '%s' inacessible\n", proxyDir.c_str());
        return 1;
    }
    std::string rulesData = read_file(opt.rules_file);
    if (rulesData.empty()) {
        fprintf(stderr, "[Deploy] ERREUR: rules '%s' vide - lancez d'abord --mock-configure\n", opt.rules_file.c_str());
        return 1;
    }
    std::string target = proxyDir + "\\rules.ini";
    if (!write_file(target, rulesData)) {
        fprintf(stderr, "[Deploy] ERREUR: ecriture impossible %s\n", target.c_str());
        return 1;
    }
    printf("[Deploy] Regles copiees : %s\n", target.c_str());
    std::vector<std::string> payloads = glob_files(opt.response_out_dir + "\\*.json");
    for (const std::string& f : payloads) {
        std::string data = read_file(f);
        if (data.empty()) continue;
        std::string dst = proxyDir + "\\" + base_name(f);
        if (write_file(dst, data)) printf("[Deploy] Payload copie : %s\n", dst.c_str());
    }
    std::vector<std::string> scripts = glob_files(opt.response_out_dir + "\\*.luau");
    for (const std::string& f : scripts) {
        std::string data = read_file(f);
        if (data.empty()) continue;
        std::string dst = proxyDir + "\\" + base_name(f);
        if (write_file(dst, data)) printf("[Deploy] Script d'injection copie : %s\n", dst.c_str());
    }
    std::string marker = proxyDir + "\\" + opt.reload_marker;
    if (!write_file(marker, std::string("\n"))) {
        fprintf(stderr, "[Deploy] ERREUR: impossible d'ecrire le marqueur %s\n", marker.c_str());
        return 1;
    }
    printf("[Deploy] Marqueur de rechargement posé : %s\n", marker.c_str());
    if (!opt.proxy_service.empty()) {
        return restart_service(opt.proxy_service);
    }
    printf("[Deploy] OK - anticipez un rechargement automatique du proxy (%s)\n", marker.c_str());
    return 0;
}

static std::string normalize_stage(const std::string& s) {
    std::string t = to_lower(trim(s));
    if (t == "a" || t == "analyser" || t == "analyse") t = "analyze";
    if (t == "c") t = "capture";
    if (t == "conf" || t == "generer" || t == "générer") t = "configure";
    if (t == "d") t = "deploy";
    if (t == "t" || t == "tout") t = "all";
    return t;
}

static const char* stage_label(const std::string& s) {
    if (s == "analyze") return "Analyse";
    if (s == "capture") return "Capture";
    if (s == "configure") return "Configuration";
    if (s == "deploy") return "Deploiement";
    return s.c_str();
}

int RunMockStage(const std::string& stage, const Options& opt) {
    std::string s = normalize_stage(stage);
    printf("=== Mock Ownership : etape '%s' ===\n", stage_label(s));
    if (s == "analyze") return stage_analyze(opt);
    if (s == "capture") return stage_capture(opt);
    if (s == "configure") return stage_configure(opt);
    if (s == "deploy") return stage_deploy(opt);
    if (s == "all" || s.empty()) {
        int rc;
        printf("--- [1/4] Analyse ---\n");
        rc = stage_analyze(opt);
        if (rc) { printf("Etape Analyse echouee. Abandon.\n"); return rc; }
        printf("--- [2/4] Capture ---\n");
        rc = stage_capture(opt);
        if (rc) { printf("Etape Capture echouee. Abandon.\n"); return rc; }
        printf("--- [3/4] Configuration ---\n");
        rc = stage_configure(opt);
        if (rc) { printf("Etape Configuration echouee. Abandon.\n"); return rc; }
        printf("--- [4/4] Deploiement ---\n");
        rc = stage_deploy(opt);
        if (rc) { printf("Etape Deploiement echouee.\n"); return rc; }
        printf("=== Mock Ownership : pipeline complet OK ===\n");
        return 0;
    }
    fprintf(stderr, "Etape inconnue '%s' (valeurs: analyze, capture, configure, deploy, all)\n",
            stage.c_str());
    return 1;
}

} // namespace mockgen