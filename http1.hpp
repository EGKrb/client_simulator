#pragma once
#include <string>
#include <unordered_map>
#include <cctype>
#include <cstdlib>

namespace http1 {

inline std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

struct Message {
    std::unordered_map<std::string, std::string> headers;   // clés normalisées minuscules
    std::string body;

    std::string get(const std::string& k) const {
        auto it = headers.find(lower(k));
        return it == headers.end() ? std::string() : it->second;
    }
    void set(const std::string& k, const std::string& v) { headers[lower(k)] = v; }
    bool has(const std::string& k) const { return headers.count(lower(k)) != 0; }

    virtual bool parse_start(const std::string& line) = 0;
    virtual std::string start_line() const = 0;
};

struct Request : Message {
    std::string method, target, version;
    bool parse_start(const std::string& line) override {
        auto s1 = line.find(' '), s2 = line.find(' ', s1 + 1);
        if (s1 == std::string::npos || s2 == std::string::npos) return false;
        method = line.substr(0, s1);
        target = line.substr(s1 + 1, s2 - s1 - 1);
        version = line.substr(s2 + 1);
        return true;
    }
    std::string start_line() const override { return method + " " + target + " " + version; }
};

struct Response : Message {
    std::string version;
    int code = 0;
    std::string reason;
    bool parse_start(const std::string& line) override {
        auto s1 = line.find(' ');
        if (s1 == std::string::npos) return false;
        version = line.substr(0, s1);
        code = std::atoi(line.c_str() + s1 + 1);
        auto s2 = line.find(' ', s1 + 1);
        reason = s2 == std::string::npos ? "" : line.substr(s2 + 1);
        return code >= 100 && code <= 999;
    }
    std::string start_line() const override {
        return version + " " + std::to_string(code) + " " + reason;
    }
};

inline bool is_hop_by_hop(const std::string& h) {
    static const std::unordered_map<std::string, int> hbh = {
        {"connection", 1}, {"keep-alive", 1}, {"proxy-connection", 1},
        {"proxy-authenticate", 1}, {"proxy-authorization", 1},
        {"te", 1}, {"trailer", 1}, {"transfer-encoding", 1},
        {"upgrade", 1}};
    return hbh.count(h) != 0;
}

inline const char* status_reason(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:  return "Response";
    }
}

inline std::string path_of(const std::string& target) {
    if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) {
        auto slash = target.find('/', target.find("://") + 3);
        return slash == std::string::npos ? "/" : target.substr(slash);
    }
    return target;
}

// Sérialisation : en-têtes hop-by-hop retirés, content-length recalculé
inline std::string serialize(const Message& m) {
    bool no_body = false;
    if (const Response* r = dynamic_cast<const Response*>(&m))
        no_body = r->code < 200 || r->code == 204 || r->code == 304;

    std::string out = m.start_line() + "\r\n";
    for (const auto& [k, v] : m.headers) {
        std::string lk = lower(k);
        if (lk == "content-length" || is_hop_by_hop(lk)) continue;
        out += k + ": " + v + "\r\n";
    }
    if (!no_body)
        out += "content-length: " + std::to_string(m.body.size()) + "\r\n";
    out += "\r\n";
    if (!no_body) out += m.body;
    return out;
}

} // namespace http1