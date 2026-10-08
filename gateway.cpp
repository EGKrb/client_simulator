#include "gateway.hpp"
#include <openssl/err.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>

#pragma comment(lib, "ws2_32.lib")

namespace localgate {

// ---------- I/O générique socket ou SSL (déchiffré) ----------
static int io_read(SOCKET s, SSL* tls, char* b, int n) { return tls ? SSL_read(tls, b, n) : recv(s, b, n, 0); }
static int io_write(SOCKET s, SSL* tls, const char* b, int n) { return tls ? SSL_write(tls, b, n) : send(s, b, n, 0); }

// Lit une ligne. Retour 1 = ligne non vide, 0 = ligne vide, -1 = EOF/erreur.
static int read_line(SOCKET s, SSL* tls, std::string& line) {
    line.clear();
    char c{};
    for (;;) {
        int r = io_read(s, tls, &c, 1);
        if (r <= 0) {
            if (tls && r < 0) {
                fprintf(stderr, "[ltg] lecture TLS interrompue: %d\n", SSL_get_error(tls, r));
                ERR_print_errors_fp(stderr);
            }
            return -1;
        }
        if (c == '\n') break;
        line += c;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line.empty() ? 0 : 1;
}

// Message HTTP complet : start-line + en-tetes + corps (content-length ou chunked décodé)
static bool read_message(SOCKET s, SSL* tls, http1::Message& msg) {
    std::string line;
    if (read_line(s, tls, line) != 1) return false;
    if (!msg.parse_start(line)) return false;

    for (;;) {
        int r = read_line(s, tls, line);
        if (r < 0) return false;
        if (r == 0) break;   // ligne vide = fin des en-tetes
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
        msg.set(line.substr(0, colon), value);
    }

    if (http1::lower(msg.get("transfer-encoding")) == "chunked") {
        std::string body;
        for (;;) {
            if (read_line(s, tls, line) != 1) break;
            auto semi = line.find(';');
            std::string sz = semi == std::string::npos ? line : line.substr(0, semi);
            unsigned long n = strtoul(sz.c_str(), nullptr, 16);
            if (n == 0) {
                while (read_line(s, tls, line) == 1 && !line.empty()) {}   // trailers
                break;
            }
            size_t base = body.size();
            body.resize(base + n);
            size_t got = 0;
            while (got < n) {
                int r = io_read(s, tls, &body[base + got], (int)(n - got));
                if (r <= 0) break;
                got += (size_t)r;
            }
            body.resize(base + got);
            if (read_line(s, tls, line) != 1) break;   // CRLF de fin de chunk
        }
        msg.body = std::move(body);
        msg.set("content-length", std::to_string(msg.body.size()));
    } else {
        std::string cl = msg.get("content-length");
        if (!cl.empty()) {
            unsigned long len = strtoul(cl.c_str(), nullptr, 10);
            std::string body;
            body.resize(len);
            size_t got = 0;
            while (got < len) {
                int r = io_read(s, tls, &body[got], (int)(len - got));
                if (r <= 0) break;
                got += (size_t)r;
            }
            body.resize(got);
            msg.body = std::move(body);
        }
    }
    return true;
}

static bool split_host_port(const std::string& authority, std::string& host, std::string& port) {
    if (authority.empty()) return false;
    if (authority[0] == '[') {
        auto close = authority.find(']');
        if (close == std::string::npos) return false;
        host = authority.substr(1, close - 1);
        port = close + 2 <= authority.size() ? authority.substr(close + 2) : "";
        if (port.empty()) port = "443";
        return !host.empty();
    }
    auto colon = authority.rfind(':');
    if (colon == std::string::npos) { host = authority; port = "443"; }
    else { host = authority.substr(0, colon); port = authority.substr(colon + 1); }
    return !host.empty();
}

// ---------- CertStore ----------
CertStore::CertStore(const std::string& cn, const std::string& org) {
    root_ = create_root_ca(cn, org);
}

void CertStore::load() {
    if (export_der(root_, "ltg-root.der") && install_into_windows_root("ltg-root.der"))
        fprintf(stderr, "[pki] Root CA installee dans LocalMachine\\Root\n");
    else
        fprintf(stderr, "[pki] ECHEC installation Root CA (privileges admin requis)\n");
}

const KeyCert& CertStore::leaf_for(const std::string& host) {
    std::lock_guard<std::mutex> lk(m_);
    auto it = leaves_.find(host);
    if (it == leaves_.end()) {
        auto leaf = std::make_unique<KeyCert>(create_leaf(root_, host, ++serial_));
        it = leaves_.emplace(host, std::move(leaf)).first;
    }
    return *it->second;
}

static int cert_cb(SSL* ssl, void* arg) {
    auto* store = static_cast<CertStore*>(arg);
    const char* sn = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    const std::string host = sn ? sn : "gateway.local";
    const KeyCert& leaf = store->leaf_for(host);
    if (SSL_use_certificate(ssl, leaf.cert) != 1) return 0;
    if (SSL_use_PrivateKey(ssl, leaf.pkey) != 1) return 0;
    return 1;
}

// ---------- Gateway ----------
Gateway::Gateway(CertStore& st, RuleEngine& rules, MockController& mock)
    : store_(st), rules_(rules), mock_(mock) {
    SSL_library_init();
    server_ctx_ = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(server_ctx_, TLS1_2_VERSION);
    SSL_CTX_set_cert_cb(server_ctx_, cert_cb, &store_);

    client_ctx_ = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(client_ctx_, TLS1_2_VERSION);
    SSL_CTX_set_verify(client_ctx_, SSL_VERIFY_NONE, nullptr); // environnement de test uniquement
}

void Gateway::run(int port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ls, (sockaddr*)&addr, sizeof(addr));
    listen(ls, 64);
    fprintf(stderr, "[ltg] Passerelle active sur 127.0.0.1:%d\n", port);

    for (;;) {
        SOCKET s = accept(ls, nullptr, nullptr);
        std::thread([this, s] { handle_client(s); }).detach();
    }
}

void Gateway::handle_client(SOCKET s) {
    std::string first;
    if (read_line(s, nullptr, first) != 1) { closesocket(s); return; }

    if (first.rfind("CONNECT ", 0) == 0) {
        auto p1 = first.find(' ');
        auto p2 = first.rfind(' ');
        handle_connect(s, first.substr(p1 + 1, p2 - p1 - 1), first);
    } else {
        // forme absolue : GET https://host:port/... HTTP/1.1 (rare, traitée en HTTPS)
        http1::Request req;
        if (!req.parse_start(first)) { closesocket(s); return; }
        std::string origin = req.get("host");
        forward(s, nullptr, req, origin);
        serve_requests(s, nullptr, origin);
    }
    closesocket(s);
}

void Gateway::handle_connect(SOCKET s, const std::string& authority, const std::string& /*start_line*/) {
    // CONNECT peut transporter des en-tetes (Host:, Proxy-*, ...) : on les
    // consomme jusqu'a la ligne vide, sinon SSL_accept lit du HTTP en clair.
    {
        std::string rest;
        while (read_line(s, nullptr, rest) == 1) {}
    }

    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(s, ok, (int)strlen(ok), 0);

    std::string host = authority, port = "443";
    auto colon = authority.rfind(':');
    if (colon != std::string::npos) { host = authority.substr(0, colon); port = authority.substr(colon + 1); }

    SSL* client = SSL_new(server_ctx_);
    SSL_set_fd(client, (int)s);
    int ar = SSL_accept(client);
    if (ar != 1) {
        int err = SSL_get_error(client, ar);
        fprintf(stderr, "[ltg] SSL_accept echec err=%d\n", err);
        ERR_print_errors_fp(stderr);
        SSL_free(client);
        return;
    }
    fprintf(stderr, "[ltg] tunnel TLS demasque pour %s (%s)\n", host.c_str(), SSL_get_cipher(client));

    serve_requests(s, client, host + ":" + port);
    SSL_shutdown(client);
    SSL_free(client);
}

void Gateway::serve_requests(SOCKET client_sock, SSL* client_tls, const std::string& origin_host) {
    for (;;) {
        http1::Request req;
        if (!read_message(client_sock, client_tls, req)) break;
        forward(client_sock, client_tls, req, origin_host);
        if (http1::lower(req.get("connection")) == "close") break;
    }
}

void Gateway::forward(SOCKET client_sock, SSL* client_tls, const http1::Request& req, const std::string& origin_host) {
    Directive d = rules_.evaluate(req);
    if (d.action == Action::kDrop) { audit(req, nullptr, "drop"); return; }
    if (d.latency_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(d.latency_ms));

    http1::Response resp;
    std::string note;

    if (!d.respond_file.empty()) {
        // Contrat proxy-mock : réponse de possession servie depuis un fichier
        // (payload JSON capturé), AUCUN appel upstream. Endpoint de type Query
        // (idempotent, non signé) -> pas d'effet de bord côté backend.
        resp.version = "HTTP/1.1";
        resp.code = d.respond_status != 0 ? d.respond_status : 200;
        resp.reason = http1::status_reason(resp.code);
        resp.set("content-type", d.respond_content_type.empty() ? "application/json" : d.respond_content_type);
        std::ifstream fin(d.respond_file.c_str(), std::ios::binary);
        if (fin) resp.body.assign((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        note = "mock-file";
    } else if (d.inject_status > 0 || !d.mock_script.empty()) {
        // pas d'appel upstream : réponse synthétique ou mock Luau
        resp.version = "HTTP/1.1";
        if (!d.mock_script.empty() && mock_.try_script(d.mock_script, req, "inject", resp)) {
            note = d.respond_note.empty() ? "mock" : d.respond_note;
            if (d.inject_status > 0) {
                resp.code = d.inject_status;
                resp.reason = http1::status_reason(resp.code);
            }
        } else {
            resp.code = d.inject_status > 0 ? d.inject_status : 500;
            resp.reason = http1::status_reason(resp.code);
            resp.set("content-type", "text/plain");
            resp.body.clear();
            note = "inject";
        }
    } else {
        std::string host, port;
        if (!split_host_port(origin_host, host, port)) {
            note = "bad authority"; resp.version = "HTTP/1.1"; resp.code = 502; goto done;
        }

        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
            note = "dns fail"; resp.version = "HTTP/1.1"; resp.code = 502; goto done;
        }

        SOCKET up = INVALID_SOCKET;
        for (auto* ai = res; ai; ai = ai->ai_next) {
            up = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (up == INVALID_SOCKET) continue;
            if (connect(up, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
            closesocket(up);
            up = INVALID_SOCKET;
        }
        freeaddrinfo(res);

        if (up == INVALID_SOCKET) {
            note = "connect fail"; resp.version = "HTTP/1.1"; resp.code = 502; goto done;
        }

        SSL* upstream = SSL_new(client_ctx_);
        SSL_set_fd(upstream, (int)up);
        if (SSL_connect(upstream) != 1) {
            note = "upstream tls fail";
        } else {
            http1::Request out = req;
            if (out.target.rfind("http://", 0) == 0 || out.target.rfind("https://", 0) == 0)
                out.target = http1::path_of(out.target);

            std::string payload = http1::serialize(out);
            size_t off = 0;
            while (off < payload.size()) {
                int n = io_write(up, upstream, payload.data() + off, (int)(payload.size() - off));
                if (n <= 0) break;
                off += (size_t)n;
            }

            if (off < payload.size()) {
                note = "upstream write fail";
            } else {
                http1::Response raw;
                if (read_message(up, upstream, raw)) {
                    resp = std::move(raw);
                    note = "forward";
                    if (resp.code >= 500) {
                        Directive d2 = rules_.evaluate(resp, req);
                        if (!d2.mock_script.empty()) {
                            http1::Response mocked;
                            if (mock_.try_fallback(req, "backend 5xx", mocked)) {
                                resp = std::move(mocked);
                                note = "mock 5xx";
                            }
                        }
                    }
                } else {
                    note = "upstream no response";
                }
            }
        }
        SSL_shutdown(upstream);
        SSL_free(upstream);
        closesocket(up);
    }

    // directives post-traitement (les deux chemins : inject et forward)
done:
    if (d.strip_body) resp.body.clear();
    if (!d.mutate_header.empty()) {
        auto colon = d.mutate_header.find(':');
        if (colon != std::string::npos)
            resp.set(d.mutate_header.substr(0, colon), d.mutate_header.substr(colon + 1));
    }

    if (resp.code < 100) {
        resp.code = 502;
        resp.reason = http1::status_reason(502);
    }
    resp.version = resp.version.empty() ? "HTTP/1.1" : resp.version;
    if (resp.reason.empty() || resp.reason == "HTTP/1.1")
        resp.reason = http1::status_reason(resp.code);

    std::string payload = http1::serialize(resp);
    size_t off = 0;
    while (off < payload.size()) {
        int n = io_write(client_sock, client_tls, payload.data() + off, (int)(payload.size() - off));
        if (n <= 0) break;
        off += (size_t)n;
    }

    audit(req, &resp, note);
}

void Gateway::audit(const http1::Request& req, const http1::Response* resp, const std::string& note) {
    if (resp)
        fprintf(stderr, "[ltg] %s %s -> %d (%s)\n", req.method.c_str(), req.target.c_str(), resp->code, note.c_str());
    else
        fprintf(stderr, "[ltg] %s %s -> (%s)\n", req.method.c_str(), req.target.c_str(), note.c_str());
}

} // namespace localgate