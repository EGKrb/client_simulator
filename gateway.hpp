#pragma once
#include "http1.hpp"
#include "pki.hpp"
#include "rules.hpp"
#include "mock_controller.hpp"
#include <openssl/ssl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mutex>
#include <unordered_map>
#include <memory>

namespace localgate {

class CertStore {
public:
    CertStore(const std::string& cn, const std::string& org);
    void load();                            // génère + installe la Root CA (une seule fois)
    const KeyCert& root() const { return root_; }
    const KeyCert& leaf_for(const std::string& host);  // feuillet paresseux + cache (SNI)
private:
    KeyCert root_;
    std::unordered_map<std::string, std::unique_ptr<KeyCert>> leaves_;
    std::mutex m_;
    long serial_ = 0x2000;
};

class Gateway {
public:
    Gateway(CertStore& st, RuleEngine& rules, MockController& mock);
    void run(int port);
private:
    SSL_CTX* server_ctx_;
    SSL_CTX* client_ctx_;
    CertStore& store_;
    RuleEngine& rules_;
    MockController& mock_;
    void handle_client(SOCKET s);
    void handle_connect(SOCKET s, const std::string& authority, const std::string& start_line);
    void serve_requests(SOCKET s, SSL* client_tls, const std::string& origin_host);
    void forward(SOCKET client_sock, SSL* client_tls, const http1::Request& req, const std::string& origin_host);
    void audit(const http1::Request& req, const http1::Response* resp, const std::string& note);
};

} // namespace localgate