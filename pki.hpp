#pragma once
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>

namespace localgate {

struct KeyCert {
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    ~KeyCert();
    KeyCert() = default;
    KeyCert(const KeyCert&) = delete;
    KeyCert& operator=(const KeyCert&) = delete;
    KeyCert(KeyCert&&) noexcept;
    KeyCert& operator=(KeyCert&&) noexcept;
};

KeyCert create_root_ca(const std::string& cn, const std::string& org);      // CA:TRUE, pathlen:1
KeyCert create_leaf (const KeyCert& ca, const std::string& host, long serial); // SAN DNS:host
bool    export_der  (const KeyCert& kc, const std::string& path);           // ltg-root.der
bool    install_into_windows_root(const std::string& der_path);            // LocalMachine\Root
}