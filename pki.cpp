#include "pki.hpp"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/applink.c>
#include <fstream>
#include <vector>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

namespace localgate {

KeyCert::~KeyCert() { if (pkey) EVP_PKEY_free(pkey); if (cert) X509_free(cert); }
KeyCert::KeyCert(KeyCert&& o) noexcept : pkey(o.pkey), cert(o.cert) { o.pkey = nullptr; o.cert = nullptr; }
KeyCert& KeyCert::operator=(KeyCert&& o) noexcept {
    if (this != &o) { this->~KeyCert(); pkey = o.pkey; cert = o.cert; o.pkey = nullptr; o.cert = nullptr; }
    return *this;
}

static X509_EXTENSION* make_ext(X509V3_CTX* ctx, int nid, const std::string& v) {
    return X509V3_EXT_conf_nid(nullptr, ctx, nid, const_cast<char*>(v.c_str()));
}
static void add_name(X509_NAME* n, const char* f, const std::string& v) {
    X509_NAME_add_entry_by_txt(n, f, MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(v.c_str()), -1, -1, 0);
}

KeyCert create_root_ca(const std::string& cn, const std::string& org) {
    KeyCert kc;
    kc.pkey = EVP_RSA_gen(4096);
    kc.cert = X509_new();

    X509_set_version(kc.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(kc.cert), 0x1001);
    X509_gmtime_adj(X509_getm_notBefore(kc.cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(kc.cert), 5L * 365 * 24 * 3600);

    X509_NAME* name = X509_get_subject_name(kc.cert);
    add_name(name, "C", "FR");
    add_name(name, "O", org);
    add_name(name, "OU", "OVS Local Test Infrastructure");
    add_name(name, "CN", cn);
    X509_set_issuer_name(kc.cert, name);
    X509_set_pubkey(kc.cert, kc.pkey);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, kc.cert, kc.cert, nullptr, nullptr, 0);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_basic_constraints, "critical,CA:TRUE,pathlen:1"), -1);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature"), -1);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_subject_key_identifier, "hash"), -1);

    if (!X509_sign(kc.cert, kc.pkey, EVP_sha256())) throw std::runtime_error("root sign failed");
    return kc;
}

KeyCert create_leaf(const KeyCert& ca, const std::string& host, long serial) {
    KeyCert kc;
    kc.pkey = EVP_RSA_gen(2048);
    kc.cert = X509_new();

    X509_set_version(kc.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(kc.cert), serial);
    X509_gmtime_adj(X509_getm_notBefore(kc.cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(kc.cert), 30L * 24 * 3600);

    X509_NAME* name = X509_get_subject_name(kc.cert);
    add_name(name, "C", "FR");
    add_name(name, "O", "Local Test Gateway");
    add_name(name, "CN", host);
    X509_set_issuer_name(kc.cert, X509_get_subject_name(ca.cert));
    X509_set_pubkey(kc.cert, kc.pkey);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca.cert, kc.cert, nullptr, nullptr, 0);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_basic_constraints, "critical,CA:FALSE"), -1);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment"), -1);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_ext_key_usage, "serverAuth,clientAuth"), -1);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_subject_alt_name, "DNS:" + host), -1);
    X509_add_ext(kc.cert, make_ext(&ctx, NID_authority_key_identifier, "keyid:always"), -1);

    if (!X509_sign(kc.cert, ca.pkey, EVP_sha256())) throw std::runtime_error("leaf sign failed");
    return kc;
}

bool export_der(const KeyCert& kc, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0) return false;
    bool ok = i2d_X509_fp(f, kc.cert) > 0;
    fclose(f);
    return ok;
}

bool install_into_windows_root(const std::string& der_path) {
    std::ifstream in(der_path, std::ios::binary);
    if (!in) return false;
    std::vector<BYTE> der((std::istreambuf_iterator<char>(in)), {});
    if (der.empty()) return false;

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"Root");
    if (!store) return false;
    bool ok = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
        der.data(), static_cast<DWORD>(der.size()),
        CERT_STORE_ADD_REPLACE_EXISTING, nullptr) != FALSE;
    CertCloseStore(store, 0);
    return ok;
}

} // namespace localgate