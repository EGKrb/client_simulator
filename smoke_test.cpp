#include "client_simulator.hpp"
#include <iostream>

using namespace ecommerce_sim;

int main() {
    RequestConfig cfg;
    cfg.base_url = "http://httpbin.org";
    cfg.session_token =
        "eyJhbGciOiJSUzI1NiJ9.eyJzZXNzaW9uX2lkIjoidGVzdC1zZXNzaW9uIn0.abc123";
    cfg.user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    cfg.sec_ch_ua =
        "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", "
        "\"Not-A.Brand\";v=\"99\"";
    cfg.sec_ch_ua_platform = "\"Windows\"";
    cfg.accept_language = "en-US,en;q=0.9,fr;q=0.8";

    RateLimitConfig rl;
    rl.min_delay_ms = 50.0;
    rl.max_delay_ms = 120.0;
    rl.burst_limit = 10;
    rl.burst_window_seconds = 5.0;
    rl.jitter_factor = 0.1;

    ClientSimulator sim(cfg);
    sim.set_rate_limit_config(rl);

    // 1. GET echo — valide l'Authentification Bearer + headers W3C
    std::cout << "== GET /anything ==" << std::endl;
    Response g = sim.get("/anything");
    std::cout << "HTTP " << g.status_code << " OK=" << g.success << std::endl;
    if (g.success) {
        std::cout << "Echoed headers:" << std::endl;
        auto marker_auth = g.body.find("\"Authorization\": \"Bearer eyJ");
        auto marker_ua   = g.body.find("\"User-Agent\": \"Mozilla");
        auto marker_sec  = g.body.find("Sec-Ch-Ua");
        auto marker_plat = g.body.find("Sec-Ch-Ua-Platform");
        std::cout << "  Authorization Bearer set : "
                  << (marker_auth != std::string::npos ? "OUI" : "NON") << std::endl;
        std::cout << "  User-Agent set           : "
                  << (marker_ua != std::string::npos ? "OUI" : "NON") << std::endl;
        std::cout << "  Sec-CH-UA present        : "
                  << (marker_sec != std::string::npos ? "OUI" : "NON") << std::endl;
        std::cout << "  Sec-CH-UA-Platform kept  : "
                  << (marker_plat != std::string::npos ? "OUI" : "NON") << std::endl;
        auto hpos = g.body.find("\"headers\":");
        if (hpos != std::string::npos) {
            std::cout << "  RAW header dump:"
                      << g.body.substr(hpos, 700) << std::endl;
        }
    }

    // 2. POST purchase payload — valide la sérialisation JSON complexe
    std::cout << "\n== POST /anything (purchase payload) ==" << std::endl;
    PurchaseRequest p;
    p.items = { {"SKU-78421", 2, "XL",
                 {{"color", "Midnight Blue"}, {"material", "Merino Wool"}}} };
    p.shipping = {"Jean Dupont", "123 Avenue", "", "Paris", "IDF",
                  "75008", "FR", "+33612345678"};
    p.payment = {"card", "tok_visa", "4242", "12", "2027"};
    p.currency = "EUR";
    p.metadata = {{"session_source", "integration_test"}, {"test_id", "IT-001"}};

    std::string payload = sim.build_purchase_payload(p);
    std::cout << "Generated JSON:" << std::endl;
    std::cout << payload << std::endl;

    Response r = sim.post("/anything", payload);

    std::cout << "HTTP " << r.status_code << " OK=" << r.success << std::endl;
    if (r.success) {
        std::cout << "Echoed JSON (payload mirror):" << std::endl;
        auto pos = r.body.find("\"json\":");
        if (pos != std::string::npos) {
            std::cout << r.body.substr(pos, 700) << std::endl;
        }
    } else {
        std::cout << r.body.substr(0, 300) << std::endl;
    }

    // 3. Stats
    std::cout << "\n== Stats ==" << std::endl;
    std::cout << "Avg response time : "
              << sim.get_average_response_time() * 1000.0 << " ms" << std::endl;
    std::cout << "Error rate        : " << sim.get_error_rate() * 100.0 << " %"
              << std::endl;

    return 0;
}