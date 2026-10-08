#include "client_simulator.hpp"
#include <iostream>
#include <cassert>

using namespace ecommerce_sim;

static void print_response(const std::string& label, const Response& r) {
    std::cout << "── " << label << " ──\n"
              << "  HTTP " << r.status_code
              << " | " << (r.total_time * 1000.0) << " ms\n"
              << "  OK: " << (r.success ? "true" : "false") << "\n";
    if (!r.body.empty() && r.body.size() < 500) {
        std::cout << "  Body: " << r.body.substr(0, 200) << "\n";
    }
    std::cout << "\n";
}

int main() {
    RequestConfig cfg;
    cfg.base_url = "https://shop.example.com";
    cfg.session_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
                        "eyJzdWIiOiIxMjM0NTY3ODkwIiwic2Vzc2lvbl9pZCI6"
                        "InNlc3MtYWJjZGVmIiwicm9sZSI6ImJyb3dzZXIiLCJp"
                        "YXQiOjE3MTgwMDAwMDB9";
    cfg.user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    cfg.sec_ch_ua =
        "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", "
        "\"Not-A.Brand\";v=\"99\"";
    cfg.sec_ch_ua_platform = "\"Windows\"";
    cfg.accept_language = "en-US,en;q=0.9,fr;q=0.8";

    ClientSimulator simulator(cfg);

    RateLimitConfig rl;
    rl.min_delay_ms = 800.0;
    rl.max_delay_ms = 2500.0;
    rl.burst_limit = 3;
    rl.burst_window_seconds = 8.0;
    rl.jitter_factor = 0.15;
    simulator.set_rate_limit_config(rl);

    // ── 1. GET request ──────────────────────────────────────────────────────
    std::cout << "1) GET /api/v1/cart\n";
    Response cart_resp = simulator.get("/api/v1/cart");
    print_response("GET /api/v1/cart", cart_resp);

    // ── 2. POST – cart validation ───────────────────────────────────────────
    std::cout << "2) POST /api/v1/cart/validate\n";
    std::vector<PurchaseItem> items = {
        {"SKU-78421", 2, "XL",
         {{"color", "Midnight Blue"},
          {"material", "Merino Wool"}}},
        {"SKU-19283", 1, "standard", {}},
    };
    Response validate_resp = simulator.validate_cart(items);
    print_response("POST /api/v1/cart/validate", validate_resp);

    // ── 3. POST – full purchase flow ────────────────────────────────────────
    std::cout << "3) POST /api/v1/checkout/purchase\n";
    PurchaseRequest purchase;
    purchase.items = {
        {"SKU-78421", 2, "XL",
         {{"color", "Midnight Blue"},
          {"material", "Merino Wool"}}},
        {"SKU-19283", 1, "standard", {{"warranty", "extended"}}},
    };
    purchase.shipping = {
        "Jean Dupont",
        "123 Avenue des Champs-Elysees",
        "Apt 4B",
        "Paris",
        "Ile-de-France",
        "75008",
        "FR",
        "+33612345678"
    };
    purchase.payment = {
        "card",
        "tok_visa_4242",
        "4242",
        "12",
        "2027"
    };
    purchase.currency = "EUR";
    purchase.metadata = {
        {"session_source", "integration_test"},
        {"test_id", "IT-2026-001"},
        {"correlation_id", "corr-" +
            std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count())}
    };

    Response purchase_resp = simulator.execute_purchase_flow(purchase);
    print_response("POST /api/v1/checkout/purchase", purchase_resp);

    // ── 4. POST – promo code ────────────────────────────────────────────────
    std::cout << "4) POST /api/v1/cart/promo\n";
    Response promo_resp = simulator.apply_promo_code("SUMMER2026");
    print_response("POST /api/v1/cart/promo", promo_resp);

    // ── 5. Token update ─────────────────────────────────────────────────────
    std::cout << "5) update_session_token()\n";
    simulator.update_session_token("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.new_token");
    Response refresh_resp = simulator.get("/api/v1/cart");
    print_response("GET /api/v1/cart (after token refresh)", refresh_resp);

    // ── 6. Rate limit stats ─────────────────────────────────────────────────
    std::cout << "── Statistics ──\n"
              << "  Avg response time : "
              << simulator.get_average_response_time() * 1000.0
              << " ms\n"
              << "  Error rate        : "
              << simulator.get_error_rate() * 100.0
              << " %\n\n";

    // ── 7. Rapid burst (demonstrates rate limiting) ─────────────────────────
    std::cout << "6) Burst test – 6 rapid GET requests\n";
    for (int i = 0; i < 6; ++i) {
        simulator.get("/api/v1/health");
    }
    std::cout << "  Done.\n";

    return 0;
}
