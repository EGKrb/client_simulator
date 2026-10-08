#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <string>
#include <vector>
#include <functional>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <iostream>
#include <curl/curl.h>

namespace ecommerce_sim {

struct RequestConfig {
    std::string base_url;
    std::string session_token;
    std::string user_agent;
    std::string sec_ch_ua;
    std::string sec_ch_ua_platform;
    std::string accept_language;
    int timeout_seconds = 30;
    bool follow_redirects = true;
    int max_redirects = 5;
};

struct Response {
    long status_code = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    double total_time = 0.0;
    bool success = false;
};

struct RateLimitConfig {
    double min_delay_ms = 1500.0;
    double max_delay_ms = 4500.0;
    int burst_limit = 5;
    double burst_window_seconds = 10.0;
    double jitter_factor = 0.2;
};

struct PurchaseItem {
    std::string product_id;
    int quantity = 1;
    std::string variant;
    std::map<std::string, std::string> attributes;
};

struct ShippingAddress {
    std::string full_name;
    std::string address_line1;
    std::string address_line2;
    std::string city;
    std::string state;
    std::string postal_code;
    std::string country;
    std::string phone;
};

struct PaymentInfo {
    std::string method;
    std::string token;
    std::string last_four;
    std::string expiry_month;
    std::string expiry_year;
};

struct PurchaseRequest {
    std::vector<PurchaseItem> items;
    ShippingAddress shipping;
    PaymentInfo payment;
    std::string currency = "USD";
    std::string promo_code;
    std::map<std::string, std::string> metadata;
};

class ClientSimulator {
public:
    explicit ClientSimulator(const RequestConfig& config);
    ~ClientSimulator();

    ClientSimulator(const ClientSimulator&) = delete;
    ClientSimulator& operator=(const ClientSimulator&) = delete;

    void set_rate_limit_config(const RateLimitConfig& config);
    void update_session_token(const std::string& token);
    void set_proxy(const std::string& proxy_url);

    Response get(const std::string& endpoint);
    Response post(const std::string& endpoint, const std::string& json_body);
    Response put(const std::string& endpoint, const std::string& json_body);
    Response del(const std::string& endpoint);

    Response execute_purchase_flow(const PurchaseRequest& purchase);
    Response validate_cart(const std::vector<PurchaseItem>& items);
    Response apply_promo_code(const std::string& code);
    std::string build_purchase_payload(const PurchaseRequest& purchase) const;

    std::vector<Response> run_load_test(
        const std::function<Response(ClientSimulator&)>& request_fn,
        int num_requests
    );

    void reset_stats();
    double get_average_response_time() const;
    double get_error_rate() const;

private:
    RequestConfig config_;
    RateLimitConfig rate_config_;
    CURL* curl_;
    std::string proxy_url_;
    mutable std::mutex curl_mutex_;
    curl_slist* current_headers_ = nullptr;

    std::vector<double> response_times_;
    std::atomic<int> total_requests_{0};
    std::atomic<int> failed_requests_{0};

    struct RequestTimestamp {
        std::chrono::steady_clock::time_point timestamp;
    };
    std::vector<RequestTimestamp> recent_requests_;
    mutable std::mutex rate_mutex_;

    void init_curl();
    void cleanup_curl();
    curl_slist* configure_headers();
    std::string build_full_url(const std::string& endpoint) const;
    void enforce_rate_limit();
    double calculate_random_delay() const;
    Response execute_request(CURL* curl, const std::string& url,
                             const std::string& method,
                             const std::string& body = "");

    static size_t write_callback(void* contents, size_t size,
                                 size_t nmemb, void* userp);
    static size_t header_callback(char* buffer, size_t size,
                                  size_t nitems, void* userp);

    std::string build_purchase_json(const PurchaseRequest& req) const;
    std::string escape_json_string(const std::string& str) const;
};

}