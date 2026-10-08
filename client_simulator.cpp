#include "client_simulator.hpp"

#include <iomanip>
#include <cctype>
#include <cstdlib>

namespace ecommerce_sim {

ClientSimulator::ClientSimulator(const RequestConfig& config)
    : config_(config) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    init_curl();
}

ClientSimulator::~ClientSimulator() {
    cleanup_curl();
    curl_global_cleanup();
}

void ClientSimulator::init_curl() {
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("curl_easy_init() failed");
    }
}

void ClientSimulator::cleanup_curl() {
    if (curl_) {
        if (current_headers_) {
            curl_slist_free_all(current_headers_);
            current_headers_ = nullptr;
            curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, nullptr);
        }
        curl_easy_cleanup(curl_);
        curl_ = nullptr;
    }
}

void ClientSimulator::set_rate_limit_config(const RateLimitConfig& config) {
    std::lock_guard<std::mutex> lock(rate_mutex_);
    rate_config_ = config;
}

void ClientSimulator::update_session_token(const std::string& token) {
    std::lock_guard<std::mutex> lock(curl_mutex_);
    config_.session_token = token;
}

void ClientSimulator::set_proxy(const std::string& proxy_url) {
    std::lock_guard<std::mutex> lock(curl_mutex_);
    proxy_url_ = proxy_url;
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

size_t ClientSimulator::write_callback(void* contents, size_t size,
                                       size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    auto* body = static_cast<std::string*>(userp);
    body->append(static_cast<char*>(contents), total_size);
    return total_size;
}

size_t ClientSimulator::header_callback(char* buffer, size_t size,
                                        size_t nitems, void* userp) {
    size_t total_size = size * nitems;
    auto* headers = static_cast<std::map<std::string, std::string>*>(userp);
    std::string line(buffer, total_size);

    auto colon_pos = line.find(':');
    if (colon_pos != std::string::npos) {
        std::string name = line.substr(0, colon_pos);
        std::string value = line.substr(colon_pos + 1);
        value.erase(0, value.find_first_not_of(" \t\r\n"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);
        std::transform(name.begin(), name.end(), name.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        (*headers)[name] = value;
    }
    return total_size;
}

// ---------------------------------------------------------------------------
// Header construction: session token + W3C-compliant client hints
// ---------------------------------------------------------------------------

curl_slist* ClientSimulator::configure_headers() {
    curl_slist* headers = nullptr;

    if (!config_.session_token.empty()) {
        std::string auth_header = "Authorization: Bearer " + config_.session_token;
        headers = curl_slist_append(headers, auth_header.c_str());
    }

    std::string ua = config_.user_agent.empty()
        ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        : config_.user_agent;
    headers = curl_slist_append(headers, ("User-Agent: " + ua).c_str());

    std::string sec_ch_ua = config_.sec_ch_ua.empty()
        ? "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", "
          "\"Not-A.Brand\";v=\"99\""
        : config_.sec_ch_ua;
    headers = curl_slist_append(headers, ("Sec-CH-UA: " + sec_ch_ua).c_str());

    std::string platform = config_.sec_ch_ua_platform.empty()
        ? "\"Windows\""
        : config_.sec_ch_ua_platform;
    headers = curl_slist_append(headers,
        ("Sec-CH-UA-Platform: " + platform).c_str());
    headers = curl_slist_append(headers,
        "Sec-CH-UA-Mobile: ?0");
    headers = curl_slist_append(headers,
        "Sec-CH-UA-Platform-Version: \"15.0.0\"");
    headers = curl_slist_append(headers,
        "Sec-Fetch-Site: same-origin");
    headers = curl_slist_append(headers,
        "Sec-Fetch-Mode: cors");
    headers = curl_slist_append(headers,
        "Sec-Fetch-Dest: empty");

    headers = curl_slist_append(headers,
        ("Accept-Language: " +
         (config_.accept_language.empty() ? std::string("en-US,en;q=0.9")
                                         : config_.accept_language)).c_str());
    headers = curl_slist_append(headers,
        "Accept: application/json, text/plain, */*");
    headers = curl_slist_append(headers,
        "Content-Type: application/json; charset=utf-8");
    headers = curl_slist_append(headers,
        "Origin: https://shop.example.com");
    headers = curl_slist_append(headers,
        "Referer: https://shop.example.com/checkout");
    headers = curl_slist_append(headers,
        "X-Requested-With: XMLHttpRequest");
    headers = curl_slist_append(headers,
        "Cache-Control: no-cache");
    headers = curl_slist_append(headers,
        "Upgrade-Insecure-Requests: 1");

    return headers;
}

// ---------------------------------------------------------------------------
// Rate limiting with randomized human-like delays
// ---------------------------------------------------------------------------

double ClientSimulator::calculate_random_delay() const {
    static std::mt19937 generator(
        std::random_device{}() ^
        static_cast<unsigned long>(
            std::chrono::system_clock::now().time_since_epoch().count()));

    std::uniform_real_distribution<double> base_delay(
        rate_config_.min_delay_ms, rate_config_.max_delay_ms);
    std::normal_distribution<double> jitter(
        0.0, rate_config_.jitter_factor *
             (rate_config_.max_delay_ms - rate_config_.min_delay_ms));

    double delay = base_delay(generator) + jitter(generator);
    return (std::max)(0.0, delay);
}

void ClientSimulator::enforce_rate_limit() {
    std::lock_guard<std::mutex> lock(rate_mutex_);
    auto now = std::chrono::steady_clock::now();

    recent_requests_.erase(
        std::remove_if(
            recent_requests_.begin(), recent_requests_.end(),
            [&](const RequestTimestamp& rt) {
                return std::chrono::duration<double>(
                           now - rt.timestamp).count() >
                       rate_config_.burst_window_seconds;
            }),
        recent_requests_.end());

    if (static_cast<int>(recent_requests_.size()) >=
        rate_config_.burst_limit) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(
                static_cast<long long>(calculate_random_delay())));
        recent_requests_.clear();
    } else {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(
                static_cast<long long>(calculate_random_delay())));
    }

    recent_requests_.push_back({now});
}

// ---------------------------------------------------------------------------
// Core request execution
// ---------------------------------------------------------------------------

std::string ClientSimulator::build_full_url(const std::string& endpoint) const {
    if (endpoint.empty()) {
        return config_.base_url;
    }
    if (config_.base_url.back() == '/' && endpoint.front() == '/') {
        return config_.base_url + endpoint.substr(1);
    }
    if (config_.base_url.back() != '/' && endpoint.front() != '/') {
        return config_.base_url + "/" + endpoint;
    }
    return config_.base_url + endpoint;
}

Response ClientSimulator::execute_request(CURL* curl, const std::string& url,
                                          const std::string& method,
                                          const std::string& body) {
    Response response;
    std::string response_body;
    std::map<std::string, std::string> response_headers;

    std::lock_guard<std::mutex> lock(curl_mutex_);

    if (current_headers_) {
        curl_slist_free_all(current_headers_);
        current_headers_ = nullptr;
    }
    current_headers_ = configure_headers();
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, current_headers_);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response_headers);

    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)config_.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate, br");

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,
                     config_.follow_redirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,
                     (long)config_.max_redirects);

    if (!proxy_url_.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url_.c_str());
    }

    // Passerelle de test ltg : faire confiance à la Root CA locale dont les
    // certificats feuilles sont générés à la volée. LTG_CA_PEM pointe vers un
    // bundle PEM (root LGT + CA publiques). Absent -> vérification par défaut.
    {
        if (const char* pem = std::getenv("LTG_CA_PEM"); pem && *pem) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, pem);
        }
    }

#ifdef CURL_AT_LEAST_VERSION
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);
#endif

    if (method == "POST" || method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    }

    if (method == "GET") {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &response.total_time);
        response.success =
            (response.status_code >= 200 && response.status_code < 300);
        response.body = response_body;
        response.headers = response_headers;
    } else {
        response.body = "curl error: " +
                        std::string(curl_easy_strerror(res));
        response.success = false;
    }

    return response;
}

// ---------------------------------------------------------------------------
// Public HTTP methods
// ---------------------------------------------------------------------------

Response ClientSimulator::get(const std::string& endpoint) {
    enforce_rate_limit();
    total_requests_++;
    Response r = execute_request(curl_, build_full_url(endpoint), "GET");
    response_times_.push_back(r.total_time);
    if (!r.success) failed_requests_++;
    return r;
}

Response ClientSimulator::post(const std::string& endpoint,
                               const std::string& json_body) {
    enforce_rate_limit();
    total_requests_++;
    Response r = execute_request(curl_, build_full_url(endpoint), "POST",
                                 json_body);
    response_times_.push_back(r.total_time);
    if (!r.success) failed_requests_++;
    return r;
}

Response ClientSimulator::put(const std::string& endpoint,
                              const std::string& json_body) {
    enforce_rate_limit();
    total_requests_++;
    Response r = execute_request(curl_, build_full_url(endpoint), "PUT",
                                 json_body);
    response_times_.push_back(r.total_time);
    if (!r.success) failed_requests_++;
    return r;
}

Response ClientSimulator::del(const std::string& endpoint) {
    enforce_rate_limit();
    total_requests_++;
    Response r = execute_request(curl_, build_full_url(endpoint), "DELETE");
    response_times_.push_back(r.total_time);
    if (!r.success) failed_requests_++;
    return r;
}

// ---------------------------------------------------------------------------
// Purchase flow helpers
// ---------------------------------------------------------------------------

Response ClientSimulator::validate_cart(const std::vector<PurchaseItem>& items) {
    std::ostringstream json;
    json << "{\"items\":[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) json << ",";
        const auto& item = items[i];
        json << "{"
             << "\"product_id\":" << escape_json_string(item.product_id)
             << ","
             << "\"quantity\":" << item.quantity << ","
             << "\"variant\":" << escape_json_string(item.variant);
        if (!item.attributes.empty()) {
            json << ",\"attributes\":{";
            size_t j = 0;
            for (const auto& [key, value] : item.attributes) {
                if (j++ > 0) json << ",";
                json << escape_json_string(key) << ":"
                     << escape_json_string(value);
            }
            json << "}";
        }
        json << "}";
    }
    json << "],\"destination\":{"
         << "\"country\":\"US\""
         << "}}";
    return post("/api/v1/cart/validate", json.str());
}

Response ClientSimulator::apply_promo_code(const std::string& code) {
    std::string json = "{\"promo_code\":" + escape_json_string(code) + "}";
    return post("/api/v1/cart/promo", json);
}

Response ClientSimulator::execute_purchase_flow(const PurchaseRequest& purchase) {
    return post("/api/v1/checkout/purchase",
                build_purchase_payload(purchase));
}

std::string ClientSimulator::build_purchase_payload(
    const PurchaseRequest& purchase) const {
    return build_purchase_json(purchase);
}

// ---------------------------------------------------------------------------
// JSON payload serialization
// ---------------------------------------------------------------------------

std::string ClientSimulator::escape_json_string(const std::string& str) const {
    std::ostringstream out;
    out << '"';
    for (char c : str) {
        switch (c) {
            case '"':  out << "\\\"";  break;
            case '\\': out << "\\\\";  break;
            case '\b': out << "\\b";   break;
            case '\f': out << "\\f";   break;
            case '\n': out << "\\n";   break;
            case '\r': out << "\\r";   break;
            case '\t': out << "\\t";   break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::nouppercase
                        << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c))
                        << std::dec << std::setfill(' ');
                } else {
                    out << c;
                }
        }
    }
    out << '"';
    return out.str();
}

std::string ClientSimulator::build_purchase_json(const PurchaseRequest& req) const {
    std::ostringstream json;

    json << "{";

    json << "\"request_id\":"
         << escape_json_string(
                "sim-" +
                std::to_string(
                    std::chrono::system_clock::now().time_since_epoch().count()))
         << ","
         << "\"version\":\"1.0\","
         << "\"currency\":" << escape_json_string(req.currency) << ",";

    json << "\"items\":";
    if (req.items.empty()) {
        json << "[]";
    } else {
        json << "[";
        for (size_t i = 0; i < req.items.size(); ++i) {
            const auto& item = req.items[i];
            if (i > 0) json << ",";
            json << "{"
                 << "\"product_id\":"
                 << escape_json_string(item.product_id)
                 << ","
                 << "\"quantity\":" << item.quantity << ","
                 << "\"variant\":"
                 << escape_json_string(item.variant);
            if (!item.attributes.empty()) {
                json << ",\"attributes\":{";
                size_t j = 0;
                for (const auto& [key, value] : item.attributes) {
                    if (j++ > 0) json << ",";
                    json << escape_json_string(key) << ":"
                         << escape_json_string(value);
                }
                json << "}";
            }
            json << "}";
        }
        json << "]";
    }

    json << ",\"shipping\":{"
         << "\"full_name\":" << escape_json_string(req.shipping.full_name) << ","
         << "\"address_line1\":"
         << escape_json_string(req.shipping.address_line1) << ","
         << "\"address_line2\":"
         << escape_json_string(req.shipping.address_line2) << ","
         << "\"city\":" << escape_json_string(req.shipping.city) << ","
         << "\"state\":" << escape_json_string(req.shipping.state) << ","
         << "\"postal_code\":"
         << escape_json_string(req.shipping.postal_code) << ","
         << "\"country\":" << escape_json_string(req.shipping.country) << ","
         << "\"phone\":" << escape_json_string(req.shipping.phone)
         << "},";

    json << "\"payment\":{"
         << "\"method\":" << escape_json_string(req.payment.method) << ","
         << "\"token_source\":" << escape_json_string(req.payment.token)
         << ","
         << "\"last_four\":" << escape_json_string(req.payment.last_four)
         << ","
         << "\"expiry_month\":"
         << escape_json_string(req.payment.expiry_month) << ","
         << "\"expiry_year\":"
         << escape_json_string(req.payment.expiry_year)
         << "}";

    json << ",\"promo_code\":"
         << (req.promo_code.empty()
                 ? std::string("null")
                 : escape_json_string(req.promo_code));

    json << ",\"metadata\":";
    if (req.metadata.empty()) {
        json << "{}";
    } else {
        json << "{";
        size_t j = 0;
        for (const auto& [key, value] : req.metadata) {
            if (j++ > 0) json << ",";
            json << escape_json_string(key) << ":"
                 << escape_json_string(value);
        }
        json << "}";
    }

    json << "}";
    return json.str();
}

// ---------------------------------------------------------------------------
// Load testing / stats
// ---------------------------------------------------------------------------

std::vector<Response> ClientSimulator::run_load_test(
    const std::function<Response(ClientSimulator&)>& request_fn,
    int num_requests) {
    std::vector<Response> responses;
    responses.reserve(num_requests);
    for (int i = 0; i < num_requests; ++i) {
        responses.push_back(request_fn(*this));
    }
    return responses;
}

void ClientSimulator::reset_stats() {
    std::lock_guard<std::mutex> lock(curl_mutex_);
    response_times_.clear();
    total_requests_ = 0;
    failed_requests_ = 0;
}

double ClientSimulator::get_average_response_time() const {
    if (response_times_.empty()) return 0.0;
    double sum = std::accumulate(response_times_.begin(),
                                 response_times_.end(), 0.0);
    return sum / response_times_.size();
}

double ClientSimulator::get_error_rate() const {
    int total = total_requests_.load();
    if (total == 0) return 0.0;
    return static_cast<double>(failed_requests_.load()) / total;
}

} // namespace ecommerce_sim