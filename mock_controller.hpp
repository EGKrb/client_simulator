#pragma once
#include "http1.hpp"
#include <string>

namespace localgate {

class MockController {
public:
    MockController();
    ~MockController();
    bool try_fallback(const http1::Request& req, const std::string& reason, http1::Response& out);
    // Exécute un script Luau spécifique (chemin résolu, ex. rules_dir\mock_success.luau)
    // qui injecte le payload via mock.respond. Retourne false si absent/erreur.
    bool try_script(const std::string& path, const http1::Request& req,
                    const std::string& reason, http1::Response& out);
private:
    bool eval_script(const std::string& source, const http1::Request& req,
                     const std::string& reason, http1::Response& out);
    void* L = nullptr;   // lua_State*
};

} // namespace localgate