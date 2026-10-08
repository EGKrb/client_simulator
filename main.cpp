#include "gateway.hpp"
#include "rules.hpp"
#include "mock_controller.hpp"
#include <cstdio>

int main(int argc, char** argv) {
    localgate::CertStore store("LGT-Root-CA", "Local Test Gateway");
    store.load();                       // phase 1 : PKI (admin requis pour le magasin)

    localgate::RuleEngine rules;
    rules.load("rules.ini");            // phase 3 : paramètres d'audit/fuzzing

    localgate::MockController mock;     // phase 4 : bascule Luau (fallback.luau)

    localgate::Gateway gw(store, rules, mock);
    gw.run(argc > 1 ? atoi(argv[1]) : 7080);
    return 0;
}