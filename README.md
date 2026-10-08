# Client Simulator - Documentation

Simulateur de client HTTP e-commerce en C++17 utilisant libcurl. Envoye des requetes HTTP avec des headers W3C Client Hints, du rate limiting, et supporte un flux d'achat complet (carte, promo, checkout).

---

## Prérequis

- **Visual Studio 2022 Build Tools** (ou supérieur)
  - Composant MSVC x64 (`vcvars64.bat`)
- **curl** (bundlé dans `third_party/curl-8.22.0_1-win64-mingw/`)
- **Windows x64**

---

## Structure du projet

```
client_simulator/
├── build.bat                  # Script de compilation (CMD)
├── build_monnouvelapp.bat     # Build de MonNouvelApp.exe (cl + lib client_simulator)
├── client_simulator.cpp       # Implémentation de la bibliothèque
├── client_simulator.hpp       # En-tête public
├── example_usage.cpp          # Démo : flux d'achat complet (shop.example.com)
├── example_usage.exe          # Exécutable généré
├── smoke_test.cpp             # Test end-to-end (httpbin.org)
├── smoke_test.exe             # Exécutable généré
├── mock_target_api.py         # Serveur mock Target (localhost:8080, --sandbox)
├── curl-ca-bundle.crt         # Bundle CA pour TLS
├── libcurl-x64.dll            # DLL curl (copiée depuis third_party)
├── libcurl.lib                # Import library (générée par build.bat)
├── libcurl.exp                # Fichier d'export
├── verify_ltg.ps1             # Vérification bout-en-bout MonNouvelApp.exe + passerelle ltg
├── Deploy-VerificationSuccess.ps1  # Scénario Capture & Replay (spéc. CQ)
├── ltg-root.der               # Root CA exportée par ltg.exe (régénérée à chaque démarrage)
├── rules.ini                  # Règles d'injection de la passerelle
├── fallback.luau              # Mock Luau (réponse 500 + corps JSON)
├── MonNouvelApp_commands.md   # Référence complète des commandes de MonNouvelApp.exe
├── GUIDE_UTILISATION.md       # Guide de prise en main (démarrage rapide, FAQ, exemples)
├── ltg_commands.md            # Référence complète de la passerelle ltg.exe / --gateway
├── tools/tg-offline/         # Gel des MAJ Target + join CLI (freeze.ps1, join.ps1) — voir tools/tg-offline/README.md
├── src/
│   ├── monnouvelapp.cpp       # Source principal de MonNouvelApp.exe (ex-Untitled-1.cpp)
│   ├── nightshift_bridge.c    # Pont C vers le moteur NightShift (--ns/--ns-batch/--ns-repl)
│   ├── ghidra_bridge.hpp      # Pont C++ vers le CLI ghidra-rpc (mode --ghidra)
│   └── ghidra_bridge.cpp      #     (lance le venv Python en sous-processus)
├── ghidra-rpc/                # Package Python ghidra-rpc 0.2.0 vendorisé (mode --ghidra)
│   ├── ghidra_rpc/            #   CLI + daemon (cli.py, daemon.py, mcp_server.py, ...)
│   ├── docs/                  #   Install/quickstart/troubleshooting/internals
│   └── .venv/                 #   Venv créé par build_monnouvelapp.bat
├── bin/
│   ├── MonNouvelApp.exe       # Binaire compilé + DLLs + bundle CA
│   ├── libcurl-x64.dll
│   ├── libssl-3-x64.dll
│   ├── libcrypto-3-x64.dll
│   └── curl-ca-bundle.crt
├── reference/
│   └── proxy-mock/            # Pipeline PS d'origine (Generate-OwnershipMock.ps1)
├── nightshift/                # Module autonome NightShift (GP CLI + DLL internal)
│   ├── src/                   #   Sources C (main, commandes, DLL loader, ODBC...)
│   ├── include/               #   En-têtes (nightshift.h, dll_loader.h, internal_cmds.h)
│   ├── build.bat              #   Build MSVC (cl + link, odbc32/ole32/uuid)
│   ├── Makefile               #   Build alternatif MinGW (gcc)
│   ├── nightshift.exe         #   Binaire compilé
│   ├── aliases.txt            #   Connexions GP nommées (user|password|company)
│   ├── mydll.map              #   Exemple de map symboles (Ghidra, 966 syms)
│   └── test_*.bat|.txt        #   Scénarios batch du processor (CMD:/SQL:) + exe
├── tests/
│   ├── test_commands.ps1      # Harnais : teste une à une toutes les commandes (62 PASS, -ForceDangerous inclut le kernel)
│   └── serve_sandbox.py       # Serveur sandbox générique (routes --sim-* sur 8080)
├── mock_target_api.py         # Serveur de mock Target (flux d'achat --buy-* sur 8080)
├── vcpkg.json                 # Manifeste vcpkg (dépendance : curl)
├── obj/                       # Fichiers obj temporaires
│   ├── client_simulator.obj
│   ├── example_usage.obj
│   └── smoke_test.obj
└── third_party/
    └── curl-8.22.0_1-win64-mingw/   # curl pré-compilé (MinGW x64)
        ├── bin/
        ├── include/
        ├── lib/
        └── dep/
```

---

## Compilation

### Build complet (CMD)

```cmd
build.bat
```

Le script effectue les étapes suivantes automatiquement :

**1. Initialiser l'environnement MSVC x64**

```cmd
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

**2. Générer la bibliothèque d'import (si elle n'existe pas)**

```cmd
lib /machine:x64 /def:"third_party\curl-8.22.0_1-win64-mingw\bin\libcurl-x64.def" /out:libcurl.lib
```

**3. Créer le répertoire obj**

```cmd
if not exist obj mkdir obj
```

**4. Compiler example_usage.exe**

```cmd
cl /nologo /std:c++17 /EHsc /O2 /W3 ^
    /I"third_party\curl-8.22.0_1-win64-mingw\include" ^
    /Fo"obj\\" ^
    client_simulator.cpp ^
    example_usage.cpp ^
    /Fe:example_usage.exe ^
    /link libcurl.lib
```

**5. Compiler smoke_test.exe**

```cmd
cl /nologo /std:c++17 /EHsc /O2 /W3 ^
    /I"third_party\curl-8.22.0_1-win64-mingw\include" ^
    /Fo"obj\\" ^
    client_simulator.cpp ^
    smoke_test.cpp ^
    /Fe:smoke_test.exe ^
    /link libcurl.lib
```

**6. Copier les DLL et certificats requis**

```cmd
copy /Y "third_party\curl-8.22.0_1-win64-mingw\bin\libcurl-x64.dll" libcurl-x64.dll
copy /Y "third_party\curl-8.22.0_1-win64-mingw\bin\curl-ca-bundle.crt" curl-ca-bundle.crt
```

### Build complet de MonNouvelApp.exe

```cmd
build_monnouvelapp.bat
```

Reprend `build.bat` (génération de `libcurl.lib` + `client_simulator.lib`) puis
compile `src\monnouvelapp.cpp` et place dans `bin\` à côté de l'exe :
`libcurl-x64.dll` et `curl-ca-bundle.crt`.

---

## Exécution

### Exécutable 1 : example_usage.exe (flux d'achat complet)

```cmd
example_usage.exe
```

Cible : `https://shop.example.com`

Déroule les étapes suivantes :
1. **GET** `/api/v1/cart` — Lecture du panier
2. **POST** `/api/v1/cart/validate` — Validation du panier (produits, variantes, attributs)
3. **POST** `/api/v1/checkout/purchase` — Flux d'achat complet (articles + livraison + paiement)
4. **POST** `/api/v1/cart/promo` — Application d'un code promo
5. **update_session_token()** — Renouvellement du token JWT
6. **Burst test** — 6 requêtes GET rapides pour démontrer le rate limiting

### Exécutable 2 : smoke_test.exe (validation end-to-end)

```cmd
smoke_test.exe
```

Cible : `http://httpbin.org`

Valide :
1. **GET** `/anything` — Vérifie que les headers Authorization (Bearer), User-Agent, Sec-CH-UA, Sec-CH-UA-Platform sont bien envoyés
2. **POST** `/anything` — Envoie un payload JSON d'achat et vérifie la sérialisation
3. **Stats** — Affiche le temps moyen de réponse et le taux d'erreur

---

### Exécutable 3 : MonNouvelApp.exe (CLI intégrée, interface du simulateur)

Prise en main rapide et grands publics : **[GUIDE_UTILISATION.md](GUIDE_UTILISATION.md)**.
Référence exhaustive des commandes : **`MonNouvelApp_commands.md`**.

Buildé depuis `src\monnouvelapp.cpp` via `build_monnouvelapp.bat`
(sortie `bin\MonNouvelApp.exe`).
Il fournit une interface en ligne de commande autour de la bibliothèque.
La **référence complète des commandes** (options, arguments, templates, codes de
sortie) est dans [`MonNouvelApp_commands.md`](MonNouvelApp_commands.md).

Depuis le dernier build, `MonNouvelApp.exe` embarque aussi la **passerelle de
test HTTPS** `ltg` (PKI, règles, mock Luau) sous le mode `--gateway [port]` —
exactement les mêmes fonctionnalités que l'exécutable autonome `ltg.exe`.
La **référence de la passerelle** (lancement, `rules.ini`, journal d'audit,
simulation 5xx) est dans [`ltg_commands.md`](ltg_commands.md).

```cmd
MonNouvelApp.exe --sim-get <url>                 :: GET
MonNouvelApp.exe --sim-post <url> <json>         :: POST avec corps JSON
MonNouvelApp.exe --sim-put  <url> <json>         :: PUT avec corps JSON
MonNouvelApp.exe --sim-del  <url>                :: DELETE
MonNouvelApp.exe --sim-purchase <baseUrl>        :: flux d'achat complet (checkout/purchase)
MonNouvelApp.exe --gateway [port]                :: passerelle HTTPS (défaut 7080)
MonNouvelApp.exe --trace <exe> [args...]        :: lance un exe suspendu et rapporte tout son démarrage
MonNouvelApp.exe --trace-attach <pid>           :: surveille un processus deja lance (ex. session Target) sans le tuer
MonNouvelApp.exe --trace notepad --trace-timeout 10  :: PEB + DLL + threads + enfants + fichiers + réseau
MonNouvelApp.exe --ns "version; load kernel32; peinfo; unload"   :: moteur NightShift intégré
MonNouvelApp.exe --ns "mapload TargetPlayerBeta.dll; sections"                :: adresses mappées par section
MonNouvelApp.exe --ns "mapload TargetPlayerBeta.dll; hexdump .byfron 64"      :: hexdump d'une section par nom
MonNouvelApp.exe --ns "mapload TargetPlayerBeta.dll; dumpsec .byfron %TEMP%\byfron.bin"  :: extrait une section
MonNouvelApp.exe --ns-batch fichier.bat          :: batch NightShift (CMD:/SQL:/LOGIN:/WAIT:)
MonNouvelApp.exe --ns-repl                       :: REPL NightShift sur stdin
MonNouvelApp.exe --ghidra start --project C:\ROBUX.gpr [--headless]  :: CLI ghidra-rpc intégré
MonNouvelApp.exe --ghidra decompile --project C:\ROBUX.gpr <bin> <fonction>
MonNouvelApp.exe --ghidra status --project C:\ROBUX.gpr
MonNouvelApp.exe --ghidra --help                 :: ~80 sous-commandes ghidra-rpc
```

### CLI ghidra-rpc intégré (`--ghidra`)

`MonNouvelApp.exe` embarque les fonctionnalités de **ghidra-rpc 0.2.0**
(décompile, désassemblage, xrefs, recherche regex dans le code décompilé,
renommage, commentaires, signatures, patch mémoire/assembleur, version
tracking, vtable, pcode/CFG, serveur MCP, batch, cancellation). Le package
Python est vendorisé dans `C:\client_simulator\ghidra-rpc` (venv `.venv` créé
par `build_monnouvelapp.bat`) et le mode `--ghidra` le lance en sous-processus.

- `GHIDRA_INSTALL_DIR` est **auto-détecté** (sinon via la variable
  d'environnement).
- Chaque projet `.gpr` a son propre endpoint ; le daemon reste chaud entre
  commandes.
- Référence complète : section 10 de
  [`MonNouvelApp_commands.md`](MonNouvelApp_commands.md).

Options transverses (place indifférente) :

- `--sandbox` (alias `--test-mode`) : **Network Mocking** — toutes les URLs HTTP sont
  redirigées vers `http://localhost:8080` via `resolve_endpoint()` (le Host d'origine
  est perdu, le mock route sur le chemin).
- `--proxy <url>` : **proxy transparent** — tout le trafic libcurl passe par un proxy
  de transit (`CURLOPT_PROXY` posé avant chaque `curl_easy_perform`), ex :
  `--proxy 127.0.0.1:8080` pour le mock.

**TLS et racine locale (`LTG_CA_PEM`)** : à chaque `curl_easy_perform`,
`client_simulator.cpp` lit la variable d'environnement `LTG_CA_PEM` ; si elle est
définie, son contenu est passé à `CURLOPT_CAINFO` (bundle PEM de CA de confiance).
Cela permet de faire confiance aux certificats feuilles signés par la racine de la
passerelle de test (voir ci-dessous) :

```powershell
$env:LTG_CA_PEM = "C:\client_simulator\_ltg_run_cacert.pem"
```

Sans `LTG_CA_PEM`, la vérification par défaut de libcurl s'applique (bundle
`curl-ca-bundle.crt` placé à côté de l'exe, ou magasin Windows selon le backend).

**Passerelle de test ltg** :
La référence de la passerelle (fonctionnalités, `rules.ini`, journal d'audit,
simulation 5xx) est dans [`ltg_commands.md`](ltg_commands.md).
`C:\client_simulator\verify_ltg.ps1` démarre `ltg.exe` sur `127.0.0.1:7080`, génère un
PEM depuis `ltg-root.der`, pose `LTG_CA_PEM`, puis exécute les 3 scénarios de
`rules.ini` à **travers** `MonNouvelApp.exe` (`--proxy`).

Résultats attendus : `POST /api/v1/commit` → **429** (latence 800 ms injectée) ;
`GET /api/v1/upload` → **413** + `x-backend: simulated` ; `GET /api/v2/export` →
**500** + body `{"error":"gateway-fallback"}` (mock Luau).

Note : `ltg.exe` régénère une **nouvelle Root CA à chaque démarrage** (`ltg-root.der`
écrasé) ; le PEM doit donc être reconstruit après toute relance du gateway — le script
le fait automatiquement (et force un processus neuf pour garantir la cohérence).

---

## Serveur mock Target (`mock_target_api.py`)

Mock Python (stdlib uniquement) des endpoints Target pour tester le mode sandbox.

```cmd
python mock_target_api.py [port]        :: port par défaut : 8080
```

États simulés (modifiables en tête de fichier) : `USER_ID`, `BALANCE` (1 000 000 R$),
`CSRF_TOKEN` (renvoyé dans `X-CSRF-Token` sur chaque réponse), `PRICES` par id produit,
`DEFAULT_PRICE`/`DEVPRODUCT_DEFAULT_PRICE`.

Endpoints couverts (acheminement par chemin HTTP) :

| Méthode | Chemin | Rôle sandbox |
|---------|--------|--------------|
| GET  | `/v1/users/authenticated` | utilisateur connecté |
| POST | `/v2/logout` | CSRF steal (comme le flux réel auth.target.com) |
| GET  | `/v1/users/<id>/currency` | solde Robux |
| GET  | `/game-passes/v1/game-passes/<id>/product-info` | info gamepass |
| GET  | `/marketplace-service/v1/products/<id>/details` | info devproduct |
| GET  | `/v2/assets/<id>/details` | info asset marketplace |
| POST | `/v1/purchases/products/<pid>` | achat (débite `BALANCE`) |

**HTTPS via CONNECT** : le handler `do_CONNECT` établit un vrai tunnel TCP
(`socket.create_connection` vers la cible + relais bidirectionnel via `select`).
Les URLs `https://` fonctionnent donc à travers `--proxy 127.0.0.1:8080`, tandis que
les appels API en `--sandbox` restent servis en HTTP par le mock.

**Limitation connue** : les pages web `www.target.com/game-pass/...` renvoient un vrai
404 en transit (blocage réseau/bot de Target) ; utilisez les endpoints API
(`apis.target.com/game-passes/v1/game-passes/<id>/product-info`) qui répondent 200.

---

## Commandes utiles (PowerShell)

### Lister les fichiers du projet

```powershell
Get-ChildItem -Path "C:\client_simulator" -Recurse -File | Select-Object FullName
```

### Vérifier qu'un exécutable existe

```powershell
Test-Path "C:\client_simulator\example_usage.exe"
Test-Path "C:\client_simulator\smoke_test.exe"
```

### Exécuter un exécutable depuis PowerShell

```powershell
& "C:\client_simulator\example_usage.exe"
& "C:\client_simulator\smoke_test.exe"
```

### Compiler manuellement sans build.bat

```powershell
# 1. Charger l'environnement MSVC
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

# 2. Générer libcurl.lib (une seule fois)
lib /machine:x64 /def:"C:\client_simulator\third_party\curl-8.22.0_1-win64-mingw\bin\libcurl-x64.def" /out:"C:\client_simulator\libcurl.lib"

# 3. Compiler
cl /nologo /std:c++17 /EHsc /O2 /W3 /I"C:\client_simulator\third_party\curl-8.22.0_1-win64-mingw\include" /Fo"C:\client_simulator\obj\\" "C:\client_simulator\client_simulator.cpp" "C:\client_simulator\smoke_test.cpp" /Fe:"C:\client_simulator\smoke_test.exe" /link "C:\client_simulator\libcurl.lib"
```

### Nettoyer les objets compilés

```powershell
Remove-Item -Path "C:\client_simulator\obj\*.obj" -Force
```

### Supprimer les exécutables générés

```powershell
Remove-Item -Path "C:\client_simulator\example_usage.exe", "C:\client_simulator\smoke_test.exe" -Force
```

### Régénérer le tout (nettoyage + build)

```powershell
Remove-Item -Path "C:\client_simulator\obj\*.obj" -Force
Remove-Item -Path "C:\client_simulator\example_usage.exe", "C:\client_simulator\smoke_test.exe" -Force
Remove-Item -Path "C:\client_simulator\libcurl.lib" -Force
& "C:\client_simulator\build.bat"
```

---

## Flags de compilation

| Flag | Description |
|------|-------------|
| `/std:c++17` | Standard C++17 |
| `/EHsc` | Gestion des exceptions C++ |
| `/O2` | Optimisation pour la vitesse |
| `/W3` | Niveau d'avertissement 3 |
| `/nologo` | Supprimer le bannière MSVC |
| `/I<path>` | Répertoire d'inclusion (headers curl) |
| `/Fo<path>` | Répertoire de sortie des .obj |
| `/Fe<path>` | Nom de l'exécutable de sortie |
| `/link` | Passer des options à l'éditeur de liens |

---

## API C++ (client_simulator.hpp)

### Structures principales

```cpp
RequestConfig cfg;
cfg.base_url = "https://shop.example.com";
cfg.session_token = "eyJ...";        // JWT Bearer token
cfg.user_agent = "Mozilla/5.0 ...";
cfg.sec_ch_ua = "\"Chromium\";v=\"124\"...";
cfg.sec_ch_ua_platform = "\"Windows\"";
cfg.accept_language = "en-US,en;q=0.9";
cfg.timeout_seconds = 30;
cfg.follow_redirects = true;
cfg.max_redirects = 5;
```

```cpp
RateLimitConfig rl;
rl.min_delay_ms = 1500.0;     // Délai minimum entre requêtes
rl.max_delay_ms = 4500.0;     // Délai maximum
rl.burst_limit = 5;           // Nombre max de requêtes en burst
rl.burst_window_seconds = 10.0; // Fenêtre de burst
rl.jitter_factor = 0.2;       // Variation aléatoire
```

### Méthodes HTTP

```cpp
ClientSimulator sim(cfg);

Response r1 = sim.get("/api/v1/cart");
Response r2 = sim.post("/api/v1/cart/validate", json_body);
Response r3 = sim.put("/api/v1/resource", json_body);
Response r4 = sim.del("/api/v1/resource");
```

### Flux d'achat

```cpp
Response validate = sim.validate_cart(items);
Response promo    = sim.apply_promo_code("SUMMER2026");
Response purchase = sim.execute_purchase_flow(purchase_req);
```

### Load testing

```cpp
auto responses = sim.run_load_test(
    [](ClientSimulator& s) { return s.get("/api/v1/health"); },
    100  // nombre de requêtes
);
```

### Statistiques

```cpp
sim.get_average_response_time();  // en secondes
sim.get_error_rate();             // 0.0 à 1.0
sim.reset_stats();
```

---

## Headers HTTP automatiques

Le simulateur injecte automatiquement les headers suivants à chaque requête :

| Header | Valeur par défaut |
|--------|-------------------|
| `Authorization` | `Bearer <session_token>` |
| `User-Agent` | Chrome 124 Windows |
| `Sec-CH-UA` | Chromium 124 |
| `Sec-CH-UA-Platform` | Windows |
| `Sec-CH-UA-Mobile` | ?0 |
| `Sec-Fetch-Site` | same-origin |
| `Sec-Fetch-Mode` | cors |
| `Sec-Fetch-Dest` | empty |
| `Accept` | application/json, text/plain, */* |
| `Content-Type` | application/json; charset=utf-8 |
| `Origin` | https://shop.example.com |
| `Referer` | https://shop.example.com/checkout |
| `Cache-Control` | no-cache |

---

## Module NightShift (`nightshift/`)

Module **autonome** (cloné depuis `C:\Users\ASUS\Downloads\nightshift`) : CLI Windows de
*pentest applicatif* — session Microsoft Dynamics GP via ODBC + exploitation de DLL
(chargement normal ou manuel, symboles, appels, inspection PE). Il possède son propre
binaire `nightshift.exe`, **et son moteur C est aussi compilé directement dans
`MonNouvelApp.exe`** (voir « Intégration » plus bas).

### Build (MSVC x64)

```cmd
cd C:\client_simulator\nightshift
build.bat
rem -> produit nightshift.exe (revendique VS2022 BuildTools, sinon Community)
```

Alternative MinGW : `make -f Makefile`.

### Invocation

```
nightshift.exe                                   REPL interactif (nightshift>)
nightshift.exe -c "commande1; commande2; ..."    chaîne de commandes (exit = dernier résultat)
nightshift.exe .\test_full.bat                   batch processor (réagit à test_ops.bat/test_full.bat...)
```

### Commandes

| Commande | Rôle |
|---|---|
| `help` / `version` | Aide / version |
| `aliases` | Liste les connexions nommées de `aliases.txt` |
| `login <alias\|user> [pass] [company]` | Session GP (ODBC) |
| `sql "SELECT ..."` | Exécution SQL sur la session |
| `batch <fichier>` | Processor batch (`CMD:` / `SQL:` par ligne) |
| `reset` / `terminate` | Fermeture session GP / sortie |
| `load <dll_path>` | LoadLibrary normale |
| `mapload <dll_path>` | Mapping manuel (pas de DllMain) |
| `map <mapfile>` | Charge des symboles depuis un map Ghidra (VA absolues) |
| `call <nom\|0xADDR> [a1] [a2] [a3]` / `calladdr <addr>` | Invocation d'export/symbole/adresse |
| `inspect <sym\|addr>` | Valeur mémoire (QWORD) à l'adresse |
| `peinfo` / `sections` | Entête PE + sections |
| `resource <offset> <len>` / `hexdump <sym\|addr> <len>` | Dump mémoire |
| `symbols [filtre]` | Exports de la DLL chargée filtrés par nom |

### Validation effectuée (binaire rebuild depuis `C:\client_simulator\nightshift`)

- `-c "version; aliases"` : OK (0 alias configurés par défaut).
- `load kernel32 → peinfo → sections` : PE AMD64, 8 sections, flags cohérents.
- `symbols GetSystemT` → 6 exports ; `inspect GetTickCount` ; `call GetTickCount` → tick réel.
- `mapload kernel32 → peinfo` : mapping manuel sans DllMain OK.
- `map mydll.map` → 966 symboles ; `resource 0 32` → dump DOS header.
- Batch `test_ops.bat` → 0 erreur.

> Les commandes `login`/`sql` nécessitent un serveur SQL/Dynamics GP joignable ;
> `mapload`/`call` sur une DLL arbitraire restent à valider avec une DLL de test dédiée.

### Intégration dans `MonNouvelApp.exe`

Le moteur NightShift est compilé dans le binaire principal via `src\nightshift_bridge.c`
(pont liant l'API `ns_*` de `C:\client_simulator\nightshift` au dispatch de
`monnouvelapp.cpp`). `src\main.c` est **exclu** du build (pas de conflit de `main`).
Le build `build_monnouvelapp.bat` compile les 9 unités C du module + le pont
(`obj\ns\`) et lie `odbc32.lib ole32.lib uuid.lib`.

```
MonNouvelApp.exe --ns "version; load C:\Windows\System32\kernel32.dll; peinfo; sections; symbols GetSystemT; unload"
MonNouvelApp.exe --ns "mapload kernel32; peinfo"           mapping manuel, pas de DllMain
MonNouvelApp.exe --ns-batch fichier.bat                    batch (CMD:/SQL:/LOGIN:/WAIT:)
MonNouvelApp.exe --ns-repl                                 REPL sur stdin (EOF ou 'terminate' -> quitte)
```

Mêmes conventions d'exit que `nightshift.exe -c` : dernier résultat de la chaîne,
les erreurs (résultat -1) sont ramenées à `1`. Couvert par le harnais
`tests\test_commands.ps1` (groupe `ns-*`, 9 cas).

---

## Notes techniques

- Le rate limiting est basé sur des délais aléatoires (distribution normale + jitter) pour simuler un comportement humain
- Les tunnels TCP keepalive sont activés (idle: 120s)
- L'encodage gzip, deflate et brotli est supporté
- Le suivi des redirections est activé par défaut (max: 5)
- Un proxy peut être configuré via `sim.set_proxy("http://proxy:port")`
- Les objets `.obj` et le répertoire `obj/` sont générés par le build et peuvent être supprimés
