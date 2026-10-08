# MonNouvelApp.exe — Référence des commandes

Source : `C:\client_simulator\src\monnouvelapp.cpp`
Build : `C:\client_simulator\build_monnouvelapp.bat` (sort : `C:\client_simulator\bin\MonNouvelApp.exe`)

## Syntaxe générale

```
MonNouvelApp.exe [options] [arguments positionnels]
```

- Tout argument inexistant (marqué `-…`) est **inconnu** → erreur + `exit 1`.
- Tout argument ne commençant pas par `-` est **positionnel** (cible, snippet, adresses…).
- Sans aucune option : **scan AOB** par défaut (voir plus bas).
- `--gateway [port]` : passerelle HTTPS embarquée (section 8).

---

## Options transverses

| Option | Description |
|--------|-------------|
| `--sandbox` / `--test-mode` | **Network Mocking** : toutes les URLs HTTP sont redirigées vers `http://localhost:8080` via `resolve_endpoint()` |
| `--proxy <url>` | **Proxy transparent** : tout le trafic sortant (WinHTTP + libcurl) passe par le proxy défini (ex. `--proxy 127.0.0.1:8080`, `--proxy http://127.0.0.1:7080`). Rejette l'appel si `<url>` absent. |
| `--pid <pid>` | PID utilisé par les modes Snyper (`RunSnyperRecord/Play`) |
| `--read-only` / `-r` | Scan AOB en lecture seule (`PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ`) au lieu de `PROCESS_ALL_ACCESS` |
| `--trace <exe> [args...]` | Lance une `.exe` suspendue et rapporte son comportement au démarrage (PEB + DLL + threads + enfants + fichiers/registre + réseau). Options : `--trace-timeout <s>`, `--trace-keep`. Voir section 11. |
| `--trace-attach <pid>` | Surveille un processus **déjà lancé** (même diffs + drivers noyau sans le tuer). Options : `--trace-timeout <s>`. Voir section 11.2. |
| `--ns <chaine>` | Exécute une chaîne de commandes NightShift (`;` sépare), moteur C intégré (sources `C:\client_simulator\nightshift`). Exit = dernier résultat (erreurs → `1`). Ex. `--ns "version; load C:\Windows\System32\kernel32.dll; peinfo"` |
| `--ns-batch <fichier>` | Batch processor NightShift (`CMD:` / `SQL:` / `LOGIN:` / `WAIT:` par ligne). Exit `1` si le fichier est introuvable ou si des étapes échouent |
| `--ns-repl` | REPL NightShift sur **stdin** (lecture ligne à ligne, `terminate` pour quitter) |
| `--ghidra <cmd> [args...]` | **CLI ghidra-rpc intégré** : exécute une sous-commande du CLI Python `ghidra-rpc` (package 0.2.0 vendorisé dans `C:\client_simulator\ghidra-rpc` + venv `.venv`) et affiche le JSON renvoyé. Le daemon Ghidra (PyGhidra + JVM) reste chaud entre commandes. Tout ce qui suit `--ghidra` est transmis tel quel (options comprisent). Voir section 10. |
| `--ghidra-help` | Affiche l'aide du mode `--ghidra` (sous-commandes disponibles) et sort |

### Variable d'environnement `LTG_CA_PEM`

Définie, elle est passée à `CURLOPT_CAINFO` : bundle PEM de CA de confiance pour
faire confiance aux certificats feuilles de la passerelle locale `ltg`
(voir `README.md`). Sans elle, vérification par défaut de libcurl
(`curl-ca-bundle.crt` à côté de l'exe).

```powershell
$env:LTG_CA_PEM = "C:\client_simulator\_ltg_run_cacert.pem"
```

---

## 1. Simulation HTTP (`--sim-*`)

| Commande | Rôle |
|----------|------|
| `--sim-get <url>` | Envoie `GET <url>` |
| `--sim-post <url> <json>` | Envoie `POST <url>` avec `<json>` comme corps |
| `--sim-put <url> <json>` | Envoie `PUT <url>` avec `<json>` comme corps |
| `--sim-del <url>` | Envoie `DELETE <url>` |
| `--sim-purchase <baseUrl>` | Flux d'achat complet : `POST <baseUrl>/api/v1/checkout/purchase` + statistiques |

Le corps `<json>` est un argument **unique** : entrez-le entre guillemets :
`--sim-post https://serveur.monapp.test/api/v1/commit "{\"order\":\"SIM-001\"}"`

Sortie (mode GET/POST/PUT/DEL) : `HTTP <code> | <temps> ms | OK=<bool>` puis `Body:` si non vide.

Exemples :

```cmd
MonNouvelApp.exe --sim-get https://serveur.monapp.test/api/v1/upload
MonNouvelApp.exe --sim-post https://serveur.monapp.test/api/v1/commit "{\"x\":1}" --proxy http://127.0.0.1:7080
MonNouvelApp.exe --sim-purchase https://serveur.monapp.test --sandbox
```

---

## 2. Achat web Target (`--buy-*`)

Nécessite un fichier `cookie.txt` contenant le cookie `.ROBLOSECURITY` **dans le
répertoire courant**. Lit l'utilisateur, le solde, récupère un `X-CSRF-TOKEN`
(`auth.target.com/v2/logout`) puis envoie l'achat.

| Commande | Usage |
|----------|-------|
| `--buy-gamepass <id>` | Achat d'un game pass (`apis.target.com` / economy) |
| `--buy-devproduct <id>` | Achat d'un dev product |
| `--buy-marketplace <id>` | Achat marketplace |
| `--buy-probe <productId> <price> [<sellerId>]` | POST brut `economy.target.com/v1/purchases/products/<productId>` ; sans `<sellerId>`, body `{expectedCurrency, expectedPrice}` |

---

## 3. Exécution Luau / VM Target

Exigent une session **élevée** (admin) — processus Target protégé.

Cible : `<pid>` (numérique) ou `<nom>` (`.exe` facultatif). Si multiple, liste les PID et refuse de deviner.

Adresses optionnelles (dans l'ordre) : `0x<luauLoad> 0x<luaPcall> 0x<luaState>`.

| Commande | Description |
|----------|-------------|
| `--luau-vm <pid\|exe> ["<snippet>"] [0x…]` | Point d'entrée VM Luau : résout `luau_load`/`lua_pcall`/`lua_State` et exécute un snippet |
| `--luau-vm … --loadstring` | Installe la **trampoline heap** pour `--loadstring` (aucun patch .text) |
| `--marketplace <pid\|exe>` | Snippet marketplace (prompt d'achat) |
| `--gamepass <pid\|exe>` | Snippet game pass |
| `--devproduct <pid\|exe>` | Snippet dev product |
| `--detect <pid\|exe>` | Snippet de détection d'environnement |
| `--survivor <pid\|exe> [secondes] ["<snippet>"]` | Exécution « survivante » (fenêtre de `secondes`, défaut 30, 1…3600) |
| `--sig-update <pid\|exe>` | Re-extraire / mettre à jour les signatures |
| `--autofix <pid\|exe>` | Tentative de réparation automatique des signatures |

---

## 4. Démos hooks (processus local)

| Commande | Description |
|----------|-------------|
| `--demo` | Démo scan de signature sur un buffer local |
| `--hook-demo` | Démo hook inline + trampoline (gel des threads, relocalisation RIP-relatif) |
| `--iat-demo` | Démo hook de table d'import (IAT) |
| `--vmt-demo` | Démo hook VMT (redirection de pointeur, aucun patch .text) |
| `--apc <pid\|exe>` | Démo exécution par APC |
| `--hijack <pid\|exe>` | Démo hijack de thread |

---

## 5. Snyper (automation UI)

Contrôle une fenêtre Target (`EnumWindows`/`SendInput`). Le titre de fenêtre est
le premier positionnel (optionnel).

| Commande | Description |
|----------|-------------|
| `--snyper-record [<titre>]` | Enregistre la séquence (clics/saisies) |
| `--snyper-play [<titre>]` | Rejouer la séquence |
| `--snyper-dryrun [<titre>]` | Rejouer **sans** envoyer réellement les événements |
| `--loop` | Boucle le rejeu (avec `--snyper-*`) |
| `--pid <pid>` | Cible explicitement un PID (sinon fenêtre par titre) |

---

## 6. BYOVD / SIV (driver physique)

Exigent une session **élevée**.

| Commande | Usage |
|----------|-------|
| `--byovd <pid\|exe>` | Démo BYOVD (injection via driver vulnérable) |
| `--hijack-byovd <pid\|exe>` | Variante hijack du BYOVD |
| `--byovd-siv [<chemin.sys>] [0x…]` | Primitive R/W mémoire physique via `SIVX64.sys` |
| `--siv-load [<chemin.sys>]` | Charge `SIVX64.sys` (chemin explicite optionnel) |
| `--siv-remove` | Décharge/supprime le driver |
| `--siv-read <physAddrHex> <len>` | Lit `len` octets à l'adresse physique hexadécimale |
| `--siv-write <physAddrHex> <hexBytes>` | Écrit les octets (hex) à l'adresse physique |

---

## 7. Mode par défaut : scan AOB (pattern signature)

Sans option « mode », `MonNouvelApp.exe` scanne la mémoire d'un processus cible
pour une signature : `aob.exe <pid|nom> "<signature>"`.

- Signature au format hexadécimal espace-séparé, `?`/`??` = wildcard :
  `48 89 5C 24 ?? 50`.
- Cible : PID numérique ou nom d'exécutable (`.exe` facultatif).
- Non-admin : `--read-only` pour les processus non élevés du même utilisateur.

Codes de retour :
- `0` — au moins une occurrence trouvée (affiche les adresses `0x…`).
- `2` — aucune occurrence.
- `1` — erreur d'usage / cible introuvable / signature invalide.

Exemples :

```cmd
MonNouvelApp.exe 31280 "48 89 5C 24 ?? 50"
MonNouvelApp.exe TargetPlayerBeta "E8 ?? ?? ?? ?? 48 8B 03"
MonNouvelApp.exe --read-only 31280
```

---

## 8. Passerelle HTTPS embarquée (`--gateway`)

Identique à l'exécutable autonome `ltg.exe` (voir `ltg_commands.md`).

| Commande | Description |
|----------|-------------|
| `--gateway` | Démarre la passerelle MITM sur `127.0.0.1:7080` |
| `--gateway <port>` | Port explicite (nombre uniquement) |

Démarrage en 4 phases : PKI (nouvelle Root CA par lancement, export
`ltg-root.der`, installation dans `LocalMachine\Root` si admin), chargement de
`rules.ini`, préparation du mock Luau (`fallback.luau`), écoute. Le répertoire
courant est important (`rules.ini`, `fallback.luau`, `ltg-root.der`).

```
MonNouvelApp.exe --gateway 7080
```

---

## 9. Mock Ownership (`--mock-*`)

Pipeline natif de simulation d'état de possession : portage C++ de
`C:\qa-automation\proxy-mock\Generate-OwnershipMock.ps1`. Génère un `rules.ini`
au **contrat proxy-mock** (sections `[Rule_*]`, tri par `Priority`
décroissante) et des payloads JSON, consomme les logs de session au format
`<timestamp>|<VERBE>|<URL>|<status>|<corps>`.

| Commande | Rôle |
|----------|------|
| `--mock [stage]` / `--mock-stage [stage]` | Exécute un étage : `analyze`, `capture`, `configure`, `deploy`, `all` (défaut `all`) |

Options du pipeline (toutes facultatives, cumulables) :

| Option | Défaut | Rôle |
|--------|--------|------|
| `--mock-log <session.log>` | — | Source de vérité explicite (Analyze/Capture) |
| `--mock-sessions <glob>` | `.\logs\sessions\*.log` | Balayage des sessions (Analyze) |
| `--mock-filter <valeur>` | `ownership` | Filtre URL (`-EndpointUrlFilter`) |
| `--mock-product <id>` | détecté | Isolation stricte (Priority 200) |
| `--mock-state <valeur>` | — | Filtre d'état (`-StateFilter`) |
| `--mock-captured <json>` | `.\captured\ownership_sample.json` | Échantillon capturé |
| `--mock-responses <dossier>` | `.\responses` | Sortie des payloads |
| `--mock-rules <rules.ini>` | `.\rules.ini` | Règles générées |
| `--mock-proxy-dir <dossier>` | requis pour Deploy | Dossier de règles du proxy |
| `--mock-service <nom>` | — | Redémarre le service Windows après déploiement |
| `--mock-reload <marqueur>` | `.reload` | Marqueur de rechargement posé chez le proxy |
| `--mock-luau` | désactivé | Configure en mode injection Luau : la règle porte `Script=mock_success.luau` (fichier `mock.respond`, audit `inject`) au lieu de `ResponseFile=` (audit `mock-file`) |

Détail par étage :

1. **analyze** — trouve une session contenant ≥ 1 hit ownership Query
   (`GET/HEAD/OPTIONS`, URL contenant `ownership`, `product_id` présent) et
   recopie la source dans `.\captured\ownership_source.txt`.
2. **capture** — choisit la meilleure occurrence (auto-cohérente token+état, puis
   état OK · 200, puis token · 200, puis 200) et écrit `ownership_sample.json`
   (`CapturedAt`, `SourceLog`, `Method`, `Url`, `Status`, `ContentType`, `Body`,
   `HasOwnershipToken`).
3. **configure** — construit les patterns (strict `product_id=<id>` · 200, any
   `(?<ProductId>…)` · 199, fallback désactivé · 198) et écrit `rules.ini` +
   payloads (UUID par défaut si corps vide). Avec `--mock-luau`, écrit
   `mock_success.luau` (appel `mock.respond(status, headers, body)`) et la règle
   strict référence `Script=mock_success.luau` ; `deploy` copie alors aussi le
   `.luau` dans `--mock-proxy-dir`.
4. **deploy** — copie `rules.ini` + payloads dans `--mock-proxy-dir`, pose le
   marqueur `.reload` et redémarre optionnellement `--mock-service`.

Exemple (chaîne complète) :

```cmd
MonNouvelApp.exe --mock all --mock-proxy-dir C:\proxyrules
```

```cmd
MonNouvelApp.exe --mock analyze --mock-log C:\logs\sessions\ownership.log
MonNouvelApp.exe --mock capture
MonNouvelApp.exe --mock configure --mock-product 1337
MonNouvelApp.exe --mock deploy --mock-proxy-dir C:\proxyrules
```

Ensuite : `MonNouvelApp.exe --gateway 7080` dans le dossier déployé (ou relance
du proxy) sert le payload capturé pour le produit couvert, sans appel upstream
(note `mock-file`), ou exécute `Script=` via `mock.respond` (note `inject`, en
succès comme en échec contrôlé), et forwarde (ex. `502 dns fail`) les produits
hors périmètre.

---

## 10. CLI ghidra-rpc intégré (`--ghidra`)

Le package **ghidra-rpc 0.2.0** (Cellebrite Labs) est vendorisé dans
`C:\client_simulator\ghidra-rpc` et installé dans un venv dédié
(`ghidra-rpc\.venv`, créé automatiquement par `build_monnouvelapp.bat`).
`MonNouvelApp.exe --ghidra <sous-commande> [args...]` lance le CLI Python en
sous-processus, hérite stdout/stderr (le JSON est affiché tel quel) et propage
le code de sortie de la commande.

Le daemon Ghidra tourne en arrière-plan : chaque projet `.gpr` possède son
propre endpoint (`%LOCALAPPDATA%\ghidra-rpc\ghidra-rpc-<hash>.sock`).
`GHIDRA_INSTALL_DIR` est auto-détecté (sinon posé via la variable
d'environnement). La commande `--ghidra --help` liste ~80 sous-commandes.

### Cycle de vie du daemon

| Commande | Rôle |
|----------|------|
| `--ghidra start --project <fichier.gpr> [--headless] [--detach]` | Démarre le daemon (mode GUI par défaut ; `--headless` sans fenêtre) |
| `--ghidra status --project <fichier.gpr>` | État du daemon + binaires chargés |
| `--ghidra stop --project <fichier.gpr>` | Arrête le daemon |
| `--ghidra list-instances` | Liste tous les daemons actifs et leurs projets |
| `--ghidra restart --project <fichier.gpr>` | Redémarre en arrière-plan |

### Analyse

| Commande | Rôle |
|----------|------|
| `--ghidra load --project <gpr> <binaire>` | Importer et analyser un binaire (`--no-analyze` / `--analysis-timeout` pour contrôler l'analyse) |
| `--ghidra list-binaries` / `--ghidra functions <binaire>` | Binaires chargés / fonctions d'un binaire |
| `--ghidra decompile --project <gpr> <binaire> <fonction>` | Décompiler en pseudo-C |
| `--ghidra disassemble --project <gpr> <binaire> <adresse>` | Désassembler à une adresse |
| `--ghidra search-decompiled --project <gpr> <binaire> <regex>` | Recherche regex dans tout le C décompilé |
| `--ghidra strings <binaire> [filtre]` / `--ghidra symbols <binaire> [filtre]` | Strings / symboles |
| `--ghidra find-bytes <binaire> <pattern>` | Recherche d'octets (ex. `48 89 5C 24 ?? 50`) |
| `--ghidra xrefs-to <binaire> <symbole>` / `--ghidra xrefs-from ...` | Références croisées vers / depuis |
| `--ghidra imports` / `--ghidra exports` / `--ghidra metadata` | API importées / exportées / métadonnées du binaire |
| `--ghidra read-bytes <binaire> <addr> <len>` / `--ghidra memory-map` | Mémoire brute / sections |

### Annotation et patch

| Commande | Rôle |
|----------|------|
| `--ghidra rename-function <gpr> <bin> <ancien> <nouveau>` | Renommer une fonction (option `--namespace`) |
| `--ghidra set-comment <gpr> <bin> <adresse> <texte>` | Commentaire à une adresse |
| `--ghidra set-signature <gpr> <bin> <fonction> <signature>` | Signature (prototype) d'une fonction |
| `--ghidra write-bytes <gpr> <bin> <adresse> <hex>` | Écrire des octets bruts |
| `--ghidra assemble <gpr> <bin> <adresse> <texte>` | Assembler (SLEIGH) à une adresse |
| `--ghidra set-bookmark` / `--ghidra list-bookmarks` / `--ghidra tag-function` | Bookmarks / tags |

### Modes avancés

| Commande | Rôle |
|----------|------|
| `--ghidra mcp --project <gpr>` | **Serveur MCP stdio** : chaque sous-commande devient un outil MCP (intégrable à Claude Code, etc.) |
| `--ghidra batch '{"cmd": "decompile", ...}'` | Exécute plusieurs requêtes en un seul processus |
| `--ghidra cancel [id]` | Annule des requêtes en vol (ex. decompile-all long) |
| `--ghidra version-track <bin1> <bin2>` / `--ghidra function-diff` | Version tracking / diff de fonctions |
| `--ghidra pcode <bin> <fonction>` / `--ghidra basic-blocks <bin> <fonction>` | P-code (IR) / CFG d'une fonction |
| `--ghidra list-vtable <bin> <adresse>` | Slots d'une vtable C++ |

Le projet par défaut peut être omis en posant `GHIDRA_RPC_PROJECT` :

```cmd
set GHIDRA_RPC_PROJECT=C:\Users\ASUS\ROBUX.gpr
MonNouvelApp.exe --ghidra decompile TargetPlayerBeta.dll FUN_1801fd900
```

Variables d'environnement : `GHIDRA_RPC_PYTHON` (python.exe alternatif du venv),
`GHIDRA_INSTALL_DIR` (dossier d'installation Ghidra), `GHIDRA_RPC_PROJECT`.

---

## 11. Trace de démarrage (`--trace`) et surveillance (`--trace-attach`)

Lance une `.exe` et rapporte **tout ce qu'elle fait au démarrage**, ou s'attache à
un processus **déjà lancé** et en surveille l'activité en direct.

### 11.1 `--trace <exe> [args...]` — lancement

| Option | Description |
|--------|-------------|
| `--trace <exe> [args...]` | Lance `<exe>` **suspendu** (`CREATE_SUSPENDED`), lit son PEB, reprend et surveille ~5 s |
| `--trace-timeout <s>` | Fenêtre de surveillance en secondes (défaut `5`, minimum `1`) |
| `--trace-keep` | À la fin de la fenêtre, **ne pas tuer** le processus (par défaut il est arrêté) |

Pendant la suspension, aucun code de l'application n'a tourné : on lit son **PEB**
(image base, ligne de commande, chemin image, répertoire courant, chemin de
recherche DLL, titre de fenêtre, taille de l'environnement).

Après la reprise, l'outil échantillonne pendant `--trace-timeout` secondes
(ou jusqu'à la sortie du processus) :

- **DLL chargées** (`EnumProcessModulesEx`, diff) — base, chemin, taille ;
- **threads créés** (Toolhelp) ;
- **processus enfants** (Toolhelp, arborescence parent → enfant) ;
- **fichiers ouverts et clés registre** (`NtQuerySystemInformation(64)` +
  `NtQueryObject`, handles de type `File`/`Key`) ;
- **connexions TCP / sockets UDP** (`iphlpapi`, filtrées par PID) ;
- **drivers noyau chargés** (`NtQuerySystemInformation(11)`, diff) — à chaque tick,
  tout `.sys` nouveau est signalé (`[KERNEL module] charge : ... base=0x… taille=0x…`),
  ce qui permet de voir le driver anti-tamper de Target (`TgDrv.sys`) se charger
  au démarrage du jeu.

### 11.2 `--trace-attach <pid>` — surveillance d'un processus en cours

S'attache à un processus **deja lancé** (même utilisateur) et en affiche l'état
immédiat : parent, modules déjà chargés, ligne de commande, chemin image,
répertoire courant, décompte initial des drivers (`[KERNEL] N drivers deja charges`).

Puis il échantillonne pendant `--trace-timeout` secondes le **diff** des mêmes
catégories que le `--trace` : modules/threads/processus enfants, fichiers/keys,
réseau, et surtout **drivers noyau** — utile pour voir Hyperion (Byfron) charger
son `.sys` pendant une vraie session de jeu. Le processus cible n'est jamais tué.

Si un objet de la cible bloque la requête de nom de handle (console d'une autre
session, etc.), le scan de handles est abandonné au bout de 1,5 s et le message
`scan des handles bloque, ignore pour la suite` apparaît ; les autres
catégories continuent à être surveillées.

Exemples :

```cmd
MonNouvelApp.exe --trace-attach 58556 --trace-timeout 60
```

Codes de sortie : `0` = fenêtre de trace menée à bien (ou processus terminé) ;
`1` = PID invalide / processus impossible à ouvrir / usage.

---

## Codes de sortie (récapitulatif)

| Code | Signification |
|------|---------------|
| `0` | Succès |
| `1` | Erreur d'usage, option inconnue, cible invalide ou échec technique |
| `2` | Scan AOB : aucune occurrence |
| `3` | Achat web : cookie absent/invalide ou échec d'authentification |