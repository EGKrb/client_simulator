# ltg.exe — Passerelle de test HTTPS (MITM)

`ltg` est une passerelle de test locale qui démasque le TLS entrant et
intercepte les requêtes HTTPS grâce à une autorité racine racine privée.
Elle sert à simuler des serveurs récalcitrants (limites, délais, erreurs 5xx…)
depuis `client_simulator` / `MonNouvelApp.exe`.

La même fonctionnalité est embarquée dans `MonNouvelApp.exe` via le mode
`--gateway [port]` (démarrage identique, même moteur de règles, même journal).

---

## 1. Lancement

### Exécutable autonome (ltg)
```
ltg.exe                 # écoute sur 127.0.0.1:7080
ltg.exe 8080            # écoute sur 127.0.0.1:8080
```

### Mode intégré (MonNouvelApp)
```
MonNouvelApp.exe --gateway             # défaut 7080
MonNouvelApp.exe --gateway 8080        # port explicite (nombre uniquement)
```

Le répertoire courant est important : `rules.ini`, `fallback.luau` sont lus
relativement au CWD et `ltg-root.der` y est écrit. Lancer depuis
`C:\client_simulator`.

---

## 2. Démarrage (4 phases)

1. **PKI** — génération d'une Root CA fraîche (`LGT-Root-CA`) ; export au
   format DER dans `ltg-root.der` ; tentative d'installation dans
   `LocalMachine\Root` (échoue sans admin : `[pki] ECHEC installation Root CA
   (privileges admin requis)`, la requête fonctionne quand même avec
   `curl -k` ou le PEM via `LTG_CA_PEM`).
2. **Règles** — chargement de `rules.ini` → `[rules] N regle(s) chargee(s)`.
3. **Mock** — préparation du contrôleur Luau pour les scripts `fallback.luau`.
4. **Écoute** — `[ltg] Passerelle active sur 127.0.0.1:<port>`.

Arrêt : `Ctrl+C`, ou `Stop-Process -Name ltg`.

---

## 3. Écriture de règles (rules.ini)

Support d'un mini-format INI : `[rule]` délimite une règle, les clés sont en
minuscules (`clé = valeur`), `#` démarre un commentaire, `*` = « toutes ».

Directives reconnues :

| Directive        | Valeur                                | Rôle                                                        |
|------------------|---------------------------------------|-------------------------------------------------------------|
| `host`           | glob (`*.monapp.test`)                | Filtre sur le nom d'hôte                     |
| `path`           | regex (`/api/.*/export`)              | Filtre sur le chemin                                        |
| `method`         | `GET/ POST/ PUT/ DELETE/ *`           | Filtre sur la méthode (`*` = toutes)                        |
| `inject_status`  | code (200/429/500/…)                  | Réponse injectée dans le statut (au lieu du forward)        |
| `latency_ms`     | millisecondes                          | Débit artificiel avant réponse                             |
| `mutate_header`  | `nom:valeur`                          | Ajoute/remplace un en-tête sur la réponse                   |
| `strip_body`     | `true/1`                              | Vide le corps de la réponse (content-length: 0)             |
| `mock_script`    | nom de fichier (ex. `fallback.luau`)| Charge la bascule Luau                                        |
| `action`         | `drop`                                | Ferme la connexion sans réponse (par défaut : forward)      |

Exemple (état actuel du dépôt) :
```
[rule]
host = *.monapp.test
path = /health
method = GET
inject_status = 200
mutate_header = x-backend:ltg-health
```

---

## 4. Journal d'audit

Chaque requête démasquée est journalisée sur **stderr** :

- `[pki] Root CA ... ; export ltg-root.der ; install ...`
- `[rules] N regle(s) chargee(s) depuis rules.ini`
- `[ltg] tunnel TLS demasque pour <hôte> (<cipher>)`
- `[ltg] <METHOD> <target> -> <code> (<note>)`
- `[ltg] SSL_accept echec err=<code>` (client a coupé pendant le handshake)

Notes (dernière cause de la réponse) :

| Note                   | Sens                                                        |
|------------------------|--------------------------------------------------------------|
| `drop`                 | `action = drop` : connexion fermée sans réponse              |
| `inject`               | réponse localement injectée (règle)                          |
| `mock`                 | réponse locale générée par script Luau                       |
| `forward`              | requête relayée vers l'upstream, réponse renvoyée            |
| `mock 5xx`             | upstream a répondu ≥500 → bascule script Luau                |
| `dns fail`             | résolution de l'upstream échouée (502)                       |
| `connect fail`         | connexion TCP upstream échouée (502)                         |
| `upstream tls fail`    | handshake TLS upstream échoué (502)                          |
| `upstream write fail`  | écriture request vers upstream échouée (502)                 |
| `upstream no response` | upstream n'a rien répondu (502)                              |
| `bad authority`        | host d'upstream invalide (502)                               |

---

## 5. Comportement réseau

- Écoute uniquement sur `127.0.0.1` (loopback).
- CONNECT transparent : masque `Host`/SNI et déchiffre TLS
  (TLS 1.2+ / TLS 1.3, RSA + ECDSA selon la clé générée).
- CERTIFICAT feuille généré dynamiquement par hôte (cache par SNI).
- Forward upstream : connexion TLS **sans vérification** du certificat
  (`SSL_VERIFY_NONE`) — la passerelle pré-décide de la réponse.
- Parser HTTP/1.1 complet : `Content-Length` et `Transfer-Encoding: chunked`
  (déchiffré) sont tous deux gérés ; le corps complet est reconstitué avant
  évaluation des règles.

---

## 6. Simulation de 5xx avec fallback Luau

Si une règle définit `mock_script`, et si l'injection renvoie ≥500 **ou**
l'upstream renvoie ≥500 (`mock 5xx`), la passerelle exécute le script Luau
(`fallback.luau` par défaut). Le script voit :

- `req` — table du requête démasquée (`method`, `target`, `host`, `body`,
  `headers` : table {nom=:valeur}).
- `mock` — table de contrôle : `mock.respond{ nom = valeur, ... }` pour écrire
  les en-têtes de la réponse, `mock.fail_reason` (cause de la bascule).
- `mock_log(str)` — journaliser sur stderr (`[ltg-mock] …`).

La réponse produite prend le code renvoyé par le moteur (ex. 500) et le corps
écrit par le script ; `respond` remplit les en-têtes additionnels.

---

## 7. Fichiers

| Fichier          | Rôle                                                    |
|------------------|---------------------------------------------------------|
| `ltg.exe`        | exécutable autonome (build CMake, `build\Release\`)     |
| `rules.ini`      | moteur de règles (lu au CWD)                            |
| `fallback.luau`  | script de bascule mock (lu au CWD)                      |
| `ltg-root.der`   | Root CA générée à chaque lancement (export DER)         |
| `http1.hpp`      | parser HTTP/1.1 header-only                             |
| `main.cpp`       | entrée : orchestration PKI → règles → mock → gateway   |
| `pki.cpp`        | racine + feuilles + export DER + install                |
| `rules.cpp`      | chargement/évaluation des règles                        |
| `mock_controller.cpp` | VM Luau pour les bascules                          |
| `gateway.cpp`    | écoute, CONNECT, démasquage, forward, audit             |

---

## 8. Vérification de bout en bout

`verify_ltg.ps1` : tue toute instance, démarre `ltg` frais (RK CA régénérée),
construit un PEM racine depuis `ltg-root.der` (via `LTG_CA_PEM` pour le client)
et teste 3 scénarios : `POST /api/v1/commit` → 429 (~800 ms),
`GET /api/v1/upload` → 413 + `x-backend: simulated`,
`GET /api/v2/export` → 500 + `{"error":"gateway-fallback"}`.