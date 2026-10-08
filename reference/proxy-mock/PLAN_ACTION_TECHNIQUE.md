# Plan d'Action Technique — Simulation d'État de Possession (Ownership State Simulation)

> **Contexte** : passerelle de transit (Proxy MITM) utilisée pour simuler des états serveur
> de backend en environnement de test. Les appels « Transaction » (Mutation) étant protégés
> par des signatures cryptographiques (JWT) impossibles à reproduire sans les clés privées de
> production, on bascule vers la simulation de l'état de possession : on intercepte uniquement
> l'appel de **vérification** (Query, lecture seule, non signé) et on injecte une réponse
> « Possédé » pré-enregistrée.
>
> **Cible** : moteur de règles du proxy MITM **in-house** (« rules.ini »).

---

## 1. Objectifs et critères de sûreté

| Cible | Détail |
|---|---|
| Endpoint à mock | Query de vérification d'état, ex. `GET /v1/ownership/status?product_id=…` |
| Payload injecté | Réponse JSON authentique capturée (contient `ownership_token`), état « Owned » |
| Effet de bord | **Aucun** — on n'intercepte que des opérations idempotentes et sans signature serveur |
| Risque à éviter | Intercepter une Mutation (`POST /purchase`) → ne jamais mock un flux signé |

**Règle d'or** : on ne mock qu'un flux de type *Query* (verbe sûreté + chemin de lecture),
jamais une *Mutation*. Un endpoint Query ne déclenche aucune écriture côté backend ; la
réponse étant non signée, elle peut être rejouée sans accès aux clés de production.

---

## 2. Méthodologie de différenciation de flux (Traffic Profiling)

### 2.1 Format de log de référence

Le script analyse des logs de session au format ligne-pipe. Parser par défaut (paramétrable) :

```
<timestamp>|<VERBE HTTP>|<URL>|<status>|<corps de réponse>
```

Exemple :
```
2026-09-20T09:12:41Z|GET|https://api.example.com/v1/ownership/status?product_id=1337&ts=1|200|{"product_id":1337,"state":"owned","ownership_token":"eyJhbGciOi...","expires_at":"2026-12-31"}
2026-09-20T09:12:43Z|POST|https://api.example.com/v1/purchase|201|{"transaction_id":"txn_9f2c","signed_payload":"..."}
```

### 2.2 Arbre de décision (heuristique automatique)

```
Ligne de log
├─ Verbe ∈ {POST, PUT, PATCH, DELETE}          → MUTATION (jamais mockée)
├─ Verbe ∈ {GET, HEAD, OPTIONS}                → potentielle Query → continuer
│   ├─ Chemin contient un mot-clé de mutation
│   │   (purchase, buy, order, pay, payment, transfer, create,
│   │    update, delete, add, remove, cancel, charge)
│   │   → MUTATION malgré GET (ex. GET /purchase/receipt)  → ne pas mock
│   └─ Chemin contient un mot-clé de lecture
│       (ownership, verify, check, status, validate, balance,
│        profile, list, get)
│       → QUERY CONFIRMÉE → mockable
└─ Corps contient `transaction_id` + pas de `ownership_token`
    → flux Transaction → ne pas mock
```

### 2.3 Tableau de signatures Mutation vs Query

| Signature | Mutation (exclue du mocking) | Query (candidate au mocking) |
|---|---|---|
| Verbes HTTP | `POST`, `PUT`, `PATCH`, `DELETE` | `GET`, `HEAD`, `OPTIONS` |
| Motifs de chemin | `/purchase`, `/order`, `/transfer`, `/payment`, `/create`, `/delete` | `/ownership/`, `/verify/`, `/check`, `/status`, `/validate`, `/balance`, `/profile` |
| Sémantique | Effet de bord, non-idempotent, **signé JWT serveur** | Lecture, idempotent, réponse non signée |
| Corps type | `transaction_id`, `signed_payload`, `receipt_id` | `ownership_token`, `state: "owned/not_owned/locked"` |
| Critère RFC 7231 | Non-safe / non-idempotent | Safe + idempotent |

> **Mode opératoire QA** : le profilage est exécuté par `-Stage Analyze` (liste les endpoints
> Query « mockables sans risque » et les mutations à ne jamais toucher). Le rapport est exporté
> en `traffic_profile.csv` pour l'audit de la campagne de test.

---

## 3. Architecture du Script d'Automatisation

Fichier : `Generate-OwnershipMock.ps1` (PowerShell 5.1+ — compatible `Windows PowerShell`,
utilisable tel quel dans `powershell.exe` et `pwsh`).

```
Analyze   → Capture   → Configure   → Deploy
 (logs)     (payload)    (rules.ini)   (proxy + reload + validation)
```

| Étage | Entrée | Sortie |
|---|---|---|
| `Analyze` | Logs de session (`tests/sessions/*.log`) | Rapport de classification + `traffic_profile.csv` |
| `Capture` | 1 log de session + filtre endpoint (`ownership`) | `captured/ownership_sample.json` (URL, status, body JSON valide) |
| `Configure` | JSON capturé + `-ProductId` (option) | `rules.ini` + `responses/ownership_<id>.json` |
| `Deploy` | `rules.ini` + dossier responses | Copie dans `$ProxyRulesDir`, marqueur `.reload`, redémarrage service (option), validation |

### 3.1 Exemples d'exécution

```powershell
# 1) Profilage (audit avant campagne) — ne touche à rien
.\Generate-OwnershipMock.ps1 -Stage Analyze -SessionLogSearchPath ".\tests\sessions\*.log"

# 2) Cycle complet, isolation produit strict 1337
.\Generate-OwnershipMock.ps1 -Stage All `
    -LogPath ".\tests\sessions\session-e2e.log" `
    -EndpointUrlFilter "ownership" `
    -ProductId 1337 `
    -StateFilter "owned" `
    -ProxyRulesDir "D:\Proxy\rules" `
    -ProxyServiceName "MitmProxySvc"

# 3) Chaîne étape par étape (CI/CD)
.\Generate-OwnershipMock.ps1 -Stage Capture   -LogPath ".\sessions\s1.log" -EndpointUrlFilter "ownership" -CapturedJson ".\out\cap.json"
.\Generate-OwnershipMock.ps1 -Stage Configure -CapturedJson ".\out\cap.json" -ProductId 1337 -RulesFile ".\out\rules.ini"
.\Generate-OwnershipMock.ps1 -Stage Deploy    -RulesFile ".\out\rules.ini" -ProxyRulesDir "\\buildagent\Proxy\rules"
```

**Paramètres clés** : `-LogPath`, `-SessionLogSearchPath`, `-EndpointUrlFilter`,
`-ProductId`, `-StateFilter`, `-LogLineParser` (regex du format de log),
`-RulesFile`, `-ResponseOutDir`, `-ProxyRulesDir`, `-ProxyServiceName`, `-ReloadMarker`.

---

## 4. Contrat du fichier `rules.ini` (moteur proxy in-house)

Le script génère un fichier conforme au contrat suivant (documenté pour
l'implémentation du moteur côté proxy) :

```ini
; ==================================================
; rules.ini — généré par Generate-OwnershipMock.ps1
; URL cible   : https://api.example.com/v1/ownership/status?product_id=1337&ts=1
; Contrat du format : voir PLAN_ACTION_TECHNIQUE.md §4
; ==================================================

[Rule_ownership_pid_1337_001]
Enabled=1
Priority=200
Method=GET
Pattern=^https?://api\.example\.com/v1/ownership/status\??([^?&]*&)*product_id=1337(?![0-9A-Za-z_\-])(&.*)?$
ResponseFile=ownership_pid_1337.json
StatusCode=200
ContentType=application/json

[Rule_ownership_pid_1337_002]
Enabled=1
Priority=199
Method=GET
Pattern=^https?://api\.example\.com/v1/ownership/status\??([^?&]*&)*product_id=(?<ProductId>[0-9A-Za-z_\-]+)(&.*)?$
ResponseFile=ownership_pid_1337.json
StatusCode=200
ContentType=application/json

[Rule_ownership_pid_1337_003]
Enabled=0
Priority=1
Method=GET
Pattern=^https?://api\.example\.com/v1/ownership/status(\?.*)?$
ResponseFile=ownership_pid_1337.json
StatusCode=200
ContentType=application/json
```

| Champ | Rôle |
|---|---|
| `[Rule_<nom>]` | Une règle par section ; le nom est stable et auditable |
| `Enabled` | `1` actif / `0` désactivé (filet de sécurité activable manuellement) |
| `Priority` | Haute pour la règle stricte produit, faible pour le filet de sécurité |
| `Method` | Verbe HTTP à intercepter (ici `GET`) |
| `Pattern` | Regex .NET complète, ancrée `^…$` (cf. §5) |
| `ResponseFile` | Payload JSON à injecter, **résolu relativement au dossier de règles du proxy** |
| `StatusCode` / `ContentType` | Enveloppe HTTP de la réponse simulée |

> **Rechargement** : le proxy surveille le dossier de règles et recharge dès qu'un
> fichier marqueur `.<ReloadMarker>` est présent/actualisé (champ horodaté). Le script
> émet ce marqueur à chaque déploiement, puis (option) redémarre le service pour un
> état réseau propre.

---

## 5. Engineering Regex (isolation précise des flux)

### 5.1 Isoler un ID produit spécifique dans l'URL

But : mock **seulement** le produit `1337` sans interférer avec `13370`, `11337`,
ni les autres flux de l'application.

| Variante | Pattern | Usage |
|---|---|---|
| A. Strict produit (position quelconque) | `^https?://api\.example\.com/v1/ownership/status\??([^?&]*&)*product_id=1337(?![0-9A-Za-z_\-])(&.*)?$` | **Recommandé** : `(?![0-9A-Za-z_\-])` bloque les préfixes (`13370`, `1337abc`) |
| B. Capture de l'ID en groupe nommé | `\??([^?&]*&)*product_id=(?<ProductId>[0-9A-Za-z_\-]+)(&.*)?$` | Pour injection conditionnelle du moteur |
| C. Anti-préfixe seul | `product_id=1337(?![0-9A-Za-z_\-])` | Interdit « 1337 suivi d'un caractère d'ID » |
| D. Nœud `\??([^?&]*&)*` (préfixe de query) | accepte `?product_id=…` (1ʳᵉ position) **et** `?x=1&product_id=…` (position suivante) | Illustre pourquoi `\?.*?[?&]product_id=` échoue quand `product_id` est le premier paramètre |
| E. Chemin slug (si l'ID est dans le path) | `^https?://api\.example\.com/v1/ownership/1337(?![0-9])(\?.*)?$` | Pour les endpoints REST `/ownership/{id}` |

> **Piège vérifié en test** : `\?.*?[?&]product_id=…` matche quand `product_id` suit d'autres
> paramètres mais **échoue quand il est le premier** (le `\?` consomme le séparateur et il n'en
> reste pas pour `[?&]`). Le préfixe `\??([^?&]*&)*` (optionnel) lève l'ambiguïté : le séparateur
> `?` est consommé, chaque paramètre intermédiaire se termine par `&`, puis `product_id=` est ciblé.
> Une alternative lookbehind `(?<=[?&])` a été écartée : fixée derrière le littéral de chemin,
> sa position d'évaluation ne bouge jamais et le match échoue systématiquement.

### 5.2 Pièges à neutraliser

1. **Collision de préfixes** : `product_id=1337` matche aussi `13370` sans
   `(?![0-9])` ou `(&|$)`.
2. **Ordre des paramètres de query** : ne jamais figer l'ordre
   (`product_id=…&ts=…`). Utiliser `\??([^?&]*&)*product_id=…` pour accepter
   `?product_id=1337&ts=1` (1ʳᵉ position) **et** `?ts=1&product_id=1337`.
3. **Encodage URL** : `%26` / `%3D` dans les valeurs. Normaliser (décoder) l'URL
   **avant** le matching, ou dupliquer le pattern en variante encodée.
4. **Caractères spéciaux** : échapper les points du domaine/chemin
   (`api\.example\.com`) et `-` dans les classes (`[a-z\-]`).
5. **Ancrage** : toujours `^…$` pour éviter qu'une sous-URL voisine
   (`/v1/ownership/status/export`) soit interceptée.
6. **Greedy tracking** : préférer `.*?` (lazy) pour ne pas « sauter » le premier
   `product_id` lorsque le corps de query contient plusieurs occurrences.

### 5.3 Interaction avec le reste de l'application

- `Method=GET` restreint les verbes — les mutations POST ne peuvent pas matcher.
- La priorité forte de la règle produit (`Priority=200`) garantit qu'elle gagne sur
  tout filet de sécurité générique.
- Le **filet de sécurité est généré `Enabled=0`** : par défaut, seul le produit isolé
  est mocké, les autres flux (produit B, autres endpoints) restent réels.

---

## 6. Drive de la capture (règles de sélection du payload)

1. Filtrer les lignes `GET|HEAD|OPTIONS` dont l'URL contient `ownership`.
2. Si `-ProductId` : conserver uniquement les URL dont `product_id=<id>` est exact
   (gardes anti-préfixe `(&|$)`).
3. Privilégier un statut `200` dont le corps contient `ownership_token`.
4. Si `-StateFilter owned` : le corps doit matcher `owned` (verrouille l'état à simuler).
5. Écrire le corpus retenu sous `captured/ownership_sample.json` avec métadonnées
   (horodatage, log source, URL, status) et corps **tel quel** (valide JSON).

---

## 7. Déploiement et validation de non-régression

| Vérification | Commande / Mécanisme |
|---|---|
| Règles présentes | `Test-Path $ProxyRulesDir\rules.ini` |
| Payload présent | `Test-Path $ProxyRulesDir\ownership_pid_1337.json` |
| Rechargement déclenché | Marqueur `.reload` mis à jour (horodaté) |
| Service healthy | `Get-Service $ProxyServiceName` → `Running` (si param fourni) |
| Smoke test E2E | Requête réelle `GET /v1/ownership/status?product_id=1337` → 200 + `"state":"owned"` + `ownership_token` valide |
| Non-régression flux réel | `GET …product_id=9999` (hors règle) → réponse backend réelle, inchangée |
| Non-régression mutations | `POST /v1/purchase` → toujours signé/pass-through, jamais mocké |

---

## 8. Intégration CI/CD

Ajoutez une étape séparée (ne bloquant pas la prod) dans la pipeline de la campagne
de tests. Voir `ci/azure-pipelines.yml`. Principe :

```
[Étape] Analyse (facultatif) → Capture (artefact) → Configure (artefact)
        → Deploy (agent Windows du proxy / share réseau) → Smoke test
```

Variables attendues dans la pipeline : `LOG_PATH`, `PRODUCT_ID`, `PROXY_RULES_DIR`,
`PROXY_SERVICE_NAME` (stockées en variables/secret de pipeline).

### Variante GitHub Actions

```yaml
- name: Capturer le payload d'état
  shell: pwsh
  run: |
    ./Generate-OwnershipMock.ps1 -Stage Capture `
      -LogPath "$env:LOG_PATH" -EndpointUrlFilter "ownership" `
      -CapturedJson "./out/ownership_sample.json"

- name: Générer les règles
  shell: pwsh
  run: |
    ./Generate-OwnershipMock.ps1 -Stage Configure `
      -CapturedJson "./out/ownership_sample.json" `
      -ProductId "$env:PRODUCT_ID" -RulesFile "./out/rules.ini"

- name: Déployer sur le proxy
  shell: pwsh
  run: |
    ./Generate-OwnershipMock.ps1 -Stage Deploy `
      -RulesFile "./out/rules.ini" -ProxyRulesDir "$env:PROXY_RULES_DIR"
```

---

## 9. Critères d'acceptation

- [ ] Le profilage isole correctement `GET /v1/ownership/*` comme Query et exclut `POST /v1/purchase`.
- [ ] Le payload capturé est un JSON valide contenant `ownership_token` + `state` attendu.
- [ ] Le `rules.ini` généré masque `product_id=1337` sans toucher `13370` ni d'autres endpoints.
- [ ] Après déploiement, le smoke test renvoie l'état « Possédé » de façon stable (10 itérations).
- [ ] Un produit hors périmètre (`9999`) et une mutation (`POST /purchase`) restent non altérés.
- [ ] L'exécution est reproductible en pipeline CI/CD (idempotente, artefacts versionnés).

---

## Annexe A — Exemple de log analysable

```
2026-09-20T09:12:41Z|GET|https://api.example.com/v1/ownership/status?product_id=1337&ts=1|200|{"product_id":1337,"state":"owned","ownership_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...","expires_at":"2026-12-31T00:00:00Z"}
2026-09-20T09:12:46Z|GET|https://api.example.com/v1/ownership/status?product_id=13370&ts=2|200|{"product_id":13370,"state":"not_owned","ownership_token":"eyJhbGciOi...","expires_at":"2026-12-31T00:00:00Z"}
2026-09-20T09:13:02Z|POST|https://api.example.com/v1/purchase|201|{"transaction_id":"txn_9f2c","signed_payload":"eyJ...","status":"completed"}
```

Interprétation : seul `product_id=1337` (produit 1337, `state=owned`) doit être mocké ;
`13370` (préfixe !) reste réel ; `POST /v1/purchase` n'est jamais intercepté.

## Annexe B — Fichiers du livrable

```
C:\qa-automation\proxy-mock\
├── PLAN_ACTION_TECHNIQUE.md            ← ce document
├── Generate-OwnershipMock.ps1          ← script d'automatisation (Analyze/Capture/Configure/Deploy)
└── ci\
    └── azure-pipelines.yml             ← pipeline QA de démonstration
```