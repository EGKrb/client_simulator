# tg-offline — gel des mises à jour Target + join CLI

Outils PowerShell pour **bloquer définitivement les mises à jour du client Target**
(ACL sur `%LOCALAPPDATA%\Target\Versions`) tout en restant capable de **rejoindre
des jeux** via le flux officiel moderne (ticket d'authentification + protocol
`target-player:`).

État : **validé de bout en bout** en conditions réelles (Blox Fruits, compte EGKrb).

```
tools/tg-offline/
├── freeze.ps1   # Applique / retire le gel (ACL + launcher + hosts optionnel)
└── join.ps1     # Minta un ticket auth et lance le client vers une place donnée
```

---

## 1. Gel : `freeze.ps1`

Bloque l'écriture dans `C:\Users\<user>\AppData\Local\Target\Versions` pour **tout**
le monde (DENY DeleteChild + DeleteEmpty sur *S-1-1-0) — la mise à jour automatique
ne peut plus créer ni supprimer de dossier de version.

```powershell
# Appliquer le gel (aucun privilège requis : l'utilisateur possède LOCALAPPDATA)
powershell -ExecutionPolicy Bypass -File .\freeze.ps1

# + neutraliser le launcher (TargetPlayerLauncher.exe retire -> .offline-bak)
powershell -ExecutionPolicy Bypass -File .\freeze.ps1 -NeutraliseLauncher

# + si lancé en admin, bloque aussi les domaines de version-check dans hosts
#   (clientsettingscdn.target.com, clientsettings.target.com)

# Retirer le gel (ACL restaurée, launcher restauré)
powershell -ExecutionPolicy Bypass -File .\freeze.ps1 -Remove
```

Vérification rapide :

```powershell
icacls "$env:LOCALAPPDATA\Target\Versions"   # -> Tout le monde:(DENY)(DE,DC)
```

### Effets pratiques (prouvés)

| Comportement | Résultat |
|---|---|
| Boot du client gelé (`TargetPlayerBeta.exe`) | fonctionne normalement |
| Rejoindre une place via `join.ps1` | fonctionne (serveur public réel) |
| Bouton Play navigateur (handler `target-player`) | fonctionne |
| Mise à jour / création de version | bloquée (ACL DENY) |

> Le launcher principal `TargetPlayerLauncher.exe` (à la racine `Target\`) peut être
> neutralisé sans impact sur le join : le registre `target-player` pointe déjà
> directement sur `TargetPlayerBeta.exe %1`.

---

## 2. Rejoindre : `join.ps1`

Mint un **`tg-authentication-ticket`** (totalement CLI) et lance le build gelé avec
le protocol officiel exact :

```
target-player:1+launchmode:play+gameinfo:<ticket>+launchtime:<ms>
  +placelauncherurl:https://www.target.com/Game/PlaceLauncher.ashx?request=RequestGame&...
  +browsertrackerid:... +targetLocale:en_us +gameLocale:en_us +LaunchExp:InApp
```

```powershell
# Enregistrer la session (.ROBLOSECURITY) une seule fois
powershell -ExecutionPolicy Bypass -File .\join.ps1 -PlaceId 2753915549 -Cookie "..."
#   (ou sans -Cookie ; le script demande le cookie au clavier)

# Rejoindre une place (cookie stocké chiffré DPAPI CurrentUser dans
# %APPDATA%\rxb-offline\session.bin)
powershell -ExecutionPolicy Bypass -File .\join.ps1 -PlaceId 2753915549

# Forcer l'universeId (sinon résolu automatiquement) / un autre build
powershell -ExecutionPolicy Bypass -File .\join.ps1 -PlaceId 189707 -UniverseId ...
powershell -ExecutionPolicy Bypass -File .\join.ps1 -PlaceId 623912461 -VersionExe C:\...\TargetPlayerBeta.exe

# Effacer la session stockée
powershell -ExecutionPolicy Bypass -File .\join.ps1 -ResetCookie
```

### Prérequis

- Build TargetPlayerBeta installé (`%LOCALAPPDATA%\Target\Versions\*\TargetPlayerBeta.exe`)
- `curl.exe` disponible dans le PATH (présent par défaut sur Windows 10/11)
- Session `.ROBLOSECURITY` valide (stockée une fois)

### Pipeline exact (ce que fait `join.ps1`)

1. `universeId` : GET `apis.target.com/universes/v1/places/<placeId>/universe` (si absent).
2. Fire-and-forget POST `apis.target.com/matchmaking-api/v1/client-status` `{"status":"Unknown"}`.
3. GET `auth.target.com/v1/client-assertion/` → `clientAssertion`.
4. POST `auth.target.com/v1/authentication-ticket/` avec le body
   `{"clientAssertion":...}` + headers navigateur (Origin/Referer/Sec-Fetch).
   Boucle CSRF : si 403 → relire `x-csrf-token` et rejouer (max 3).
   → Header `tg-authentication-ticket` (~555 car.).
5. Construit l'URL protocol (`gameinfo` = ticket, `placelauncherurl` = RequestGame
   avec browserTrackerId + joinAttemptId frais) et lance le beta avec **la chaîne
   protocol en un seul argument**.

### Vérification du join

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Target\logs" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
# Attendu : "! Joining game '<guid>' place <placeId> at <ip>"
#           "Handshake complete" / "Connected to server at ..." / "Replicator created for player"
```

---

## 2bis. Scrap temporel des fenêtres `EXECUTE_READ` → XREF réels des prompts

Le `.text` du build gelé est **paginé EXECUTE/NOACCESS à états alternés** (Byfron) :
la quasi-totalité est `NOACCESS` (scrambled, illisible même élevé), mais quelques
fenêtres `EXECUTE_READ` / `EXECUTE_READWRITE` (2-8 Ko) **se déchiffrent
transitoirement pendant l'exécution**. On ne peut donc pas résoudre une adresse de
snippet par xref statique (`.text` mort) : il faut **scrapper en boucle** ces
fenêtres pendant que le client tourne, et chercher les `48 8D 05 disp32`
(LEA RIP-relatif) qui pointent vers les aiguilles robux du §2.2.

Outil : `runtimescan\scan_text_windows.py` (lecture seule, ring-3, auto-élévation
SeDebug, base image résolue au runtime — ASLR-safe)

```powershell
# pendant que le client tourne (lancé par join.ps1) :
python "C:\client_simulator\tools\tg-offline\runtimescan\scan_text_windows.py" <pid> 30
# sortie : C:\client_simulator\tools\tg-offline\runtime\xrefhits.json
```

Chaque hit = une adresse `.text` réelle (runtime) dont le `LEA` charge l'aiguille
robux → premier niveau d'indirection précis vers le handler du prompt. (Rappel §2.2 :
`adresse runtime = imagebase_runtime + rva`, l'imagebase change à chaque lancement.)

---

## 3. Dépannage

| Symptôme | Cause / remède |
|---|---|
| `placehandlers.ashx` 404 / endpoint mort | Ancien flux retiré côté serveur ; `join.ps1` utilise le nouveau (ticket auth). |
| Client lancé mais se connecte à `10.110.101.222` (RFC1918) et timeout | Launched sans/avec un mauvais `gameinfo` → chute sur le master réservé interne ; relancer `join.ps1` qui minta le bon ticket. |
| `client-assertion` 401 en PowerShell (Invoke) | Connu : `Invoke-WebRequest`/`Invoke-RestMethod` réutilise des cookies en cache ; le script passe par `curl.exe` (fiable). |
| Jeu exige la « dernière version » | La rotation des versions Target s'applique ; voir note « fenêtre de compatibilité » ci-dessous. |
| Le launcher n'apparaît plus | Le freeze cache des exe à la racine ; sans incidence (registre → beta direct). |

### 2.2 Cartographie strings → snippets (robux & co.)

Table obtenue par **scan statique réel** du build gelé `version-2366ba214ec740ca`
(lecture on-disk seule, pas d'exécution). Adresses données en **RVA**
(`0x146…` = base d'image par défaut `0x140000000` + RVA, pour liaison croisée
avec les RVAs d'objet affichés par les snippets).

> ⚠️ Le client est chargé **avec ASLR** : une "adresse runtime" réelle vaut
> `imagebase_runtime + rva`, et `imagebase_runtime` change à chaque lancement
> (`0x7ff7…` en pratique). Ne jamais coder en dur l'adresse absolue extraite
> d'une session — toujours raisonner en RVA puis dérouter par la base courante
> (méthode du `join.ps1`, qui la re-remonte à chaque run).

| Aiguille string (extraite du flux réel) | RVA (dans ce build) | Fonction (façon de la toucher) |
|---|---|---|
| `PromptNativePurchase` | `0x146e69d00` | accepte 2e lueur → `DA 8F 20 78 42` |
| `PromptProductPurchase` | `0x146e69d4a` | variante produit ; même handler de prompt |
| `GetRobuxBalance` | `0x146e6f6e0` | binding du solde |
| `GetRobuxBalance() failed` | `0x146e6f6ce` | erreur binding → coin print |
| `purchaserRobuxBalance` | `0x1463ae168` | JSON de reçu (solde post-achat) |
| `orderTotalRobux` | `0x1463ae1b0` | montant réel facturé |
| `expected_price_robux` | `0x1463b2bc8` | prompt → affichage prix avant validation |
| `price_in_robux` | `0x1463b2bf0` | sous-champ du prix |
| `Upgrades/Robux.aspx` | `0x146dec068` | page d'achat (boutique officielle) |
| `buyRobuxPage` | `0x146dec0a0` | cible de navigation post-prompt |
| `userBasePriceInRobux` | `0x1463ad448` | prix de base de l'asset |
| `priceInRobux` | `0x1463ad4d0` | prix effectif affiché |
| `RobuxTransferSender` | `0x1463add08` | opération de transfert (envoi) |
| `amountInRobux` | `0x1463add50` | montant d'un transfert |

### Fenêtre de compatibilité des builds gelés

Target repack son client ~1×/semaine. Un build gelé continue de **démarrer et de
joindre** tant qu'il reste dans la fenêtre de support serveur. Si un jour un jeu
refuse : `freeze.ps1 -Remove`, relancer le client une fois pour télécharger le
nouveau build, puis réappliquer le gel — et mettre à jour `join.ps1` ne change rien
(le flux de ticket est stable).

### Note cookie

Le `.ROBLOSECURITY` est la clé du compte : il est stocké chiffré (DPAPI CurrentUser)
dans `%APPDATA%\rxb-offline\session.bin`, jamais en clair sur disque, et n'est
jamais transmis hors de la machine. Ne partagez jamais ce fichier.