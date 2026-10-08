# GUIDE_UTILISATION — MonNouvelApp.exe

Guide de prise en main de `MonNouvelApp.exe` (client simulateur d'achat web,
scan de processus, passerelle MITM et moteur NightShift). Conçu pour être
utilisé **sans connaissance du code source** : lancez, expérimentez, testez.

> Si vous cherchez la liste exhaustive des options, consultez
> [`MonNouvelApp_commands.md`](MonNouvelApp_commands.md).

---

## 1. Récupérer l'outil

L'exécutable est déjà compilé :

```
C:\client_simulator\bin\MonNouvelApp.exe
```

Il s'accompagne de DLLs obligatoires dans **le même dossier** :
`libcurl-x64.dll`, `libssl-3-x64.dll`, `libcrypto-3-x64.dll` et
`curl-ca-bundle.crt`. Pour déplacer l'outil, **copiez tout le dossier `bin\`**.

### Recompiler (optionnel, pour développeurs)

Prérequis : Visual Studio 2022 Build Tools (charge de travail C++ x64).

```cmd
C:\client_simulator\build_monnouvelapp.bat
```

---

## 2. Prérequis

| Besoin | Détail |
|---|---|
| Windows x64 | Peu importe la version (10/11/Server) |
| Droits **administrateur** | Uniquement pour les modes avancés (voir section 6) |
| Python | Uniquement pour les tests automatiques (section 8) |
| Connexion internet | Uniquement pour les vrais achats / appels distants |

Rien à installer pour lancer l'outil. Toutes les commandes ci-dessous se font
dans un terminal `cmd` ou `PowerShell`.

---

## 3. Démarrage rapide (10 secondes)

Ces commandes fonctionnent **sans droits spéciaux et sans serveur** :

```cmd
MonNouvelApp.exe --ns "version"
MonNouvelApp.exe --ns "load C:\Windows\System32\kernel32.dll; peinfo; sections; symbols GetSystemT; unload"
```

La deuxième charge `kernel32.dll`, affiche son entête PE, ses sections et ses
exports filtrés par « GetSystemT », puis décharge la DLL. Très utile pour
vérifier que l'outil fonctionne lors d'une première utilisation.

> **Clé de lecture des sorties** : `[OK]` = succès, `[FAIL]` = échec.
> Les couleurs (vert/rouge) ne s'affichent que dans un terminal qui les gère.

---

## 4. Les familles de commandes

### 4.1 Simulation HTTP (`--sim-*`)

Envoie de vraies requêtes HTTP(S) depuis l'outil, sans écrire de code :

```cmd
MonNouvelApp.exe --sim-get https://exemple.com/api/v1/status
MonNouvelApp.exe --sim-post https://exemple.com/api/v1/commit "{\"order\":\"SIM-001\"}"
MonNouvelApp.exe --sim-purchase https://shop.exemple.com
```

Sortie : `HTTP <code> | <temps> ms | OK=true` puis le corps de la réponse.

### 4.2 Achat web Target (`--buy-*`)

Achète un game pass / dev product / objet marketplace. Prérequis : un fichier
`cookie.txt` contenant le cookie `.ROBLOSECURITY`, placé **dans le dossier où
vous lancez la commande** :

```cmd
MonNouvelApp.exe --buy-gamepass 6738811
MonNouvelApp.exe --buy-devproduct 1234567
MonNouvelApp.exe --buy-probe 6738811 100 1234567
```

### 4.3 Moteur NightShift (`--ns*`)

CLI d'exploitation de DLL + session Microsoft Dynamics GP :

```cmd
MonNouvelApp.exe --ns "version"                                  :: version du moteur
MonNouvelApp.exe --ns "aliases"                                  :: listes les connexions GP nommées (aliases.txt)
MonNouvelApp.exe --ns "load C:\Windows\System32\user32.dll; sections; unload"
MonNouvelApp.exe --ns-batch mon_script.bat                      :: batch (CMD:/SQL:/LOGIN:/WAIT: par ligne)
MonNouvelApp.exe --ns-repl                                       :: mode interactif (tapez "help")
```

Les fichiers `aliases.txt` (connexions nommées) et vos scripts `.bat` sont lus
depuis le **dossier courant**.

### 4.7 Trace de démarrage (`--trace`) et surveillance d'un processus en cours (`--trace-attach`)

Lance une `.exe` et rapporte **tout ce qu'elle fait au démarrage** :

```cmd
MonNouvelApp.exe --trace notepad
MonNouvelApp.exe --trace C:\tools\monapp.exe --arg1 --arg2 --trace-timeout 10
MonNouvelApp.exe --trace cmd.exe /c ipconfig
```

Le processus est lancé **suspendu** : avant même qu'il exécute la moindre ligne,
l'outil lit son PEB (ligne de commande, chemin image, répertoire courant, chemin
de recherche DLL, taille de l'environnement). Puis il le reprend et surveille
pendant ~5 secondes (configurable via `--trace-timeout <s>`) : **DLL chargées**,
**threads créés**, **processus enfants**, **fichiers ouverts**, **clés registre**,
**connexions TCP/UDP** et **drivers noyau chargés** (utile pour voir le driver
anti-tamper de Byfron se charger au démarrage du jeu). Sans `--trace-keep`, le
processus est arrêté à la fin de la fenêtre.

> Les arguments après l'exe sont transmis tels quels à la cible.

Pour surveiller un processus **déjà lancé** (par exemple une vraie session de jeu
où Hyperion/Byfron charge son `.sys`), utilisez `--trace-attach` — la cible n'est
**jamais tuée** :

```cmd
MonNouvelApp.exe --trace-attach 58556 --trace-timeout 60
```

L'affichage commence par l'état immédiat (parent, modules chargés, ligne de
commande, drivers noyau présents) puis échantillonne les mêmes diffs que le
`--trace`. Si le scan de handles d'une cible bloque (console d'une autre
session, etc.), il est abandonné au bout de 1,5 s (`scan des handles bloque`)
sans stopper le reste de la surveillance.

### 4.8 Scan de signature AOB (mode par défaut)

Sans option « mode », l'outil scanne la mémoire d'un processus pour une
signature hexadécimale (wildcards `??`) :

```cmd
MonNouvelApp.exe 31280 "48 89 5C 24 ?? 50"
MonNouvelApp.exe TargetPlayerBeta "E8 ?? ?? ?? ?? 48 8B 03"
MonNouvelApp.exe --read-only 31280           :: lecture seule, sans droits admin
```

Résultat : `0` = au moins une occurrence trouvée · `2` = aucune · `1` = erreur.

### 4.9 Passerelle HTTPS de test (`--gateway`)

Démarre une passerelle MITM locale (comme `ltg.exe`) qui sert des réponses
mockées à partir d'un fichier de règles :

```cmd
MonNouvelApp.exe --gateway 7080
```

Les fichiers `rules.ini`, `fallback.luau` et `ltg-root.der` doivent être dans
**le dossier courant**. À chaque démarrage, une nouvelle racine de certification
est générée (`ltg-root.der`) et installée si vous êtes admin.

### 4.10 Mock Ownership (`--mock*`)

Pipeline qui analyse des logs de session et génère/déploie des règles de mock :

```cmd
MonNouvelApp.exe --mock analyze  --mock-log C:\logs\session.log
MonNouvelApp.exe --mock capture
MonNouvelApp.exe --mock configure --mock-product 1337
MonNouvelApp.exe --mock deploy --mock-proxy-dir C:\proxyrules
```

---

## 5. Les options utilisées partout

| Option | Effet |
|---|---|
| `--sandbox` (alias `--test-mode`) | Redirige tout le HTTP vers `localhost:8080` (mock local, aucun appel réel) |
| `--proxy <url>` | Fait passer tout le trafic par un proxy (ex. `--proxy 127.0.0.1:8080`) |
| `--pid <pid>` | Vise un PID précis (modes Snyper) |
| `--read-only` / `-r` | Accès lecture seule (scan AOB sans admin) |
| `--trace-timeout <s>` | Fenêtre de surveillance du `--trace` / `--trace-attach` (défaut 5 s) |
| `--trace-keep` | `--trace` : ne pas tuer le processus à la fin de la fenêtre |

**Testez sans risques** avec `--sandbox` + le serveur de test inclus :

```cmd
python C:\client_simulator\tests\serve_sandbox.py 8080
MonNouvelApp.exe --sim-get https://api.target.com/v1/users/authenticated --sandbox
```

---

## 6. Modes qui exigent une session administrateur

Ces fonctions touchent aux processus protégés ou aux drivers système. Lancez
le terminal **en tant qu'administrateur** (UAC) ou elles refuseront proprement
de démarrer (`Elevation UAC requise`) :

- Exécution Luau dans un processus Target : `--luau-vm`, `--marketplace`,
  `--gamepass`, `--devproduct`, `--detect`, `--survivor`, `--sig-update`,
  `--autofix`, `--loadstring`
- Hooks locaux : `--hook-demo`, `--iat-demo`, `--vmt-demo`, `--apc`,
  `--hijack`
- Accès driver : `--byovd`, `--hijack-byovd`, `--byovd-siv`, `--siv-load`,
  `--siv-read`, `--siv-write`, `--siv-remove`

> ⚠️ Les commandes BYOVD/SIV manipulent la mémoire **physique** via un driver.
> Elles sont destinées à un environnement de test isolé. Ne les exécutez pas
> sur une machine de production.

---

## 7. Codes de sortie

| Code | Signification |
|---|---|
| `0` | Succès |
| `1` | Erreur d'usage, option inconnue, cible invalide ou échec technique |
| `2` | Scan AOB : aucune occurrence trouvée |
| `3` | Achat web : cookie absent/invalide ou échec d'authentification |

Vérifiez toujours le code retour dans vos scripts PowerShell :

```powershell
& 'C:\client_simulator\bin\MonNouvelApp.exe' --sim-get https://exemple.com --sandbox
if ($LASTEXITCODE -ne 0) { Write-Host "Echec (code $LASTEXITCODE)" }
```

---

## 8. Tests automatiques

Un harnais teste une à une **toutes** les commandes et vérifie codes de sortie,
marqueurs de sortie et conditions post-exécution :

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File 'C:\client_simulator\tests\test_commands.ps1'
```

- `-Only 'regex'` : ne lancer qu'un sous-ensemble (ex. `-Only 'sim-|mock-'`).
- `-Report` : affiche la sortie complète en cas d'échec.
- `-ForceDangerous` : inclut les commandes drivers/noyau (⚠️ risque kernel).

Résultat attendu : `PASS=n FAIL=0 SKIP=0`.

---

## 9. Dépannage (FAQ)

| Symptôme | Cause probable | Solution |
|---|---|---|
| `Option inconnue : ...` | Typo ou option inexistante | Vérifiez l'orthographe dans `MonNouvelApp_commands.md` |
| `--ns ... --` requiert une chaîne | Argument manquant | Passez la chaîne entre guillemets |
| `Elevation UAC requise` | Mode avancé sans admin | Relancez en terminal administrateur (ou `--read-only` pour le scan) |
| `cookie.txt` introuvable | Achat web sans cookie | Créez `cookie.txt` avec `.ROBLOSECURITY` **dans le dossier courant** |
| `Passerelle active` jamais observée | `rules.ini` absent | Lancez `--gateway` depuis le dossier contenant `rules.ini`/`fallback.luau` |
| Port 8080 occupé | Ancien serveur de test | `Get-NetTCPConnection -LocalPort 8080` puis tuez le processus |
| `Cannot load DLL` (NightShift) | Chemin absent | Utilisez un chemin absolu de DLL existante |
| Sorties avec caractères bizarres | ANSI affiché dans un terminal non compatible | Utilisez Windows Terminal ou `cmd` récent |

---

## 10. Où aller ensuite

- **Référence complète des commandes** : [`MonNouvelApp_commands.md`](MonNouvelApp_commands.md)
- **Passerelle HTTPS / `ltg`** : [`ltg_commands.md`](ltg_commands.md)
- **Moteur NightShift** : section « Module NightShift » du [`README.md`](README.md)
- **Code et structure** : [`README.md`](README.md) (sections « Structure du projet », « Compilation »…)