<#
.SYNOPSIS
  Vérification bout-en-bout de la passerelle ltg avec MonNouvelApp.exe (libcurl)
  routé derrière le proxy transparent 127.0.0.1:7080.

.DESCRIPTION
  1. Démarre (ou réutilise) ltg.exe sur 127.0.0.1:<Port>.
  2. Exporte la racine LGT-Root-CA (ltg-root.der produit par la passerelle) en
     PEM pour libcurl de MonNouvelApp.exe via la variable LTG_CA_PEM
     (CURLOPT_CAINFO dans client_simulator.cpp). Le PEM est supprimé à la fin.
  3. Exécute 3 scénarios contre les règles de rules.ini :
       - POST /api/v1/commit  -> 429 (latence 800 ms injectée)
       - GET  /api/v1/upload  -> 413 + header x-backend: simulated
       - GET  /api/.*/export  -> 500 + mock Luau (fallback.luau)
  4. Affiche les logs d'audit de la passerelle.

.PARAMETER Port
  Port d'écoute de la passerelle (défaut : 7080).
.PARAMETER StopGateway
  Arrête la passerelle en fin de script uniquement si elle a été démarrée ici.
#>
param(
    [int]$Port = 7080,
    [switch]$StopGateway
)

$ErrorActionPreference = 'Stop'

$proj       = 'C:\client_simulator'
$ltgExe     = Join-Path $proj 'build\Release\ltg.exe'
$appDir     = 'C:\client_simulator\bin'
$appExe     = Join-Path $appDir 'MonNouvelApp.exe'
$rootDer    = Join-Path $proj 'ltg-root.der'
$caPem      = Join-Path $proj '_ltg_run_cacert.pem'
$ltgLog     = Join-Path $proj 'ltg-run.log'
$ltgOwned   = $false

# ---------- prérequis ---------------------------------------------------------
foreach ($p in @($ltgExe, $appExe)) {
    if (-not (Test-Path $p)) { throw "Fichier introuvable : $p" }
}

# ---------- 1. Passerelle (toujours fraîche) ------------------------------------
# ltg.exe génère une NOUVELLE Root CA à chaque démarrage (ltg-root.der écrasé).
# Pour que la confiance du client colle aux feuilles servies, on repart toujours
# d'un processus neuf : on tue tout ltg existant avant de lancer le nôtre.
Get-Process -Name 'ltg' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Write-Host "[1] Démarrage de la passerelle sur 127.0.0.1:$Port ..."
$gw = Start-Process -FilePath $ltgExe -ArgumentList "$Port" `
    -WorkingDirectory $proj `
    -RedirectStandardError $ltgLog -RedirectStandardOutput "$ltgLog.out" -PassThru
Start-Sleep -Seconds 2
if ($gw.HasExited) { throw "ltg.exe s'est arrêté immédiatement (voir $ltgLog)." }
$ltgOwned = $true
Write-Host "       PID $($gw.Id) - logs dans $ltgLog"

if (-not (Test-Path $rootDer)) {
    throw "Racine LGT introuvable : $rootDer (relancez la passerelle pour l'exporter)."
}

# ---------- 2. CA bundle pour libcurl (LTG_CA_PEM) -----------------------------
# client_simulator.cpp n'imposait pas de CA : la vérification OpenSSL utilisait
# le défaut (échec sur nos feuilles). On fournit désormais via LTG_CA_PEM un PEM
# contenant LA racine LGT (+ les CA publiques en option) ; la racine SEULE suffit
# aux scénarios d'injection de rules.ini (hosts *.monapp.test servis par ltg).
function Convert-DerToPem([string]$derPath) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($derPath))
    $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $len = [Math]::Min(64, $b64.Length - $i)
        $b64.Substring($i, $len)
    }
    # Ne PAS imbriquer $lines dans @(...) : le -join afficherait
    # "System.Object[]" au lieu des lignes base64 (PEM corrompu).
    return ("-----BEGIN CERTIFICATE-----`n" +
            ($lines -join "`n") +
            "`n-----END CERTIFICATE-----")
}
$rootPem = Convert-DerToPem $rootDer
Set-Content -Path $caPem -Value ($rootPem + "`n") -NoNewline -Encoding ASCII

$savedEnv = $env:LTG_CA_PEM
$env:LTG_CA_PEM = $caPem
Write-Host "[2] LTG_CA_PEM -> $caPem (LGT-Root-CA)"

try {
    # ---------- 3. Scénarios ----------------------------------------------------
    $tests = @(
        @{ label = 'POST /api/v1/commit (attendu HTTP 429, ~800 ms)'
           args  = @('--proxy', "http://127.0.0.1:$Port", '--sim-post',
                     'https://serveur.monapp.test/api/v1/commit', '{"order":"SIM-001"}') },
        @{ label = 'GET  /api/v1/upload (attendu HTTP 413 + x-backend: simulated)'
           args  = @('--proxy', "http://127.0.0.1:$Port", '--sim-get',
                     'https://serveur.monapp.test/api/v1/upload') },
        @{ label = 'GET  /api/v2/export (attendu HTTP 500 + mock Luau)'
           args  = @('--proxy', "http://127.0.0.1:$Port", '--sim-get',
                     'https://serveur.monapp.test/api/v2/export') }
    )

    Push-Location $appDir   # libcurl y résout curl-ca-bundle.crt / libcurl-x64.dll
    try {
        foreach ($t in $tests) {
            Write-Host "`n=== $($t.label) ==="
            $output = & $appExe @($t.args) 2>&1
            $exitCode = $LASTEXITCODE
            $output | ForEach-Object { Write-Host "  $_" }
            Write-Host "  -> exit code : $exitCode"
        }
    } finally {
        Pop-Location
    }
} finally {
    # ---------- nettoyage -------------------------------------------------------
    if ($null -eq $savedEnv) {
        Remove-Item Env:LTG_CA_PEM -ErrorAction SilentlyContinue
    } else {
        $env:LTG_CA_PEM = $savedEnv
    }
    Remove-Item $caPem -Force -ErrorAction SilentlyContinue
    Write-Host "`n[4] LTG_CA_PEM restauré, PEM temporaire supprimé."
}

# ---------- 4. Audit ------------------------------------------------------------
Write-Host "`n=== Logs de la passerelle ($ltgLog) ==="
if (Test-Path $ltgLog) {
    Get-Content $ltgLog
} else {
    Write-Host "(aucun fichier de log)"
}

# ---------- 5. Aperçu de l'environnement proxy ----------------------------------
$machineProxy = [Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'Machine')
if ($machineProxy) {
    Write-Host "`n=== NOTE : HTTPS_PROXY machine défini ($machineProxy) ==="
    Write-Host "Le trafic système (y compris les sondes Windows kessel-api.parsec.app)"
    Write-Host "passe par la passerelle : c'est normal dans les logs. Pour l'arrêter :"
    Write-Host '  [Environment]::SetEnvironmentVariable("HTTPS_PROXY", $null, "Machine")'
}

if ($StopGateway -and $ltgOwned) {
    Stop-Process -Name 'ltg' -Force -ErrorAction SilentlyContinue
    Write-Host "`nPasserelle arrêtée."
} elseif ($ltgOwned) {
    Write-Host "`nPasserelle laissée active (ajoutez -StopGateway pour l'arrêter)."
}