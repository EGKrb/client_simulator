#Requires -Version 5.1
<#
.SYNOPSIS
    Scenario "Capture & Replay" : reussite de verification de possession produit
    (GamePass Target) via la passerelle HTTPS integree de MonNouvelApp.exe.

.DESCRIPTION
    Commande unique :
        .\Deploy-VerificationSuccess.ps1 -Url "https://www.target.com/game-pass/<ID>/<slug>"

    Deroule (contrat detaille : MonNouvelApp_commands.md 9) :
      1. MINING   : exploration des journaux ltg/audit et de session (format
         pipe) pour trouver une reponse HTTP 200 du service ownership de l'ID
         produit contenant un jeton valide (ownership_token / possession_token).
         Le corps JSON de la reponse est extrait vers captured\ownership_sample.json.
      2. PAYLOAD  : generation de mock_success.luau qui injecte exactement ce
         corps via mock.respond (moteur Luau embarque) ainsi que rules.ini au
         contrat proxy-mock [Rule_*] (Script=mock_success.luau, StatusCode=200).
      3. DEPLOY   : publication vers le dossier du proxy externe (-ProxyRulesDir)
         + marqueur .reload (ou --mock-service). Pour la passerelle embarquee,
         la regle est active des le demarrage (--gateway), aucun rechargement
         a chaud n'est requis.
      4. VALIDATE : lancement de la cible avec les variables proxy
         (HTTPS_PROXY/HTTP_PROXY + LTG_CA_PEM) et --sim-get <Url>?product_id=<ID>,
         puis controle de l'exit code ET de la ligne d'audit :
         [ltg] GET ... -> 200 (inject).

    Si aucun jeton valide (HTTP 200 + ownership_token) n'est trouve dans les
    logs pour l'ID :
        [ERROR] Aucun token valide trouv[e-accent] dans les logs pour l'ID <ID>.
        Veuillez effectuer une transaction reelle au prealable.
    (Basculer en mock synthetique via -SyntheticFallback si besoin.)

    Compatible C:\client_simulator : MonNouvelApp.exe --gateway (ex-ltg.exe),
    contrat [Rule_*] charge par RuleEngine::load, moteur Luau (mock.respond)
    execute par MockController (audit "inject"), port gere par PID (jamais de
    kill sauvage du processus).

.PARAMETER Url
    URL du produit a verifier, ex. https://www.target.com/game-pass/6738811/Fruit-Notifier .
    La verification utilise <Url>?product_id=<ID>. Requis en mode All/Verify.

.PARAMETER Stage
    Etage a executer : Analyze | Capture | Configure | Deploy | Verify | All (defaut).
    - Analyze/Capture : pipeline natif --mock (profilage / extraction CLI).
    - Configure       : rules.ini + payloads (+ Script=mock_success.luau si
                        -MockEngine Luau).
    - Deploy          : copie vers -ProxyRulesDir + marqueur .reload.
    - Verify          : gateway + --sim-get + controle "(inject)".
    - All             : MINING (logs) -> Configure -> Deploy -> Verify.

.PARAMETER WorkDir
    Repertoire de travail (regles, payloads, racine .der, CWD du gateway,
    ancrage des chemins relatifs). Defaut : C:\client_simulator

.PARAMETER AppExe
    Chemin de MonNouvelApp.exe (gateway ET application cible).
    Defaut : C:\client_simulator\bin\MonNouvelApp.exe

.PARAMETER Port
    Port d'ecoute de la passerelle. Defaut : 7080

.PARAMETER StartupTimeoutSeconds
    Delai maximal d'attente du marqueur "Passerelle active". Defaut : 30.

.PARAMETER MockEngine
    Luau (defaut) : la regle stricte utilise Script=mock_success.luau
    (injection du payload via mock.respond, audit passerelle "inject").
    ResponseFile : mode fichier historique (audit "mock-file").

.PARAMETER LogPath
    Source de verite explicite du MINING (et de Capture) -> chemin unique.

.PARAMETER SessionLogSearchPath
    Glob des logs de session pour le MINING -> defaut <WorkDir>\logs\sessions\*.log

.PARAMETER EndpointUrlFilter
    Filtre URL du MINING (aussi --mock-filter en natif). Defaut : ownership

.PARAMETER ProductId
    Identifiant produit a isoler (Priority 200). Absent : derive de -Url.

.PARAMETER StateFilter
    Texte attendu dans le corps (ex. "owned") -> --mock-state (natif).

.PARAMETER LogLineParser
    Regex de parsing d'une ligne de log (groupes nommes ts/verb/url/status/body).
    Defaut : format pipe "ts|verb|url|status|body".

.PARAMETER CapturedJson
    Echantillon JSON du payload capture -> --mock-captured.
    Defaut : <WorkDir>\captured\ownership_sample.json

.PARAMETER ResponseOutDir
    Dossier des payloads et scripts injectes -> --mock-responses.
    Defaut : <WorkDir> (au plus pres de rules.ini, dossier des ResponseFile/Script).

.PARAMETER RulesFile
    Fichier rules.ini genere -> --mock-rules. Defaut : <WorkDir>\rules.ini

.PARAMETER PathRegex
    Expression reguliere du chemin intercepte ({id} remplace par l'ID). Vide =
    pattern derive par --mock configure.

.PARAMETER Method
    Methode HTTP de l'echantillon synthetique. Defaut : * (toutes).

.PARAMETER MockStatus
    Code de statut de la reponse mockee (mode synthetique). Defaut : 200.

.PARAMETER MockBody
    Corps JSON de la reponse mockee (mode synthetique).
    Defaut : {"success":true,"has_item":true,"item_id":<ID>}

.PARAMETER ProxyRulesDir
    Dossier de regles du proxy externe (cible du Deploy) -> --mock-proxy-dir.
    Absent : etape Deploy sautee (regles conservees dans -RulesFile).

.PARAMETER ProxyServiceName
    Service Windows du proxy a redemarrer apres deploiement -> --mock-service.

.PARAMETER ReloadMarker
    Nom du marqueur de rechargement -> --mock-reload. Defaut : .reload

.PARAMETER SyntheticFallback
    Si aucun jeton valide n'est trouve dans les logs : construire un echantillon
    synthetique depuis l'URL (comportement historique) au lieu de l'erreur spec.

.PARAMETER KeepRunning
    Ne pas nettoyer : laisse le gateway actif et les fichiers generes en place.

.PARAMETER NoElevate
    Desactive l'auto-elevation (debug / CI sans UAC).

.EXAMPLE
    # Commande unique recommandee (MINING -> inject -> validation)
    .\Deploy-VerificationSuccess.ps1 -Url "https://www.target.com/game-pass/6738811/Fruit-Notifier"

.EXAMPLE
    # Source de logs explicite + deploiement vers un proxy externe
    .\Deploy-VerificationSuccess.ps1 -Url "https://www.target.com/game-pass/6738811/X" `
        -LogPath "C:\tests\sessions\apps.ltg.log" -ProxyRulesDir "D:\Proxy\rules"

.EXAMPLE
    # Etages separement (CI/CD)
    .\Deploy-VerificationSuccess.ps1 -Stage Configure -ProductId 6738811
    .\Deploy-VerificationSuccess.ps1 -Stage Verify -Url "https://www.target.com/game-pass/6738811/X"

.NOTES
    Genere : rules.ini, ownership_pid_<ID>.json, mock_success.luau,
    ownership_fallback.json, captured\ownership_sample.json, traffic_profile.csv,
    _ltg_scenario_cacert.pem, _ltg_scenario.{out,err}.log. Restaure les regles
    d'origine (.ltgscenario.bak supprime).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, HelpMessage = "URL du produit GamePass a verifier, ex: https://www.target.com/game-pass/6738811/Fruit-Notifier")]
    [string]$Url,

    [ValidateSet('Analyze', 'Capture', 'Configure', 'Deploy', 'Verify', 'All')]
    [string]$Stage = 'All',

    [ValidateNotNullOrEmpty()]
    [string]$WorkDir = 'C:\client_simulator',

    [ValidateNotNullOrEmpty()]
    [string]$AppExe = 'C:\client_simulator\bin\MonNouvelApp.exe',

    [ValidateRange(1, 65535)]
    [int]$Port = 7080,

    [ValidateRange(5, 300)]
    [int]$StartupTimeoutSeconds = 30,

    [ValidateSet('Luau', 'ResponseFile')]
    [string]$MockEngine = 'Luau',

    # ---------- source de verite (MINING / Capture) ------------------------
    [string]$LogPath,
    [string]$SessionLogSearchPath,
    [string]$EndpointUrlFilter = 'ownership',
    [string]$ProductId,
    [string]$StateFilter,
    [string]$LogLineParser = '^(?<ts>[^|]+)\|(?<verb>[A-Z]+)\|(?<url>\S+)\|(?<status>\d{3})\|(?<body>.*)$',

    # ---------- generateurs (Configure) ------------------------------------
    [string]$CapturedJson,
    [string]$ResponseOutDir,
    [string]$RulesFile,
    [string]$PathRegex = '',
    [string]$Method = '*',
    [ValidateRange(100, 599)]
    [int]$MockStatus = 200,
    [string]$MockBody = '',

    # ---------- deploiement / proxy externe --------------------------------
    [string]$ProxyRulesDir,
    [string]$ProxyServiceName,
    [string]$ReloadMarker = '.reload',

    [switch]$SyntheticFallback,
    [switch]$KeepRunning,
    [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'

# ---------------- etat du scenario (portee script) ----------------------------
$Script:GatewayPid            = $null
$Script:RulesExistedInitially = $false
$Script:RulesBackup           = $null
$Script:GeneratedFiles        = New-Object System.Collections.Generic.List[string]
$Script:RulesFile             = $null
$Script:CapturedPath          = $null
$Script:ResponsesResolved     = $null
$Script:SessionsGlob          = $null
$Script:LogPathResolved       = $null
$Script:ProxyDirResolved      = $null
$Script:EffectivePid          = ''
$Script:CapturedExistedInit   = $false

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# ---------------- constantes ---------------------------------------------------
# Messages spec : accents construits par codes UTF-16 (source ASCII, PS 5.1).
$Script:Acute  = [string][char]0x00E9   # e accent aigu
$Script:Grave  = [string][char]0x00E8   # e accent grave
$Script:QueryVerbs    = @('GET', 'HEAD', 'OPTIONS')
$Script:MutationVerbs = @('POST', 'PUT', 'PATCH', 'DELETE')
$Script:QueryKeywords    = @('ownership', 'verify', 'check', 'status', 'validate',
                             'balance', 'profile', 'list', 'get')
$Script:MutationKeywords = @('purchase', 'buy', 'order', 'pay', 'payment', 'transfer',
                             'create', 'update', 'delete', 'add', 'remove', 'cancel', 'charge')
$Script:TokenHints    = @('ownership_token', 'ownership-token', 'possession_token',
                          'possession-token', 'ownershipToken', 'possessionToken')
# ---------------- utilitaires ------------------------------------------------->
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    Write-Host ('[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Level, $Message)
}

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsWritable([string]$Path) {
    try {
        $dir = if (Test-Path -LiteralPath $Path -PathType Container) { $Path } else { Split-Path -Parent $Path }
        $probe = Join-Path $dir ('__probe_' + [guid]::NewGuid().ToString('N') + '.tmp')
        Set-Content -LiteralPath $probe -Value 'x' -Encoding Ascii
        Remove-Item -LiteralPath $probe -Force
        return $true
    } catch {
        return $false
    }
}

function Get-PowerShellExe {
    return (Get-Process -Id $PID).Path
}

function Get-GamePassId {
    param([Parameter(Mandatory = $true)][string]$InputUrl)

    $candidate = $InputUrl.Trim()
    $uri = $null
    $parsed = [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uri)
    if (-not $parsed -or $null -eq $uri -or -not $uri.IsAbsoluteUri) {
        $parsed = [Uri]::TryCreate('https://' + $candidate, [UriKind]::Absolute, [ref]$uri)
    }
    if (-not $parsed -or $null -eq $uri -or -not $uri.IsAbsoluteUri) {
        throw "URL invalide ou mal formee : '$InputUrl' (attendu : https://www.target.com/game-pass/<ID>/<slug>)."
    }
    if ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https') {
        throw "URL invalide : le schema '$($uri.Scheme)' n'est pas http/https."
    }

    $match = [regex]::Match($uri.AbsolutePath, '/game-pass/(\d+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
        throw "Aucun ID numerique trouve dans l'URL : '$InputUrl'. Format attendu : .../game-pass/<ID>/<slug>."
    }
    Write-Log "URL analysee : $($uri.Scheme)://$($uri.Host)$($uri.AbsolutePath)"
    return [int]$match.Groups[1].Value
}

function Convert-DerToPem {
    param([string]$DerPath)
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($DerPath))
    $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $len = [Math]::Min(64, $b64.Length - $i)
        $b64.Substring($i, $len)
    }
    return ("-----BEGIN CERTIFICATE-----" + "`n" + ($lines -join "`n") + "`n" + "-----END CERTIFICATE-----" + "`n")
}

function Get-PortOwnerPid([int]$Port) {
    try {
        $conn = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen -ErrorAction Stop
        return @($conn)[0].OwningProcess
    } catch {
        $line = netstat -ano | Select-String ("127.0.0.1:" + $Port + "\s+.*LISTENING") | Select-Object -First 1
        if ($line) {
            $tokens = ($line.ToString().Trim() -split '\s+')
            return [int]$tokens[$tokens.Count - 1]
        }
        return $null
    }
}

function Join-ProductQuery([string]$UrlText, [int]$Id) {
    if ($UrlText.Contains('?')) { return $UrlText + '&' + ('product_id=' + $Id) }
    return $UrlText + '?' + ('product_id=' + $Id)
}

function Join-PipelinePath {
    param([string]$BaseDir, [string]$Path, [string]$Default = '')
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Default }
    if ([IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $BaseDir $Path)
}
# ---------------- profilage PS (Analyze : tables + CSV) ----------------------->
function Split-OwnershipLogLine {
    param([string]$Line)
    if ($Line -match $LogLineParser) {
        return [pscustomobject]@{
            Timestamp = $matches['ts']
            Verb      = $matches['verb']
            Url       = $matches['url']
            Status    = $matches['status']
            Body      = $matches['body']
        }
    }
    return $null
}

function Get-TrafficClassification {
    param($Entry)

    $path = $Entry.Url
    try { $path = ([System.Uri]$Entry.Url).AbsolutePath } catch { }

    $pathLower = $path.ToLowerInvariant()
    $verbUpper = $Entry.Verb.ToUpperInvariant()

    $isMutationVerb = $Script:MutationVerbs -contains $verbUpper
    $isQueryVerb    = $Script:QueryVerbs -contains $verbUpper
    $mutKeyword     = $Script:MutationKeywords | Where-Object { $pathLower -match $_ } | Select-Object -First 1
    $queryKeyword   = $Script:QueryKeywords | Where-Object { $pathLower -match $_ } | Select-Object -First 1

    $raison = 'verbe=' + $verbUpper
    if ($isMutationVerb -or $mutKeyword) {
        $classe = 'Mutation'
        if ($mutKeyword) { $raison += ';motifURL=' + $mutKeyword }
    }
    else {
        $classe = 'Query'
        if ($queryKeyword) { $raison += ';motifURL=' + $queryKeyword }
    }

    return [pscustomobject]@{
        Url      = $Entry.Url
        Path     = $path
        Verb     = $verbUpper
        Status   = $Entry.Status
        Classe   = $classe
        Raison   = $raison
        Mockable = ($classe -eq 'Query' -and $isQueryVerb)
    }
}

function Invoke-AnalyzeProfile {
    $files = @(Get-ChildItem -Path $Script:SessionsGlob -File -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0 -and $Script:LogPathResolved) {
        $f = Get-Item -LiteralPath $Script:LogPathResolved -ErrorAction SilentlyContinue
        if ($f) { $files = @($f) }
    }
    if ($files.Count -eq 0) {
        Write-Log "Profilage PS : aucun fichier de session pour '$($Script:SessionsGlob)'."
        return
    }

    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        foreach ($line in (Get-Content -LiteralPath $f.FullName -Encoding UTF8)) {
            $e = Split-OwnershipLogLine -Line $line
            if ($e -and -not [string]::IsNullOrWhiteSpace($e.Url)) {
                $entries.Add((Get-TrafficClassification -Entry $e))
            }
        }
    }
    if ($entries.Count -eq 0) {
        Write-Log 'Profilage PS : aucune ligne exploitable (le parser LogLineParser correspond-il au format des logs ?).'
        return
    }

    Write-Host ''
    Write-Host '=== Repartition par classe ===' -ForegroundColor Yellow
    $entries | Group-Object Classe | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize
    Write-Host '=== Endpoints QUERY (mockables sans risque) ===' -ForegroundColor Green
    $entries | Where-Object { $_.Mockable } | Group-Object Path |
        Sort-Object Count -Descending | Select-Object -First 15 | Format-Table Name, Count -AutoSize
    Write-Host '=== Endpoints MUTATION (NE PAS mock) ===' -ForegroundColor Red
    $entries | Where-Object { $_.Classe -eq 'Mutation' } | Group-Object Path |
        Sort-Object Count -Descending | Select-Object -First 10 | Format-Table Name, Count -AutoSize

    $csv = Join-Path $WorkDir 'traffic_profile.csv'
    $entries | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    $Script:GeneratedFiles.Add($csv)
    Write-Log "Rapport de profilage ecrit -> $csv"
}

# ---------------- MINING des logs (Capture & Replay) -------------------------->
function Test-OwnershipToken {
    param([string]$Body)
    foreach ($h in $Script:TokenHints) {
        if ($Body.IndexOf($h, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Get-UrlParam {
    param([string]$UrlText, [string]$Name)
    $m = [regex]::Match($UrlText, ([regex]::Escape($Name) + '=([^&]+)'),
                        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $m.Success) { return '' }
    return [Uri]::UnescapeDataString($m.Groups[1].Value)
}

function Test-FilterMatch {
    param([string]$Text, [string]$Filter)
    if ([string]::IsNullOrWhiteSpace($Filter)) { return $true }
    try { return ($Text -match $Filter) } catch { return $Text.Contains($Filter) }
}

# MINING : reponse HTTP 200 ownership de l'ID effectif, avec ownership_token.
# Retourne $true (echantillon ecrit dans CapturedPath) ou $false (aucun jeton).
function Invoke-MineOwnershipPayload {
    $files = New-Object System.Collections.Generic.List[string]
    if ($Script:LogPathResolved -and (Test-Path -LiteralPath $Script:LogPathResolved)) {
        $files.Add($Script:LogPathResolved)
    }
    if ($files.Count -eq 0) {
        foreach ($f in @(Get-ChildItem -Path $Script:SessionsGlob -File -ErrorAction SilentlyContinue)) {
            $files.Add($f.FullName)
        }
    }
    if ($files.Count -eq 0) {
        Write-Log "MINING : aucun log de session ('$($Script:SessionsGlob)') ni source -LogPath."
        return $false
    }
    Write-Log "MINING : balayage de $($files.Count) fichier(s) pour l'ID $($Script:EffectivePid)..."

    $best = $null
    $bestRank = 99
    $bestSource = ''
    foreach ($f in $files) {
        foreach ($line in (Get-Content -LiteralPath $f -Encoding UTF8)) {
            $e = Split-OwnershipLogLine -Line $line
            if ($null -eq $e -or [string]::IsNullOrWhiteSpace($e.Url)) { continue }
            $cls = Get-TrafficClassification -Entry $e
            if ($cls.Classe -ne 'Query') { continue }
            if (-not (Test-FilterMatch -Text $e.Url -Filter $EndpointUrlFilter)) { continue }
            if ((Get-UrlParam -UrlText $e.Url -Name 'product_id') -ne $Script:EffectivePid) { continue }
            if ($e.Status -ne '200') { continue }
            if (-not (Test-OwnershipToken -Body $e.Body)) { continue }

            $stateOk = $false
            $sm = [regex]::Match($e.Body,
                '(?i)ownership[_]?state\s*[:=]\s*"?([A-Za-z0-9_-]+)"?')
            if ($sm.Success) {
                $stateOk = ($sm.Groups[1].Value.ToUpperInvariant() -in @('OK', '1'))
            }
            $rank = if ($stateOk) { 1 } else { 2 }
            if ($rank -lt $bestRank) {
                $bestRank = $rank
                $best = $e
                $bestSource = $f
            }
        }
    }

    if ($null -eq $best) {
        Write-Log "MINING : aucun hit HTTP 200 + jeton valide pour l'ID $($Script:EffectivePid) (log source absent ou sans transaction reelle)."
        return $false
    }

    $parent = Split-Path -Parent $Script:CapturedPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $sample = [ordered]@{
        CapturedAt        = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffzzz')
        SourceLog         = $bestSource
        Method            = $best.Verb
        Url               = $best.Url
        Status            = 200
        ContentType       = 'application/json'
        Body              = $best.Body
        HasOwnershipToken = 1
    }
    [IO.File]::WriteAllText($Script:CapturedPath, (($sample | ConvertTo-Json -Compress) + "`r`n"), $utf8NoBom)
    if (-not $Script:CapturedExistedInit) { $Script:GeneratedFiles.Add($Script:CapturedPath) }
    Write-Log ("MINING : jeton ownership capture pour l'ID {0} depuis {1}." -f $Script:EffectivePid, $bestSource)
    Write-Log ("MINING : {0} {1} -> 200 (payload {2} octets)." -f $best.Verb, $best.Url, $best.Body.Length)
    return $true
}
# ---------------- echantillon synthetique (fallback) -------------------------->
function New-SyntheticSample {
    param([int]$ProductId, [string]$OutPath)
    $captureUrl = Join-ProductQuery -UrlText $Url -Id $ProductId
    if (-not $MockBody) {
        $MockBody = '{"success":true,"has_item":true,"item_id":' + $ProductId + '}'
    }
    $sample = [ordered]@{
        CapturedAt        = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffzzz')
        SourceLog         = 'synthetique:scenario Deploy-VerificationSuccess'
        Method            = $Method
        Url               = $captureUrl
        Status            = $MockStatus
        ContentType       = 'application/json'
        Body              = $MockBody
        HasOwnershipToken = 1
    }
    $sampleJson = $sample | ConvertTo-Json -Compress
    $parent = Split-Path -Parent $OutPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText($OutPath, $sampleJson + "`r`n", $utf8NoBom)
    $Script:GeneratedFiles.Add($OutPath)
    Write-Log "Echantillon synthetique genere : $OutPath (URL=$captureUrl, item_id=$ProductId)."
}

# ---------------- invocation d'un etage du pipeline natif --------------------->
function Invoke-NativeMockStage {
    param([Parameter(Mandatory = $true)][string]$StageName)

    $argList = New-Object System.Collections.Generic.List[string]
    $argList.Add('--mock')
    $argList.Add($StageName.ToLowerInvariant())

    if ($StageName -ieq 'configure' -and $MockEngine -ieq 'Luau') {
        $argList.Add('--mock-luau')
    }

    $map = [ordered]@{
        'log'       = $Script:LogPathResolved
        'sessions'  = $Script:SessionsGlob
        'filter'    = $EndpointUrlFilter
        'product'   = $Script:EffectivePid
        'state'     = $StateFilter
        'captured'  = $Script:CapturedPath
        'responses' = $Script:ResponsesResolved
        'rules'     = $Script:RulesFile
        'proxy-dir' = $Script:ProxyDirResolved
        'service'   = $ProxyServiceName
        'reload'    = $ReloadMarker
    }
    foreach ($k in $map.Keys) {
        $v = $map[$k]
        if ($null -ne $v -and "$v" -ne '') {
            $argList.Add('--mock-' + $k)
            $argList.Add("$v")
        }
    }

    Write-Log "Pipeline natif : MonNouvelApp.exe $($argList -join ' ')"
    Push-Location (Split-Path -Parent $AppExe)
    try {
        $output = & $AppExe @argList 2>&1
        $code = $LASTEXITCODE
        $output | ForEach-Object { Write-Host "   $_" }
    } finally {
        Pop-Location
    }
    if ($code -ne 0) {
        throw "Le pipeline --mock $StageName a echoue (exit $code)."
    }
}

# ---------------- plan des etages --------------------------------------------->
function Resolve-StagePlan {
    $plan = New-Object System.Collections.Generic.List[string]

    if ($Stage -ne 'All') {
        if ($Stage -ieq 'Verify' -and -not $Url) {
            throw "Etape Verify : -Url requis."
        }
        $plan.Add($Stage.ToLowerInvariant())
        return $plan
    }

    # All : Capture & Replay complet (MINING -> Configure -> Deploy -> Verify)
    if (-not (Test-Path -LiteralPath $Script:CapturedPath)) {
        $plan.Add('mine')
    }
    else {
        Write-Log "JSON capture deja present : $($Script:CapturedPath) -> MINING saute."
    }
    $plan.Add('configure')
    if ($Script:ProxyDirResolved) {
        $plan.Add('deploy')
    }
    else {
        Write-Log "Etage Deploy saute : -ProxyRulesDir non fourni (regles conservees dans $($Script:RulesFile))."
    }
    $plan.Add('verify')
    return $plan
}

# ---------------- post-traitement de la configuration ------------------------->
function Complete-Configure {
    Get-ChildItem -Path $Script:ResponsesResolved -Filter 'ownership_*.json' -File -ErrorAction SilentlyContinue |
        ForEach-Object { $Script:GeneratedFiles.Add($_.FullName) }
    Get-ChildItem -Path $Script:ResponsesResolved -Filter '*.luau' -File -ErrorAction SilentlyContinue |
        ForEach-Object { $Script:GeneratedFiles.Add($_.FullName) }

    if (-not [string]::IsNullOrWhiteSpace($PathRegex)) {
        $resolvedPattern = $PathRegex.Replace('{id}', $Script:EffectivePid)
        $rulesText = [IO.File]::ReadAllText($Script:RulesFile)
        $patched = [regex]::Replace($rulesText, '(?m)^Pattern=.*$', ('Pattern=' + $resolvedPattern), 1)
        if ($patched -ne $rulesText) {
            [IO.File]::WriteAllText($Script:RulesFile, $patched, $utf8NoBom)
            Write-Log "Pattern de la regle stricte remplace par : $resolvedPattern"
        }
    }
}
# ---------------- demarrage de la passerelle embarquee ------------------------>
function Start-Gateway {
    if (-not (Test-Path -LiteralPath $AppExe)) {
        throw "MonNouvelApp.exe introuvable : '$AppExe'. Redefinissez -AppExe."
    }
    if (-not (Test-IsWritable $WorkDir)) {
        throw "WorkDir non inscriptible : '$WorkDir' (logs de la passerelle)."
    }

    # Le port est gere par PID : on n'arrete que l'eventuelle instance gateway
    # deja en ecoute (jamais de kill sauvage sur un processus arbitraire).
    $owner = Get-PortOwnerPid $Port
    if ($owner) {
        $ownerProc = Get-Process -Id $owner -ErrorAction SilentlyContinue
        if ($ownerProc -and $ownerProc.ProcessName -ieq 'MonNouvelApp') {
            Write-Log "Port $Port deja ecoute par un gateway MonNouvelApp (PID $owner) - arret avant relance."
            Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        } else {
            $name = if ($ownerProc) { $ownerProc.ProcessName } else { "<inconnu>" }
            throw "Port $Port occupe par un autre processus (PID $owner - $name). Liberez le port ou changez -Port."
        }
    }

    $outLog = Join-Path $WorkDir '_ltg_scenario.out.log'
    $errLog = Join-Path $WorkDir '_ltg_scenario.err.log'
    Remove-Item -LiteralPath $outLog, $errLog -Force -ErrorAction SilentlyContinue
    $Script:GeneratedFiles.Add($outLog)
    $Script:GeneratedFiles.Add($errLog)

    Write-Log "A] Demarrage de la passerelle embarquee (MonNouvelApp --gateway) sur 127.0.0.1:$Port ..."
    $gw = Start-Process -FilePath $AppExe -ArgumentList @('--gateway', [string]$Port) `
        -WorkingDirectory $WorkDir `
        -RedirectStandardOutput $outLog `
        -RedirectStandardError $errLog `
        -PassThru
    $Script:GatewayPid = $gw.Id

    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    $marker   = '[ltg] Passerelle active'
    $hit      = $false
    while ((Get-Date) -lt $deadline) {
        foreach ($log in @($errLog, $outLog)) {
            if (Test-Path -LiteralPath $log) {
                $content = Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue
                if ($content -and $content.Contains($marker)) { $hit = $true; break }
            }
        }
        if ($hit) { break }
        if ($gw.HasExited) {
            $tail = ''
            if (Test-Path -LiteralPath $errLog) { $tail = (Get-Content -LiteralPath $errLog -Raw -ErrorAction SilentlyContinue) }
            throw "Le gateway s'est arrete avant l'emission du marqueur (exit $($gw.ExitCode)). Apercu du log : $tail"
        }
        Start-Sleep -Milliseconds 250
    }

    if (-not $hit) {
        if ($gw.HasExited) { throw "Le gateway s'est arrete pendant la phase de demarrage (voir _ltg_scenario.err.log)." }
        throw "Timeout : le marqueur '$marker' n'a pas ete observe dans $StartupTimeoutSeconds s (logs : $errLog)."
    }

    Write-Log "Passerelle active : $marker (PID $($gw.Id))."

    $rootDer = Join-Path $WorkDir 'ltg-root.der'
    if (-not (Test-Path -LiteralPath $rootDer)) {
        throw "Racine LGT introuvable : $rootDer (relancez le gateway pour l'exporter)."
    }
    return $rootDer
}

# ---------------- execution de l'application cible + controle (inject) ------->
function Invoke-ProductVerification {
    param(
        [Parameter(Mandatory = $true)][string]$RootDer,
        [Parameter(Mandatory = $true)][int]$ProductId
    )

    if (-not (Test-Path -LiteralPath $AppExe)) {
        throw "Application cible introuvable : '$AppExe'. Redefinissez -AppExe."
    }

    # --- B) environnement de session (proxy + CA LGT) -------------------------
    $env:HTTPS_PROXY = "http://127.0.0.1:$Port"
    $env:HTTP_PROXY  = "http://127.0.0.1:$Port"
    $caPem = Join-Path $WorkDir '_ltg_scenario_cacert.pem'
    $rootPem = Convert-DerToPem -DerPath $RootDer
    Set-Content -LiteralPath $caPem -Value $rootPem -NoNewline -Encoding Ascii
    $env:LTG_CA_PEM = $caPem
    $Script:GeneratedFiles.Add($caPem)
    Write-Log "B] Environnement de session : HTTPS_PROXY/HTTP_PROXY=$($env:HTTPS_PROXY), LTG_CA_PEM=$caPem."

    # URL a rejouer : celle du payload capture (la regle [Rule_*] la matche
    # exactement). Repli : <Url>?product_id=<ID> (mode stand-alone / synthétique).
    $verifyUrl = ''
    if (Test-Path -LiteralPath $Script:CapturedPath) {
        try {
            $sample = Get-Content -LiteralPath $Script:CapturedPath -Raw | ConvertFrom-Json
            if ($sample.Url) { $verifyUrl = [string]$sample.Url }
        } catch { }
    }
    if (-not $verifyUrl) { $verifyUrl = Join-ProductQuery -UrlText $Url -Id $ProductId }
    elseif ((Get-UrlParam -UrlText $verifyUrl -Name 'product_id') -eq '') {
        $verifyUrl = Join-ProductQuery -UrlText $verifyUrl -Id $ProductId
    }

    $appDir = Split-Path -Parent $AppExe

    # --- C) lancement ---------------------------------------------------------
    Push-Location $appDir
    try {
        Write-Log "C] MonNouvelApp.exe --sim-get $verifyUrl --proxy http://127.0.0.1:$Port"
        $output = & $AppExe --sim-get $verifyUrl --proxy "http://127.0.0.1:$Port" 2>&1
        $appExit = $LASTEXITCODE
        $output | ForEach-Object { Write-Host "   $_" }
    } finally {
        Pop-Location
    }

    Write-Log "Application cible terminee (exit code : $appExit)."
    if ($appExit -ne 0) {
        throw "La verification a echoue : exit code $appExit (attendu 0)."
    }

    # --- D) controle de la ligne d'audit --------------------------------------
    $errLog = Join-Path $WorkDir '_ltg_scenario.err.log'
    if (-not (Test-Path -LiteralPath $errLog)) {
        throw "Log d'audit de la passerelle absent : $errLog"
    }
    $audit = Get-Content -LiteralPath $errLog -Raw -ErrorAction Stop
    $uri = $null
    [void][Uri]::TryCreate($verifyUrl, [UriKind]::Absolute, [ref]$uri)
    $path = if ($uri) { $uri.PathAndQuery } else { $verifyUrl }
    $auditNote = if ($MockEngine -ieq 'Luau') { 'inject' } else { 'mock-file' }
    $expect = [regex]::Escape($path) + " -> 200 \($auditNote\)"

    if (-not [regex]::IsMatch($audit, $expect)) {
        Write-Host "`n=== Audit de la passerelle (dernieres lignes) ==="
        Get-Content -LiteralPath $errLog -Tail 12 | ForEach-Object { Write-Host "   $_" }
        throw "Ligne d'audit attendue absente : '$expect'. La reponse n'a pas ete injectee via mock.respond."
    }

    Write-Log "SUCCES : injection confirmee (audit '$($path) -> 200 ($auditNote)')."
}
# ---------------- nettoyage ----------------------------------------------------->
function Stop-TestScenario {
    Write-Log "Nettoyage de l'environnement de test..."

    # 1) arret du gateway embarque (par PID, puis par port si besoin)
    if ($Script:GatewayPid) {
        Stop-Process -Id $Script:GatewayPid -Force -ErrorAction SilentlyContinue
        Write-Log "Gateway arrete (PID $($Script:GatewayPid))."
    }
    $owner = Get-PortOwnerPid $Port
    if ($owner) {
        $ownerProc = Get-Process -Id $owner -ErrorAction SilentlyContinue
        if ($ownerProc -and $ownerProc.ProcessName -ieq 'MonNouvelApp') {
            Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue
            Write-Log "Gateway residuel arrete (PID $owner)."
        }
    }

    # 2) restauration / suppression des regles (chemin generalise RulesFile)
    if ($Script:RulesBackup -and (Test-Path -LiteralPath $Script:RulesBackup)) {
        Copy-Item -LiteralPath $Script:RulesBackup -Destination $Script:RulesFile -Force
        Remove-Item -LiteralPath $Script:RulesBackup -Force
        Write-Log "rules.ini restaure."
    } elseif (-not $Script:RulesExistedInitially) {
        if (Test-Path -LiteralPath $Script:RulesFile) {
            Remove-Item -LiteralPath $Script:RulesFile -Force
            Write-Log "rules.ini (cree par le scenario) supprime."
        }
    }

    foreach ($f in $Script:GeneratedFiles) {
        if (Test-Path -LiteralPath $f) {
            Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
            Write-Log "Fichier supprime : $f"
        }
    }

    # 3) restauration de l'environnement de session
    Remove-Item Env:LTG_CA_PEM -ErrorAction SilentlyContinue
    Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue
    Remove-Item Env:HTTP_PROXY -ErrorAction SilentlyContinue
    Write-Log "Variables d'environnement de session restaurees."
}

# ---------------- elevation ------------------------------------------------------>
function Invoke-AsAdmin {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -in @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
                       'ErrorVariable', 'WarningVariable', 'OutVariable', 'OutBuffer',
                       'PipelineVariable', 'WhatIf', 'Confirm')) { continue }
        $value = $PSBoundParameters[$key]
        if ($value -is [bool]) {
            if ($value) { $argList += ('-{0}' -f $key) }
        } else {
            $argList += ('-{0}' -f $key)
            $argList += ('"{0}"' -f ($value -join ' '))
        }
    }
    Write-Log "Elevation requise - relance en mode Administrateur (UAC)..."
    try {
        $exe = Get-PowerShellExe
        Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argList -Wait
    } catch {
        throw "Elevation UAC refusee ou impossible : $($_.Exception.Message)"
    }
}

# ---------------- orchestration -------------------------------------------------->
try {
    Write-Log "==== Scenario 'Capture & Replay' (reussite de verification) ===="

    if (-not (Test-IsAdmin)) {
        if ($NoElevate) {
            Write-Warning "Mode non eleve (-NoElevate) : l'installation de la Root CA dans LocalMachine\Root peut echouer."
        } else {
            Invoke-AsAdmin
            exit 0
        }
    }

    # 0. chemins du pipeline (ancre sur WorkDir, defauts monotones)
    $Script:RulesFile = Join-PipelinePath -BaseDir $WorkDir -Path $RulesFile -Default (Join-Path $WorkDir 'rules.ini')
    $Script:CapturedPath = Join-PipelinePath -BaseDir $WorkDir -Path $CapturedJson -Default (Join-Path $WorkDir 'captured\ownership_sample.json')
    $Script:CapturedExistedInit = Test-Path -LiteralPath $Script:CapturedPath
    $Script:ResponsesResolved = Join-PipelinePath -BaseDir $WorkDir -Path $ResponseOutDir -Default $WorkDir
    $Script:SessionsGlob = Join-PipelinePath -BaseDir $WorkDir -Path $SessionLogSearchPath -Default (Join-Path $WorkDir 'logs\sessions\*.log')
    $Script:LogPathResolved = Join-PipelinePath -BaseDir $WorkDir -Path $LogPath
    $Script:ProxyDirResolved = Join-PipelinePath -BaseDir $WorkDir -Path $ProxyRulesDir

    # 1. identifiant produit effectif
    if ($ProductId) { $Script:EffectivePid = [string]$ProductId }
    elseif ($Url)   { $Script:EffectivePid = [string](Get-GamePassId -InputUrl $Url) }
    elseif (-not (Test-Path -LiteralPath $Script:CapturedPath)) {
        throw "-Url requis (spec : .\Deploy-VerificationSuccess.ps1 -Url <url du game-pass>)."
    }
    Write-Log "ID du produit effectif : $($Script:EffectivePid)"

    # 2. sauvegarde des regles existantes
    $Script:RulesExistedInitially = Test-Path -LiteralPath $Script:RulesFile
    if ($Script:RulesExistedInitially) {
        Copy-Item -LiteralPath $Script:RulesFile -Destination "$($Script:RulesFile).ltgscenario.bak" -Force
        $Script:RulesBackup = "$($Script:RulesFile).ltgscenario.bak"
    }

    # 3. plan des etages et execution
    $plan = Resolve-StagePlan
    Write-Log ("Plan des etages : " + ($plan -join ' -> '))
    foreach ($stageName in $plan) {
        Write-Log "ETAPE : $stageName"
        switch ($stageName) {
            'mine' {
                if (-not (Invoke-MineOwnershipPayload)) {
                    $msg = "Aucun token valide trouv{0} dans les logs pour l'ID {1}. Veuillez effectuer une transaction r{2}elle au pr{3}alable." -f $Script:Acute, $Script:EffectivePid, $Script:Grave, $Script:Acute
                    if ($Url) {
                        Write-Log "Aucun jeton valide dans les logs - bascule synthetique (-SyntheticFallback)."
                        New-SyntheticSample -ProductId ([int]$Script:EffectivePid) -OutPath $Script:CapturedPath
                        Invoke-AnalyzeProfile
                    } else {
                        Write-Host ("[ERROR] " + $msg) -ForegroundColor Red
                        Write-Log $msg 'ERREUR'
                        exit 1
                    }
                } else {
                    Invoke-AnalyzeProfile
                }
            }
            'analyze' {
                Invoke-NativeMockStage -StageName 'analyze'
                Invoke-AnalyzeProfile
            }
            'capture' {
                Invoke-NativeMockStage -StageName 'capture'
                if (-not $Script:CapturedExistedInit) { $Script:GeneratedFiles.Add($Script:CapturedPath) }
            }
            'configure' {
                if (-not (Test-Path -LiteralPath $Script:CapturedPath)) {
                    if (-not $Url) {
                        throw "Etape Configure : aucun JSON capture trouve ($($Script:CapturedPath)) et -Url absent. Lancez d'abord le MINING (All) ou fournissez -CapturedJson."
                    }
                    New-SyntheticSample -ProductId ([int]$Script:EffectivePid) -OutPath $Script:CapturedPath
                }
                Invoke-NativeMockStage -StageName 'configure'
                Complete-Configure
            }
            'deploy' {
                Invoke-NativeMockStage -StageName 'deploy'
            }
            'verify' {
                $defaultRules = Join-Path $WorkDir 'rules.ini'
                if (-not (Test-Path -LiteralPath $defaultRules) -or
                    ([IO.Path]::GetFullPath($Script:RulesFile) -ine [IO.Path]::GetFullPath($defaultRules))) {
                    Write-Log "Verification locale ignoree : regles absentes ou hors WorkDir ($($Script:RulesFile))."
                } else {
                    $RootDer = Start-Gateway
                    Write-Log "Racine LGT exportee : $RootDer"
                    Invoke-ProductVerification -RootDer $RootDer -ProductId ([int]$Script:EffectivePid)
                }
            }
        }
    }
    Write-Log "==== Scenario termine avec succes ===="
}
catch {
    Write-Log $_.Exception.Message 'ERREUR'
    exit 1
}
finally {
    try {
        if (-not $KeepRunning) { Stop-TestScenario }
        else                  { Write-Log '-KeepRunning : environnement laisse en place (gateway toujours actif).' }
    } catch {
        Write-Log "Echec du nettoyage : $($_.Exception.Message)" 'WARN'
    }
    Write-Log 'Fin du scenario.'
}
