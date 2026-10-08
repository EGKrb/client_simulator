<#
.SYNOPSIS
Automatise la configuration d'un environnement de test qui mock l'endpoint de
vérification d'état de possession (Query) en injectant une réponse JSON
pré-enregistrée via le moteur de règles du proxy MITM in-house ("rules.ini").

.DESCRIPTION
Pipeline en 4 étages pensé pour un cycle de tests sans simulation de transaction
(JWT impossible à reproduire) :
  - Analyze   : profilage des logs de session pour distinguer Mutations vs Queries.
  - Capture   : extrait une réponse valide (ownership_token) depuis un log de session.
  - Configure : génère rules.ini (regex précises, isolation produit) + payload sérialisé.
  - Deploy    : injecte la configuration dans le dossier du proxy et déclenche le rechargement.

Compatibilité : Windows PowerShell 5.1+ et PowerShell Core. Syntaxe volontairement
rétrocompatible (pas d'opérateur ternaire, pas de ??, pas de -AsHashtable).

.PARAMETER Stage
Étage à exécuter : Analyze | Capture | Configure | Deploy | All (défaut = All).

.PARAMETER LogPath
Chemin du log de session exploité par Capture.

.PARAMETER SessionLogSearchPath
Glob (chemin relatif ou absolu) des logs de session pour l'analyse. Défaut : .\logs\sessions\*.log

.PARAMETER EndpointUrlFilter
Sous-chaîne/regex de filtrage de l'URL (chemin de query), ex. "ownership". Défaut : ownership

.PARAMETER ProductId
Identifiant produit à isoler. Si fourni, seul product_id=<id> exact est mocké
(garde anti-préfixe : 1337 ne matche pas 13370).

.PARAMETER StateFilter
Texte optionnel attendu dans le corps (ex. "owned") pour verrouiller l'état à simuler.

.PARAMETER CapturedJson
Chemin de sortie du payload capturé. Défaut : .\captured\ownership_sample.json

.PARAMETER ResponseOutDir
Dossier de sortie des payloads sérialisés (copiés à plat chez le proxy). Défaut : .\responses

.PARAMETER RulesFile
Chemin de sortie du fichier rules.ini. Défaut : .\rules.ini

.PARAMETER ProxyRulesDir
Dossier de règles surveillé par le proxy (cible du déploiement).

.PARAMETER ProxyServiceName
Nom du service Windows du proxy à redémarrer (optionnel).

.PARAMETER ReloadMarker
Nom du marqueur de rechargement surveillé par le proxy. Défaut : .reload

.PARAMETER LogLineParser
Regex de parsing d'une ligne de log (groupes nommés ts/verb/url/status/body).
Défaut : format pipe, ex. "2026-...|GET|https://...|200|{...}"

.EXAMPLE
# Analyse d'une session complète (aucun effet de bord)
.\Generate-OwnershipMock.ps1 -Stage Analyze -SessionLogSearchPath ".\tests\sessions\*.log"

.EXAMPLE
# Cycle complet ciblé sur le produit 1337 avec déploiement
.\Generate-OwnershipMock.ps1 -Stage All -LogPath ".\tests\sessions\session-e2e.log" `
    -EndpointUrlFilter "ownership" -ProductId 1337 -StateFilter "owned" `
    -ProxyRulesDir "D:\Proxy\rules" -ProxyServiceName "MitmProxySvc"

.EXAMPLE
# Étages séparés pour CI/CD
.\Generate-OwnershipMock.ps1 -Stage Capture   -LogPath ".\s.json.log" -EndpointUrlFilter "ownership" -CapturedJson ".\out\cap.json"
.\Generate-OwnershipMock.ps1 -Stage Configure -CapturedJson ".\out\cap.json" -ProductId 1337 -RulesFile ".\out\rules.ini"
.\Generate-OwnershipMock.ps1 -Stage Deploy    -RulesFile ".\out\rules.ini" -ProxyRulesDir "\\buildagent\Proxy\rules"
#>
[CmdletBinding()]
param(
    [ValidateSet('Analyze', 'Capture', 'Configure', 'Deploy', 'All')]
    [string]$Stage = 'All',

    [string]$LogPath,
    [string]$SessionLogSearchPath = '.\logs\sessions\*.log',
    [string]$EndpointUrlFilter = 'ownership',
    [string]$ProductId,
    [string]$StateFilter,
    [string]$CapturedJson = '.\captured\ownership_sample.json',
    [string]$ResponseOutDir = '.\responses',
    [string]$RulesFile = '.\rules.ini',
    [string]$ProxyRulesDir,
    [string]$ProxyServiceName,
    [string]$ReloadMarker = '.reload',
    [string]$LogLineParser = '^(?<ts>[^|]+)\|(?<verb>[A-Z]+)\|(?<url>\S+)\|(?<status>\d{3})\|(?<body>.*)$',
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- Constantes
$OWNERSHIP_MARKER = 'ownership_token'

$QUERY_KEYWORDS = @(
    'ownership', 'verify', 'check', 'status', 'validate',
    'balance', 'profile', 'list', 'get'
)
$MUTATION_KEYWORDS = @(
    'purchase', 'buy', 'order', 'pay', 'payment', 'transfer',
    'create', 'update', 'delete', 'add', 'remove', 'cancel', 'charge'
)
$HTTP_QUERY_VERBS   = @('GET', 'HEAD', 'OPTIONS')
$HTTP_MUTATION_VERBS = @('POST', 'PUT', 'PATCH', 'DELETE')

# ---------------------------------------------------------------- Helpers
function Write-Step {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Msg" -ForegroundColor Cyan
}

function Set-Utf8NoBom {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function Resolve-PathOrThrow {
    param([string]$Path, [string]$Desc)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Introuvable ($Desc) : $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Ensure-ParentDir {
    param([string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

function Split-LogLine {
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

    $isMutationVerb = $HTTP_MUTATION_VERBS -contains $verbUpper
    $isQueryVerb    = $HTTP_QUERY_VERBS -contains $verbUpper
    $mutKeyword     = $MUTATION_KEYWORDS | Where-Object { $pathLower -match $_ } | Select-Object -First 1
    $queryKeyword   = $QUERY_KEYWORDS | Where-Object { $pathLower -match $_ } | Select-Object -First 1

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

# ---------------------------------------------------------------- Stage 1 : Analyze
function Invoke-AnalyzeStage {
    Write-Step "Profilage du trafic sur : $SessionLogSearchPath"
    $files = Get-ChildItem -Path $SessionLogSearchPath -File -ErrorAction SilentlyContinue
    if (-not $files) { throw "Aucun log trouvé pour '$SessionLogSearchPath'." }

    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        foreach ($line in (Get-Content -LiteralPath $f.FullName -Encoding UTF8)) {
            $entry = Split-LogLine -Line $line
            if ($entry -and -not [string]::IsNullOrWhiteSpace($entry.Url)) {
                $entries.Add((Get-TrafficClassification -Entry $entry))
            }
        }
    }
    if ($entries.Count -eq 0) { throw 'Aucune ligne de log exploitable (parser a-t-il le bon format ?).' }

    Write-Host ''
    Write-Host '=== Répartition par classe ===' -ForegroundColor Yellow
    $entries | Group-Object Classe | Sort-Object Count -Descending |
        Format-Table Name, Count -AutoSize

    Write-Host '=== Endpoints QUERY (mockables sans risque) ===' -ForegroundColor Green
    $entries | Where-Object { $_.Mockable } | Group-Object Path |
        Sort-Object Count -Descending | Select-Object -First 15 |
        Format-Table Name, Count -AutoSize

    Write-Host '=== Endpoints MUTATION (NE PAS mock) ===' -ForegroundColor Red
    $entries | Where-Object { $_.Classe -eq 'Mutation' } | Group-Object Path |
        Sort-Object Count -Descending | Select-Object -First 10 |
        Format-Table Name, Count -AutoSize

    $csvPath = Join-Path (Split-Path -Parent $SessionLogSearchPath) 'traffic_profile.csv'
    Ensure-ParentDir -Path $csvPath
    $entries | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Step "Rapport de profilage écrit -> $csvPath"
}

# ---------------------------------------------------------------- Stage 2 : Capture
function Invoke-CaptureStage {
    if (-not $LogPath) { throw 'Paramètre -LogPath requis pour l''étage Capture.' }
    $log = Resolve-PathOrThrow -Path $LogPath -Desc 'log de session'

    Write-Step "Capture depuis : $log (filtre URL='$EndpointUrlFilter', product='$ProductId')"
    $hits = @()
    foreach ($line in (Get-Content -LiteralPath $log -Encoding UTF8)) {
        $entry = Split-LogLine -Line $line
        if (-not $entry) { continue }
        if ($HTTP_QUERY_VERBS -notcontains $entry.Verb.ToUpperInvariant()) { continue }
        if ($entry.Url -notmatch $EndpointUrlFilter) { continue }

        if ($ProductId) {
            $pidEsc = $ProductId
            if ($entry.Url -notmatch "product_id=$pidEsc(&|\?|$)|product_id=$pidEsc%") { continue }
        }

        $hasOwnershipToken = ($entry.Body -match $OWNERSHIP_MARKER)
        $stateOk = (-not $StateFilter) -or ($entry.Body -match $StateFilter)
        $hits += [pscustomobject]@{
            Entry      = $entry
            Ownership  = $hasOwnershipToken
            StateOk    = $stateOk
        }
    }
    if ($hits.Count -eq 0) {
        throw "Aucune réponse Query ne correspond au filtre '$EndpointUrlFilter' (produit '$ProductId')."
    }

    $candidates = @($hits | Where-Object { $_.Ownership -and $_.StateOk -and $_.Entry.Status -eq '200' })
    if ($candidates.Count -eq 0) { $candidates = @($hits | Where-Object { $_.Ownership -and $_.StateOk }) }
    if ($candidates.Count -eq 0) { $candidates = @($hits | Where-Object { $_.Ownership }) }
    if ($candidates.Count -eq 0) { $candidates = @($hits) }

    $best = $candidates[0]
    Write-Host "Payload sélectionné -> $($best.Entry.Verb) $($best.Entry.Status) $($best.Entry.Url)"
    if ($best.Ownership) { Write-Host "  - contient '$OWNERSHIP_MARKER': OUI" }
    if ($StateFilter)    { Write-Host "  - état '$StateFilter': $($best.StateOk)" }

    Ensure-ParentDir -Path $CapturedJson
    $sample = [pscustomobject]@{
        CapturedAt         = (Get-Date).ToString('O')
        SourceLog          = $log
        Method             = $best.Entry.Verb
        Url                = $best.Entry.Url
        Status             = $best.Entry.Status
        ContentType        = 'application/json'
        Body               = $best.Entry.Body
        HasOwnershipToken  = $best.Ownership
    }
    Set-Utf8NoBom -Path $CapturedJson -Content ($sample | ConvertTo-Json -Depth 6)
    Write-Step "Capture OK -> $CapturedJson"
}

# ---------------------------------------------------------------- Stage 3 : Configure
function Get-UrlPatterns {
    param($CapturedUrl, [string]$ProductId)

    $authority = [regex]::Escape($CapturedUrl.Authority)
    $pathEsc   = [regex]::Escape($CapturedUrl.AbsolutePath)
    # Préfixe de query tolérant : product_id en première position OU après d'autres
    # paramètres, quel que soit leur nombre ($idPosition = 'product_id=' littéral).
    $queryPre  = '\??([^?&]*&)*'
    $idToken   = 'product_id='
    $tailGd    = '(?![0-9A-Za-z_\-])(&.*)?$'

    $patterns = @()
    if ($ProductId) {
        $pidEsc = [regex]::Escape($ProductId)
        # A. Strict : ID isolé, garde anti-préfixe (1337 != 13370), séparateur ?/& toléré
        $patterns += @{
            Enabled   = 1
            Pattern   = '^https?://' + $authority + $pathEsc + $queryPre + $idToken + $pidEsc + $tailGd
            Response  = $null
            Label     = 'strict-' + $ProductId
        }
        # B. Capture de l'ID en groupe nommé (même payload, filet élargi)
        $patterns += @{
            Enabled   = 0
            Pattern   = '^https?://' + $authority + $pathEsc + $queryPre + $idToken + '(?<ProductId>[0-9A-Za-z_\-]+)(&.*)?$'
            Response  = $null
            Label     = 'anyproduct'
        }
    }
    else {
        $patterns += @{
            Enabled   = 1
            Pattern   = '^https?://' + $authority + $pathEsc + $queryPre + $idToken + '(?<ProductId>[0-9A-Za-z_\-]+)(&.*)?$'
            Response  = $null
            Label     = 'anyproduct'
        }
    }
    # C. Filet de sécurité : le même endpoint sans paramètre, désactivé par défaut
    $patterns += @{
        Enabled   = 0
        Pattern   = '^https?://' + $authority + $pathEsc + '(\?.*)?$'
        Response  = $null
        Label     = 'fallback'
    }
    return $patterns
}

function Invoke-ConfigureStage {
    $capPath = Resolve-PathOrThrow -Path $CapturedJson -Desc 'JSON capturé'
    $cap = Get-Content -LiteralPath $capPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $cap.Body) { throw 'Le JSON capturé ne contient pas de champ Body.' }
    if (-not $cap.Url)  { throw 'Le JSON capturé ne contient pas de champ Url.' }

    $urlObj = $null
    if (-not ([System.Uri]::TryCreate($cap.Url, [System.UriKind]::Absolute, [ref]$urlObj))) {
        throw "URL capturée invalide : $($cap.Url)"
    }

    if (-not (Test-Path -LiteralPath $ResponseOutDir)) {
        New-Item -ItemType Directory -Path $ResponseOutDir -Force | Out-Null
    }

    $suffix  = if ($ProductId) { 'pid_' + $ProductId } else { 'any' }
    $respName = 'ownership_' + $suffix + '.json'
    $respFull = Join-Path $ResponseOutDir $respName
    Set-Utf8NoBom -Path $respFull -Content $cap.Body
    Write-Step "Payload sérialisé -> $respFull"

    $patterns = Get-UrlPatterns -CapturedUrl $urlObj -ProductId $ProductId

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('; ==================================================')
    $out.Add('; rules.ini — généré par Generate-OwnershipMock.ps1')
    $out.Add('; URL cible   : ' + $cap.Url)
    $out.Add('; Capturé le  : ' + $cap.CapturedAt)
    $out.Add('; Contrat de format : voir PLAN_ACTION_TECHNIQUE.md §4')
    $out.Add('; ==================================================')

    $prio = 200
    $built = New-Object System.Collections.Generic.List[string]
    foreach ($p in $patterns) {
        $currentPrio = $prio
        $ruleName = 'Rule_' + $p.Label + '_' + ($currentPrio.ToString('000'))
        $out.Add('')
        $out.Add('[' + $ruleName + ']')
        $out.Add('Enabled=' + $p.Enabled)
        $out.Add('Priority=' + $currentPrio)
        $out.Add('Method=' + $cap.Method)
        $out.Add('Pattern=' + $p.Pattern)
        $out.Add('ResponseFile=' + $respName)
        $out.Add('StatusCode=' + $cap.Status)
        $out.Add('ContentType=' + $cap.ContentType)
        $built.Add(('  [{0}] Priority={1} Enabled={2} : {3}' -f $p.Label, $currentPrio, $p.Enabled, $p.Pattern))
        $prio -= 1
    }

    Ensure-ParentDir -Path $RulesFile
    Set-Utf8NoBom -Path $RulesFile -Content ($out -join [Environment]::NewLine)
    Write-Step "Règles générées -> $RulesFile"
    foreach ($b in $built) {
        Write-Host $b
    }
}

# ---------------------------------------------------------------- Stage 4 : Deploy
function Invoke-DeployStage {
    if (-not $ProxyRulesDir) { throw 'Paramètre -ProxyRulesDir requis pour l''étage Deploy.' }
    if (-not (Test-Path -LiteralPath $ProxyRulesDir)) {
        throw "Dossier de règles du proxy introuvable : $ProxyRulesDir"
    }
    $rulesPath = Resolve-PathOrThrow -Path $RulesFile -Desc 'rules.ini'

    Write-Step "Déploiement dans : $ProxyRulesDir"
    Copy-Item -LiteralPath $rulesPath -Destination $ProxyRulesDir -Force

    if (Test-Path -LiteralPath $ResponseOutDir) {
        Copy-Item -Path (Join-Path $ResponseOutDir '*') -Destination $ProxyRulesDir -Force
    }

    $marker = Join-Path $ProxyRulesDir $ReloadMarker
    Set-Utf8NoBom -Path $marker -Content (Get-Date).ToString('O')
    Write-Step "Marqueur '$ReloadMarker' émis -> rechargement du proxy"

    if ($ProxyServiceName) {
        $svc = Get-Service -Name $ProxyServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Restart-Service -Name $ProxyServiceName -Force
            Write-Step "Service proxy redémarré : $ProxyServiceName"
        }
        else {
            Write-Warning "Service '$ProxyServiceName' introuvable — rechargement différé via marqueur."
        }
    }

    $deployed = Join-Path $ProxyRulesDir (Split-Path -Leaf $rulesPath)
    if (Test-Path -LiteralPath $deployed) {
        Write-Step "Validation OK -> $deployed"
    }
    else {
        Write-Warning 'Validation : le fichier rules.ini n''est pas visible dans le dossier proxy.'
    }
}

# ---------------------------------------------------------------- Orchestrateur
$stages = if ($Stage -eq 'All') { @('Analyze', 'Capture', 'Configure', 'Deploy') } else { @($Stage) }

foreach ($s in $stages) {
    Write-Step "ÉTAPE : $s"
    switch ($s) {
        'Analyze'   { Invoke-AnalyzeStage }
        'Capture'   { Invoke-CaptureStage }
        'Configure' { Invoke-ConfigureStage }
        'Deploy'    { Invoke-DeployStage }
    }
}

Write-Step 'Terminé.'