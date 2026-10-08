<#
.SYNOPSIS
    Teste une a une TOUTES les commandes de MonNouvelApp.exe (client simulator).

.DESCRIPTION
    Harnais local, sans reseau externe :
      - serveur HTTP generique (tests\serve_sandbox.py) sur 127.0.0.1:8080 pour
        les commandes --sim-* (via --sandbox) ;
      - mock_target_api.py sur 8080 pour le flux d'achat web --buy-* ;
      - passerelle --gateway demarree/arretee par le harnais (PKI + regles + ecoute) ;
      - chaque commande s'exécute dans un WorkDir propre avec timeout + kill ;
      - les commandes "dangereuses" (driver physique BYOVD/SIV, manip kernel)
        sont SAUTEES par defaut (securite) : voir -ForceDangerous.

.EXAMPLE
    .\tests\test_commands.ps1
    .\tests\test_commands.ps1 -Only 'sim-get|mock-configure'
    .\tests\test_commands.ps1 -Report

.PARAMETER Exe
    Chemin de MonNouvelApp.exe a tester. Defaut : C:\client_simulator\bin\MonNouvelApp.exe.

.PARAMETER Root
    Racine de l'outil (fournit tests\, mock_target_api.py).

.PARAMETER Only
    Regex optionnelle pour ne lancer qu'un sous-ensemble de tests (par nom).

.PARAMETER CommandTimeoutSeconds
    Duree max par commande (s). Au-dela -> kill + echec.

.PARAMETER ForceDangerous
    Lance aussi les commandes touchant aux drivers (BYOVD/SIV). NON recommande,
    risque kernel reel. Par defaut desactive.

.PARAMETER KeepServers
    Laisse les serveurs python demarres (debug).

.PARAMETER Report
    Affiche la commande lancee + l'integralite de la sortie en cas d'echec.
#>
[CmdletBinding()]
param(
    [string]$Exe = 'C:\client_simulator\bin\MonNouvelApp.exe',
    [string]$Root = 'C:\client_simulator',
    [string]$Only = '',
    [int]$CommandTimeoutSeconds = 40,
    [switch]$ForceDangerous,
    [switch]$KeepServers,
    [switch]$Report
)

$ErrorActionPreference = 'Stop'
$TestRoot  = Join-Path $env:TEMP ('opencode\cmdtest-' + (Get-Random))
$MockApi   = Join-Path $Root 'mock_target_api.py'
$Generic   = Join-Path $Root 'tests\serve_sandbox.py'
$PythonExe = $null
$Servers   = @()

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$IsAdminSession = Test-IsAdmin

function Get-Python {
    if ($PythonExe) { return $PythonExe }
    $cand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $cand) { $cand = Get-Command py -ErrorAction SilentlyContinue }
    if (-not $cand) { throw 'python introuvable (requis pour les serveurs de sandbox).' }
    $script:PythonExe = $cand.Source
    return $script:PythonExe
}

function Wait-Port([int]$Port, [int]$TimeoutSec = 15) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', $Port)
            $c.Close()
            return $true
        } catch { Start-Sleep -Milliseconds 300 }
    }
    return $false
}

function Get-HttpCode([string]$Url) {
    try {
        $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 4
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return -1
    }
}

function Stop-Port8080 {
    $conns = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
    foreach ($x in $conns) {
        try { Stop-Process -Id $x.OwningProcess -Force -ErrorAction SilentlyContinue } catch {}
    }
    Start-Sleep -Milliseconds 300
}

function Start-TestServer([string]$Kind) {
    $py   = Get-Python
    $src  = if ($Kind -eq 'target') { $MockApi } else { $Generic }
    Stop-Port8080
    $p    = Start-Process -FilePath $py -ArgumentList @($src, '8080') -WindowStyle Hidden -PassThru
    if (-not (Wait-Port 8080 15)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; throw "Serveur '$Kind' sans reponse sur 8080." }
    if ($p.HasExited) { throw "Le serveur python '$Kind' s'est arrete au demarrage (port 8080 occupe ?)." }
    $code = Get-HttpCode 'http://127.0.0.1:8080/__probe'
    $expected = if ($Kind -eq 'target') { 404 } else { 200 }
    if ($code -ne $expected) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        throw "Le port 8080 repond code $code (attendu $expected) - mauvais serveur actif."
    }
    $script:Servers += $p
    Write-Host "[srv] $Kind ecoute sur 127.0.0.1:8080 (PID $($p.Id))"
}

function Stop-TestServers {
    foreach ($p in $Servers) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    $script:Servers = @()
    Start-Sleep -Milliseconds 300
}

function New-WorkDir([string]$Name) {
    $d = Join-Path $TestRoot ($Name -replace '[^A-Za-z0-9_-]', '-')
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    return $d
}

function Invoke-Tool {
    param([string[]]$ArgList, [string]$WorkDir, [int]$TimeoutSec)
    $outLog = Join-Path $WorkDir '_case.out.log'
    $errLog = Join-Path $WorkDir '_case.err.log'
    $argLine = ($ArgList | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join ' '
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $argLine
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $WorkDir
    $pr = New-Object System.Diagnostics.Process
    $pr.StartInfo = $psi
    try { $pr.Start() | Out-Null } catch { throw "StartProcess echoue (exe=$Exe args=[$argLine]) : $($_.Exception.Message)" }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $outTask = $pr.StandardOutput.ReadToEndAsync()
    $errTask = $pr.StandardError.ReadToEndAsync()
    while (-not $pr.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 120 }
    $killed = $false
    if (-not $pr.HasExited) { try { $pr.Kill() } catch {}; $killed = $true }
    $code = if ($killed) { -1 } elseif ($null -ne $pr.ExitCode) { [int]$pr.ExitCode } else { -1 }
    $out = $outTask.Result
    $err = $errTask.Result
    return [pscustomobject]@{ ExitCode = $code; Killed = $killed; Out = $out + $err }
}

# ------------------------------------------------------------ catalogue des tests
$cases = @()
function Add-Case {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Args,
        [int[]]$Expect = @(0),
        [string]$Match = '',
        [string]$NeedServer = 'none',
        [switch]$Danger,
        [scriptblock]$Setup = $null,
        [scriptblock]$Check = $null,
        [int]$Timeout = $CommandTimeoutSeconds,
        [switch]$SkipAdmin
    )
    $script:cases += [pscustomobject]@{
        Name = $Name; Args = $Args; Expect = $Expect; Match = $Match; NeedServer = $NeedServer
        Danger = $Danger; Setup = $Setup; Check = $Check; Timeout = $Timeout; SkipAdmin = $SkipAdmin
    }
}

$MoneyFix  = '2026-09-20T10:00:01.000Z|GET|https://api.example.com/v1/ownership/status?product_id=6738811|200|{"state":"OK","ownership_token":"tok-6738811","product_id":"6738811"}'
# --- groupe SIM : serveur generique 8080 + --sandbox --------------------------
Add-Case 'sim-get-200'  @('--sim-get', 'https://api.target.com/v1/users/authenticated', '--sandbox') -NeedServer generic -Match 'HTTP 200'
Add-Case 'sim-post-200' @('--sim-post', 'https://api.target.com/api/v1/commit', '{"x":1}', '--sandbox') -NeedServer generic -Match 'HTTP 200'
Add-Case 'sim-put-200'  @('--sim-put', 'https://api.target.com/api/v1/commit', '{"x":1}', '--sandbox') -NeedServer generic -Match 'HTTP 200'
Add-Case 'sim-del-200'  @('--sim-del', 'https://api.target.com/api/v1/items/42', '--sandbox') -NeedServer generic -Match 'HTTP 200'
Add-Case 'sim-purchase-200' @('--sim-purchase', 'https://shop.example.com', '--sandbox') -NeedServer generic -Match 'Statistiques'
Add-Case 'sim-get-sans-url'      @('--sim-get') -Expect @(1) -Match 'Usage'
Add-Case 'sim-post-sans-corps'   @('--sim-post', 'https://api.target.com/x', '--sandbox') -Expect @(1) -Match 'Corps JSON manquant'
Add-Case 'sim-get-proxy-refused' @('--sim-get', 'https://api.target.com/x', '--sandbox', '--proxy', 'http://127.0.0.1:1') -Expect @(0) -Match 'Could not connect'
Add-Case 'option-inconnue'      @('--je-suis-inconnu') -Expect @(1) -Match 'Option inconnue'
Add-Case 'proxy-sans-argument'  @('--proxy') -Expect @(1) -Match 'requiert une URL'

# --- pipeline mock ownership (sans serveur) -----------------------------------
$SetupCapture = { Invoke-Tool -ArgList @('--mock', 'capture', '--mock-log', '{FIXTURE}') -WorkDir $work -TimeoutSec 60 | Out-Null }
$SetupPipe    = {
    Invoke-Tool -ArgList @('--mock', 'capture', '--mock-log', '{FIXTURE}') -WorkDir $work -TimeoutSec 60 | Out-Null
    Invoke-Tool -ArgList @('--mock', 'configure', '--mock-log', '{FIXTURE}', '--mock-responses', '{WORK}', '--mock-rules', '{RULES}') -WorkDir $work -TimeoutSec 60 | Out-Null
}
Add-Case 'mock-analyse' @('--mock', 'analyze', '--mock-log', '{FIXTURE}') `
    -Check { Test-Path (Join-Path $work 'captured\ownership_source.txt') }
Add-Case 'mock-capture' @('--mock', 'capture', '--mock-log', '{FIXTURE}') `
    -Check { Test-Path (Join-Path $work 'captured\ownership_sample.json') }
Add-Case 'mock-configure' @('--mock', 'configure', '--mock-log', '{FIXTURE}',
        '--mock-responses', '{WORK}', '--mock-rules', '{RULES}') -Setup $SetupCapture `
    -Check { (Test-Path '{RULES}') -and (Select-String -Path '{RULES}' -Pattern 'ResponseFile=' -Quiet) }
Add-Case 'mock-configure-luau' @('--mock', 'configure', '--mock-log', '{FIXTURE}',
        '--mock-responses', '{WORK}', '--mock-rules', '{RULES}.luau.ini', '--mock-luau') -Setup $SetupCapture `
    -Check { (Test-Path '{RULES}.luau.ini') -and (Test-Path '{WORK}\mock_success.luau') -and
             (Select-String -Path '{RULES}.luau.ini' -Pattern 'Script=mock_success.luau' -Quiet) }
Add-Case 'mock-deploy-sans-proxy-dir' @('--mock', 'deploy', '--mock-log', '{FIXTURE}',
        '--mock-responses', '{WORK}', '--mock-rules', '{RULES}') -Setup $SetupPipe -Expect @(1) -Match 'dossier de regles cible'
Add-Case 'mock-deploy-ok' @('--mock', 'deploy', '--mock-log', '{FIXTURE}',
        '--mock-responses', '{WORK}', '--mock-rules', '{RULES}', '--mock-proxy-dir', '{PROXYDIR}') -Setup $SetupPipe `
    -Check { (Test-Path '{PROXYDIR}\rules.ini') -and (Test-Path '{PROXYDIR}\.reload') }
Add-Case 'mock-etage-manquant' @('--mock') -Expect @(1) -Match 'requiert un etage'
Add-Case 'mock-log-sans-valeur' @('--mock-log') -Expect @(1) -Match 'requiert un chemin'

# --- demos locales ------------------------------------------------------------
Add-Case 'demo'       @('--demo') -Timeout 60
Add-Case 'hook-demo'  @('--hook-demo') -Timeout 60
Add-Case 'iat-demo'   @('--iat-demo') -Timeout 60
Add-Case 'vmt-demo'   @('--vmt-demo') -Timeout 60

# --- famille VM Target / livraison : cible invalide -> echec rapide -----------
Add-Case 'luau-vm-cible-ininvisible'    @('--luau-vm', '999999') -Expect @(1)
Add-Case 'marketplace-cible-invisible'  @('--marketplace', '999999') -Expect @(1)
Add-Case 'gamepass-cible-invisible'     @('--gamepass', '999999') -Expect @(1)
Add-Case 'devproduct-cible-invisible'   @('--devproduct', '999999') -Expect @(1)
Add-Case 'detect-cible-invisible'       @('--detect', '999999') -Expect @(1)
Add-Case 'survivor-cible-invisible'     @('--survivor', '999999', '1') -Expect @(1)
Add-Case 'apc-cible-invisible'          @('--apc', '999999') -Expect @(1)
Add-Case 'hijack-cible-invisible'       @('--hijack', '999999') -Expect @(1)
Add-Case 'probe-thread-cible-invisible' @('--probe-thread', '999999') -Expect @(1)
Add-Case 'probe-hijack-cible-invisible' @('--probe-hijack', '999999') -Expect @(1)
Add-Case 'sig-update-cible-invisible'   @('--sig-update', '999999') -Expect @(1)
Add-Case 'autofix-cible-invisible'      @('--autofix', '999999') -Expect @(1)

# --- BYOVD / SIV : SAUTES par defaut (danger kernel) --------------------------
Add-Case 'byovd'        @('--byovd', '999999') -Expect @(0, 1, 2) -Match 'introuvable' -Danger
Add-Case 'hijack-byovd' @('--hijack-byovd', '999999') -Expect @(1) -Danger
Add-Case 'byovd-siv'    @('--byovd-siv') -Expect @(0, 1, 2) -Match '(Elevation UAC requise|SIVX64.sys introuvable|lecture|primitive)' -Danger
Add-Case 'siv-load'     @('--siv-load') -Expect @(0, 1) -Match '(Elevation UAC requise|introuvable|charge|demarre)' -Danger
Add-Case 'siv-read'     @('--siv-read', '100000', '16') -Expect @(0, 1, 2) -Danger
Add-Case 'siv-write'    @('--siv-write', '100000', 'AABB') -Expect @(0, 1, 2) -Match '(Elevation UAC requise|introuvable|ecriture)' -Danger
Add-Case 'siv-remove'   @('--siv-remove') -Expect @(0, 1) -Danger

# --- Snyper : fenetre inexistante -> refus propre ----------------------------
Add-Case 'snyper-record-fenetre-absente' @('--snyper-record', 'ZZZ_NoSuchWindow') -Expect @(1) -Match 'fenetre cible introuvable'
Add-Case 'snyper-play-fenetre-absente'   @('--snyper-play', 'ZZZ_NoSuchWindow') -Expect @(1)
Add-Case 'snyper-dryrun-fenetre-absente' @('--snyper-dryrun', 'ZZZ_NoSuchWindow') -Expect @(1)

# --- achat web : sandbox via mock_target_api.py -------------------------------
Add-Case 'buy-cookie-absent' @('--buy-gamepass', '6738811', '--sandbox') -Expect @(1) -Match 'cookie.txt'
Add-Case 'buy-gamepass-sans-id' @('--buy-gamepass') -Expect @(1) -Match 'Usage'
Add-Case 'buy-gamepass-ok'  @('--buy-gamepass', '6738811', '--sandbox') -NeedServer target -Match 'Achat REUSSI' `
    -Setup { [IO.File]::WriteAllText((Join-Path $work 'cookie.txt'), 'FAKE_ROBLOSECURITY_001') }
Add-Case 'buy-probe-ok'     @('--buy-probe', '6738811', '100', '1234567', '--sandbox') -NeedServer target `
    -Setup { [IO.File]::WriteAllText((Join-Path $work 'cookie.txt'), 'FAKE_ROBLOSECURITY_001') }

# --- AOB (mode par defaut) ----------------------------------------------------
Add-Case 'aob-pid-invalide'       @('0', '48 89 5C 24 ?? 50') -Expect @(1) -Match 'PID invalide'
Add-Case 'aob-cible-absente'      @('999999', '48 89 5C 24 ?? 50') -Expect @(1)
Add-Case 'aob-scan-propre-process' @('--read-only', '{SELF}', 'DE AD BE EF CA FE BA BE 0D F0 AD BA DE AD BE EF') -Expect @(2) -Match 'occurrence'
# Mode complet : non-eleve -> refus "Elevation UAC" (exit 1) ; eleve -> scan reel (exit 0 ou 2, "occurrence(s)")
$AobScanExpect = if ($IsAdminSession) { @(0, 2) } else { @(1) }
$AobScanMatch  = if ($IsAdminSession) { 'occurrence' } else { 'Elevation UAC' }
Add-Case 'aob-scan-session'       @('{SELF}', '48 89 5C 24 ?? 50') -Expect $AobScanExpect -Match $AobScanMatch

# --- trace de demarrage (--trace) ---------------------------------------------
Add-Case 'trace-sans-argument'  @('--trace') -Expect @(1) -Match 'Usage'
Add-Case 'trace-cible-absente'  @('--trace', 'ZZZ_Trace_NoSuch.exe') -Expect @(1) -Match 'introuvable'
Add-Case 'trace-cmd-exit'       @('--trace', 'cmd.exe', '/c', 'exit', '--trace-timeout', '2') `
    -Match 'reprise du processus' -Timeout 60
Add-Case 'trace-cmd-ipconfig'   @('--trace', 'cmd.exe', '/c', 'ipconfig', '--trace-timeout', '3') `
    -Match '(reprise du processus|PEB|DLL chargee)' -Timeout 60
Add-Case 'trace-attach-sans-pid'     @('--trace-attach') -Expect @(1) -Match 'requiert un PID'
Add-Case 'trace-attach-pid-invalide' @('--trace-attach', 'zz') -Expect @(1) -Match 'PID invalide'
Add-Case 'trace-attach-cible'        @('--trace-attach', '{SELF}', '--trace-timeout', '2') `
    -Match 'trace-attach|PEB' -Timeout 60

# --- NightShift integre (--ns/--ns-batch) -------------------------------------
Add-Case 'ns-version'        @('--ns', 'version') -Match 'NightShift v'
Add-Case 'ns-chaine-2'       @('--ns', 'version; aliases') -Match 'NightShift v'
Add-Case 'ns-chaine-terminate' @('--ns', 'version; terminate') -Match 'Session terminated'
Add-Case 'ns-load-peinfo'    @('--ns', 'load C:\Windows\System32\kernel32.dll; peinfo; sections; symbols GetSystemT; unload') -Match 'PE Header' -Timeout 60
Add-Case 'ns-mapload-peinfo' @('--ns', 'mapload C:\Windows\System32\kernel32.dll; peinfo') -Match 'DLL mapped' -Timeout 60
Add-Case 'ns-load-absente'   @('--ns', 'load C:\nope_nope.dll') -Expect @(1) -Match 'Cannot load DLL'
Add-Case 'ns-sans-chaine'    @('--ns') -Expect @(1) -Match 'requiert une chaine'
Add-Case 'ns-batch-ok'       @('--ns-batch', '{WORK}\ns_batch_test.bat') -Match 'Batch complete: 0 error' `
    -Setup { [IO.File]::WriteAllLines((Join-Path $work 'ns_batch_test.bat'), @('# test', 'CMD: version', 'CMD: aliases', 'WAIT: 10')) }
Add-Case 'ns-batch-absent'   @('--ns-batch', 'C:\z_z_z_absent.bat') -Expect @(1) -Match 'Cannot open batch file'

# ------------------------------------------------------------------ fixtures
$FixtureBase = New-WorkDir 'fixture'
$FixtureLog  = "$FixtureBase\apps.ltg.log"
$MoneyFix    = '2026-09-20T10:00:01.000Z|GET|https://api.example.com/v1/ownership/status?product_id=6738811|200|{"state":"OK","ownership_token":"tok-6738811","product_id":"6738811"}'
[IO.File]::WriteAllLines($FixtureLog, @($MoneyFix, '2026-09-20T10:00:02.000Z|POST|https://api.example.com/v1/purchase|201|{}'))

# --------------------------------------------------------------- substitutions
$script:work  = $null
function Resolve-Ph([string]$s, [string]$work, [string]$rulesPath) {
    $t = $s.Replace('{FIXTURE}', $FixtureLog)
    $t = $t.Replace('{WORK}', $work)
    $t = $t.Replace('{RULES}', $rulesPath)
    $t = $t.Replace('{PROXYDIR}', (Join-Path $work 'proxydir'))
    $t = $t.Replace('{SELF}', [string]$PID)
    return $t
}

# ------------------------------------------------------------------ boucle
$results   = @()
$serverState = 'none'
try {
    foreach ($case in $cases) {
        if ($Only -and $case.Name -notmatch $Only) { continue }
        if ($case.Danger -and -not $ForceDangerous) {
            $results += [pscustomobject]@{ Test = $case.Name; Status = 'SKIP'; Detail = 'commande driver/noyau - activez -ForceDangerous' }
            continue
        }
        if ($case.SkipAdmin -and $IsAdminSession) {
            $results += [pscustomobject]@{ Test = $case.Name; Status = 'SKIP'; Detail = 'chemin dependant d''une session non elevee' }
            continue
        }

        if ($case.NeedServer -ne $serverState) {
            if ($serverState -ne 'none') { Stop-TestServers }
            if ($case.NeedServer -ne 'none') { Start-TestServer $case.NeedServer }
            $serverState = $case.NeedServer
            Start-Sleep -Milliseconds 250
        }

        $script:work = New-WorkDir $case.Name
        $work        = $script:work
        $rulesPath   = Join-Path $work 'rules.ini'
        $proxydir    = Join-Path $work 'proxydir'
        New-Item -ItemType Directory -Path $proxydir -Force | Out-Null

        if ($case.Setup) {
            $sb = [scriptblock]::Create((Resolve-Ph $case.Setup.ToString() $work $rulesPath))
            & $sb
        }

        $realArgs = @($case.Args | ForEach-Object { Resolve-Ph $_ $work $rulesPath })
        if ($Report) { Write-Host ("[run] " + ($realArgs -join ' ')) }

        $tsk = Invoke-Tool -ArgList $realArgs -WorkDir $work -TimeoutSec $case.Timeout

        $ok = (-not $tsk.Killed) -and ($case.Expect -contains $tsk.ExitCode)
        $detail = 'exit=' + $tsk.ExitCode
        if ($tsk.Killed) { $detail = 'TIMEOUT (>' + $case.Timeout + 's) -> kill' }
        if ($ok -and $case.Match -ne '' -and $tsk.Out -notmatch $case.Match) {
            $ok = $false; $detail += " (attendu /$($case.Match)/ absent)"
        }
        if ($ok -and $case.Check) {
            $sb = [scriptblock]::Create((Resolve-Ph $case.Check.ToString() $work $rulesPath))
            if (-not (& $sb)) { $ok = $false; $detail += ' (post-condition echec)' }
        }
        if (-not $ok -and $Report) {
            Write-Host "----- sortie de $($case.Name) -----"
            Write-Host $tsk.Out
        }
        $results += [pscustomobject]@{ Test = $case.Name; Status = if ($ok) { 'PASS' } else { 'FAIL' }; Detail = $detail }
    }

    if ($serverState -ne 'none') { Stop-TestServers; $serverState = 'none' }

    # ------------------------------------------------------------------ gateway
    if (-not $Only -or 'gateway' -match $Only) {
        $gwWork = New-WorkDir 'gateway'
        $gwRules = @'
; test_commands.ps1 -- seed gateway
[Rule_Ownership_Pid_6738811]
Enabled=1
Priority=200
Method=*
Pattern=^https?://api\.example\.com/v1/ownership/status\??([^?&]*&)*product_id=6738811(?![0-9A-Za-z_\-])(&.*)?$
Script=mock_success.luau
StatusCode=200
ContentType=application/json
'@
        $gwLuau  = @'
mock.respond(200, {
  ["content-type"] = "application/json",
}, "{\"state\":\"OK\",\"ownership_token\":\"tok-gw\",\"product_id\":\"6738811\"}")
'@
        [IO.File]::WriteAllText((Join-Path $gwWork 'rules.ini'), $gwRules.Replace("`r`n", "`n"))
        [IO.File]::WriteAllText((Join-Path $gwWork 'mock_success.luau'), $gwLuau)

        $gwOut = Join-Path $gwWork '_ltg.out.log'
        $gwErr = Join-Path $gwWork '_ltg.err.log'
        $gwP   = Start-Process -FilePath $Exe -ArgumentList @('--gateway', '7096') -WorkingDirectory $gwWork `
                 -RedirectStandardOutput $gwOut -RedirectStandardError $gwErr -PassThru
        $deadline = (Get-Date).AddSeconds(30)
        $marker = $false
        while ((Get-Date) -lt $deadline -and -not $marker) {
            Start-Sleep -Milliseconds 300
            if (Test-Path $gwErr) { $m = Get-Content -LiteralPath $gwErr -Raw -ErrorAction SilentlyContinue } else { $m = '' }
            if ($m -and $m.Contains('[ltg] Passerelle active')) { $marker = $true }
        }
        $der  = Test-Path (Join-Path $gwWork 'ltg-root.der')
        if (-not $KeepServers) { Stop-Process -Id $gwP.Id -Force -ErrorAction SilentlyContinue }
        $results += [pscustomobject]@{
            Test = 'gateway-demarrage'
            Status = if ($marker -and $der) { 'PASS' } else { 'FAIL' }
            Detail = if ($marker) { 'marqueur observe, ltg-root.der present' } else { 'marqueur de demarrage absent' }
        }
    }
} finally {
    if (-not $KeepServers) { Stop-TestServers }
}

# ------------------------------------------------------------------ synthese
Write-Host ''
Write-Host '=== RESULTATS ==='
$W = [Math]::Max(30, (($results | ForEach-Object { $_.Test.Length }) | Measure-Object -Maximum).Maximum)
$fmt = '{0,-' + $W + '}  {1,-5}  {2}'
Write-Host ($fmt -f 'TEST', 'STAT', 'DETAIL')
Write-Host ('-' * 120)
foreach ($r in $results) {
    $color = switch ($r.Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'Yellow' } default { 'Gray' } }
    Write-Host ($fmt -f $r.Test, $r.Status, $r.Detail) -ForegroundColor $color
}
$nFail = @($results | Where-Object Status -eq 'FAIL').Count
$nSkip = @($results | Where-Object Status -eq 'SKIP').Count
$nPass = @($results | Where-Object Status -eq 'PASS').Count
Write-Host ''
Write-Host "PASS=$nPass  FAIL=$nFail  SKIP=$nSkip  TOTAL=$($results.Count)"
if (-not $KeepServers) { Write-Host "Repertoire de tests : $TestRoot" }
$global:LASTEXITCODE = $nFail
exit $nFail