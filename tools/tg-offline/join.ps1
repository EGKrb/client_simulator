param(
    [Parameter(Mandatory = $true)][string]$PlaceId,
    [string]$UniverseId,
    [string]$Cookie,
    [string]$VersionExe,
    [switch]$ResetCookie,
    [string]$DumpProtocol
)

Add-Type -AssemblyName System.Security
$Dir = Join-Path $env:APPDATA 'rxb-offline'
$Store = Join-Path $Dir 'session.bin'
$Ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
$Curl = 'curl.exe'

function Get-UnixMillis { [long]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) }

function Set-SessionCookie {
    param([string]$Value)
    if (-not $Value) { $Value = Read-Host "Colle .ROBLOSECURITY (sans guillemets)" }
    if (-not $Value) { Write-Error 'cookie vide'; exit 1 }
    $H = @{ Cookie = ".ROBLOSECURITY=$Value" }
    try {
        $Me = Invoke-RestMethod -Uri 'https://users.target.com/v1/users/authenticated' -Headers $H
    } catch {
        Write-Error "cookie invalide : $($_.Exception.Message)"
        exit 1
    }
    if (-not $Me.id) { Write-Error 'reponse auth inattendue'; exit 1 }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    [IO.File]::WriteAllBytes($Store, [System.Security.Cryptography.ProtectedData]::Protect(
        [Text.Encoding]::UTF8.GetBytes($Value), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
    Write-Host "Session enregistree (DPAPI, utilisateur $env:USERNAME). Compte : $($Me.displayName) (id $($Me.id))."
}

function Get-SessionCookie {
    if (-not (Test-Path -LiteralPath $Store)) { Write-Error 'Aucune session. Fournis -Cookie ou exporte-la d abord.'; exit 1 }
    return [Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect(
        [IO.File]::ReadAllBytes($Store), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
}

if ($ResetCookie) {
    if (Test-Path -LiteralPath $Store) { Remove-Item -LiteralPath $Store -Force }
    Write-Host 'Session effacee.'
    exit 0
}
if ($Cookie) { Set-SessionCookie $Cookie; exit 0 }

$Auth = Get-SessionCookie
$CookieHdr = ".ROBLOSECURITY=$Auth"

if (-not $UniverseId) {
    $Json = & $Curl -s -H "Cookie: $CookieHdr" -H "User-Agent: $Ua" "https://apis.target.com/universes/v1/places/$PlaceId/universe"
    try {
        $UniverseId = [string]((($Json | ConvertFrom-Json) | Select-Object -ExpandProperty universeId))
        Write-Host "place $PlaceId -> universe $UniverseId"
    } catch {
        Write-Error "Resol du universe echouee : $Json. Passe -UniverseId"
        exit 1
    }
}

# 1) client-status (fire-and-forget, comme le site)
& $Curl -s -o NUL -X POST -H "Cookie: $CookieHdr" -H "User-Agent: $Ua" -H "Content-Type: application/json" -H "Accept: application/json" --data '{"status":"Unknown"}' "https://apis.target.com/matchmaking-api/v1/client-status" 2>$null

# 2) client-assertion (curl, pas Invoke qui est rejete 401)
$Assertion = $null
try {
    $Assertion = ((& $Curl -s -H "Cookie: $CookieHdr" -H "User-Agent: $Ua" -H "Accept: application/json" "https://auth.target.com/v1/client-assertion/") | ConvertFrom-Json).clientAssertion
} catch { }
if (-not $Assertion) { Write-Error 'clientAssertion introuvable'; exit 1 }

# 3) authentication-ticket -> tg-authentication-ticket (+ boucle CSRF)
$Ticket = $null
$Csrf = ''
for ($i = 0; $i -lt 3 -and -not $Ticket; $i++) {
    $Hdr = "$env:TEMP\opencode\psj_$PID.txt"
    if (-not (Test-Path $env:TEMP\opencode)) { New-Item -ItemType Directory -Force -Path $env:TEMP\opencode | Out-Null }
    $Body = '{';
    [IO.File]::WriteAllText($Hdr, '')
    [IO.File]::WriteAllText("$env:TEMP\opencode\psjbody_$PID.json", "{`"clientAssertion`":`"$Assertion`"}")
    $CArgs = @('-s','-D',$Hdr,'-o',"$env:TEMP\opencode\psjbody_$PID.txt", '-X','POST',
        '-H',"Cookie: $CookieHdr", '-H',"User-Agent: $Ua", '-H','Accept: application/json',
        '-H','Content-Type: application/json', '-H','Origin: https://www.target.com',
        '-H',"Referer: https://www.target.com/games/$PlaceId/",
        '-H','Sec-Fetch-Site: same-site', '-H','Sec-Fetch-Mode: cors', '-H','Sec-Fetch-Dest: empty')
    if ($Csrf) { $CArgs += @('-H',"X-CSRF-TOKEN: $Csrf") }
    $CArgs += @('--data-binary',"@$env:TEMP\opencode\psjbody_$PID.json", "https://auth.target.com/v1/authentication-ticket/")
    & $Curl @CArgs 2>$null
    $Hd = Get-Content -Raw -LiteralPath $Hdr -ErrorAction SilentlyContinue
    if (-not $Hd) { Write-Error 'reponse ticket vide'; exit 1 }
    $FirstLine = ($Hd -split "`r?`n")[0]
    if ($FirstLine -match '200') {
        $Ticket = (($Hd -split "`r?`n") | Where-Object { $_ -match '^tg-authentication-ticket: ' } | Select-Object -First 1) -replace '^tg-authentication-ticket: ',''
        $Ticket = $Ticket.Trim()
    } elseif ($FirstLine -match '403') {
        $Csrf = (($Hd -split "`r?`n") | Where-Object { $_ -match '^x-csrf-token: ' } | Select-Object -First 1) -replace '^x-csrf-token: ',''
        $Csrf = $Csrf.Trim()
        Write-Host "CSRF 403 -> relance"
    } else {
        Write-Error "ticket http: $FirstLine"; exit 1
    }
}
if (-not $Ticket) { Write-Error 'tg-authentication-ticket introuvable apres retries'; exit 1 }
Write-Host "ticket minted (len $($Ticket.Length))"

# BrowserTrackerId : le site lit un cookie navigateur; ici on en genere un stable par run
$BtId = (Get-Random -Minimum 1000000000000000 -Maximum 9999999999999999)
$JoinAttemptId = [guid]::NewGuid().ToString()
$PlaceLauncherUrl = "https://www.target.com/Game/PlaceLauncher.ashx?request=RequestGame" +
    "&browserTrackerId=$BtId&placeId=$PlaceId&isPlayTogetherGame=false&referredByPlayerId=0" +
    "&joinAttemptId=$JoinAttemptId&joinAttemptOrigin=PlayButton"

# Protocol officiel : gameinfo = ticket auth, placelauncherurl = URL RequestGame
$Proto = "target-player:1+launchmode:play+gameinfo:$Ticket" +
    "+launchtime:$(Get-UnixMillis)" +
    "+placelauncherurl:$([Uri]::EscapeDataString($PlaceLauncherUrl))" +
    "+browsertrackerid:$BtId+targetLocale:en_us+gameLocale:en_us+LaunchExp:InApp"

if (-not $VersionExe) {
    $Current = Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Target\Versions') -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'TargetPlayerBeta.exe') } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $Current) { Write-Error 'Aucun build Player installe.'; exit 1 }
    $VersionExe = Join-Path $Current.FullName 'TargetPlayerBeta.exe'
}
if (-not (Test-Path -LiteralPath $VersionExe)) { Write-Error "Build introuvable : $VersionExe"; exit 1 }

if ($DumpProtocol) {
    [IO.File]::WriteAllText($DumpProtocol, $Proto, [Text.Encoding]::UTF8)
    Write-Host "Protocol ecrit : $DumpProtocol"
    exit 0
}

$P = Start-Process -FilePath $VersionExe -ArgumentList ('"' + $Proto + '"') -PassThru
Write-Host "Lancement protocol officiel : $VersionExe"
Write-Host "place $PlaceId / uni $UniverseId -> PID $($P.Id)"
Write-Host 'Verif : logs %LOCALAPPDATA%\Target\logs\0.740*.last.log (attendu "Joining game ... at ..." puis Replicator).'
exit 0