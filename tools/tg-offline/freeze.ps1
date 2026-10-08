param([switch]$Remove, [switch]$NeutraliseLauncher = $false)

$Versions = Join-Path $env:LOCALAPPDATA 'Target\Versions'
$Launcher = Join-Path $env:LOCALAPPDATA 'Target\TargetPlayerLauncher.exe'
$LauncherBak = "$Launcher.offline-bak"

function Test-Elevated {
    return (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $Remove) {
    if (-not (Test-Path -LiteralPath $Versions)) {
        Write-Error "Dossier Versions introuvable : $Versions"
        exit 1
    }
    & icacls $Versions '/deny' '*S-1-1-0:(DC,DE)' | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Error 'Echec du /deny sur Versions'; exit 1 }
    if ($NeutraliseLauncher) {
        if (Test-Path -LiteralPath $Launcher) { Move-Item -LiteralPath $Launcher -Destination $LauncherBak -Force }
    }
    Write-Host 'Freeze applique : aucune nouvelle version ne peut etre creee ni supprimee.'
    if (Test-Elevated) {
        $Hosts = Join-Path $env:windir 'System32\drivers\etc\hosts'
        $Lines = @(Get-Content -LiteralPath $Hosts)
        $Added = @()
        foreach ($h in 'clientsettingscdn.target.com','clientsettings.target.com') {
            if ($Lines -notmatch ('[0-9\.:]+\s+' + [regex]::Escape($h))) { $Added += "0.0.0.0 $h" }
        }
        if ($Added.Count) { Add-Content -LiteralPath $Hosts -Value $Added; Write-Host 'hosts: version-check domaines bloques.' }
    }
    exit 0
}

if (-not (Test-Path -LiteralPath $Versions)) { Write-Error "Dossier Versions introuvable : $Versions"; exit 1 }
& icacls $Versions /remove:d *S-1-1-0 | Out-Null
if (Test-Path -LiteralPath $LauncherBak) { Move-Item -LiteralPath $LauncherBak -Destination $Launcher -Force }
Write-Host 'Freeze retire : ACL restauree, launcher restaure.'
exit 0