<#
.SYNOPSIS
    Benchmarks de performance - mesurer l'impact d'un agent de securite (antivirus/EDR)
    sur les operations de base d'une charge de travail de test.

.DESCRIPTION
    Outil de diagnostic purement observationnel. Il ne modifie aucune donnee :
    il mesure uniquement des delais (timing) via Stopwatch haute resolution et WMI
    pour documenter l'overhead induit par les agents de securite installes.

    Metriques mesurees :
      1. Resource Access Latency    - I/O fichiers, I/O memoire (scan AOB), handles processus
      2. Syscall Overhead Analysis  - NtWriteVirtualMemory, NtProtectVirtualMemory,
                                      NtQuerySystemInformation, NtQueryInformationProcess,
                                      OpenProcess / ReadProcessMemory (lecture seule)
      3. Performance Impact Report  - coefficient de latence + operations les plus couteuses

.PARAMETER TargetProcess
    Processus cible utilise pour le benchmark des handles processus.
    Accepte un nom de processus (avec ou sans ".exe") ou un chemin complet vers l'exécutable.
    Si absent ou introuvable, le processus courant est utilise.

.PARAMETER Iterations
    Nombre de mesures par operation (par defaut 15). Minimum 3.

.PARAMETER OutputDir
    Repertoire de sortie du rapport. Par defaut : <script>\Reports

.PARAMETER NoBaseline
    Ne pas devier le coefficient par rapport a NtQuerySystemInformation (baseline la moins couteuse).

.EXAMPLE
    .\SecurityImpactBenchmark.ps1 --TargetProcess "MonNouvelApp.exe"

.EXAMPLE
    .\SecurityImpactBenchmark.ps1 -TargetProcess "notepad.exe" -Iterations 30 -OutputDir "C:\Bench"
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [string]$TargetProcess = "",

    [Parameter(Mandatory = $false)]
    [ValidateRange(3, 200)]
    [int]$Iterations = 15,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$NoBaseline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. Detection des agents de securite presents (lecture seule, via WMI)
# ---------------------------------------------------------------------------
function Get-SecurityAgents {
    $agents = @()
    try {
        $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct'
        foreach ($p in $av) {
            $state = if ($p.productState -ge 4096) { 'actif' } else { 'inactif' }
            $agents += "$($p.displayName) [etat: $state]"
        }
    }
    catch {
        Write-Verbose "WMI SecurityCenter2 indisponible : $($_.Exception.Message)"
    }

    $known = @('MsMpEng','savservice','McAfee','ekrn','bdagent','ccsvchst','edr','NortonSecurity')
    $running = @()
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            foreach ($n in $known) {
                if ($p.Name -like "*$n*") { $running += $p.Name; break }
            }
        }
    }
    catch { }

    return [pscustomobject]@{
        WmiAgents = ($agents -join ', ')
        EnrichRun = (($running | Sort-Object -Unique) -join ', ')
    }
}

# ---------------------------------------------------------------------------
# 2. Interop natif - signatures P/Invoke minimales (aucun appel ne modifie de donnee)
# ---------------------------------------------------------------------------
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NativeBench
{
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int SystemInformationClass,
        IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr ProcessHandle,
        int ProcessInformationClass, IntPtr ProcessInformation,
        int ProcessInformationLength, out int ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtProtectVirtualMemory(IntPtr ProcessHandle,
        ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

    [DllImport("ntdll.dll")]
    public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle,
        IntPtr BaseAddress, byte[] Buffer, int BufferSize, out int BytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint DesiredAccess, bool InheritHandle, uint ProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr Handle);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr ProcessHandle, IntPtr BaseAddress,
        byte[] Buffer, int Size, out int BytesRead);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr Address, IntPtr Size,
        uint AllocationType, uint Protect);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr Address, IntPtr Size, uint FreeType);

    // Scan memoire "type AOB" (Array Of Bytes) : localise un motif dans un tampon.
    // Lecture seule, aucune modification.
    public static int AobScan(byte[] haystack, byte[] needle, int startIndex)
    {
        if (needle == null || needle.Length == 0) return startIndex;
        int maxStart = haystack.Length - needle.Length;
        if (maxStart < 0) return -1;
        if (startIndex < 0) startIndex = 0;

        for (int i = startIndex; i <= maxStart; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    // Mesure de base (overhead du harness seul), methode vide.
    public static int BaselineNoop(int x)
    {
        return x;
    }
}
'@

# ---------------------------------------------------------------------------
# 3. Helpers de mesure
# ---------------------------------------------------------------------------
function Perf-NetMicros {
    param(
        [scriptblock]$Action,
        [int]$Count,
        [double]$NoopCost = 0
    )
    # warm-up
    & $Action | Out-Null

    $samples = @()
    1..$Count | ForEach-Object {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $Action | Out-Null
        $sw.Stop()
        # microsecondes brutes : 1 tick Stopwatch = 1e-7 s => us = ticks / freq * 1e6
        $us = $sw.Elapsed.Ticks * (1e6 / [System.Diagnostics.Stopwatch]::Frequency)
        $net = $us - $NoopCost
        if ($net -lt 0) { $net = 0 }   # le bruit de mesure ne peut produire de valeurs negatives
        $samples += $net
    }
    $sorted = $samples | Sort-Object
    return [pscustomobject]@{
        Min    = [math]::Round($sorted[0], 2)
        Median = [math]::Round($sorted[[int]($sorted.Count / 2)], 2)
        Max    = [math]::Round($sorted[-1], 2)
        Avg    = [math]::Round(($sorted | Measure-Object -Average).Average, 2)
    }
}

# ---------------------------------------------------------------------------
# 4. Benchmarks
# ---------------------------------------------------------------------------
function Measure-FileIO {
    param([int]$Count)

    $dir = Join-Path $env:TEMP "BenchSecurity"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $cfgPath   = Join-Path $dir ("config_" + [guid]::NewGuid().ToString() + ".json")
    $cachePath = Join-Path $dir ("cache_"   + [guid]::NewGuid().ToString() + ".bin")

    # Contenu deterministe, aucune donnee sensible
    $cfgBytes = [System.Text.Encoding]::UTF8.GetBytes((1..256 | ForEach-Object { "key_$_=value_$_;host=bench.default;timeout=5000" }) -join "`n")
    $rnd = New-Object System.Random(2024)
    $cacheBytes = New-Object byte[] (8MB)
    $rnd.NextBytes($cacheBytes)

    [System.IO.File]::WriteAllBytes($cfgPath, $cfgBytes)
    [System.IO.File]::WriteAllBytes($cachePath, $cacheBytes)

    $noop = (Perf-NetMicros -Action { [void][NativeBench]::BaselineNoop(1) } -Count $Count -NoopCost 0).Avg

    $res = @{}
    $res.WriteConfig = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
        [System.IO.File]::WriteAllBytes($cfgPath, $cfgBytes)
    }
    $res.ReadConfig = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
        $null = [System.IO.File]::ReadAllBytes($cfgPath)
    }
    $res.WriteCache = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
        [System.IO.File]::WriteAllBytes($cachePath, $cacheBytes)
    }
    $res.ReadCache = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
        $null = [System.IO.File]::ReadAllBytes($cachePath)
    }

    Remove-Item $cfgPath, $cachePath -Force -ErrorAction SilentlyContinue
    return $res
}

function Measure-MemoryScan {
    param([int]$Count, [int]$BufferMB = 16)

    $bufSize = $BufferMB * 1MB
    $rnd = New-Object System.Random(42)
    $haystack = New-Object byte[] $bufSize
    $rnd.NextBytes($haystack)
    $needle = [byte[]](0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x09)
    # Ne jamais cibler une donnee reelle : le motif est absent du tampon, scan purement
    # observationnel du cout de lecture memoire.
    $noop = (Perf-NetMicros -Action { [void][NativeBench]::BaselineNoop(0) } -Count $Count -NoopCost 0).Avg
    $r = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
        $found = [NativeBench]::AobScan($haystack, $needle, 0)
        if ($found -ne -1) { throw "Scan inattendu : le motif ne doit pas etre present" }
    }
    return [pscustomobject]@{ BufferMB = $BufferMB; Result = $r }
}

function Resolve-TargetProcess {
    param([string]$ProcSpec)
    if ([string]::IsNullOrWhiteSpace($ProcSpec)) { return $null }

    $candidates = @(Get-Process -ErrorAction SilentlyContinue)

    # Cas 1 : chemin complet vers l'executable (contient un separateur de chemin)
    if ($ProcSpec -match '[:\\/]') {
        try { $fullPath = [System.IO.Path]::GetFullPath($ProcSpec) } catch { $fullPath = $null }
        if ($fullPath) {
            $byPath = $candidates | Where-Object {
                try { $_.MainModule.FileName -eq $fullPath } catch { $false }
            } | Select-Object -First 1
            if ($byPath) { return $byPath }
        }
    }

    # Cas 2 : nom de processus, avec ou sans ".exe"
    $name = $ProcSpec
    if ($ProcSpec -match '\.exe$') { $name = [System.IO.Path]::GetFileName($ProcSpec) -replace '\.exe$', '' }
    return $candidates | Where-Object { $_.Name -eq $name } | Select-Object -First 1
}

function Measure-ProcessHandles {
    param([int]$Count, [string]$ProcName)

    $noop = (Perf-NetMicros -Action { [void][NativeBench]::BaselineNoop(0) } -Count $Count -NoopCost 0).Avg

    $curobj = [System.Diagnostics.Process]::GetCurrentProcess()
    $targetPid = $curobj.Id
    $useExternal = $false

    if ($ProcName) {
        $p = Resolve-TargetProcess -ProcSpec $ProcName
        if ($p) { $targetPid = $p.Id; $useExternal = $true }
        else {
            Write-Warning "Processus '$ProcName' introuvable ; fallback sur le processus courant."
        }
    }

    $res = @{}
    $res.OpenClose = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
        $h = [NativeBench]::OpenProcess(0x0410, $false, $targetPid)  # QUERY_LIMITED_INFORMATION = lecture seule
        if ($h -eq [IntPtr]::Zero) { throw "OpenProcess refuse (0x0410)" }
        [void][NativeBench]::CloseHandle($h)
    }
    $hTarget = if ($useExternal) { [NativeBench]::OpenProcess(0x0410, $false, $targetPid) } else { [NativeBench]::GetCurrentProcess() }
    if ($hTarget -eq [IntPtr]::Zero) { throw "Impossible d'ouvrir le processus cible" }
    try {
        $res.QueryInfo = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
            $arena = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(256)
            try {
                $len = 0
                [void][NativeBench]::NtQueryInformationProcess($hTarget, 0, $arena, 256, [ref]$len)
            }
            finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($arena) }
        }
    }
    finally {
        if ($useExternal) { [void][NativeBench]::CloseHandle($hTarget) }
    }

    if ($useExternal) {
        # Adresse de lecture : base du module principal du processus cible (en-tete PE, lecture seule).
        $readBase = [IntPtr]::Zero
        try { $readBase = $p.MainModule.BaseAddress } catch { }

        $res.ReadMem = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
            $h = [NativeBench]::OpenProcess(0x0010, $false, $targetPid)  # PROCESS_VM_READ = lecture seule
            if ($h -eq [IntPtr]::Zero) { throw "OpenProcess refuse (0x0010)" }
            try {
                $buf = New-Object byte[] 64
                $read = 0
                [void][NativeBench]::ReadProcessMemory($h, $readBase, $buf, $buf.Length, [ref]$read)
            }
            finally { [void][NativeBench]::CloseHandle($h) }
        }
    }

    return [pscustomobject]@{ Pid = $targetPid; Result = $res }
}

function Measure-Syscalls {
    param([int]$Count)

    $self = [NativeBench]::GetCurrentProcess()
    $noop = (Perf-NetMicros -Action { [void][NativeBench]::BaselineNoop(0) } -Count $Count -NoopCost 0).Avg

    # N'ecrit rien de significatif : reecrit les memes octets, aucun changement observaible.
    $memSize = 64KB
    $memBlock = [NativeBench]::VirtualAlloc([IntPtr]::Zero, [IntPtr]$memSize, 0x3000, 0x04) # MEM_RESERVE|COMMIT, PAGE_READWRITE
    if ($memBlock -eq [IntPtr]::Zero) { throw "VirtualAlloc refuse" }
    try {
        $payload = New-Object byte[] 4096
        for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = 0x90 }

        $res = @{}
        $res.NtQuerySystem = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
            $arena = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(64)
            try {
                $len = 0
                [void][NativeBench]::NtQuerySystemInformation(5, $arena, 64, [ref]$len) # SystemProcessInformation
            }
            finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($arena) }
        }

        # Protection memoire : PAGE_READWRITE -> PAGE_READONLY puis restauration PAGE_READWRITE.
        $res.NtProtectMem = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
            $addr = $memBlock
            $size = [IntPtr]$memSize
            $old = 0
            [void][NativeBench]::NtProtectVirtualMemory($self, [ref]$addr, [ref]$size, 0x02, [ref]$old)   # -> RO
            [void][NativeBench]::NtProtectVirtualMemory($self, [ref]$addr, [ref]$size, 0x04, [ref]$old)   # -> RW (restauration)
        }

        # Ecriture d'un contenu identique (aucune donnee modifiee).
        $res.NtWriteMem = Perf-NetMicros -Count $Count -NoopCost $noop -Action {
            $written = 0
            [void][NativeBench]::NtWriteVirtualMemory($self, $memBlock, $payload, $payload.Length, [ref]$written)
        }

        return $res
    }
    finally {
        [void][NativeBench]::VirtualFree($memBlock, [IntPtr]::Zero, 0x8000) # MEM_RELEASE
    }
}

# ---------------------------------------------------------------------------
# 5. Orchestration
# ---------------------------------------------------------------------------
$reportDir = if ($OutputDir) { $OutputDir } else { Join-Path $PSScriptRoot 'Reports' }
if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { $reportDir = Join-Path (Get-Location) 'Reports' }
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

Write-Host "[SecurityImpactBenchmark] Detection de l'environnement..." -ForegroundColor Cyan
$envAgents = Get-SecurityAgents

Write-Host "[SecurityImpactBenchmark] Benchmark I/O fichiers ($Iterations iterations)..." -ForegroundColor Cyan
$fileIo = Measure-FileIO -Count $Iterations

Write-Host "[SecurityImpactBenchmark] Benchmark memoire / scan AOB..." -ForegroundColor Cyan
$memScan = Measure-MemoryScan -Count $Iterations

Write-Host "[SecurityImpactBenchmark] Benchmark handles processus..." -ForegroundColor Cyan
$procBench = Measure-ProcessHandles -Count $Iterations -ProcName $TargetProcess

Write-Host "[SecurityImpactBenchmark] Benchmark appels systeme..." -ForegroundColor Cyan
$syscalls = Measure-Syscalls -Count $Iterations

# ---------------------------------------------------------------------------
# 6. Assemblage des resultats + coefficient de latence
# ---------------------------------------------------------------------------
$rows = @()
$rows += [pscustomobject]@{ Group='FileIO';     Operation='I/O fichier : ecriture config (petit)'; Min=$fileIo.WriteConfig.Min; Median=$fileIo.WriteConfig.Median; Avg=$fileIo.WriteConfig.Avg }
$rows += [pscustomobject]@{ Group='FileIO';     Operation='I/O fichier : lecture  config (petit)'; Min=$fileIo.ReadConfig.Min;  Median=$fileIo.ReadConfig.Median;  Avg=$fileIo.ReadConfig.Avg }
$rows += [pscustomobject]@{ Group='FileIO';     Operation='I/O fichier : ecriture cache (8MB)';   Min=$fileIo.WriteCache.Min;   Median=$fileIo.WriteCache.Median;   Avg=$fileIo.WriteCache.Avg }
$rows += [pscustomobject]@{ Group='FileIO';     Operation='I/O fichier : lecture  cache (8MB)';   Min=$fileIo.ReadCache.Min;    Median=$fileIo.ReadCache.Median;    Avg=$fileIo.ReadCache.Avg }
$rows += [pscustomobject]@{ Group='Memory';     Operation=("Memoire : scan AOB ($($memScan.BufferMB)MB)"); Min=$memScan.Result.Min; Median=$memScan.Result.Median; Avg=$memScan.Result.Avg }
$rows += [pscustomobject]@{ Group='Process';    Operation='Processus : OpenProcess + CloseHandle';      Min=$procBench.Result.OpenClose.Min;  Median=$procBench.Result.OpenClose.Median;  Avg=$procBench.Result.OpenClose.Avg }
$rows += [pscustomobject]@{ Group='Process';    Operation='Processus : NtQueryInformationProcess';      Min=$procBench.Result.QueryInfo.Min;   Median=$procBench.Result.QueryInfo.Median;   Avg=$procBench.Result.QueryInfo.Avg }
if ($procBench.Result.ContainsKey('ReadMem')) {
    $rows += [pscustomobject]@{ Group='Process'; Operation='Processus : ReadProcessMemory (64o)';     Min=$procBench.Result.ReadMem.Min;     Median=$procBench.Result.ReadMem.Median;     Avg=$procBench.Result.ReadMem.Avg }
}
foreach ($k in $syscalls.Keys) {
    $rows += [pscustomobject]@{ Group='Syscall'; Operation=("Syscall : $k"); Min=$syscalls[$k].Min; Median=$syscalls[$k].Median; Avg=$syscalls[$k].Avg }
}

# Coefficient de latence : rapport de la mediane de chaque operation a la mediane la plus
# legere de sa propre categorie (FileIO / Memory / Process / Syscall). La comparaison
# intra-categorie met en evidence les operations que l'interception de l'agent penalise le plus.
$groupBaseline = @{}
foreach ($g in ($rows | Select-Object -ExpandProperty Group -Unique)) {
    $groupBaseline[$g] = ($rows | Where-Object { $_.Group -eq $g } | Measure-Object -Property Median -Minimum).Minimum
}

$out = $rows | ForEach-Object {
    $base = $groupBaseline[$_.Group]
    $coef = if ($NoBaseline) { 1.00 } else { if ($base -gt 0) { [math]::Round($_.Median / $base, 2) } else { 1.00 } }
    $severity = if ($coef -ge 4.0) { "CRITIQUE" }
                elseif ($coef -ge 2.0) { "Important" }
                else { "Faible" }
    [pscustomobject]@{
        Group        = $_.Group
        Operation    = $_.Operation
        Min_us       = $_.Min
        Median_us    = $_.Median
        Avg_us       = $_.Avg
        CoefLatence  = $coef
        Seuil_Impact = $severity
    }
} | Sort-Object Median_us -Descending

Write-Host ""
Write-Host "=== Rapport de Performance Impact - Execution de tests ===" -ForegroundColor Green
if ($envAgents.WmiAgents) { Write-Host "Agents de securite (WMI SecurityCenter2) : $($envAgents.WmiAgents)" }
else { Write-Host "Agents de securite (WMI SecurityCenter2) : aucun detecte / acces refuse" }
if ($envAgents.EnrichRun) { Write-Host "Processus securite detectes en cours : $($envAgents.EnrichRun)" }
else { Write-Host "Processus securite detectes en cours : aucun" }
Write-Host ""
$out | Format-Table Operation, Min_us, Median_us, Avg_us, CoefLatence, Seuil_Impact -AutoSize

Write-Host "Operations les plus couteuses (coefficient >= 2.0x la reference de categorie) :" -ForegroundColor Yellow
$costly = $out | Where-Object { $_.CoefLatence -ge 2.0 }
if ($costly) {
    $costly | ForEach-Object { Write-Host ("  - {0}  {1} us (mediane, x{2})" -f $_.Operation, $_.Median_us, $_.CoefLatence) }
}
else {
    Write-Host "  Aucune operation ne depasse 2.0x la reference : impact global faible."
}

# ---------------------------------------------------------------------------
# 7. Rapport persiste (Markdown)
# ---------------------------------------------------------------------------
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile = Join-Path $reportDir "SecurityImpactBenchmark_$ts.md"
$osInfo = Get-CimInstance Win32_OperatingSystem
$md = @()
$md += "# Rapport d'impact de l'agent de securite sur le pipeline de test"
$md += ""
$md += "- Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$md += "- Machine : $env:COMPUTERNAME"
$md += "- OS : $($osInfo.Caption) $($osInfo.Version)"
$md += "- Iterations mesurees : $Iterations"
$md += "- Processus cible : $(if ($TargetProcess) { $TargetProcess } else { 'processus courant' }) (PID $($procBench.Pid))"
$md += ""
$md += "## Agent de securite detecte"
$md += ""
if ($envAgents.WmiAgents) { $md += "- WMI SecurityCenter2 : $($envAgents.WmiAgents)" }
else { $md += "- WMI SecurityCenter2 : aucun / acces refuse" }
if ($envAgents.EnrichRun) { $md += "- Processus securite actifs : $($envAgents.EnrichRun)" }
else { $md += "- Processus securite actifs : aucun" }
$md += ""
$md += "## Mesures (microsecondes, net hors overhead du harness, mediane robuste)"
$md += ""
$md += "| Operation | Min (us) | Mediane (us) | Moyenne (us) | Coefficient de latence | Impact |"
$md += "|---|---|---|---|---|---|"
foreach ($r in $out) {
    $md += "| $($r.Operation) | $($r.Min_us) | $($r.Median_us) | $($r.Avg_us) | $($r.CoefLatence) | $($r.Seuil_Impact) |"
}
$md += ""
$md += "## Operations les plus couteuses"
$md += ""
if ($costly) {
    foreach ($r in $costly) { $md += "- **$($r.Operation)** : $($r.Median_us) us (mediane), x$($r.CoefLatence) la reference de categorie" }
}
else {
    $md += "- Aucune operation au-dessus du seuil de 2.0x."
}
$md += ""
$md += "## Methode"
$md += ""
$md += "- Stopwatch haute resolution (1 tick = 100 ns)."
$md += "- Lecture observationnelle uniquement : aucune donnee systeme ou processus n'est modifiee."
$md += "- Coefficient de latence = mediane de l'operation / mediane la plus legere de la meme categorie (FileIO, Memory, Process, Syscall)."
if ($NoBaseline) { $md += "- Baseline desactivee (NoBaseline) : coefficient force a 1.00." }
$md += ""
$md += "> Note : en presence d'une exclusion antivirus du repertoire TEMP, les valeurs I/O peuvent etre optimistes. Rejouer dans le repertoire de travail reel si besoin."
$md | Set-Content -Path $reportFile -Encoding UTF8
Write-Host ""
Write-Host "Rapport genere : $reportFile" -ForegroundColor Green