param(
    [Parameter(Mandatory=$true)][int]$TargetPid,
    [string]$Duree = "45",            # secondes de survol
    [string]$Interval = "0.35",       # delai entre deux passes
    [string]$OutJson = "C:\client_simulator\tools\tg-offline\tg_xrefs_hits.json"
)
$Elev = @'
import ctypes, ctypes.wintypes as w, struct, json, time, sys, datetime

PID = int(sys.argv[1])
DUR  = float(sys.argv[2])
IVAL = float(sys.argv[3])
OUT  = sys.argv[4]

# RVAs cibles (robux) dans le build gele 2366ba214ec740ca (mesurees sur fichier)
TARGETS = {
    0x146e69d00: "PromptNativePurchase",
    0x146e69d4a: "PromptProductPurchase",
    0x146e6f6e0: "GetRobuxBalance",
    0x146e6f6ce: "GetRobuxBalance() failed",
    0x1463ae168: "purchaserRobuxBalance",
    0x1463ae1b0: "orderTotalRobux",
    0x1463b2bc8: "expected_price_robux",
    0x1463b2bf0: "price_in_robux",
    0x146dec068: "Upgrades/Robux.aspx",
    0x146dec0a0: "buyRobuxPage",
    0x1463ad448: "userBasePriceInRobux",
    0x1463ad4d0: "priceInRobux",
    0x1463add08: "RobuxTransferSender",
    0x1463add50: "amountInRobux",
}

k32 = ctypes.WinDLL('kernel32', use_last_error=True)

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", w.DWORD),
                ("PartitionId", w.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", w.DWORD),
                ("Protect", w.DWORD),
                ("Type", w.DWORD)]

PROC_VM_READ = 0x10
PROC_QUERY   = 0x0400
PROC_QUERY_LIMIT = 0x1000

h = k32.OpenProcess(PROC_VM_READ | PROC_QUERY | PROC_QUERY_LIMIT, False, PID)
if not h:
    print("OpenProcess FAIL err=", ctypes.get_last_error()); sys.exit(2)

# base image : 0x7ff7d0080000 du PS head lu au boot ? -> on l'ancre via VQuery du .text
# (scan Auto: on cherche la plage EXECUTE_READ qui contient nos RVAs de code)
def rpm(addr, size):
    buf = ctypes.create_string_buffer(size)
    rd = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(rd)):
        return None
    return buf.raw

def scan_window(row):
    """cherche les LEA 48 8D modrm disp32 dont le registre = registre robux et
       dont la cible = l'un de TARGETS (x86-64 RIP-relatif : cible = next_ip + disp)"""
    out = []
    d = rpm(row.BaseAddress, row.RegionSize)
    if d is None:
        return out
    n = len(d)
    for i in range(n-6):
        if d[i] == 0x48 and d[i+1] == 0x8D and (d[i+2] & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', d, i+3)[0]
            inst = row.BaseAddress_va_base + row.region_va_rel + i
            nxt  = inst + 7
            tgt  = nxt + disp
            if tgt in TARGETS:
                out.append({"inst": (row.base + row.offset_in_text + i + row.text_va),
                            "cible": TARGETS[tgt]})
    return out

# survol temporel : on re-scanne la meme zone .text a l'identique pendant DUR s
# (Hyperion dechiffre les fenetres EXECUTE_READ par blocs -> on les lit en rotation)
deb = time.monotonic()
hits = {}
state_page = 0x1000
seen = 0
addr = 0x7ff7d0080000          # debut VM (haute, image base ASLR)

# Etape 1 : localiser .text par VQuery de la region commitee la plus grande
#           (execute/execute_read seulement -> ce sont les pages code)
best = None
a = addr
while a < 0x7ff7d0080000 + 0x9C00000:
    mbi = MBI()
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(a), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        break
    is_code = mbi.State == 0x1000 and mbi.Protect & 0xE0 in (0x20, 0x10, 0x40, 0x80)
    if is_code:
        end = mbi.BaseAddress + mbi.RegionSize
        print(f"  [code] {mbi.BaseAddress:#x}+{mbi.RegionSize:#x} prot={mbi.Protect:#x}")
    a = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value + mbi.RegionSize

while time.monotonic() - deb < DUR:
    # chaque passe : on relit la meme plage .text => les fenetres dechiffrees
    a = 0x7ff7d0080000 + 0x1000
    end = 0x7ff7d0080000 + 0x9C00000
    while a < end:
        mbi = MBI()
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(a), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            a += 0x1000; continue
        if mbi.State == 0x1000 and (mbi.Protect & 0xE0) in (0x20, 0x10, 0x40, 0x80, 0x04, 0x02):
            rum = rpm(mbi.BaseAddress, mbi.RegionSize)
            if rum is not None:
                n = len(rum)
                for i in range(n-6):
                    if rum[i] == 0x48 and rum[i+1] == 0x8D and (rum[i+2] & 0xC7) == 0x05:
                        disp = struct.unpack_from('<i', rum, i+3)[0]
                        inst = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value + i
                        nxt  = inst + 7
                        tgt  = nxt + disp
                        if tgt in TARGETS:
                            hits.setdefault(TARGETS[tgt], set()).add(inst)
        a = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value + mbi.RegionSize
    seen += 1
    time.sleep(IVAL)

print(f"[scrap] {seen} passes en {time.monotonic()-deb:.1f}s")

result = {k: sorted(v) for k, v in hits.items()}
with open(OUT, 'w') as f:
    json.dump(result, f, indent=1)
for k, v in result.items():
    print(f"  {k:26s} {len(v):3d} xref(s)  premier={v[0]:#x}" if v else f"  {k:26s}  0 xref")
print("SAUVEGARDE:", OUT)
k32.CloseHandle(h)
'@

$tmp = "$env:TEMP\tg_scrap.py"
[IO.File]::WriteAllText($tmp, $Elev, [Text.UTF8Encoding]::new($false))

$log = "$env:TEMP\tg_scrap_log.txt"
$elev = @"
param()
\$TargetPid = `$args[0]; \$Duree = `$args[1]; \$Interval = `$args[2]; \$OutJson = `$args[3]
python `$env:TEMP\tg_scrap.py `$TargetPid `$Duree `$Interval `$OutJson *> `$env:TEMP\tg_scrap_log.txt 2>&1
Write-Host "TG_SCRAP_DONE"
"@
$elevP = "$env:TEMP\tg_scrap_elev.ps1"
[IO.File]::WriteAllText($elevP, $elev, [Text.UTF8Encoding]::new($false))

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$elevP`" $TargetPid $Duree $Interval `"$OutJson`""
    Start-Process powershell.exe -ArgumentList $args -Verb RunAs -Wait
} else {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $elevP $TargetPid $Duree $Interval $OutJson
}
if (Test-Path $log) { Get-Content $log }
