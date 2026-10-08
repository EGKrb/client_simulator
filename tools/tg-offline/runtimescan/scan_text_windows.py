# scan_text_windows.py -- scrap temporel des fenetres EXECUTE_READ du client gele
#
# Trace les XREF reels (LEA RIP-relatif `48 8D 05 disp32`) qui pointent vers les
# aiguilles robux (PromptProductPurchase / GetRobuxBalance / purchaserRobuxBalance
# / expected_price_robux ...) alors que le .text est scramble par Byfron.
# Byfron laisse quelques pages en EXECUTE_READ (fenetres 2-8 Ko) qui ne se
# dechiffrent que transitoirement pendant l'execution ; on les relit en boucle.
#
# Ring-3, lecture seule (ReadProcessMemory), auto-elevation pour SeDebug.
# Usage : python scan_text_windows.py <pid> [duree_secondes]
import ctypes, ctypes.wintypes as w, struct, sys, time, json, os, subprocess

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

PID   = int(sys.argv[1]) if len(sys.argv) > 1 else 0
DURATION = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
INTERVAL = 0.25
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "runtime", "xrefhits.json"))

# RVA cibles (strings robux) = adresses README 2.2 - 0x140000000 (base d'image)
TARGETS_RVA = {
    0x6e69d00: "PromptNativePurchase",
    0x6e69d4a: "PromptProductPurchase",
    0x6e6f6e0: "GetRobuxBalance",
    0x6e6f6ce: "GetRobuxBalance() failed",
    0x63ae168: "purchaserRobuxBalance",
    0x63ae1b0: "orderTotalRobux",
    0x63b2bc8: "expected_price_robux",
    0x63b2bf0: "price_in_robux",
    0x6dec068: "Upgrades/Robux.aspx",
    0x6dec0a0: "buyRobuxPage",
    0x63ad448: "userBasePriceInRobux",
    0x63ad4d0: "priceInRobux",
    0x63add08: "RobuxTransferSender",
    0x63add50: "amountInRobux",
}

# --- auto-elevation : SeDebug requis sur le client protege ---
# Start-Process ne permet PAS de combiner -Verb RunAs avec -RedirectStandard*;
# le child admin soude donc lui-meme son stdout/stderr et signale sa fin par un
# fichier .done (car sa fenetre console est perdue).
import traceback as _tb

SCRIPT_DIR2 = SCRIPT_DIR
RUNLOG = os.path.join(SCRIPT_DIR2, "..", "runtime", "scan_last.log")

def _bootstrap_run():
    """re-execute ce fichier en admin (runas). Le child s'auto-logue."""
    me = os.path.abspath(__file__)
    RT = os.path.join(os.path.dirname(me), "..", "runtime")
    os.makedirs(RT, exist_ok=True)
    ps = (
        "Start-Process -Verb RunAs -Wait -FilePath python.exe "
        f"-ArgumentList @('{me}', '{PID}', '{DURATION}')"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)

if not is_admin():
    _bootstrap_run()
    # on laisse un instant au child pour poser son JSON puis on affiche le log
    time.sleep(1.0)
    if os.path.exists(RUNLOG):
        print(open(RUNLOG, encoding="utf-8", errors="replace").read()[-2000:])
    sys.exit(0)

if not PID:
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq TargetPlayerBeta.exe", "/FO", "CSV"],
                       capture_output=True, text=True)
    for line in r.stdout.strip().splitlines()[1:]:
        try:
            PID = int(line.split('","')[1]); break
        except Exception:
            pass
    if not PID:
        print("client non trouve : lancer join.ps1 d'abord"); sys.exit(2)

k32   = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

# prototypes explicites (sinon ctypes tronque handle 64b -> err 87 / acces denie)
DWORD, BOOL, HANDLE = w.DWORD, w.BOOL, w.HANDLE
SIZE_T = ctypes.c_size_t
k32.OpenProcess.restype = HANDLE
k32.OpenProcess.argtypes = [w.DWORD, BOOL, w.DWORD]
k32.ReadProcessMemory.restype = BOOL
k32.ReadProcessMemory.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_void_p, SIZE_T, ctypes.POINTER(SIZE_T)]
k32.CloseHandle.restype = BOOL
k32.CloseHandle.argtypes = [HANDLE]
k32.VirtualQueryEx.restype = SIZE_T
k32.VirtualQueryEx.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_void_p, SIZE_T]
psapi.EnumProcessModulesEx.restype = BOOL
psapi.EnumProcessModulesEx.argtypes = [HANDLE, ctypes.POINTER(ctypes.c_void_p), w.DWORD, ctypes.POINTER(w.DWORD), w.DWORD]
psapi.EnumProcessModules.restype = BOOL
psapi.EnumProcessModules.argtypes = [HANDLE, ctypes.POINTER(ctypes.c_void_p), w.DWORD, ctypes.POINTER(w.DWORD)]
psapi.GetModuleFileNameExW.restype = w.DWORD
psapi.GetModuleFileNameExW.argtypes = [HANDLE, ctypes.c_void_p, w.LPWSTR, w.DWORD]

# --- logging interne (child admin : console perdue => on re-ecrit stdout) ---
if is_admin():
    os.makedirs(os.path.dirname(RUNLOG), exist_ok=True)
    with open(RUNLOG, 'w', encoding='utf-8') as _lf:
        _lf.write(f"[admin] start pid={PID} dur={DURATION}\n")

    class _TeedFile:
        def __init__(self, real):
            self._real = real
            self._log = open(RUNLOG, 'a', encoding='utf-8')
        def write(self, s):
            try:
                self._real.write(s); self._real.flush()
            except Exception:
                pass
            self._log.write(s); self._log.flush()
        def flush(self):
            try: self._real.flush()
            except Exception: pass
            self._log.flush()
    import sys as _sys
    _sys.stdout = _TeedFile(_sys.stdout)
    print("[admin] logger branche")

# OpenProcess : QUERY_LIMITED(0x1000) | VM_READ(0x10) | QUERY_INFORMATION(0x400)
h = k32.OpenProcess(0x1410, False, PID)
if not h:
    print("OpenProcess echec err=", ctypes.get_last_error()); sys.exit(3)

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", w.DWORD), ("__a1", w.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", w.DWORD),
                ("Protect", w.DWORD), ("Type", w.DWORD)]

# --- base image resolue au runtime = module0 du process (ASLR-safe) ---
def resolve_image_base():
    _mod = ctypes.c_void_p()
    _need = ctypes.c_ulong()
    if not psapi.EnumProcessModulesEx(h, ctypes.byref(_mod), ctypes.sizeof(_mod),
                                      ctypes.byref(_need), 0x03):
        if not psapi.EnumProcessModules(h, ctypes.byref(_mod), ctypes.sizeof(_mod),
                                        ctypes.byref(_need)):
            return 0
    if not _mod.value:
        return 0
    nm = ctypes.create_unicode_buffer(260)
    psapi.GetModuleFileNameExW(h, _mod, nm, 260)
    return _mod.value, nm.value

BASE = resolve_image_base()
if isinstance(BASE, tuple):
    BASE, MODNAME = BASE
else:
    BASE, MODNAME = BASE, "?"
if not BASE:
    print("EnumProcessModules echec err=", ctypes.get_last_error()); sys.exit(3)
print(f"[i] pid={PID} image base=0x{BASE:X} name={os.path.basename(MODNAME)}")

def rpm(addr, size):
    buf = ctypes.create_string_buffer(size)
    rd = ctypes.c_size_t()
    nread = ctypes.c_size_t()
    rc = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(rd))
    if not rc:
        return None
    return buf.raw, rd.value

def find_lea_xrefs(base_addr, blob, base, targets):
    """cherche 48 8D 05 disp32 : cible = next_insn + disp ; ramene en RVA."""
    n = len(blob)
    out = []
    for i in range(n - 7):
        if (blob[i] == 0x48 and blob[i+1] == 0x8D and (blob[i+2] & 0x07) == 0x05):
            disp = struct.unpack_from('<i', blob, i+3)[0]
            here = base_addr + i
            nxt = here + 7
            t = nxt + disp
            rva = (t - base) & 0xFFFFFFFF
            if rva in targets:
                out.append((here, rva))
    return out

found = {}
t0 = time.monotonic()
addr = BASE
img_end = BASE + 0x19000000   # image ~400 Mo max (TargetPlayerBeta est gros)
step = BASE

print(f"[!] scan {DURATION:.0f}s : reglages par fenetres EXECUTE_READ ...")
sys.stdout.flush()

while time.monotonic() - t0 < DURATION:
    a = BASE
    while a < img_end:
        mbi = MBI()
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(a), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        region_end = mbi.BaseAddress + mbi.RegionSize
        prot = mbi.Protect & 0xFF
        is_exec = prot in (0x10, 0x20, 0x40)   # EXECUTE / EXECUTE_READ / EXECUTE_READWRITE
        if (mbi.State == 0x1000) and is_exec:
            # on lit page par page : chaque page executee est une "fenetre" qui
            # peut etre lisible (Byfron dechiffre souvent page par page)
            p = mbi.BaseAddress
            while p < region_end:
                r = rpm(p, 0x1000)
                if r:
                    blob, rd = r
                    if rd >= 7:
                        for (xref, rva) in find_lea_xrefs(p, blob, BASE, TARGETS_RVA):
                            found.setdefault(rva, []).append(xref)
                            if len(found[rva]) <= 1:
                                print(f"  HIT xref=0x{xref:X} -> {TARGETS_RVA[rva]} (rva=0x{rva:X})")
                                sys.stdout.flush()
                        p += rd
                    else:
                        p += 0x1000
                else:
                    p += 0x1000
        a = region_end
        if a <= mbi.BaseAddress:
            break
    time.sleep(INTERVAL)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
summary = {}
for rva, xs in found.items():
    summary[TARGETS_RVA[rva]] = sorted(set(xs))
with open(OUT, 'w') as f:
    json.dump(summary, f, indent=1)
print(f"\nDONE {len(found)} aiguilles touchees -> {OUT}")
for k, v in summary.items():
    print(f"  {k:28} {len(v)} xref(s)")
k32.CloseHandle(h)