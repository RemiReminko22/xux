"""
Combat Master Advanced Bypass — IL2CPP Edition (auto offset grabber)

Offsets are no longer typed in by hand: `il2cpp_auto.OffsetGrabber` walks the
live typesTable, self-calibrates the Il2CppClass / Il2CppFieldInfo layout and
dumps every field offset for THIS build. The hardcoded values below are only
fallbacks for the build they were taken from (6A63D3AD) and for the runtime
field-learning path.

Install:
    pip install pymem keyboard
Run as Administrator.

First launch: the grabber detects + dumps (~2-8 s, writes offsets_cache.json,
offsets_generated.py, il2cpp_offsets_generated.h). Every later launch reuses the
cache until GameAssembly.dll changes (fingerprint check).

Hotkeys:
    F1  Clean MEGA XP (CE flag)      F2  Bot Vacuum (CE flag)
    F3  infinite ammo                F4  godmode (20 Hz hold)
    F5  kill streak (CE flag)        F6  instant weapon levelup (CE flag)
    F7  re-resolve metadata class    F8  wallhack (stub)
    F9  no recoil (stub)             F10 teleport (stub)
    F11 exit                         F12 list modules
    HOME  dump MyPlayer              INSERT  refresh pointers
    PGUP  dump PlayerHealth          PGDN  dump active weapon
    END   show learned offsets       DEL   force full re-dump (new build)
"""

import json
import os
import sys
import time
import threading

import pymem
import pymem.process
import keyboard

from il2cpp_auto import OffsetGrabber

PROCESS_NAME = "CombatMaster.exe"
MODULE_NAME = "GameAssembly.dll"
CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "offsets_cache.json")
PY_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "offsets_generated.py")
HDR_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "il2cpp_offsets_generated.h")

PTR_MIN = 0x0000_0000_0001_0000
PTR_MAX = 0x0000_7FFF_FFFF_FFFF
MAX_TYPES = 500_000

# -----------------------------------------------------------------------------
# Fallback IL2CPP layout — build 6A63D3AD. The grabber overwrites these at
# runtime; they only matter if detection fails (e.g. attached too early).
# -----------------------------------------------------------------------------
class Il2CppClassLayout:
    IMAGE          = 0x000
    SELF           = 0x010
    NAMESPACE      = 0x018
    BYVAL_ARG      = 0x020
    THIS_ARG       = 0x030
    DECLARING_TYPE = 0x088
    TYPEMETA       = 0x068
    PARENT         = 0x078
    METHODS        = 0x080
    FIELDS         = 0x090
    INTERFACES     = 0x098
    NAME           = 0x0A0
    STATIC_FIELDS  = 0x0B8
    INSTANCE_SIZE  = 0x0F8
    FLAGS          = 0x118
    METHOD_COUNT   = 0x120
    FIELD_COUNT    = 0x124


OFF_TYPES_TABLE_RVA = 0x4431120
TYPES_TABLE_COUNT = 64589

# PlayerRoot / PlayerHealth / PlayerArming — dump.cs values for 6A63D3AD.
OFF_PLAYERROOT_PLAYER_HEALTH     = 0xB8
OFF_PLAYERROOT_PLAYER_ARMING     = 0xA8
OFF_PLAYERROOT_CAMERA_CTRL       = 0x48
OFF_PLAYERROOT_STATIC_MYPLAYER   = 0x08
OFF_PLAYERROOT_STATIC_ALLPLAYERS = 0x18

OFF_PLAYERHEALTH_LAST_KNOW_HEALTH = 0xD0   # int32
OFF_PLAYERHEALTH_ACCUM_HEALTH     = 0xE0   # float

OFF_PLAYERARMING_ACTIVE_WEAPON = 0x538
OFF_PLAYERARMING_PRIMARY       = 0xD0
OFF_PLAYERARMING_SECONDARY     = 0xD8

PLAYERROOT_STATIC_FIELDS_RVA = 0x3B074D8


# -----------------------------------------------------------------------------
# Safe read/write
# -----------------------------------------------------------------------------
def safe_write(pm, func, address, *args):
    try:
        func(address, *args)
        return True
    except Exception:
        return False


def read_u64(pm, addr):
    try:
        return pm.read_longlong(addr) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def read_u32(pm, addr):
    try:
        return pm.read_int(addr) & 0xFFFFFFFF
    except Exception:
        return None


def read_f32(pm, addr):
    try:
        return pm.read_float(addr)
    except Exception:
        return None


def read_cstring(pm, addr, max_len=256):
    if not addr:
        return ""
    try:
        data = pm.read_bytes(addr, max_len)
        end = data.find(b"\x00")
        if end == -1:
            end = max_len
        return data[:end].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def dump_memory(pm, address, size=128):
    try:
        data = pm.read_bytes(address, size)
    except Exception as e:
        print(f"[-] dump failed @ 0x{address:X}: {e}")
        return
    for i in range(0, size, 16):
        chunk = data[i:i + 16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    0x{address + i:016X}: {hex_str:<48s} {ascii_str}")


def is_ptr(v):
    return v is not None and PTR_MIN <= v <= PTR_MAX


def in_range(v, base, size):
    return v is not None and base <= v < base + size


def get_module(pm, name):
    try:
        mod = pymem.process.module_from_name(pm.process_handle, name)
        if mod:
            return mod.lpBaseOfDll, mod.SizeOfImage
    except Exception:
        pass
    return None, None


def enum_modules(pm):
    """(name, base, size) for every module in the process."""
    out = []
    try:
        for m in pm.list_modules():
            out.append((m.name, m.lpBaseOfDll, m.SizeOfImage))
    except Exception:
        try:
            import pymem.process
            for m in pymem.process.enum_process_module(pm.process_handle):
                out.append((m.name, m.lpBaseOfDll, m.SizeOfImage))
        except Exception:
            pass
    return out


# -----------------------------------------------------------------------------
# Metadata resolver — walks the typesTable array directly (legacy fallback)
# -----------------------------------------------------------------------------
class Il2CppResolver:
    def __init__(self, pm, ga_base, ga_size):
        self.pm = pm
        self.ga_base = ga_base
        self.ga_size = ga_size
        self._cache = {}

    def _types_table_va(self):
        return self.ga_base + OFF_TYPES_TABLE_RVA

    def find_class(self, target_name, target_ns=""):
        key = (target_ns, target_name)
        if key in self._cache:
            return self._cache[key]

        table = self._types_table_va()
        print(f"[*] scanning {TYPES_TABLE_COUNT} Il2CppClass* for "
              f"'{target_ns}.{target_name}' @ 0x{table:X}")

        for i in range(TYPES_TABLE_COUNT):
            cp = read_u64(self.pm, table + i * 8)
            if not is_ptr(cp):
                continue
            name_p = read_u64(self.pm, cp + Il2CppClassLayout.NAME)
            if not is_ptr(name_p):
                continue
            name = read_cstring(self.pm, name_p, 128)
            if name != target_name:
                continue
            ns_p = read_u64(self.pm, cp + Il2CppClassLayout.NAMESPACE)
            ns = read_cstring(self.pm, ns_p, 128) if is_ptr(ns_p) else ""
            if target_ns and ns != target_ns:
                continue
            self._cache[key] = cp
            print(f"[+] found {ns}.{name} @ 0x{cp:X} (index {i})")
            return cp

        print(f"[-] '{target_ns}.{target_name}' not found")
        return None

    def find_player_root(self):
        cp = self.find_class("PlayerRoot")
        if not cp:
            return None, None
        sf = read_u64(self.pm, cp + Il2CppClassLayout.STATIC_FIELDS)
        if not is_ptr(sf):
            print(f"[-] static_fields invalid: 0x{(sf or 0):X}")
            return cp, None
        print(f"[+] PlayerRoot class     @ 0x{cp:X}")
        print(f"[+] PlayerRoot static_f. @ 0x{sf:X}")
        return cp, sf

# -----------------------------------------------------------------------------
# Main bypass
# -----------------------------------------------------------------------------
class CombatMasterBypass:
    GODMODE_HOLD_HZ = 20
    WATCHDOG_HZ     = 2
    RESCAN_INTERVAL = 3.0

    def __init__(self):
        self.pm = None
        self.pid = None
        self.ga_base = None
        self.ga_size = None
        self.resolver = None
        self.grabber = None

        self.static_fields = None
        self.my_player = None
        self.player_health = None
        self.player_arming = None

        # every offset below is filled from the dump; the values here are the
        # 6A63D3AD fallbacks and are overwritten by _resolve_offsets()
        self.off = {
            "pr_health":        OFF_PLAYERROOT_PLAYER_HEALTH,
            "pr_arming":        OFF_PLAYERROOT_PLAYER_ARMING,
            "pr_camera":        OFF_PLAYERROOT_CAMERA_CTRL,
            "pr_myplayer":      OFF_PLAYERROOT_STATIC_MYPLAYER,
            "pr_allplayers":    OFF_PLAYERROOT_STATIC_ALLPLAYERS,
            "ph_last":          OFF_PLAYERHEALTH_LAST_KNOW_HEALTH,
            "ph_accum":         OFF_PLAYERHEALTH_ACCUM_HEALTH,
            "pa_active":        OFF_PLAYERARMING_ACTIVE_WEAPON,
            "pa_primary":       OFF_PLAYERARMING_PRIMARY,
            "pa_secondary":     OFF_PLAYERARMING_SECONDARY,
        }
        self.off_source = {}          # key -> "dump:Type.field" | "fallback"
        self.grabber_ok = False

        self.hp_field_off = None
        self.ammo_field_off = None
        self.weapon_ptr_off = self.off["pa_active"]

        self._hp_snapshot = None
        self._ammo_snapshot = None

        self.state = {
            "clean_xp": False, "bot_vacuum": False, "inf_ammo": False,
            "godmode": False, "killstreak": False, "instant_wl": False,
            "wallhack": False, "norecoil": False,
        }

        self._stop = threading.Event()

    # ------------------------------------------------------------------ attach
    def connect(self):
        try:
            self.pm = pymem.Pymem(PROCESS_NAME)
            self.pid = self.pm.process_id
            base, size = get_module(self.pm, MODULE_NAME)
            if base is None:
                print(f"[-] {MODULE_NAME} not found")
                return False
            self.ga_base, self.ga_size = base, size
            self.resolver = Il2CppResolver(self.pm, self.ga_base, self.ga_size)
            print(f"[+] attached to {PROCESS_NAME} | PID {self.pid}")
            print(f"[+] {MODULE_NAME} base 0x{self.ga_base:X} "
                  f"size 0x{self.ga_size:X}")

            self._build_grabber()
            self._resolve_offsets()
            self._resolve_static_fields()
            return True
        except Exception as e:
            print(f"[-] attach failed: {e}")
            return False

    def _build_grabber(self):
        """Snapshot the module and (re)dump offsets. Cache-aware, ~2-8 s cold."""
        print("[*] offset grabber: calibrating IL2CPP layout ...")
        try:
            self.grabber = OffsetGrabber(
                pm=self.pm, ga_base=self.ga_base, ga_size=self.ga_size,
                process_name=PROCESS_NAME, cache_path=CACHE_PATH,
                log=self._grab_log)
            self.grabber.attach()
            t0 = time.time()
            self.grabber.dump()
            self.grabber_ok = True
            print(f"[+] offsets ready in {time.time() - t0:.1f}s "
                  f"({len(self.grabber.types)} types)")
            lay = self.grabber.layout
            if lay is not None:
                print(f"[+] layout name=0x{lay.name_off:X} "
                      f"ns=0x{lay.namespace_off:X} fields=0x{lay.fields_off:X}"
                      f"/0x{lay.field_stride:X} field_off="
                      f"0x{lay.field_offset_pos:X} statics="
                      f"0x{lay.static_fields_off:X} table=0x{lay.table_rva:X}")
        except Exception as e:
            print(f"[!] grabber failed ({e})")
            print("[!] continuing with build-6A63D3AD static offsets")
            self.grabber = None
            self.grabber_ok = False

    @staticmethod
    def _grab_log(msg):
        if msg.startswith("[detect]") or msg.startswith("[grab]"):
            print("   " + msg)



    # ------------------------------------------------------------- offsets
    def _pick(self, types, field_names, fallback):
        """First (type, field) pair the dump knows about, else the fallback."""
        if self.grabber is None:
            return fallback, "fallback"
        for t in types:
            for f in field_names:
                v = self.grabber.field(t, f)
                if v is not None:
                    return v, f"dump:{t}.{f}"
        return fallback, "fallback"

    def _resolve_offsets(self):
        """Overwrite the hardcoded table with dumped values."""
        if self.grabber is None:
            print("[!] using static fallback offsets")
            return
        table = {
            "pr_health":     (("PlayerRoot",), ("playerHealth", "health"),
                              OFF_PLAYERROOT_PLAYER_HEALTH),
            "pr_arming":     (("PlayerRoot",), ("playerArming", "arming",
                                                "weaponArming"),
                              OFF_PLAYERROOT_PLAYER_ARMING),
            "pr_camera":     (("PlayerRoot",), ("cameraCtrl", "camera",
                                                "playerCamera"),
                              OFF_PLAYERROOT_CAMERA_CTRL),
            "ph_last":       (("PlayerHealth",), ("lastKnowHealth",
                                                  "lastKnownHealth", "health"),
                              OFF_PLAYERHEALTH_LAST_KNOW_HEALTH),
            "ph_accum":      (("PlayerHealth",), ("accumHealth",
                                                  "accumulatedHealth"),
                              OFF_PLAYERHEALTH_ACCUM_HEALTH),
            "pa_active":     (("PlayerArming",), ("activeWeapon", "currentWeapon",
                                                  "weapon"),
                              OFF_PLAYERARMING_ACTIVE_WEAPON),
            "pa_primary":    (("PlayerArming",), ("primary", "primaryWeapon"),
                              OFF_PLAYERARMING_PRIMARY),
            "pa_secondary":  (("PlayerArming",), ("secondary", "secondaryWeapon"),
                              OFF_PLAYERARMING_SECONDARY),
        }
        for key, (types, names, fb) in table.items():
            val, src = self._pick(types, names, fb)
            self.off[key] = val
            self.off_source[key] = src

        self.weapon_ptr_off = self.off["pa_active"]

        n_dump = sum(1 for v in self.off_source.values() if v.startswith("dump"))
        print(f"[+] offsets from dump: {n_dump}/{len(table)} "
              f"(worst case fallbacks kept)")
        for key in ("pr_health", "pr_arming", "pa_active", "ph_last"):
            print(f"    {key:<10} +0x{self.off[key]:<5X} {self.off_source[key]}")

    def _resolve_static_fields(self):
        """Find PlayerRoot's static blob live, then locate MyPlayer/AllPlayers
        by the class of the object sitting in each slot — no hardcoded statics."""
        if self.grabber is not None:
            sf = self.grabber.statics_va("PlayerRoot")
            if is_ptr(sf):
                self.static_fields = sf
                print(f"[+] PlayerRoot static_fields @ 0x{sf:X} (class struct)")
                slots = {}
                try:
                    slots = self.grabber.static_slots("PlayerRoot", slots=16)
                except Exception as e:
                    print(f"[!] static slot scan failed: {e}")
                if slots:
                    for s, cn in sorted(slots.items()):
                        print(f"    blob+0x{s:<3X} -> {cn}")
                    my = next((s for s, cn in slots.items()
                               if cn == "PlayerRoot"), None)
                    arr = next((s for s, cn in slots.items()
                                if cn and cn.endswith("[]")), None)
                    if my is not None:
                        self.off["pr_myplayer"] = my
                        self.off_source["pr_myplayer"] = "blob-scan:PlayerRoot"
                    if arr is not None:
                        self.off["pr_allplayers"] = arr
                        self.off_source["pr_allplayers"] = f"blob-scan:{arr}"
                else:
                    print("[*] static blob empty — enter a match/lobby so "
                          "PlayerRoot statics get initialised")
                return
        # fallback: RVA pinned from INSERT scan of build 6A63D3AD
        self.static_fields = self.ga_base + PLAYERROOT_STATIC_FIELDS_RVA
        print(f"[!] static_fields fallback (RVA-pinned) @ 0x{self.static_fields:X}")

    def _statics_ok(self):
        sf = self.static_fields
        if not sf:
            return False
        my = read_u64(self.pm, sf + self.off["pr_myplayer"])
        return bool(is_ptr(my) and not self._in_ga(my))

    def _in_ga(self, v):
        return in_range(v, self.ga_base, self.ga_size)


    # ------------------------------------------------------------------ state
    def _refresh(self):
        sf = self.static_fields
        if not sf:
            self._resolve_static_fields()
            sf = self.static_fields
            if not sf:
                return False
        my = read_u64(self.pm, sf + self.off["pr_myplayer"])
        if not is_ptr(my) or self._in_ga(my):
            self.my_player = None
            self.player_health = None
            self.player_arming = None
            # statics die on respawn / scene change — re-anchor once
            if self.grabber is not None:
                self._resolve_static_fields()
            return False
        self.my_player = my
        hp = read_u64(self.pm, my + self.off["pr_health"])
        self.player_health = hp if (is_ptr(hp) and not self._in_ga(hp)) else None
        arm = read_u64(self.pm, my + self.off["pr_arming"])
        self.player_arming = arm if (is_ptr(arm) and not self._in_ga(arm)) else None
        return self.player_health is not None

    def get_my_player(self):
        if self._refresh():
            return self.my_player
        return None

    # ------------------------------------------------------------------ learn
    def _learn_hp(self):
        if self.hp_field_off is not None or not self.player_health:
            return
        data = None
        try:
            data = self.pm.read_bytes(self.player_health, 0x180)
        except Exception:
            return
        if self._hp_snapshot is None:
            self._hp_snapshot = data
            return
        if data == self._hp_snapshot:
            return
        cands = []
        for off in range(0, min(len(data), len(self._hp_snapshot)) - 3, 4):
            b = int.from_bytes(self._hp_snapshot[off:off + 4], "little",
                               signed=True)
            a = int.from_bytes(data[off:off + 4], "little", signed=True)
            if b == a:
                continue
            if not (0 < a < 100_000 and 0 < b < 100_000):
                continue
            if b - a <= 0:
                continue
            cands.append((off, b, a))
        if cands:
            off, b, a = max(cands, key=lambda t: t[1] - t[2])
            self.hp_field_off = off
            print(f"[learn] HP field -> +0x{off:X} ({b} -> {a})")
        self._hp_snapshot = data

    def _learn_ammo(self):
        if self.ammo_field_off is not None or not self.player_arming:
            return
        wpn = read_u64(self.pm, self.player_arming + self.weapon_ptr_off)
        if not is_ptr(wpn) or self._in_ga(wpn):
            return
        try:
            data = self.pm.read_bytes(wpn, 0x100)
        except Exception:
            return
        if self._ammo_snapshot is None:
            self._ammo_snapshot = data
            return
        if data == self._ammo_snapshot:
            return
        cands = []
        for off in range(0, min(len(data), len(self._ammo_snapshot)) - 3, 4):
            b = int.from_bytes(self._ammo_snapshot[off:off + 4], "little",
                               signed=True)
            a = int.from_bytes(data[off:off + 4], "little", signed=True)
            if b == a:
                continue
            if not (0 <= a < 1000 and 0 < b < 1000):
                continue
            if b - a <= 0 or b - a > 200:
                continue
            cands.append((off, b, a))
        if cands:
            off, b, a = max(cands, key=lambda t: t[1] - t[2])
            self.ammo_field_off = off
            print(f"[learn] ammo field -> +0x{off:X} ({b} -> {a})")
        self._ammo_snapshot = data


    # ----------------------------------------------------------------- threads
    def _learner(self):
        while not self._stop.is_set():
            try:
                self._learn_hp()
                self._learn_ammo()
            except Exception as e:
                print(f"[learn] error: {e}")
            self._stop.wait(2.0)

    def _godmode_hold(self):
        period = 1.0 / self.GODMODE_HOLD_HZ
        while not self._stop.is_set():
            if self.state["godmode"] and self.player_health \
                    and self.hp_field_off is not None:
                safe_write(self.pm, self.pm.write_int,
                           self.player_health + self.hp_field_off, 999999)
            self._stop.wait(period)

    # ------------------------------------------------------------------ cheats
    def toggle_godmode(self):
        if not self.state["godmode"]:
            if not self._refresh() or not self.player_health:
                print("[-] godmode: no PlayerHealth (in match?)")
                return
            if self.hp_field_off is None:
                self.hp_field_off = self.off["ph_last"]
                self.off_source["ph_field"] = self.off_source.get("ph_last",
                                                                 "fallback")
                print(f"[*] godmode: using dumped HP field "
                      f"+0x{self.hp_field_off:X} ({self.off_source['ph_field']})")
            self.state["godmode"] = True
            addr = self.player_health + self.hp_field_off
            before = read_u32(self.pm, addr) or 0
            safe_write(self.pm, self.pm.write_int, addr, 999999)
            after = read_u32(self.pm, addr) or 0
            print(f"[+] godmode ON @ 0x{addr:X} ({before} -> {after}, "
                  f"hold {self.GODMODE_HOLD_HZ} Hz)")
        else:
            self.state["godmode"] = False
            print("[+] godmode OFF")

    def toggle_inf_ammo(self):
        enable = not self.state["inf_ammo"]
        if enable:
            if not self._refresh() or not self.player_arming:
                print("[-] inf_ammo: no PlayerArming")
                return
            if self.ammo_field_off is None:
                print("[*] inf_ammo: ammo field not learned — fire once")
                self.state["inf_ammo"] = enable
                return
            wpn = read_u64(self.pm, self.player_arming + self.weapon_ptr_off)
            if is_ptr(wpn) and not self._in_ga(wpn):
                safe_write(self.pm, self.pm.write_int,
                           wpn + self.ammo_field_off, 999)
                print(f"[+] inf_ammo ON @ 0x{wpn + self.ammo_field_off:X}")
            else:
                print("[-] inf_ammo: weapon ptr invalid")
        else:
            print("[+] inf_ammo OFF")
        self.state["inf_ammo"] = enable

    def toggle_norecoil(self):
        self.state["norecoil"] = not self.state["norecoil"]
        print(f"[*] norecoil {'ON' if self.state['norecoil'] else 'OFF'}")

    def toggle_wallhack(self):
        self.state["wallhack"] = not self.state["wallhack"]
        print(f"[*] wallhack {'ON' if self.state['wallhack'] else 'OFF'} (stub)")

    def _ce(self, k, label):
        self.state[k] = not self.state[k]
        print(f"[+] {label} -> {'ON' if self.state[k] else 'OFF'} (CE flag)")

    def teleport(self, x, z):
        print(f"[*] teleport stub X={x} Z={z}")


    # ------------------------------------------------------------------- debug
    def resolve_metadata(self):
        """Re-walk the typesTable with the legacy resolver (F7)."""
        if not self.resolver:
            return
        cp, sf = self.resolver.find_player_root()
        if cp and sf and not self._in_ga(sf):
            self.static_fields = sf
            print(f"[+] using metadata static_fields 0x{sf:X}")
            self._refresh()

    def redump(self):
        """Force a fresh calibration + dump (DEL) — after a game update."""
        try:
            if self.grabber is None:
                self._build_grabber()
                self._resolve_offsets()
                self._resolve_static_fields()
                return
            self.grabber.attach()
            self.grabber.dump(force=True)
            self.grabber.write_python(PY_OUT)
            self.grabber.write_header(HDR_OUT)
            self._resolve_offsets()
            self._resolve_static_fields()
            print("[+] re-dump done (json + py + h refreshed)")
        except Exception as e:
            print(f"[-] re-dump failed: {e}")

    def show_learned(self):
        rva = (self.static_fields - self.ga_base) if self.static_fields else None
        print("=== LEARNED ===")
        print(f" static_fields    : 0x{self.static_fields:X}" if self.static_fields else " static_fields    : ?")
        print(f" static_fields RVA: 0x{rva:X}" if rva is not None else " static_fields RVA: ?")
        print(f" MyPlayer         : 0x{self.my_player:X}" if self.my_player else " MyPlayer         : ?")
        print(f" PlayerHealth     : 0x{self.player_health:X}" if self.player_health else " PlayerHealth     : ?")
        print(f" PlayerArming     : 0x{self.player_arming:X}" if self.player_arming else " PlayerArming     : ?")
        print(f" HP field         : +0x{self.hp_field_off:X}" if self.hp_field_off is not None else " HP field         : ?")
        print(f" weapon ptr off   : +0x{self.weapon_ptr_off:X}")
        print(f" ammo field       : +0x{self.ammo_field_off:X}" if self.ammo_field_off is not None else " ammo field       : ?")
        print("--- offsets (source) ---")
        for k, v in self.off.items():
            print(f" {k:<14}: +0x{v:<5X} [{self.off_source.get(k, 'fallback')}]")
        if self.grabber is not None:
            print(f" dump types       : {len(self.grabber.types)}")
        print("===============")

    def dump_player_health(self):
        if not self._refresh() or not self.player_health:
            print("[-] no live PlayerHealth")
            return
        print(f"[*] PlayerHealth @ 0x{self.player_health:X}")
        dump_memory(self.pm, self.player_health, 0x180)

    def dump_active_weapon(self):
        if not self._refresh() or not self.player_arming:
            print("[-] no live PlayerArming")
            return
        print(f"[*] PlayerArming @ 0x{self.player_arming:X}")
        dump_memory(self.pm, self.player_arming, 0x600)
        wpn = read_u64(self.pm, self.player_arming + self.weapon_ptr_off)
        if is_ptr(wpn) and not self._in_ga(wpn):
            print(f"[*] WeaponBase @ 0x{wpn:X}")
            dump_memory(self.pm, wpn, 0x100)


    # --------------------------------------------------------------------- run
    def run(self):
        print("=== Combat Master IL2CPP Bypass by [R] (auto-offset) ===")
        print("F1 F2 F5 F6 = CE flags | F3 ammo | F4 godmode (per-frame)")
        print("F7 metadata resolve | F8 wallhack | F9 norecoil | F10 teleport")
        print("F11 exit | F12 modules | DEL re-dump offsets")
        print("HOME MyPlayer | INSERT rescan | PGUP health | PGDN weapon")
        print("END learned offsets")
        print("======================================================")

        for fn in (self._learner, self._godmode_hold):
            threading.Thread(target=fn, daemon=True).start()

        while True:
            try:
                if keyboard.is_pressed("f1"):
                    self._ce("clean_xp", "Clean MEGA XP"); time.sleep(0.3)
                if keyboard.is_pressed("f2"):
                    self._ce("bot_vacuum", "Bot Vacuum"); time.sleep(0.3)
                if keyboard.is_pressed("f3"):
                    self.toggle_inf_ammo(); time.sleep(0.3)
                if keyboard.is_pressed("f4"):
                    self.toggle_godmode(); time.sleep(0.3)
                if keyboard.is_pressed("f5"):
                    self._ce("killstreak", "Kill Streak"); time.sleep(0.3)
                if keyboard.is_pressed("f6"):
                    self._ce("instant_wl", "Instant Weapon Levelup"); time.sleep(0.3)
                if keyboard.is_pressed("f7"):
                    self.resolve_metadata(); time.sleep(0.3)
                if keyboard.is_pressed("f8"):
                    self.toggle_wallhack(); time.sleep(0.3)
                if keyboard.is_pressed("f9"):
                    self.toggle_norecoil(); time.sleep(0.3)
                if keyboard.is_pressed("f10"):
                    self.teleport(-3.2418, 0.8720); time.sleep(0.3)
                if keyboard.is_pressed("f11"):
                    print("[!] exiting"); self._stop.set(); break
                if keyboard.is_pressed("f12"):
                    print("[*] modules:")
                    for n, b, s in enum_modules(self.pm):
                        print(f"    {n:40s} base=0x{b:016X} size=0x{s:X}")
                    time.sleep(0.5)
                if keyboard.is_pressed("delete"):
                    self.redump(); time.sleep(0.5)
                if keyboard.is_pressed("home"):
                    pr = self.get_my_player()
                    if pr:
                        print(f"[*] MyPlayer @ 0x{pr:X}")
                        dump_memory(self.pm, pr, 256)
                    else:
                        print("[-] no MyPlayer")
                    time.sleep(0.5)
                if keyboard.is_pressed("insert"):
                    self._refresh(); time.sleep(0.5)
                if keyboard.is_pressed("page up"):
                    self.dump_player_health(); time.sleep(0.5)
                if keyboard.is_pressed("page down"):
                    self.dump_active_weapon(); time.sleep(0.5)
                if keyboard.is_pressed("end"):
                    self.show_learned(); time.sleep(0.5)
            except Exception as e:
                print(f"[!] hotkey loop: {e}")
            time.sleep(0.05)


if __name__ == "__main__":
    b = CombatMasterBypass()
    if b.connect():
        b.run()

