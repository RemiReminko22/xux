"""
il2cpp_auto.py — automatic IL2CPP offset grabber (dump-accurate, no hardcoded RVAs)

Pipeline, in order, against a live process:

  1. snapshot GameAssembly.dll (image base + SizeOfImage) into one byte buffer
  2. locate the `Il2CppClass**` typesTable by anchor-name density search
  3. self-calibrate the Il2CppClass layout:
         name / namespace / fields / field_count / static_fields / instance_size
  4. self-calibrate the Il2CppFieldInfo layout:
         name / type / parent / offset / stride
  5. dump every type -> field name -> field offset (+ best-effort field type)
  6. resolve static-field data blocks per type (ASLR-safe, read from class)
  7. cache the dump to JSON keyed by a build fingerprint and regenerate
     `offsets_generated.py` + `il2cpp_offsets_generated.h` from it

Calibrated against Unity 2021/2022 IL2CPP, metadata v24.5-29 (Combat Master
build 6A63D3AD included — its known values are used as a cross-check printout
only, never as a required input).

Standalone:
    python il2cpp_auto.py
    python il2cpp_auto.py --process Foo.exe --out offsets.json
    python il2cpp_auto.py --cache-only

Library:
    from il2cpp_auto import OffsetGrabber
    g = OffsetGrabber.from_process("CombatMaster.exe")
    g.dump()                                   # -> g.types
    g.field("PlayerRoot", "playerHealth")      # 0xB8
    g.type_info("PlayerHealth")                # dict
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
PTR_MIN = 0x0000_0000_0001_0000
PTR_MAX = 0x0000_7FFF_FFFF_FFFF

MAX_IMAGE_BYTES = 512 << 20        # refuse to snapshot an absurd module
CLASS_SCAN_SPAN = 0x140            # offsets probed inside Il2CppClass
FIELD_SCAN_SPAN = 0x30             # offsets probed inside Il2CppFieldInfo
MAX_FIELDS = 1024                  # per-class sanity cap

# IL2CPP_TYPE_* -> C-ish name, used for best-effort field typing
IL2CPP_TYPE_NAMES = {
    0x01: "void", 0x02: "bool", 0x03: "char16", 0x04: "int8", 0x05: "uint8",
    0x06: "int16", 0x07: "uint16", 0x08: "int32", 0x09: "uint32",
    0x0A: "int64", 0x0B: "uint64", 0x0C: "float", 0x0D: "double",
    0x0E: "string", 0x0F: "ptr", 0x10: "byref", 0x11: "valuetype",
    0x12: "class", 0x13: "var", 0x14: "array", 0x15: "genericinst",
    0x16: "typedbyref", 0x18: "nativeint", 0x19: "nativeuint",
    0x1B: "fnptr", 0x1C: "object", 0x1D: "szarray", 0x1E: "mvar",
}
TYPE_CLASS, TYPE_VALUETYPE = 0x12, 0x11
TYPE_STRING, TYPE_OBJECT = 0x0E, 0x1C
TYPE_PRIMITIVES = frozenset(range(0x01, 0x0E)) | {0x18, 0x19}

# Types that exist in essentially any Unity IL2CPP build. Used only to seed the
# typesTable search — first hit wins.
ANCHOR_NAMES = (
    "PlayerRoot", "Object", "GameObject", "MonoBehaviour", "Transform",
    "Camera", "Component", "Behaviour", "Texture2D",
)

# Known-good values for build 6A63D3AD. Cross-check printout only.
KNOWN_GOOD = {
    "name_off": 0x0A0,
    "static_fields_off": 0x0B8,
    "fields_off": 0x090,
    "field_count_off": 0x124,
    "field_offset_pos": 0x18,
    "PlayerRoot.playerHealth": 0xB8,
    "PlayerRoot.playerArming": 0xA8,
}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def is_ptr(v) -> bool:
    return v is not None and PTR_MIN <= v <= PTR_MAX


def is_ident(s, max_len: int = 200) -> bool:
    """True for things shaped like IL2CPP identifiers: PlayerRoot, <Module>,
    List`1, get_Health, System.Collections.Generic."""
    if not s or len(s) > max_len:
        return False
    c = s[0]
    if not (c.isalpha() or c in "_<"):
        return False
    for ch in s:
        if ch.isalnum() or ch in "_.<>`$@":
            continue
        return False
    return True


def pack64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFF_FFFF_FFFF_FFFF)



# --------------------------------------------------------------------------- #
# image snapshot
# --------------------------------------------------------------------------- #
class GameImage:
    """Read-only snapshot of a module image, addressed by RVA.

    One buffer instead of hundreds of thousands of ReadProcessMemory calls:
    calibration does a lot of byte searching and `.find()` on bytes is C-speed.
    """

    def __init__(self, pm, base: int, size: int, chunk: int = 16 << 20,
                 log=print):
        if size <= 0 or size > MAX_IMAGE_BYTES:
            raise ValueError(f"refusing to snapshot {size:#x} bytes")
        self.pm = pm
        self.base = base
        self.size = size
        buf = bytearray(size)
        bad = 0
        for off in range(0, size, chunk):
            n = min(chunk, size - off)
            try:
                data = pm.read_bytes(base + off, n)
            except Exception:
                data = b""
                bad += 1
            if data:
                buf[off:off + len(data)] = data
        self.buf = bytes(buf)
        if bad:
            log(f"[img] {bad} unreadable chunk(s) — zero-filled")

    # -- bounds ------------------------------------------------------------
    def ok(self, rva: int, n: int = 1) -> bool:
        return 0 <= rva and rva + n <= self.size

    # -- scalar reads by RVA ----------------------------------------------
    def u64(self, rva):
        if not self.ok(rva, 8):
            return None
        return struct.unpack_from("<Q", self.buf, rva)[0]

    def u32(self, rva):
        if not self.ok(rva, 4):
            return None
        return struct.unpack_from("<I", self.buf, rva)[0]

    def i32(self, rva):
        if not self.ok(rva, 4):
            return None
        return struct.unpack_from("<i", self.buf, rva)[0]

    def u16(self, rva):
        if not self.ok(rva, 2):
            return None
        return struct.unpack_from("<H", self.buf, rva)[0]

    def u8(self, rva):
        if not self.ok(rva, 1):
            return None
        return self.buf[rva]

    # -- scalar reads by VA ------------------------------------------------
    def va_u64(self, va):
        if not is_ptr(va):
            return None
        return self.u64(va - self.base)

    def va_i32(self, va):
        if not is_ptr(va):
            return None
        return self.i32(va - self.base)

    def va_u16(self, va):
        if not is_ptr(va):
            return None
        return self.u16(va - self.base)

    def in_image(self, va) -> bool:
        return is_ptr(va) and self.base <= va < self.base + self.size

    def va_cstr(self, va, max_len: int = 200):
        """UTF-8 C string at a VA inside the image, or None."""
        if not is_ptr(va):
            return None
        rva = va - self.base
        if not self.ok(rva, 1):
            return None
        end = self.buf.find(b"\x00", rva, min(rva + max_len, self.size))
        if end < 0:
            return None
        try:
            return self.buf[rva:end].decode("utf-8")
        except UnicodeDecodeError:
            return None

    # -- searches ----------------------------------------------------------
    def find_u64_all(self, value: int, limit: int = 64):
        """All 8-aligned RVAs whose stored u64 equals `value`."""
        pat = pack64(value)
        out, start = [], 0
        while len(out) < limit:
            i = self.buf.find(pat, start)
            if i < 0:
                break
            if i % 8 == 0:
                out.append(i)
            start = i + 1
        return out

    def find_u64_first(self, value: int):
        pat = pack64(value)
        start = 0
        while True:
            i = self.buf.find(pat, start)
            if i < 0:
                return None
            if i % 8 == 0:
                return i
            start = i + 1

    def find_str_all(self, needle: bytes, limit: int = 32):
        out, start = [], 0
        while len(out) < limit:
            i = self.buf.find(needle, start)
            if i < 0:
                break
            out.append(i)
            start = i + 1
        return out

    # -- PE helpers --------------------------------------------------------
    def pe_fingerprint(self) -> dict:
        """Cheap, stable per-build identity: PE header + first 2 KiB hash."""
        fp = {"size": self.size}
        try:
            e_lfanew = struct.unpack_from("<I", self.buf, 0x3C)[0]
            if self.buf[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                machine, nsect, _ts, _sym, _nsym, opt_size, chars = \
                    struct.unpack_from("<HHIIIHH", self.buf, e_lfanew + 4)
                fp.update({
                    "machine": machine,
                    "sections": nsect,
                    "timestamp": struct.unpack_from(
                        "<I", self.buf, e_lfanew + 8)[0],
                    "opt_size": opt_size,
                    "characteristics": chars,
                })
        except Exception:
            pass
        fp["head_sha1"] = hashlib.sha1(self.buf[:0x800]).hexdigest()
        return fp


# --------------------------------------------------------------------------- #
# detected layout
# --------------------------------------------------------------------------- #
class Layout:
    """Detected Il2CppClass / Il2CppFieldInfo geometry."""

    CLASS_KEYS = ("name_off", "namespace_off", "fields_off", "field_count_off",
                  "static_fields_off", "instance_size_off")

    def __init__(self):
        self.name_off = None
        self.namespace_off = None
        self.fields_off = None
        self.field_count_off = None
        self.static_fields_off = None
        self.instance_size_off = None
        self.field_stride = None
        self.field_offset_pos = None
        self.field_parent_pos = None
        self.field_name_pos = 0x0
        self.field_type_pos = 0x8
        self.table_rva = None
        self.type_count = 0

    def fmt(self, key):
        v = getattr(self, key)
        return f"0x{v:X}" if isinstance(v, int) else str(v)

    def to_dict(self) -> dict:
        return dict(vars(self))

    def missing(self):
        need = ("name_off", "namespace_off", "fields_off", "field_stride",
                "field_offset_pos", "table_rva")
        return [k for k in need if getattr(self, k) is None]



# --------------------------------------------------------------------------- #
# layout detector
# --------------------------------------------------------------------------- #
class LayoutDetector:
    """Derives every offset we need from the image itself.

    Strategy — density scoring instead of magic numbers:

      * find the UTF-8 bytes of a common type name ("PlayerRoot", "Object", ...)
      * find 8-byte references to that string; they live at
        `Il2CppClass + name_off`, so `class = ref - name_off`
      * for each candidate `name_off`, check whether `class` sits inside a dense
        run of pointers whose `+name_off` slots all decode to identifiers —
        that run is the typesTable, and its density is the score
      * everything else (namespace, fields, field_count, static_fields) is then
        found by probing the now-known class struct
    """

    def __init__(self, img: GameImage, log=print):
        self.img = img
        self.log = log

    # -- step 1: types table ----------------------------------------------
    def _score_class(self, cls_va: int, name_off: int):
        """How many neighbours in a pointer array look like classes?

        A class pointer shows up in several places (field `parent` slots, type
        structs, the table itself), so every occurrence is scored and the
        densest one wins — that is the typesTable.
        """
        best = (0, None)
        for table in self.img.find_u64_all(cls_va, limit=24):
            hits = 0
            for k in (-4, -3, -2, -1, 1, 2, 3, 4):
                slot = table + k * 8
                if slot < 0:
                    continue
                e = self.img.u64(slot)
                if not self.img.in_image(e):
                    continue
                if is_ident(self.img.va_cstr(self.img.va_u64(e + name_off))):
                    hits += 1
            if hits > best[0]:
                best = (hits, table)
            if hits >= 8:
                break
        return best

    def find_table(self):
        img = self.img
        for anchor in ANCHOR_NAMES:
            needle = anchor.encode("utf-8") + b"\x00"
            str_rvas = img.find_str_all(needle, limit=16)
            if not str_rvas:
                continue
            found = []
            for srva in str_rvas:
                sva = img.base + srva
                for ref in img.find_u64_all(sva, limit=8):
                    for name_off in range(0, CLASS_SCAN_SPAN, 8):
                        cls_rva = ref - name_off
                        if cls_rva < 0 or cls_rva % 8:
                            continue
                        score, table = self._score_class(img.base + cls_rva,
                                                         name_off)
                        if score >= 7:
                            found.append((score, table, name_off, cls_rva))
            if not found:
                continue
            found.sort(key=lambda t: (-t[0], t[1]))
            self.log(f"[detect] anchor '{anchor}': {len(found)} candidate(s), "
                     f"best score {found[0][0]}/8")
            name_off = found[0][2]
            table_rva, count = self._expand_table(found[0][1], name_off)
            if count >= 200:
                self.log(f"[detect] typesTable @ RVA 0x{table_rva:X} "
                         f"({count} types), name_off 0x{name_off:X} "
                         f"(anchor '{anchor}')")
                return table_rva, count, name_off
            self.log(f"[detect] anchor '{anchor}' table too small ({count}) "
                     f"— trying next")
        raise RuntimeError(
            "typesTable not found — wrong module, or the game isn't loaded yet")

    def _expand_table(self, seed_rva: int, name_off: int):
        img = self.img

        def valid(rva):
            if rva < 0 or rva + 8 > img.size:
                return False
            e = img.u64(rva)
            return img.in_image(e) and is_ident(img.va_cstr(img.va_u64(e + name_off)))

        start = seed_rva
        while start - 8 >= 0 and valid(start - 8):
            start -= 8
        end = seed_rva
        while end + 8 <= img.size and valid(end + 8):
            end += 8
        return start, (end - start) // 8 + 1

    # -- step 2: namespace -------------------------------------------------
    def _entries(self, table_rva, count, sample=400):
        img = self.img
        step = max(1, count // sample)
        out = []
        for i in range(0, count, step):
            e = img.u64(table_rva + i * 8)
            if img.in_image(e):
                out.append(e)
            if len(out) >= sample:
                break
        return out

    def _string_offset_ratios(self, entries, skip=()):
        """Fraction of sampled classes whose `+off` points at a string."""
        scores = {}
        for off in range(0, CLASS_SCAN_SPAN, 8):
            if off in skip:
                continue
            hits = 0
            for cls in entries:
                v = self.img.va_u64(cls + off)
                if not self.img.in_image(v):
                    continue
                s = self.img.va_cstr(v, 96)
                if s == "" or is_ident(s, 96):
                    hits += 1
            if hits:
                scores[off] = hits / len(entries)
        return scores

    def find_namespace(self, entries, name_off, skip=()) -> int:
        ratios = self._string_offset_ratios(
            entries, skip=tuple(skip) + (name_off,))
        if not ratios:
            raise RuntimeError("namespace offset not found")
        off, ratio = sorted(ratios.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        self.log(f"[detect] namespace_off 0x{off:X} (coverage {ratio:.0%})")
        return off

    # -- step 3: fields ----------------------------------------------------
    def find_fields(self, entries, skip):
        """Locate `Il2CppClass::fields` and the Il2CppFieldInfo stride."""
        img = self.img
        best = None
        for off in range(0, CLASS_SCAN_SPAN, 8):
            if off in skip:
                continue
            for stride in (0x20, 0x28, 0x18, 0x10, 0x30):
                hits = checked = 0
                for cls in entries:
                    p = img.va_u64(cls + off)
                    if not img.in_image(p):
                        continue
                    checked += 1
                    run = 0
                    for k in range(4):
                        nm = img.va_cstr(img.va_u64(p + k * stride), 64)
                        if not is_ident(nm, 64):
                            break
                        run += 1
                    if run >= 3:
                        hits += 1
                if checked >= 20 and hits / checked >= 0.5:
                    score = hits / checked
                    if best is None or score > best[0]:
                        best = (score, off, stride)
        if best is None:
            raise RuntimeError("Il2CppClass::fields not found")
        score, off, stride = best
        self.log(f"[detect] fields_off 0x{off:X}, field stride 0x{stride:X} "
                 f"(coverage {score:.0%})")
        return off, stride

    def find_parent_pos(self, entries, fields_off, stride) -> int:
        """Where Il2CppFieldInfo stores its declaring class (`parent`).

        Essential: field arrays of different classes are laid out back-to-back in
        metadata, so name validity alone would happily run into the next class's
        fields. `parent` gives us the exact stop condition.
        """
        img = self.img
        best = None
        for pos in (0x10, 0x8, 0x18, 0x20, 0x28):
            good = total = 0
            for cls in entries:
                p = img.va_u64(cls + fields_off)
                if not img.in_image(p):
                    continue
                total += 1
                if img.va_u64(p + pos) == cls:
                    good += 1
            if total >= 20:
                ratio = good / total
                if best is None or ratio > best[0]:
                    best = (ratio, pos)
        if best is None or best[0] < 0.5:
            self.log("[detect] field parent pointer not found — falling back to "
                     "name-run walking (may bleed into neighbouring arrays)")
            return None
        self.log(f"[detect] field_parent_pos 0x{best[1]:X} "
                 f"(coverage {best[0]:.0%})")
        return best[1]

    def _field_names(self, cls, fields_off, stride, limit=MAX_FIELDS,
                     parent_pos=None):
        """(name, field_struct_va) pairs for one class, declaration order."""
        img = self.img
        p = img.va_u64(cls + fields_off)
        if not img.in_image(p):
            return []
        out = []
        for k in range(limit):
            fva = p + k * stride
            if parent_pos is not None and img.va_u64(fva + parent_pos) != cls:
                break
            nm = img.va_cstr(img.va_u64(fva), 128)
            if not is_ident(nm, 128):
                break
            out.append((nm, fva))
        return out

    def find_field_offset_pos(self, entries, fields_off, stride,
                              parent_pos=None) -> int:
        """Where Il2CppFieldInfo stores the member offset (int32).

        A member offset is small, positive, unique and non-decreasing across a
        class's field list. Pointer low-halves (name/type/parent) never are.
        """
        img = self.img
        best = None
        for pos in range(0x8, 0x28, 4):
            good = total = 0
            for cls in entries:
                pairs = self._field_names(cls, fields_off, stride,
                                           parent_pos=parent_pos)[:12]
                if len(pairs) < 2:
                    continue
                vals = [img.va_i32(fva + pos) for _, fva in pairs]
                vals = [v for v in vals if v is not None and v >= 0]
                if len(vals) < 2:
                    continue
                total += 1
                if all(0x8 <= v < 0x10000 for v in vals) \
                        and vals == sorted(vals) and len(set(vals)) == len(vals):
                    good += 1
            if total >= 20:
                ratio = good / total
                if best is None or ratio > best[0]:
                    best = (ratio, pos)
        if best is None or best[0] < 0.3:
            raise RuntimeError("Il2CppFieldInfo offset field not found")
        self.log(f"[detect] field_offset_pos 0x{best[1]:X} "
                 f"(coverage {best[0]:.0%})")
        return best[1]

    def find_field_count_off(self, entries, fields_off, stride,
                             parent_pos=None):
        """Optional: Il2CppClass::field_count (int32) for validation."""
        img = self.img
        counted = {}
        for cls in entries[:120]:
            counted[cls] = len(self._field_names(cls, fields_off, stride,
                                                 parent_pos=parent_pos))
        best = None
        for off in range(0, CLASS_SCAN_SPAN, 4):
            good = total = 0
            for cls, n in counted.items():
                if n < 2:
                    continue
                v = img.va_i32(cls + off)
                if v is None:
                    continue
                total += 1
                if v == n:
                    good += 1
            if total >= 40 and good / total >= 0.8:
                best = (good / total, off)
                break
        if best:
            self.log(f"[detect] field_count_off 0x{best[1]:X} "
                     f"(coverage {best[0]:.0%})")
            return best[1]
        return None


    # -- step 4: static fields --------------------------------------------
    def _read_u64_any(self, va):
        """u64 from the snapshot when possible, otherwise from the process."""
        if self.img.in_image(va):
            return self.img.va_u64(va)
        try:
            return self.img.pm.read_longlong(va) & 0xFFFF_FFFF_FFFF_FFFF
        except Exception:
            return None

    def _static_blob_hits(self, cls, off, name_off, slots=8):
        """1 if `cls+off` looks like real static-field data, else 0.

        A populated static-field block holds GC references; the first qword of
        a GC object is its Il2CppClass*, whose name must be a valid identifier.
        That is very hard to satisfy by accident.
        """
        img = self.img
        p = img.va_u64(cls + off)
        if not is_ptr(p):
            return 0
        for s in range(0, slots * 8, 8):
            v = self._read_u64_any(p + s)
            if not is_ptr(v):
                continue
            k = self._read_u64_any(v)          # object header -> klass*
            if not img.in_image(k):
                continue
            if is_ident(img.va_cstr(img.va_u64(k + name_off), 96)):
                return 1
        return 0

    def find_static_fields(self, entries, name_off, skip=(), anchor_cls=None):
        img = self.img
        scores = {}
        # anchor class first: PlayerRoot always has MyPlayer/AllPlayers statics
        probe = ([anchor_cls] if anchor_cls else []) + entries[:150]
        for off in range(0, CLASS_SCAN_SPAN, 8):
            if off in skip:
                continue
            hits = sum(self._static_blob_hits(c, off, name_off) for c in probe)
            if hits:
                scores[off] = hits
        if not scores:
            return None
        best = max(scores.items(), key=lambda kv: kv[1])[0]
        self.log(f"[detect] static_fields_off 0x{best:X} "
                 f"({scores[best]} class(es) with live statics)")
        return best

    def find_instance_size(self, entries, skip=()):
        """Il2CppClass::instance_size — plausible-looking int32."""
        img = self.img
        best = None
        for off in range(0, CLASS_SCAN_SPAN, 4):
            if off in skip:
                continue
            good = total = 0
            for cls in entries[:100]:
                v = img.va_i32(cls + off)
                if v is None:
                    continue
                total += 1
                if 0x10 <= v <= 0x4000 and v % 8 == 0:
                    good += 1
            if total and good / total >= 0.85:
                best = (good / total, off)
                break
        if best:
            self.log(f"[detect] instance_size_off 0x{best[1]:X} "
                     f"(coverage {best[0]:.0%})")
            return best[1]
        return None

    # -- orchestrator ------------------------------------------------------
    def detect(self) -> Layout:
        L = Layout()
        table_rva, count, name_off = self.find_table()
        L.table_rva, L.type_count, L.name_off = table_rva, count, name_off

        entries = self._entries(table_rva, count)
        if not entries:
            raise RuntimeError("typesTable has no readable entries")

        L.namespace_off = None
        L.fields_off, L.field_stride = self.find_fields(
            entries, skip=(name_off,))
        L.namespace_off = self.find_namespace(
            entries, name_off, skip=(name_off, L.fields_off))
        L.field_parent_pos = self.find_parent_pos(
            entries, L.fields_off, L.field_stride)
        L.field_offset_pos = self.find_field_offset_pos(
            entries, L.fields_off, L.field_stride, L.field_parent_pos)
        L.field_count_off = self.find_field_count_off(
            entries, L.fields_off, L.field_stride, L.field_parent_pos)

        anchor_cls = None
        for cls in entries:
            if self.img.va_cstr(self.img.va_u64(cls + name_off), 96) \
                    in ("PlayerRoot", "GameManager", "Object"):
                anchor_cls = cls
                break

        L.static_fields_off = self.find_static_fields(
            entries, name_off,
            skip=(name_off, L.namespace_off, L.fields_off),
            anchor_cls=anchor_cls)
        if L.static_fields_off is None:
            L.static_fields_off = KNOWN_GOOD["static_fields_off"]
            self.log("[detect] static_fields_off undetected — falling back to "
                     f"0x{L.static_fields_off:X} (statics only populate once "
                     "the class is initialised; be in a match/lobby)")

        L.instance_size_off = self.find_instance_size(
            entries, skip=(name_off, L.namespace_off, L.fields_off))

        self._cross_check(L)
        return L

    def _cross_check(self, L: Layout):
        """Print how the autonomous result lines up with the known build."""
        pairs = [
            ("name_off", L.name_off),
            ("fields_off", L.fields_off),
            ("field_count_off", L.field_count_off),
            ("static_fields_off", L.static_fields_off),
            ("field_offset_pos", L.field_offset_pos),
        ]
        for key, got in pairs:
            want = KNOWN_GOOD.get(key)
            if got is None or want is None:
                continue
            tag = "match" if got == want else f"differs (known 0x{want:X})"
            self.log(f"[cross] {key:<18} 0x{got:<5X} {tag}")

    def detect_by_anchor(self, type_name: str):
        """Fallback: find a single class by name without a full detect()."""
        img = self.img
        needle = type_name.encode() + b"\x00"
        for srva in img.find_str_all(needle, limit=8):
            for ref in img.find_u64_all(img.base + srva, limit=8):
                for name_off in range(0, CLASS_SCAN_SPAN, 8):
                    cls_rva = ref - name_off
                    if cls_rva < 0 or cls_rva % 8:
                        continue
                    score, _table = self._score_class(img.base + cls_rva,
                                                      name_off)
                    if score >= 7:
                        return img.base + cls_rva, name_off
        return None, None


# --------------------------------------------------------------------------- #
# the grabber
# --------------------------------------------------------------------------- #
class OffsetGrabber:
    """Attach, calibrate, dump, cache, query."""

    CACHE_VERSION = 3

    def __init__(self, pm=None, ga_base=None, ga_size=None,
                 process_name="", cache_path="offsets_cache.json", log=print):
        self.pm = pm
        self.ga_base = ga_base
        self.ga_size = ga_size
        self.process_name = process_name
        self.cache_path = cache_path
        self.log = log

        self.img = None
        self.layout = None
        self.detector = None
        self.fingerprint = None
        self.meta = {}
        self.types = {}
        self._by_short = {}
        self._class_va = {}

    # -- construction ------------------------------------------------------
    @classmethod
    def from_process(cls, process_name="CombatMaster.exe",
                     module="GameAssembly.dll",
                     cache_path="offsets_cache.json", log=print):
        import pymem
        import pymem.process

        self = cls(process_name=process_name, cache_path=cache_path, log=log)
        self.pm = pymem.Pymem(process_name)
        mod = pymem.process.module_from_name(self.pm.process_handle, module)
        if not mod:
            raise RuntimeError(f"{module} not found in {process_name}")
        self.ga_base = mod.lpBaseOfDll
        self.ga_size = mod.SizeOfImage
        return self

    def attach(self, module_check=True):
        if self.pm is None or self.ga_base is None:
            raise RuntimeError("no process attached")
        self.img = GameImage(self.pm, self.ga_base, self.ga_size, log=self.log)
        self.fingerprint = self.img.pe_fingerprint()
        self.detector = LayoutDetector(self.img, log=self.log)
        self.log(f"[grab] image 0x{self.ga_base:X}+0x{self.ga_size:X} "
                 f"sha1 {self.fingerprint['head_sha1'][:12]}")
        return self

    # -- dump --------------------------------------------------------------
    def dump(self, force=False, min_type_count=200):
        if not force and self.load_cache():
            return self.types
        if self.img is None:
            self.attach()
        t0 = time.time()
        self.layout = self.detector.detect()
        self.types, self._by_short = self._dump_types()
        self.meta = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "process": self.process_name,
            "ga_base": f"0x{self.ga_base:X}",
            "ga_size": f"0x{self.ga_size:X}",
            "type_count": len(self.types),
            "layout": self.layout.to_dict(),
            "fingerprint": self.fingerprint,
        }
        took = time.time() - t0
        self.log(f"[grab] dumped {len(self.types)} types in {took:.1f}s")
        if len(self.types) < min_type_count:
            self.log(f"[grab] WARNING: only {len(self.types)} types — "
                     "table looks truncated")
        self.save()
        return self.types

    def _dump_types(self):
        img, L = self.img, self.layout
        base = self.ga_base
        types, by_short = {}, {}

        for i in range(L.type_count):
            cls = img.u64(L.table_rva + i * 8)
            if not img.in_image(cls):
                continue
            name = img.va_cstr(img.va_u64(cls + L.name_off), 128)
            if not is_ident(name, 128):
                continue
            ns = img.va_cstr(img.va_u64(cls + L.namespace_off), 128) or ""
            key = f"{ns}.{name}" if ns else name

            info = types.get(key)
            if info is not None:
                info.setdefault("alts", []).append(cls - base)
                continue

            fields = {}
            for fname, fva in self._class_fields(cls):
                off = img.va_i32(fva + L.field_offset_pos)
                if off is None:
                    continue
                fields[fname] = {
                    "o": off,
                    "t": self._field_type(fva),
                    "s": off in (-1, -2),     # il2cpp marks statics negative
                }

            sf = img.va_u64(cls + L.static_fields_off) \
                if L.static_fields_off is not None else 0
            types[key] = {
                "rva": cls - base,
                "ns": ns,
                "name": name,
                "statics_rva": (sf - base) if img.in_image(sf) else None,
                "size": (img.va_i32(cls + L.instance_size_off)
                         if L.instance_size_off is not None else None),
                "fields": fields,
            }
            by_short.setdefault(name, []).append(key)

        return types, by_short

    def _class_fields(self, cls):
        if self.layout is None:
            return []
        return self.detector._field_names(
            cls, self.layout.fields_off, self.layout.field_stride,
            parent_pos=self.layout.field_parent_pos)

    def _field_type(self, fva):
        """Best-effort type name for a field (class name, primitive, or None)."""
        img, L = self.img, self.layout
        t = img.va_u64(fva + L.field_type_pos)
        if not img.in_image(t):
            return None
        tag = img.va_u16(t + 0xA)
        if tag is None:
            return None
        if tag in TYPE_PRIMITIVES or tag == TYPE_STRING:
            return IL2CPP_TYPE_NAMES.get(tag)
        if tag in (TYPE_CLASS, TYPE_VALUETYPE):
            idx = img.va_i32(t)
            if idx is not None and 0 <= idx < L.type_count:
                k = img.u64(L.table_rva + idx * 8)
                nm = img.va_cstr(img.va_u64(k + L.name_off), 96) \
                    if img.in_image(k) else None
                if is_ident(nm, 96):
                    return nm
            cand = img.va_u64(t)
            if img.in_image(cand):
                nm = img.va_cstr(img.va_u64(cand + L.name_off), 96)
                if is_ident(nm, 96):
                    return nm
        return IL2CPP_TYPE_NAMES.get(tag)

    # -- persistence -------------------------------------------------------
    def save(self, path=None):
        path = path or self.cache_path
        if not path:
            return
        payload = {
            "cache_version": self.CACHE_VERSION,
            "meta": self.meta,
            "types": self.types,
        }
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"))
        os.replace(tmp, path)
        self.log(f"[grab] cache written -> {path} "
                 f"({os.path.getsize(path) / 1e6:.1f} MB)")

    def load_cache(self, path=None) -> bool:
        path = path or self.cache_path
        if not path or not os.path.exists(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as e:
            self.log(f"[grab] cache unreadable ({e}) — will re-dump")
            return False
        if payload.get("cache_version") != self.CACHE_VERSION:
            self.log("[grab] cache version changed — will re-dump")
            return False
        meta = payload.get("meta", {})
        fp = meta.get("fingerprint", {})
        if self.fingerprint and fp and \
                (fp.get("size") != self.fingerprint.get("size") or
                 fp.get("head_sha1") != self.fingerprint.get("head_sha1")):
            self.log("[grab] build changed since cache — will re-dump")
            return False
        self.meta = meta
        self.types = payload.get("types", {})
        self._by_short = {}
        for key, info in self.types.items():
            self._by_short.setdefault(info.get("name", key), []).append(key)
            self._class_va[key] = self.ga_base + info["rva"]
        lay = meta.get("layout")
        if lay:
            self.layout = Layout()
            for k, v in lay.items():
                if hasattr(self.layout, k):
                    setattr(self.layout, k, v)
        self.log(f"[grab] cache hit: {len(self.types)} types "
                 f"from {meta.get('generated', '?')}")
        return bool(self.types)

    # -- queries -----------------------------------------------------------
    def type_info(self, type_name, ns=None):
        """Look up a type by full name, short name, or 'ns.Name' suffix."""
        if not type_name:
            return None
        if ns:
            key = f"{ns}.{type_name}"
            if key in self.types:
                return self.types[key]
        if type_name in self.types:
            return self.types[type_name]
        hits = self._by_short.get(type_name)
        if hits:
            return self.types[hits[0]]
        suffix = "." + type_name
        for key, info in self.types.items():
            if key.endswith(suffix):
                return info
        return None

    def class_va(self, type_name, ns=None):
        info = self.type_info(type_name, ns)
        if not info:
            return None
        return self.ga_base + info["rva"]

    def field_info(self, type_name, field_name, ns=None):
        info = self.type_info(type_name, ns)
        if not info:
            return None
        f = info["fields"].get(field_name)
        if f is None:
            # case-insensitive / fuzzy fallback: exact-lowercase match
            low = field_name.lower()
            for k, v in info["fields"].items():
                if k.lower() == low:
                    return v
            return None
        return f

    def field(self, type_name, field_name, default=None, ns=None):
        """Member offset of `field_name` inside `type_name`, or `default`."""
        f = self.field_info(type_name, field_name, ns)
        return default if f is None else f["o"]

    def fields_of(self, type_name, ns=None) -> dict:
        info = self.type_info(type_name, ns)
        return dict(info["fields"]) if info else {}

    def instance_size(self, type_name, ns=None):
        info = self.type_info(type_name, ns)
        return None if not info else info.get("size")

    def statics_va(self, type_name, ns=None):
        """Live static-field block VA: re-read from the class each call so it
        survives respawns, scene reloads and static_construct recalcs."""
        cls = self.class_va(type_name, ns)
        if cls is None or self.pm is None:
            return None
        off = self.layout.static_fields_off if self.layout else None
        if off is not None:
            try:
                v = self.pm.read_longlong(cls + off) & 0xFFFF_FFFF_FFFF_FFFF
                if is_ptr(v):
                    return v
            except Exception:
                pass
        info = self.type_info(type_name, ns)
        if info and info.get("statics_rva"):
            return self.ga_base + info["statics_rva"]
        return None

    def resolve(self, spec: str, default=None):
        """'CombatMaster.PlayerRoot.playerHealth' or 'PlayerRoot.playerHealth'
        -> 0xB8. Handy for config tables."""
        if "." not in spec:
            return default
        for cut in range(spec.count("."), 0, -1):
            parts = spec.split(".")
            type_name = ".".join(parts[:-1])
            field_name = parts[-1]
            v = self.field(type_name, field_name)
            if v is not None:
                return v
        return default

    def find_types(self, pattern: str, limit=200):
        """Substring search over dumped type names (case-insensitive)."""
        pat = pattern.lower()
        out = [k for k in self.types if pat in k.lower()]
        return out[:limit]

    def report(self, type_names, log=print):
        """Print a compact field table for the types you actually care about."""
        for t in type_names:
            info = self.type_info(t)
            if not info:
                log(f"[-] {t}: not in dump")
                continue
            log(f"[+] {t}  rva 0x{info['rva']:X}  "
                f"size {info.get('size')}  "
                f"statics_rva "
                f"{('0x%X' % info['statics_rva']) if info.get('statics_rva') else '?'}")
            for fname, f in info["fields"].items():
                tag = "static" if f.get("s") else "member"
                log(f"      +0x{f['o']:<6X} {tag:<6} "
                    f"{f.get('t') or '?':<24} {fname}")


    # -- codegen -----------------------------------------------------------
    @staticmethod
    def _ident(key: str) -> str:
        out = "".join(c if c.isalnum() else "_" for c in key)
        if out and out[0].isdigit():
            out = "_" + out
        return out.upper()

    def write_python(self, path="offsets_generated.py", keys=None,
                     min_fields=1):
        """Emit a constants module so hot paths never touch JSON again."""
        keys = list(self.types) if keys is None else keys
        lay = self.layout
        lines = [
            '"""Auto-generated by il2cpp_auto.py — do not edit by hand.',
            '',
            f"build sha1 : {self.meta.get('fingerprint', {}).get('head_sha1', '?')}",
            f"generated  : {self.meta.get('generated', '?')}",
            f"types      : {len(keys)} of {len(self.types)}",
            '"""',
            '',
            "# Il2CppClass layout",
        ]
        if lay is not None:
            for k in ("name_off", "namespace_off", "fields_off",
                      "field_count_off", "static_fields_off",
                      "instance_size_off", "field_stride",
                      "field_offset_pos", "table_rva", "type_count"):
                v = getattr(lay, k, None)
                if v is None:
                    continue
                lines.append(f"{k.upper()} = 0x{v:X}" if isinstance(v, int)
                             else f"{k.upper()} = {v!r}")
        lines.append("")
        lines.append("TYPES = {}")

        emitted = 0
        for key in keys:
            info = self.types.get(key)
            if not info:
                continue
            fields = info["fields"]
            if len(fields) < min_fields:
                continue
            ident = self._ident(key)
            lines.append("")
            lines.append(f"# {key}  rva 0x{info['rva']:X}  "
                         f"size {info.get('size')}")
            lines.append(f"{ident}_RVA = 0x{info['rva']:X}")
            if info.get("statics_rva"):
                lines.append(f"{ident}_STATICS_RVA = 0x{info['statics_rva']:X}")
            lines.append(f"{ident} = {{")
            for fname, f in fields.items():
                lines.append(f"    {fname!r}: 0x{f['o'] & 0xFFFF_FFFF:X},"
                             f"   # {f.get('t') or '?'}")
            lines.append("}")
            lines.append(f"TYPES[{key!r}] = {ident}")
            emitted += 1
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self.log(f"[grab] python constants -> {path} ({emitted} types)")
        return emitted

    def write_header(self, path="il2cpp_offsets_generated.h", keys=None):
        """Emit constexpr offsets for C++ trainers/DLLs."""
        if keys is None:
            keys = [k for k in self.types
                    if any(t in k for t in ("Player", "Weapon", "Arming",
                                            "Health", "Damage", "Bot", "Camera"))
                    ][:400]
        lay = self.layout
        out = ["// Auto-generated by il2cpp_auto.py — do not edit.",
               f"// build sha1 {self.meta.get('fingerprint', {}).get('head_sha1', '?')}",
               f"// generated  {self.meta.get('generated', '?')}",
               "#pragma once", "#include <cstdint>", "",
               "namespace il2cpp_layout {"]
        if lay is not None:
            for k in ("name_off", "namespace_off", "fields_off",
                      "field_count_off", "static_fields_off",
                      "instance_size_off", "field_stride",
                      "field_offset_pos", "table_rva"):
                v = getattr(lay, k, None)
                if isinstance(v, int):
                    out.append(f"    constexpr uintptr_t {k} = 0x{v:X};")
        out.append("}")
        out.append("")
        for key in keys:
            info = self.types.get(key)
            if not info or not info["fields"]:
                continue
            ident = self._ident(key)
            out.append(f"namespace {ident} {{")
            out.append(f"    constexpr uintptr_t rva = 0x{info['rva']:X};")
            for fname, f in info["fields"].items():
                out.append(f"    constexpr int32_t {fname} = 0x{f['o'] & 0xFFFF_FFFF:X};")
            out.append("}")
            out.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        self.log(f"[grab] c++ header -> {path} ({len(keys)} candidates)")
        return path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(
        description="Automatic IL2CPP offset grabber (self-calibrating)")
    ap.add_argument("--process", default="CombatMaster.exe")
    ap.add_argument("--module", default="GameAssembly.dll")
    ap.add_argument("--cache", default="offsets_cache.json")
    ap.add_argument("--out", default=None,
                    help="write the dump to this json (default: cache path)")
    ap.add_argument("--py", default=None, help="emit offsets_generated.py")
    ap.add_argument("--header", default=None,
                    help="emit il2cpp_offsets_generated.h")
    ap.add_argument("--cache-only", action="store_true",
                    help="do not touch the process, use the cache")
    ap.add_argument("--force", action="store_true", help="ignore cache")
    ap.add_argument("--find", default=None, help="substring type search")
    ap.add_argument("--report", default=None,
                    help="comma separated types to print (PlayerRoot,...)")
    args = ap.parse_args(argv)

    if args.cache_only:
        g = OffsetGrabber(cache_path=args.cache)
        if not g.load_cache():
            print("[!] no usable cache")
            return 1
    else:
        g = OffsetGrabber.from_process(args.process, args.module,
                                       cache_path=args.cache)
        g.dump(force=args.force)
        if args.out:
            g.save(args.out)

    if args.find:
        hits = g.find_types(args.find)
        print(f"[+] {len(hits)} type(s) matching '{args.find}':")
        for h in hits:
            info = g.types[h]
            print(f"    {h}  rva 0x{info['rva']:X}  "
                  f"{len(info['fields'])} field(s)")

    if args.report:
        g.report([t.strip() for t in args.report.split(",") if t.strip()])

    if args.py:
        g.write_python(args.py)
    if args.header:
        g.write_header(args.header)

    lay = g.layout
    if lay:
        print("[+] layout: " + "  ".join(
            f"{k}=0x{getattr(lay, k):X}" for k in
            ("name_off", "namespace_off", "fields_off", "static_fields_off",
             "field_stride", "field_offset_pos", "table_rva")
            if isinstance(getattr(lay, k), int)))
    return 0


if __name__ == "__main__":
    sys.exit(main())


