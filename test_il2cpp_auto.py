"""
test_il2cpp_auto.py — validates the detector against a synthetic IL2CPP image.

We fabricate a module shaped like the GameAssembly.dll of an IL2CPP build
(typesTable of Il2CppClass*, deduplicated name strings, fields arrays,
static-field blobs, GC objects on a "heap"), hand it to the grabber through a
fake ReadProcessMemory, and assert the autonomous calibration recovers every
offset we planted.

Run:  python test_il2cpp_auto.py
"""

import json
import os
import struct
import tempfile

from il2cpp_auto import OffsetGrabber, GameImage, LayoutDetector

IMAGE_BASE = 0x7FF6_0000_0000
IMAGE_SIZE = 0x120000
HEAP_BASE = 0x7FF9_0000_0000
HEAP_SIZE = 0x4000

CLASS_STRIDE = 0x200
FIELD_STRIDE = 0x20
TYPE_STRIDE = 0x10

TABLE_RVA = 0x80000
STATIC_RVA = 0xA0000

# where this fake build keeps things — the detector must find these blindly
OFF_NAME = 0x0A0
OFF_NAMESPACE = 0x018
OFF_FIELDS = 0x090
OFF_FIELD_COUNT = 0x124
OFF_STATICS = 0x0B8
OFF_INSTANCE_SIZE = 0x0F8


class FakePM:
    """Minimal pymem look-alike backed by byte buffers."""

    def __init__(self, regions):
        self.regions = list(regions)        # [(base, bytes)]
        self.writes = []

    def _locate(self, addr, size):
        for base, buf in self.regions:
            if base <= addr and addr + size <= base + len(buf):
                return buf, addr - base
        raise OSError(f"unmapped read @ 0x{addr:X} (+{size})")

    def read_bytes(self, addr, size):
        buf, off = self._locate(addr, size)
        return bytes(buf[off:off + size])

    def read_longlong(self, addr):
        return struct.unpack("<q", self.read_bytes(addr, 8))[0]

    def read_int(self, addr):
        return struct.unpack("<i", self.read_bytes(addr, 4))[0]

    def read_float(self, addr):
        return struct.unpack("<f", self.read_bytes(addr, 4))[0]

    def write_int(self, addr, value):
        self.writes.append((addr, value))


class ImageBuilder:
    """Lays out a fake GameAssembly image."""

    def __init__(self):
        self.buf = bytearray(IMAGE_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.strs = {}
        self._next_str = 0x1000
        self._next_type = 0x20000
        self._next_class = 0x30000
        self._next_field = 0x60000
        self._next_heap = 0x1000
        self.classes = []
        self._write_pe_header()

    # -- primitives --------------------------------------------------------
    def w64(self, rva, v):
        struct.pack_into("<Q", self.buf, rva, v & 0xFFFF_FFFF_FFFF_FFFF)

    def w32(self, rva, v):
        struct.pack_into("<I", self.buf, rva, v & 0xFFFF_FFFF)

    def w16(self, rva, v):
        struct.pack_into("<H", self.buf, rva, v & 0xFFFF)

    def wraw(self, rva, data):
        self.buf[rva:rva + len(data)] = data

    def va(self, rva):
        return IMAGE_BASE + rva

    def intern(self, s):
        if s in self.strs:
            return self.strs[s]
        rva = self._next_str
        raw = s.encode("utf-8") + b"\x00"
        self.wraw(rva, raw)
        self._next_str += (len(raw) + 7) & ~7
        self.strs[s] = self.va(rva)
        return self.strs[s]

    def _write_pe_header(self):
        self.wraw(0, b"MZ")
        self.w32(0x3C, 0x80)
        self.wraw(0x80, b"PE\x00\x00")
        struct.pack_into("<HHIIIHH", self.buf, 0x84, 0x8664, 3,
                         0x5F00_0000, 0, 0, 0xF0, 0x2022)

    # -- heap --------------------------------------------------------------
    def heap_object(self, klass_va):
        rva = self._next_heap
        self._next_heap += 0x40
        struct.pack_into("<Q", self.heap, rva, klass_va)
        return HEAP_BASE + rva

    # -- content -----------------------------------------------------------
    def add_class(self, name, ns="", fields=(), size=0x40):
        self.classes.append({
            "name": name, "ns": ns, "fields": list(fields), "size": size,
            "rva": self._next_class,
            "class_va": self.va(self._next_class),
        })
        self._next_class += CLASS_STRIDE

    def class_by_name(self, name):
        return next(c for c in self.classes if c["name"] == name)

    def _type_va(self, kind):
        rva = self._next_type
        self._next_type += TYPE_STRIDE
        if kind in ("int32", "float", "bool"):
            tag = {"int32": 0x08, "float": 0x0C, "bool": 0x02}[kind]
            self.w16(rva + 0x0A, tag)
        elif kind == "string":
            self.w16(rva + 0x0A, 0x0E)
        else:
            idx = [c["name"] for c in self.classes].index(kind)
            self.w32(rva, idx)                  # klassIndex, v24.x style
            self.w16(rva + 0x0A, 0x12)          # TYPE_CLASS
        return self.va(rva)

    def build(self):
        """Write table, class structs, fields, types. Returns class count."""
        self.intern("")                         # shared empty namespace
        for i, c in enumerate(self.classes):
            self.w64(TABLE_RVA + i * 8, c["class_va"])

        # allocate field/type blink first so a class can reference itself
        layouts = []
        for c in self.classes:
            base = self._next_field
            self._next_field += len(c["fields"]) * FIELD_STRIDE
            layouts.append(base)

        for c, fields_rva in zip(self.classes, layouts):
            cls = c["rva"]
            self.w32(cls + 0x008, 0x0100_0000)      # decoy, not a pointer
            self.w64(cls + 0x010, 0)                # null self ptr
            self.w64(cls + OFF_NAMESPACE, self.intern(c["ns"]))
            self.w64(cls + OFF_NAME, self.intern(c["name"]))
            self.w64(cls + OFF_FIELDS, self.va(fields_rva))
            self.w32(cls + OFF_FIELD_COUNT, len(c["fields"]))
            self.w32(cls + OFF_INSTANCE_SIZE, c["size"])
            for k, (fname, foff, kind) in enumerate(c["fields"]):
                fva = fields_rva + k * FIELD_STRIDE
                self.w64(fva + 0x00, self.intern(fname))
                self.w64(fva + 0x08, self._type_va(kind))
                self.w64(fva + 0x10, c["class_va"])         # parent
                self.w32(fva + 0x18, foff & 0xFFFF_FFFF)    # member offset
                self.w32(fva + 0x1C, 0x0400_0000 + k)       # token
        return len(self.classes)

    def make_static_object(self, class_name, blob_index=0, slot=0):
        """Allocate a GC object for `class_name` and store it in its static
        blob, exactly like il2cpp does when a static reference is assigned."""
        c = self.class_by_name(class_name)
        blob = STATIC_RVA + blob_index * 0x40
        self.w64(c["rva"] + OFF_STATICS, self.va(blob))
        obj = self.heap_object(c["class_va"])
        self.w64(blob + slot * 8, obj)
        return blob, obj



def build_world():
    """A fake build containing the classes a Combat Master trainer touches."""
    b = ImageBuilder()
    b.add_class("Object", "System", [
        ("m_CachedPtr", 0x10, "int32"),
    ], 0x10)
    b.add_class("MonoBehaviour", "UnityEngine", [
        ("m_CachedPtr", 0x10, "int32"),
        ("m_Enabled", 0x18, "bool"),
        ("m_Script", 0x20, "Object"),
    ], 0x28)
    b.add_class("Camera", "UnityEngine", [
        ("m_ClearFlags", 0x10, "int32"),
        ("m_FieldOfView", 0x18, "float"),
        ("m_Depth", 0x1C, "float"),
        ("m_TargetTexture", 0x20, "Object"),
    ], 0x30)
    b.add_class("Weapon", "", [
        ("ammo", 0x10, "int32"),
        ("magSize", 0x14, "int32"),
        ("fireRate", 0x18, "float"),
        ("owner", 0x20, "Object"),
    ], 0x40)
    b.add_class("PlayerHealth", "", [
        ("lastKnownHealth", 0xD0, "int32"),
        ("accumHealth", 0xE0, "float"),
        ("maxHealth", 0xE4, "int32"),
        ("isDead", 0xE8, "bool"),
    ], 0xF0)
    b.add_class("PlayerArming", "", [
        ("primary", 0xD0, "Weapon"),
        ("secondary", 0xD8, "Weapon"),
        ("activeWeapon", 0x538, "Weapon"),
    ], 0x600)
    b.add_class("PlayerRoot", "", [
        ("playerHealth", 0xB8, "PlayerHealth"),
        ("playerArming", 0xA8, "PlayerArming"),
        ("cameraCtrl", 0x48, "Camera"),
    ], 0x120)
    for i in range(260):
        b.add_class(f"Filler{i:03d}", "CombatMaster.Game", [
            ("id", 0x10, "int32"),
            ("value", 0x14, "float"),
            ("owner", 0x18, "Object"),
            ("label", 0x20, "string"),
        ], 0x28)

    count = b.build()
    blob, obj = b.make_static_object("PlayerRoot", blob_index=0, slot=0)
    pm = FakePM([(IMAGE_BASE, bytes(b.buf)), (HEAP_BASE, bytes(b.heap))])
    return pm, b, count, blob, obj


def silence(*_a, **_k):
    pass


def test_layout_detection():
    pm, b, count, blob, obj = build_world()
    img = GameImage(pm, IMAGE_BASE, IMAGE_SIZE, log=silence)
    det = LayoutDetector(img, log=silence)
    L = det.detect()

    assert L.name_off == OFF_NAME, hex(L.name_off)
    assert L.namespace_off == OFF_NAMESPACE, hex(L.namespace_off)
    assert L.fields_off == OFF_FIELDS, hex(L.fields_off)
    assert L.field_stride == FIELD_STRIDE, hex(L.field_stride)
    assert L.field_offset_pos == 0x18, hex(L.field_offset_pos)
    assert L.field_count_off == OFF_FIELD_COUNT, hex(L.field_count_off or 0)
    assert L.static_fields_off == OFF_STATICS, hex(L.static_fields_off)
    assert L.table_rva == TABLE_RVA, hex(L.table_rva)
    assert L.type_count == count, (L.type_count, count)
    print(f"[ok] layout: name=0x{L.name_off:X} ns=0x{L.namespace_off:X} "
          f"fields=0x{L.fields_off:X}/{L.field_stride:#x} "
          f"field_off=0x{L.field_offset_pos:X} count=0x{L.field_count_off:X} "
          f"statics=0x{L.static_fields_off:X} table=0x{L.table_rva:X} "
          f"({L.type_count} types)")


def test_full_dump():
    pm, b, count, blob, obj = build_world()
    tmp = tempfile.mkdtemp()
    g = OffsetGrabber(pm=pm, ga_base=IMAGE_BASE, ga_size=IMAGE_SIZE,
                      process_name="fake",
                      cache_path=os.path.join(tmp, "c.json"), log=silence)
    g.attach()
    types = g.dump(force=True)
    assert len(types) == count, (len(types), count)

    root = g.type_info("PlayerRoot")
    assert root["fields"]["playerHealth"]["o"] == 0xB8
    assert root["fields"]["playerHealth"]["t"] == "PlayerHealth"
    assert root["fields"]["playerArming"]["o"] == 0xA8
    assert root["fields"]["cameraCtrl"]["o"] == 0x48
    assert root["statics_rva"] == blob
    assert root["size"] == 0x120

    # query API
    assert g.field("PlayerRoot", "playerHealth") == 0xB8
    assert g.field("CombatMaster.Game.Filler007", "value") == 0x14
    assert g.field("PlayerRoot", "nope", default=-1) == -1
    assert g.resolve("PlayerRoot.playerHealth") == 0xB8
    assert g.resolve("PlayerArming.activeWeapon") == 0x538
    assert g.resolve("Weapon.ammo") == 0x10
    assert g.statics_va("PlayerRoot") == IMAGE_BASE + blob
    assert g.instance_size("PlayerArming") == 0x600

    ph = g.type_info("PlayerHealth")
    assert ph["fields"]["lastKnownHealth"]["o"] == 0xD0
    assert ph["fields"]["accumHealth"]["t"] == "float"

    print(f"[ok] dump: {len(types)} types, playerHealth=0x"
          f"{root['fields']['playerHealth']['o']:X}, "
          f"statics_rva=0x{root['statics_rva']:X}, field types resolved")


def test_cache_and_codegen():
    pm, b, count, blob, _obj = build_world()
    tmp = tempfile.mkdtemp()
    cache = os.path.join(tmp, "off.json")
    g = OffsetGrabber(pm=pm, ga_base=IMAGE_BASE, ga_size=IMAGE_SIZE,
                      process_name="fake", cache_path=cache, log=silence)
    g.attach()
    g.dump()
    assert os.path.exists(cache)

    # a second grabber must reuse the cache instead of re-detecting
    g2 = OffsetGrabber(pm=pm, ga_base=IMAGE_BASE, ga_size=IMAGE_SIZE,
                       process_name="fake", cache_path=cache, log=silence)
    g2.attach()
    assert g2.load_cache(), "cache rejected despite identical fingerprint"
    assert g2.field("PlayerRoot", "playerHealth") == 0xB8
    assert g2.layout is not None and g2.layout.name_off == OFF_NAME
    assert g2.layout.table_rva == TABLE_RVA

    # build-change invalidation
    g3 = OffsetGrabber(pm=pm, ga_base=IMAGE_BASE, ga_size=IMAGE_SIZE,
                       process_name="fake", cache_path=cache, log=silence)
    g3.attach()
    g3.fingerprint = dict(g3.fingerprint, head_sha1="deadbeef")
    assert not g3.load_cache(), "stale cache accepted for a new build"

    py = os.path.join(tmp, "offsets_generated.py")
    hdr = os.path.join(tmp, "il2cpp_offsets_generated.h")
    g.write_python(py)
    g.write_header(hdr, keys=["PlayerRoot", "PlayerHealth", "PlayerArming",
                              "Weapon"])
    with open(py, encoding="utf-8") as f:
        py_text = f.read()
    assert "'playerHealth': 0xB8" in py_text
    assert "NAME_OFF = 0xA0" in py_text
    with open(hdr, encoding="utf-8") as f:
        hdr_text = f.read()
    assert "constexpr int32_t playerHealth = 0xB8;" in hdr_text
    assert "constexpr uintptr_t table_rva = 0x80000;" in hdr_text
    print("[ok] cache hit / staleness detection / python + c++ codegen")


def test_report_and_find():
    pm, b, count, blob, _obj = build_world()
    tmp = tempfile.mkdtemp()
    g = OffsetGrabber(pm=pm, ga_base=IMAGE_BASE, ga_size=IMAGE_SIZE,
                      process_name="fake",
                      cache_path=os.path.join(tmp, "c.json"), log=silence)
    g.attach()
    g.dump()
    hits = g.find_types("filler01")
    assert len(hits) == 10, hits
    lines = []
    g.report(["PlayerArming"], log=lines.append)
    assert any("activeWeapon" in ln and "+0x538" in ln for ln in lines), lines
    print(f"[ok] find_types -> {len(hits)} hits; report rendered "
          f"{len(lines)} line(s)")


def main():
    test_layout_detection()
    test_full_dump()
    test_cache_and_codegen()
    test_report_and_find()
    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()

