# Auto Offset Grabber — how it works

`il2cpp_auto.py` removes every hand-typed RVA/offset from the Combat Master
trainer. Nothing about a build is assumed: the class layout, the typesTable and
every field offset are recovered from the live process, then cached per build.

```
combatmaster_bypass.py     trainer, offsets now come from the dump
il2cpp_auto.py             the grabber itself (standalone CLI + library)
test_il2cpp_auto.py        synthetic IL2CPP image -> proves the calibration
```

## 1. Install / run

```
pip install pymem keyboard
python combatmaster_bypass.py        (as Administrator, game already running)
```

On first launch the grabber does a cold run: snapshot → calibrate → dump
(2-8 s on a 65k-type table). It writes:

| file | contents |
|---|---|
| `offsets_cache.json` | full dump: type → rva, statics rva, size, fields |
| `offsets_generated.py` | constants module (`PLAYERROOT['playerHealth']`, `NAME_OFF`, ...) |
| `il2cpp_offsets_generated.h` | same, C++ `constexpr` (Player/Weapon/Health/Bot types) |

Every later launch reuses the cache until `GameAssembly.dll` changes (PE
timestamp + header sha1 fingerprint).

## 2. Pipeline (all read-only, no injected code)

1. snapshot `GameAssembly.dll` (`lpBaseOfDll` + `SizeOfImage`) into one buffer —
   all searching is `bytes.find`, not millions of `ReadProcessMemory` calls
2. seed on the UTF-8 name of a common type (`PlayerRoot`, `Object`, …)
3. find 8-byte references to that string; they sit at `Il2CppClass + name_off`,
   so `class = ref - name_off`
4. for each candidate `name_off`, score the containing pointer array by how many
   neighbours (`±4` slots) decode to valid identifiers → densest run is the
   typesTable, the score is the confidence
5. probe the class struct for `namespace` (second string-pointer offset),
   `fields` + `Il2CppFieldInfo` stride, `field offset` position (small, unique,
   ascending int32), `field_count`, `static_fields`, `instance_size`
6. walk the whole table → `Type.field -> offset`, best-effort field type from
   `Il2CppType` (primitive tag or klass name for class/valuetype)
7. statics: `Il2CppClass::static_fields` is read live per call, and each blob
   slot is identified by the class of the object inside it — so
   `PlayerRoot.MyPlayer` is "the slot holding a PlayerRoot", not `0x08`

Field arrays of different classes are contiguous in metadata, so the walk stops
on `Il2CppFieldInfo::parent != class` — otherwise field lists bleed together.

## 3. Trainer hotkeys

| key | action |
|---|---|
| F1 / F2 / F5 / F6 | CE flags (XP, bot vacuum, kill streak, weapon level) |
| F3 | infinite ammo (needs one shot first: ammo field is learned) |
| F4 | godmode, 20 Hz hold on the dumped/learned HP field |
| F7 | legacy metadata resolve (`Il2CppResolver`) |
| F8 / F9 / F10 | wallhack / no-recoil / teleport stubs |
| F11 / F12 | exit / list modules |
| DEL | **force full re-dump** (after a game update) |
| END | print learned offsets *with their source* (`dump:Type.field` vs `fallback`) |

`END` is the one to look at if something stops working — it shows for every
offset whether it came from the dump, from the static-blob scan, or from the
build-6A63D3AD fallback.

## 4. After a game update

Nothing to edit. Press `DEL` in-game (or delete `offsets_cache.json`). If the new
build renamed a field, add the new name to the candidate list in
`CombatMasterBypass._resolve_offsets()`:

```python
"pr_health": (("PlayerRoot",), ("playerHealth", "health"), 0xB8),
```

## 5. Standalone use

```
python il2cpp_auto.py                        # dump + write json/py/h
python il2cpp_auto.py --find PlayerRoot      # substring type search
python il2cpp_auto.py --report PlayerRoot,PlayerHealth,PlayerArming
python il2cpp_auto.py --cache-only --report PlayerArming   # offline
python il2cpp_auto.py --force --py outs.py --header outs.h
```

Library:

```python
from il2cpp_auto import OffsetGrabber
g = OffsetGrabber.from_process("CombatMaster.exe")
g.dump()                                   # cache-aware
g.field("PlayerRoot", "playerHealth")      # 0xB8
g.resolve("PlayerArming.activeWeapon")     # 0x538
g.statics_va("PlayerRoot")                 # live static blob VA
g.static_slots("PlayerRoot")               # {0: 'PlayerRoot', 8: 'PlayerRoot[]'}
g.write_header("il2cpp_offsets_generated.h")
```

## 6. Troubleshooting

- **`typesTable not found`** — attached too early (game still unpacking), or
  `GameAssembly.dll` isn't the module holding metadata. Retry from the lobby.
- **`static_fields_off ... falling back to 0xB8`** — no class had live statics
  yet. Enter a match/lobby so `PlayerRoot` gets initialised, then press `DEL`.
- **`PlayerRoot statics not initialised`** — same thing: the blob is all zeros
  until the game constructs them.
- **`only N types — table looks truncated`** — the expansion hit a null entry;
  the dump is still usable but the table walk stopped early.

## 7. Assumptions / limits

- x64 IL2CPP, metadata v24.5-29 (Unity 2021/2022) — the layouts that expose
  `Il2CppClass`/`Il2CppFieldInfo` as plain structs.
- static field offsets are *not* in metadata; they're recovered from live objects
  by class name, which needs the type to be instantiated at least once.
- field types are best-effort: primitives and class references resolve exactly,
  arrays/generics resolve to their element/definition name.
- the grabber never writes to the process; all writes are the trainer's.
