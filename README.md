# mpr-pt-translation
Translation of Minna no Pokemon Bokujou - Platina Taiouban (Japan) (WiiWare)

This is mainly a workspace repo.
jpnormal contains files extracted from the original Japanese release.  
usupdate contains files extracted from the updated US release.
jpplat contains files extracted from the Japanese Platinum Update, in various states of translation.

## Building

`tools/61.sh` builds the USA and EUR WADs. **It is a tracked mirror, not the copy
that runs** — compilation still happens on the server, from
`/opt/ranch/www/61.sh` in the `pokemon` incus container on vine. Edit the server
copy, then sync it back here so the history stays useful:

```sh
ssh vine 'incus exec pokemon -- cat /opt/ranch/www/61.sh' > tools/61.sh
```

The script `git clone`s this repo fresh on every run and calls `$TMPDIR/tools/*`
for the patch tools, so **changes to `tools/` only take effect once pushed**. It
never re-executes itself from the clone, which is why `tools/61.sh` is a mirror.

Roughly: `sharpii WAD -u` the base WAD → `lzx -d` the `00000001.app` →
`tools/appl.py <USA|EUR>` → `tools/patch_tmd_ios.py` on the TMD →
`sharpii WAD -p` (re-fakesigns) into `/opt/ranch/wad/usplatt-<date>-<locale>.wad`.

### Japanese Platinum build (`61.sh JPN`)

A plain run of `61.sh` also builds a third WAD after USA and EUR, and
`61.sh JPN` builds only that one. It takes the untouched Japanese Platinum WAD
(`/opt/ranch/www/Minna no Pokemon Bokujou - Platina Taiouban (Japan) (WiiWare).wad`),
replaces **only** `00000001.app` with the `appl.py`-patched DOL (RC24 server,
SDHC, Classic/GameCube controllers), moves the TMD to IOS58, and packs
`/opt/ranch/wad/usplatt-<date>-JPN.wad` as `WBMJ`. Nothing is translated and
`00000004`/`00000005` are not rebuilt. If that WAD is missing, the plain run
skips this step with a note. The `usplatt-` prefix is on purpose: the download
page lists files by name, so this keeps the JPN WAD next to its USA and EUR
siblings.

A push to GitHub starts a full build on the server through
`mypokemonranch.cgi`. Every run uses the same clone directory, so don't push
again until the previous build has finished. To update the server script, push
it under a temporary name and `mv` it over `61.sh`. Overwriting it in place
corrupts a build that is still running, because bash reads the script as it
goes.

This works because the Japanese DOL is the same build the T-Eng base WAD was made
from: the two differ only in the three spots `appl.py` rewrites (code 1 at
`0x2C42FC`, the RSA key, the `nwcs` hostname), so every patch address applies
unchanged. `appl.py JPN` on the Japanese DOL is byte-identical to `appl.py USA`
on the T-Eng one. Any region other than `EUR` skips the EUR dialog payload.

## Classic Controller and GameCube controller

`appl.py` also lets you play with a **Classic Controller** (on any Wii Remote) or a
**GameCube controller** (in the port with the same number as the player). The
GameCube controller works without any Wii Remote connected. A real Wii Remote
keeps working as before, and pointing it takes the cursor back from the stick.

Each input is fed to the game as the Wii Remote / Nunchuk input in the first column:

| Wii Remote + Nunchuk | Classic Controller | GameCube controller |
|---|---|---|
| pointer | left stick | control stick |
| Nunchuk stick | right stick | C-stick |
| A / B | A / B | A / B |
| D-pad | D-pad | D-pad |
| + | + or R | R (click, or analog past 2/3) |
| – | – or L | L (click, or analog past 2/3) |
| 1 | Y | Y |
| 2 | X | X |
| Z | ZR | Z |
| C | ZL | — |
| HOME | HOME | START |

The table lives in `tools/classic_pad/classic_pad.c` (`k_map_classic`, `k_map_gamecube`).

How it works: the game's 30 Hz pad sampler (`0x8038C3E0`) calls `KPADRead` once
per channel at `0x8038C434`. `appl.py` redirects that `bl` to a wrapper
(`tools/classic_pad/classic_pad.c`) that calls the real `KPADRead` and then
rewrites the `KPADStatus` to look like a Wii Remote + Nunchuk: buttons are
remapped, one stick drives a virtual pointer (clamped to the game's own
±0.889/±0.929 range, only valid while the game has the pointer enabled), and the
other is reported as the Nunchuk stick. The GameCube data comes from the PADRead
ring the same sampler already fills (pad manager `r13-0x1280`, ring at `+0x86C8`).
So that Dolphin's default "Standard Controller in port 1" can't take over a Wii
Remote player, a GameCube controller only joins in once it has been used.

The C is compiled with devkitPPC by `tools/classic_pad/build.sh` into
`classic_pad.bin`, which **is committed**: the server has no devkitPPC, and
`appl.py` only reads the `.bin`. Rerun `build.sh` and commit the `.bin` after
changing the C or `classic_pad.ld`. The code is split across zero-filled gaps
between the unused MetroTRK exception stubs in Text 0:

| | |
|---|---|
| wrapper + GameCube poll | `0x80005BF4` – `0x80006098` |
| pointer | `0x800058F4` – `0x80005AA4` |
| helpers | `0x80004F80` – `0x800050A8` (after the SDHC guard word) |
| helpers + libgcc FPR save/restore | `0x800045C4` – `0x800046A4` |
| tuning constants | `0x8000470C` – `0x80004794` |
| button maps | `0x800047F4` – `0x80004860` |
| per-channel state (written at run time) | `0x800048F4` – `0x80004954` |

`appl.py` refuses to write a piece over anything that is not still zero, and
checks the original `bl 0x80586910` at the hook site. Like the SDHC patch, this
is not in the reference `tools/00000001.app`.

Tested in Dolphin with scripted DSU input on the WBME and WBMJ builds: every
mapping above for both controllers, the pointer clicking menu buttons, START /
Classic HOME opening the HOME Menu and its pointer closing it, and a plain Wii
Remote passing through unchanged. Not yet tested on real hardware.

## SDHC card support

SDHC needs **two** independent things, and it only works when both are present.
Both are applied automatically by the build (`61.sh`).

**1. The addressing patch (`tools/appl.py`).**
Bero's SDHC Extension, ported to Ranch's copies of the RVL-SDK `sdi_api.o` /
`sd_drv.o`, applied in place as `b` trampolines rather than Gecko codes. It
converts the SD driver's byte addressing to the block (512-byte) addressing an
SDHC card expects. `appl.py` writes the codecave and the 12 hook/bl sites into
the decompressed `00000001.app`, alongside its other patches.

(`tools/00000001.app` is a *reference* copy that already has this patch applied —
the byte source these values were extracted from. The build does **not** read it;
it patches the `00000001.app` from the base WAD. Keep them in sync if you change
the patch.)

Layout in Text 0 free space:

| | |
|---|---|
| codecave | `0x80004DF4` – `0x80004F78` |
| SDHC flag | `0x80004F04` |
| guard flag | `0x80004F78` |
| helpers | `0x80004F08`, `0x80004F28`, `0x80004F50` |
| hooked | `0x804A3D3C`, `0x804A1B00`, `0x804A3F84`, `0x804A3E10`, `0x804A3F38`, `0x804A0D38` |
| bl-redirected | `0x804A4388`, `0x804A46C4`, `0x804A1708`, `0x804A1904`, `0x804A1854`, `0x804A1A50` |

This does not collide with the EUR dialog payload `appl.py` injects at
`0x800044F0` or with the controller patch (see its table below), but keep all
three in mind before using Text 0 free space for anything else.

**2. The IOS (`tools/patch_tmd_ios.py`).**
Ranch requires **IOS35, which has no SDHC (SDv2) support** — on real hardware as
well as in Dolphin. The addressing patch only fixes addressing; it never
*initialises* the card, because that is IOS's job. Under IOS35 nothing ever
initialises an SDHC card, so the driver gives up and the game reports the card as
not recognized no matter how correct the patch is. Repoint the title at an
SDHC-capable IOS (48, 56–62, 70, 80). `61.sh` does this on the unpacked TMD just
before `sharpii WAD -p`, which re-fakesigns on pack:

```sh
python3 tools/patch_tmd_ios.py "$BUILD_DIR"/*.tmd 58 --no-backup
```

Standalone use:

```sh
python3 tools/patch_tmd_ios.py path/to/title.tmd 58   # default is 58
python3 tools/patch_tmd_ios.py path/to/title.tmd --show
```

Confirmed working on the EUR build: the game wrote `DCIM/100NIN01/WBMP0001.JPG`
to a 4 GB SDHC card. Signals to check in Dolphin's log, with `IOS_SD` logging on:

| | IOS35 (broken) | IOS58 (working) |
|---|---|---|
| `IOCTL_GETSTATUS` | `SDHC card is inserted` | `SDHC card is inserted and initialized` |
| `IOCTL_GETOCR` | `ocr 40ff8000` | `ocr c0ff8000` |
| DMA transfers | none | many, block-addressed |

Patching the TMD invalidates its signature. Dolphin does not check it for NAND
titles, so the raw edit is enough there; for real hardware the WAD must be
fakesigned (trucha) afterwards and the target IOS must be installed.

To exercise this in Dolphin you also need a real SDHC image: set
`WiiSDCardPath` in the **`[General]`** section of `Dolphin.ini` (in `[Core]` it is
silently ignored, and Dolphin falls back to a blank 128 MB card that reports a
fixed `ocr 80ff8000`), with `WiiSDCard = True` in `[Core]` and an image larger
than 2 GB.

Note: `tools/sdhcpatch.gct` is stale — it is byte-identical to `tools/WBME01.gct`
and contains none of the above. The original 512-byte Gecko version is in git
history at `3e1803a`. The patch that matters is the one already applied to
`tools/00000001.app`.
