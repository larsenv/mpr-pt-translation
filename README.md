# mpr-pt-translation
Translation of Minna no Pokemon Bokujou - Platina Taiouban (Japan) (WiiWare)

This is mainly a workspace repo.
jpnormal contains files extracted from the original Japanese release.  
usupdate contains files extracted from the updated US release.
jpplat contains files extracted from the Japanese Platinum Update, in various states of translation.

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
`0x800044F0`, but keep both in mind before using Text 0 free space for anything else.

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
