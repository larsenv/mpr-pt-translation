#!/usr/bin/env bash
#
# CANONICAL COPY: /opt/ranch/www/61.sh, in the `pokemon` incus container on vine.
# That is the copy that actually runs.  tools/61.sh in the mpr-pt-translation
# repo is a tracked mirror for review/history only -- this script clones the
# repo and uses $TMPDIR/tools/* for the patch tools, but never re-executes
# itself from the clone.  Edit the server copy, then sync it back to the repo.
#
if [ "$(id -u)" -eq 0 ] && id caddy >/dev/null 2>&1; then
    chown -R caddy:caddy /opt/ranch || true
    exec su -s /bin/bash caddy -c "$(realpath "$0" 2>/dev/null || echo "$0") $*"
fi
export XDG_RUNTIME_DIR="/tmp/xdg-runtime-$USER"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
set -euo pipefail
IFS=$'\n\t'

# === Config ===
REPO="http://github.com/larsenv/mpr-pt-translation/"
TMPDIR="/opt/ranch/mpr-pt-translation"
TOOLS_DIR="/opt/ranch/www"
BUILD_DIR="$TOOLS_DIR/My Pokemon Ranch Platinum Update (T-Eng) (USA)"
BASE_WAD="${BUILD_DIR}.wad"
DATE_SUFFIX="$(date +"%Y-%m-%d_%H%M%p")"
LOCALES=(USA EUR)
ASH_COMPRESS=0
RECOMPRESS_LZX=0

cd "$(dirname "$0")/.." || true

# Fail early if the base WAD is missing
if [ ! -f "$BASE_WAD" ]; then
    echo "ERROR: Base WAD not found at $BASE_WAD"
    echo "Please place the base .wad file in $TOOLS_DIR before running."
    exit 1
fi

# Clean prior workspace & clone
rm -rf "$BUILD_DIR" "$TMPDIR"
git clone "$REPO" "$TMPDIR"
chmod -R 777 "$TMPDIR" || true

# Normalize PNGs
find "$TMPDIR/usplat/00000005.app" -type f -path "*/l10n_ui/arc/timg/*.png" -exec mogrify {} + || true

APP4_SRC="$TMPDIR/usplat/00000004.app"
APP4_BLD="$BUILD_DIR/00000004.d"

cp -rv "$APP4_SRC/ui/" "$APP4_SRC/ui_EUR/"

for LOCALE in "${LOCALES[@]}"; do
    case "$LOCALE" in
        USA)   LOCAL="" ;;
        EUR)   LOCAL="_EUR" ;;
    esac
    
    rm -f "ui.arc.ash" "$APP4_BLD/ui.arc" "$APP4_BLD/ui.arc.ash" || true
    
    if [ "$LOCALE" = "EUR" ]; then
        OAL=(begin begin_txt end end_txt fadein fadeout hover_normal next_fast next normal_hover pressed prev_fast prev select unselect)
        
        # Rename dlg_b4 to dlg_en
        mv "${APP4_SRC}/ui${LOCAL}/arc/blyt/dlg_b4.brlyt" "${APP4_SRC}/ui${LOCAL}/arc/blyt/dlg_en.brlyt" || true
        for OA1 in "${OAL[@]}"; do
            mv "${APP4_SRC}/ui${LOCAL}/arc/anim/dlg_b4_${OA1}.brlan" "${APP4_SRC}/ui${LOCAL}/arc/anim/dlg_en_${OA1}.brlan" || true
        done
        
        # Copy dlg_en to es, de, it, fr
        OTHER_PREFIXES=(es de it fr)
        for PFX in "${OTHER_PREFIXES[@]}"; do
            # keep the repo localized dlg_XX.brlyt when it ships one
            [ -f "${APP4_SRC}/ui${LOCAL}/arc/blyt/dlg_${PFX}.brlyt" ] || \
                cp "${APP4_SRC}/ui${LOCAL}/arc/blyt/dlg_en.brlyt" "${APP4_SRC}/ui${LOCAL}/arc/blyt/dlg_${PFX}.brlyt" || true
            for OA1 in "${OAL[@]}"; do
                cp "${APP4_SRC}/ui${LOCAL}/arc/anim/dlg_en_${OA1}.brlan" "${APP4_SRC}/ui${LOCAL}/arc/anim/dlg_${PFX}_${OA1}.brlan" || true
            done
        done
    fi
    
    wszst CREATE "${APP4_SRC}/ui${LOCAL}/" || true
    mv "${APP4_SRC}/ui${LOCAL}.u8" "ui${LOCAL}.arc"
    ashcomp "ui${LOCAL}.arc" -c "$ASH_COMPRESS" -d 15
    mv "ui${LOCAL}.arc.ash" "${APP4_SRC}/ui${LOCAL}.arc.ash"
    rm -f "ui${LOCAL}.arc" || true
done

# Pack and compress locale subdirs
for f in "$TMPDIR"/usplat/00000005.app/*/; do
    [ -d "$f" ] || continue

    for d in l10n_ui man msg esrborn; do
        mkdir -p "$f/$d"
        ext=$([ "$d" = "man" ] && echo "brres" || echo "arc")

        rm -f "$f/$d.$ext" "$f/$d.$ext.ash"
        wszst CREATE "$f/$d" -a -v -d "$f/$d.$ext"
        ashcomp "$f/$d.$ext" -c $ASH_COMPRESS -d 15
        rm -rf "$f/$d" "$f/$d.$ext"
    done
done

# === Per-locale build loop ===
for LOCALE in "${LOCALES[@]}"; do
    case "$LOCALE" in
        USA)   TITLE="" ;;
        EUR)   TITLE="_EUR" ;;
    esac

    echo "=== Building locale: $LOCALE ==="

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    sharpii WAD -u "$BASE_WAD" "$BUILD_DIR"

    # Decompress and patch 00000001.app
    lzx -d "$BUILD_DIR/00000001.app" "$BUILD_DIR/00000001.app.dec" || true
    python3 "$TMPDIR/tools/appl.py" "$LOCALE" "$BUILD_DIR/00000001.app.dec"
    mv "$BUILD_DIR/00000001.app.dec" "$BUILD_DIR/00000001.app" || true
    if [ "$RECOMPRESS_LZX" -eq 1 ]; then
        lzx -evb "$BUILD_DIR/00000001.app" "$BUILD_DIR/00000001.app.enc" || true
        mv "$BUILD_DIR/00000001.app.enc" "$BUILD_DIR/00000001.app" || true
    fi

    APP4_SRC="$TMPDIR/usplat/00000004.app"
    APP4_BLD="$BUILD_DIR/00000004.d"

    rm -f "$APP4_SRC/savedata_ja.arc/banner_ja.tpl" "$APP4_SRC/savedata_ja.arc/icon_ja.tpl"
    wszst x "$BUILD_DIR/00000004.app"
    cp "$TMPDIR/tools/fonts.arc.ash" "$APP4_BLD/fonts.arc.ash"
    cp "${APP4_SRC}/ui${TITLE}.arc.ash" "$APP4_BLD/ui.arc.ash"
    wimgt ENCODE "$APP4_SRC/savedata_ja.arc/banner_ja.tpl.png" -x TPL.RGB5A3 || true
    wimgt ENCODE "$APP4_SRC/savedata_ja.arc/icon_ja.tpl.png" -x TPL.RGB5A3 || true

    mkdir -p "$APP4_SRC/savedata.arc/"
    cp -rv "$APP4_SRC/savedata_ja.arc/banner_ja.tpl" "$APP4_SRC/savedata.arc/banner.tpl" || true
    cp -rv "$APP4_SRC/savedata_ja.arc/icon_ja.tpl" "$APP4_SRC/savedata.arc/icon.tpl" || true
    cp -rv "$APP4_SRC/savedata_ja.arc/wszst-setup.txt" "$APP4_SRC/savedata.arc/wszst-setup.txt" || true

    # Build 00000004 savedata
    rm -f "$APP4_BLD/savedata.arc" "$APP4_BLD/savedata.arc.ash" || true
    wszst CREATE "$APP4_SRC/savedata.arc" -a -v -d "$APP4_BLD/savedata.arc" || true
    ashcomp "$APP4_BLD/savedata.arc" -c $ASH_COMPRESS -d 15
    rm -f "$APP4_BLD/savedata.arc" || true

    APP5_BLD="$BUILD_DIR/00000005.d"
    mkdir -p "$APP5_BLD"

    if [ "$LOCALE" = "EUR" ]; then
        EUR_LOCALES=(es_ES de_DE it_IT fr_FR en_GB)
        for L in "${EUR_LOCALES[@]}"; do cp -rv "$TMPDIR/usplat/00000005.app/$L/" "$APP5_BLD/$L/"; done
    elif [ "$LOCALE" = "USA" ]; then
        cp -rv "$TMPDIR/usplat/00000005.app/en_US/" "$APP5_BLD/en_US/"
    else
        cp -rv "$TMPDIR/usplat/00000005.app/$LOCALE/" "$APP5_BLD/$LOCALE"
    fi

    cp -v "$APP4_SRC/savedata_ja.arc/wszst-setup.txt" "$APP5_BLD/"

    cp -v "$TMPDIR/usplat/00000000$TITLE.app" "$BUILD_DIR/00000000.app"

    # Recreate .app containers
    rm -f "$BUILD_DIR/00000005.app" "$BUILD_DIR/00000004.app" || true
    wszst CREATE "$APP5_BLD/" -a -v -d "$BUILD_DIR/00000005.app" || true
    wszst CREATE "$APP4_BLD/" -a -v -d "$BUILD_DIR/00000004.app" || true

    case "$LOCALE" in
        ja_JP) SRL="JPN" TITLE_ID="WBMJ" ;;
        USA)   SRL="USA" TITLE_ID="WBME" ;;
        *)     SRL="EUR" TITLE_ID="WBMP" ;;
    esac

    # Fixed quotes and syntax for 00000006 processing
    wszst x "$BUILD_DIR/00000006.app" -d "$BUILD_DIR/00000006.d/" || true
    rm -f "$BUILD_DIR/00000006.d/"*.srl
    rm "$BUILD_DIR/00000006.app"
    cp "$TMPDIR/usplat/srl/Rom-client.$SRL.srl" "$BUILD_DIR/00000006.d/Rom-client.$SRL.srl"
    wszst CREATE "$BUILD_DIR/00000006.d/" -d "$BUILD_DIR/00000006.app" || true
    rm -rf "$BUILD_DIR/00000006.d/"

    # Repoint the title at an SDHC-capable IOS.  Stock Ranch requires IOS35,
    # which has no SDHC (SDv2) support, so the SDHC addressing patch applied by
    # appl.py can never work on its own -- IOS is what initialises the card.
    # sharpii re-fakesigns on pack, so editing the TMD here is safe.
    python3 "$TMPDIR/tools/patch_tmd_ios.py" "$BUILD_DIR"/*.tmd 58 --no-backup
    rm -f "$BUILD_DIR"/*.tmd.bak

    sharpii WAD -p "$BUILD_DIR/" "/opt/ranch/wad/usplatt-${DATE_SUFFIX}-${LOCALE}.wad" -id "$TITLE_ID"
done
