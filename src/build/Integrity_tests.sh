#!/usr/bin/env bash
# dm-verity Parser Robustness Tester
# Tests kernel's ability to safely handle corrupted disk metadata
# 
# Creates intentionally corrupted rootfs images to verify that:
# - dm-verity parser rejects invalid metadata without crashing
# - Kernel fails safely when integrity checks don't pass
# - All corruption scenarios are handled gracefully
#
# Test modes target specific parser vulnerabilities (header, signature, 
# bounds checking, overflow protection, input validation).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_DEFAULT="$SCRIPT_DIR/Binaries/rootfs.img"

# Defaults
MODE=""
IMG_PATH="$IMG_DEFAULT"
INPLACE=0
DRYRUN=0
VERBOSE=0
YES=0
BACKUP=0
RESTORE=0

usage(){
  cat <<EOF
Usage: $0 <mode> [image-path] [options]

Modes:
  meta1        flip 1 byte in dm-verity metadata header (meta_off + 64)
  sig1         flip 1 byte in detached PKCS#7 signature (sig_off)
  int_overflow write locator fields with overflowed offsets/lengths
  buf_overflow set metadata length to 0xFFFFFFFF (buffer overflow test)
  trunc_meta   claim more metadata bytes than actually exist
  bad_offsets  use offsets beyond end-of-disk
  sanitize     write random locator (input validation)

Options:
  --inplace    modify image in-place (dangerous)
  --yes        assume yes to prompts (required to --inplace in CI)
  --backup     when --inplace, create a .bak copy before changing
  --dry-run    don't perform writes, only print what would happen
  --verbose    print more diagnostic info
  --restore    restore a .bak file if present and exit
  -h, --help   show this message

Default image path: $IMG_DEFAULT
Example:
  $0 meta1 $IMG_DEFAULT
  $0 --inplace --yes sig1 $IMG_DEFAULT
EOF
}

# Parse args
args=()
for a in "$@"; do
  case "$a" in
    --inplace) INPLACE=1 ;;
    --dry-run) DRYRUN=1 ;;
    --verbose) VERBOSE=1 ;;
    --yes) YES=1 ;;
    --backup) BACKUP=1 ;;
    --restore) RESTORE=1 ;;
    -h|--help) usage; exit 0 ;;
    meta1|sig1|int_overflow|buf_overflow|trunc_meta|bad_offsets|sanitize) MODE="$a" ;;
    *) args+=("$a") ;;
  esac
done

# Optional explicit image path (first non-flag arg that is not the mode)
if ((${#args[@]} > 0)); then
  IMG_PATH="${args[0]}"
fi

if (( RESTORE )); then
  # Attempt restore: look for .bak next to IMG_PATH
  IMG="$(readlink -f -- "$IMG_PATH")"
  BAK="${IMG}.bak"
  if [[ -f "$BAK" ]]; then
    echo "Restoring $BAK -> $IMG"
    if (( DRYRUN )); then
      echo "(dry-run) would copy $BAK -> $IMG"
      exit 0
    fi
    cp -f -- "$BAK" "$IMG"
    echo "Restore complete"
    exit 0
  else
    echo "No backup found at $BAK" >&2
    exit 1
  fi
fi

# Require a mode
if [[ -z "${MODE:-}" ]]; then
  echo "ERROR: missing mode" >&2
  usage
  exit 2
fi

# Command availability checks
required_cmds=(sudo losetup python3 blockdev sha256sum dd cp mktemp printf)
for cmd in "${required_cmds[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command '$cmd' not found in PATH" >&2
    exit 2
  fi
done

IMG="$(readlink -f -- "$IMG_PATH")"
if [[ ! -f "$IMG" ]]; then
  echo "ERROR: image not found: $IMG" >&2
  exit 1
fi
if (( ! INPLACE )) && (( ! YES )) && [[ -t 0 ]]; then
  echo "Corruption mode: $MODE"
  echo "Target image: $IMG"
  echo ""
  echo "Choose an option:"
  echo "  1) Create a new file (rootfs.bad.img) - SAFER"
  echo "  2) Overwrite the original file (rootfs.img) - DANGEROUS"
  echo "  3) Cancel"
  echo ""
  read -r -p "Enter your choice [1/2/3] (default: 1): " choice
  case "${choice:-1}" in
    1) 
      INPLACE=0
      echo "Will create a new .bad.img file"
      ;;
    2)
      INPLACE=1
      echo "WARNING: Will overwrite the original image!"
      read -r -p "Are you sure? This cannot be undone! [y/N] " confirm
      if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        exit 0
      fi
      ;;
    3|*)
      echo "Operation cancelled."
      exit 0
      ;;
  esac
fi

# Prepare output image
if (( INPLACE )); then
  BAD_IMG="$IMG"
  if (( BACKUP )); then
    BAK_PATH="${IMG}.bak"
    if [[ -f "$BAK_PATH" ]]; then
      echo "Backup already exists at $BAK_PATH; not overwriting unless --yes provided"
      if [[ -t 0 ]] && (( ! YES )); then
        read -r -p "Overwrite backup $BAK_PATH? [y/N] " r
        [[ "$r" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
      fi
    fi
    if (( DRYRUN )); then
      echo "(dry-run) would create backup: $BAK_PATH"
    else
      echo "Creating backup: $BAK_PATH"
      cp -a -- "$IMG" "$BAK_PATH"
    fi
  fi
  echo "==> IN-PLACE corruption requested on $IMG"
else
  # create a temp file next to the original image
  tmpdir="$(dirname -- "$IMG")"
  BAD_IMG="$(mktemp --tmpdir="$tmpdir" "$(basename "${IMG%.img}").bad.XXXXXX.img")"
  echo "==> Creating copy: $BAD_IMG"
  if (( DRYRUN )); then
    echo "(dry-run) would copy $IMG -> $BAD_IMG"
  else
    if ! cp -f --reflink=auto -- "$IMG" "$BAD_IMG" 2>/dev/null; then
      echo "reflink not available or failed; falling back to regular copy"
      cp -f -- "$IMG" "$BAD_IMG"
    fi
  fi
fi

if (( DRYRUN )); then
  echo "Dry-run mode: no changes will be written. Exiting after planned actions are shown." 
fi

printf "==> Mode  : %s\n" "$MODE"
printf "==> Input : %s\n" "$IMG"
printf "==> Output: %s\n" "$BAD_IMG"

# Function: log (respect verbose)
log(){
  if (( VERBOSE )); then
    printf "%s\n" "$*"
  fi
}

# Function: human print offsets
print_offsets(){
  local label=$1; shift
  printf "  %s offset (disk): %d (0x%08x) len %d (0x%08x)\n" "$label" "$1" "$1" "$2" "$2"
}

# Attach loop device
cleanup() {
  if [[ -n "${LOOP:-}" ]]; then
    echo "Cleaning up loop device $LOOP"
    sudo losetup -d "$LOOP" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if (( DRYRUN )); then
  echo "(dry-run) skipping losetup attach and modifications"
fi

if (( ! DRYRUN )); then
  echo "==> Attaching loop…"
  LOOP="$(sudo losetup -f --show -- "$BAD_IMG")" || { echo "ERROR: losetup failed" >&2; exit 1; }
  export LOOP
  sleep 1

  # Get disk size and read locator with robust checks
  DISK_BYTES="$(sudo blockdev --getsize64 "$LOOP")"
  read -r META_OFFSET META_LEN SIG_OFFSET SIG_SIZE LOCATOR_OFFSET <<<"$(
    sudo env LOOP="$LOOP" python3 - "$LOOP" "$DISK_BYTES" <<'PY'
import sys, struct, os
loop = sys.argv[1]
size = int(sys.argv[2])
loc_off = size - 4096
with open(loop, 'rb', buffering=0) as f:
    f.seek(loc_off)
    blk = f.read(24)
if len(blk) < 24:
    sys.stderr.write(f"ERROR: locator read too short: got {len(blk)} bytes (expected 24)\n")
    sys.exit(2)
magic, ver, meta_off, meta_len, sig_off, sig_len = struct.unpack('<IIIIII', blk[:24])
# Magic 0x564C4F43 == 'VLOC'
if magic == 0x564C4F43:
    print(f"{meta_off} {meta_len} {sig_off} {sig_len} {loc_off}")
else:
    # Fallback guess: assume last 3 blocks for signature/meta
    sig_len = 4096
    sig_off = loc_off - 4096
    meta_off = sig_off - 4096
    meta_len = 4096
    print(f"{meta_off} {meta_len} {sig_off} {sig_len} {loc_off}")
PY
  )"

  if [[ -z "${META_OFFSET:-}" || -z "${SIG_OFFSET:-}" ]]; then
    echo "ERROR: failed to compute offsets" >&2
    exit 1
  fi

  echo "Offsets:"
  print_offsets "META" "$META_OFFSET" "$META_LEN"
  print_offsets "SIG " "$SIG_OFFSET" "$SIG_SIZE"
  printf "  LOC  offset (disk): %d (0x%08x)\n" "$LOCATOR_OFFSET" "$LOCATOR_OFFSET"

  # Pre-change checksum for meta header (for meta1)
  if [[ "$MODE" == "meta1" ]]; then
    BEFORE="$(sudo dd if="$LOOP" bs=1 skip="$META_OFFSET" count=196 2>/dev/null | sha256sum | awk '{print $1}')"
    echo "  header sha256 before: $BEFORE"
  fi
fi

# Helper to run embedded python with environment variables
run_python() {
  # Usage: run_python "ENVVARS" <<'PY'
  sudo env LOOP="$LOOP" LOCATOR_OFFSET="$LOCATOR_OFFSET" DISK_BYTES="$DISK_BYTES" META_OFFSET="$META_OFFSET" SIG_OFFSET="$SIG_OFFSET" python3 - <<'PY'
$1
PY
}

# Perform mode actions
case "$MODE" in
  meta1)
    echo "==> Flipping 1 byte in METADATA header (offset META+64)…"
    if (( DRYRUN )); then
      echo "(dry-run) would flip one byte at meta offset $((META_OFFSET+64))"
    else
      sudo env LOOP="$LOOP" META_OFFSET="$META_OFFSET" python3 - <<'PY'
import os, sys
p = os.environ['LOOP']
off = int(os.environ['META_OFFSET']) + 64
with open(p, 'r+b', buffering=0) as f:
    f.seek(off)
    b = f.read(1)
    if len(b) != 1:
        sys.stderr.write(f"ERROR: could not read 1 byte at {off}\n")
        sys.exit(2)
    f.seek(off)
    written = f.write(bytes([b[0] ^ 0x01]))
    if written != 1:
        sys.stderr.write("ERROR: short write when flipping byte\n")
        sys.exit(2)
    f.flush()
    os.fsync(f.fileno())
print(f"flipped 1 byte at {off}")
PY
      AFTER="$(sudo dd if="$LOOP" bs=1 skip="$META_OFFSET" count=196 2>/dev/null | sha256sum | awk '{print $1}')"
      echo "  header sha256 after : $AFTER"
      if [[ "$BEFORE" == "$AFTER" ]]; then
        echo "!! WARNING: header digest unchanged — check offsets" >&2
      fi
    fi
    ;;

  sig1)
    echo "==> Flipping 1 byte in SIGNATURE (offset SIG)…"
    if (( DRYRUN )); then
      echo "(dry-run) would flip one byte at sig offset $SIG_OFFSET"
    else
      sudo env LOOP="$LOOP" SIG_OFFSET="$SIG_OFFSET" python3 - <<'PY'
import os, sys
p = os.environ['LOOP']
off = int(os.environ['SIG_OFFSET'])
with open(p, 'r+b', buffering=0) as f:
    f.seek(off)
    b = f.read(1)
    if len(b) != 1:
        sys.stderr.write(f"ERROR: could not read 1 byte at {off}\n")
        sys.exit(2)
    f.seek(off)
    written = f.write(bytes([b[0] ^ 0x01]))
    if written != 1:
        sys.stderr.write("ERROR: short write when flipping byte\n")
        sys.exit(2)
    f.flush(); os.fsync(f.fileno())
print(f"flipped 1 byte at {off}")
PY
    fi
    ;;

  int_overflow)
    echo "==> Writing locator with integer overflow fields (wrap-around test)..."
    if (( DRYRUN )); then
      echo "(dry-run) would write overflow locator at $LOCATOR_OFFSET"
    else
      sudo env LOOP="$LOOP" LOCATOR_OFFSET="$LOCATOR_OFFSET" python3 - <<'PY'
import struct, os, sys
loop_dev = os.environ['LOOP']
loc_off = int(os.environ['LOCATOR_OFFSET'])
with open(loop_dev, 'rb', buffering=0) as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    if len(locator_data) < 24:
        sys.stderr.write('ERROR: short locator read\n')
        sys.exit(2)
    magic, version, orig_meta_off, orig_meta_len, orig_sig_off, orig_sig_len = struct.unpack('<IIIIII', locator_data)
print('Original values:')
print(f'  meta_off: {orig_meta_off}, meta_len: {orig_meta_len}')
print(f'  sig_off:  {orig_sig_off}, sig_len:  {orig_sig_len}')
# Values that would wrap when added
meta_off = 0xFFFFFF00
meta_len = 0xFFFFFF00
sig_off = 0xFFFF0000
sig_len = 0xFFFF0000
print('Corrupted values:')
print(f'  meta_off: {meta_off} (0x{meta_off:08x})')
print(f'  meta_len: {meta_len} (0x{meta_len:08x})')
print(f'  sig_off:  {sig_off} (0x{sig_off:08x})')
print(f'  sig_len:  {sig_len} (0x{sig_len:08x})')
new_locator = struct.pack('<IIIIII', magic, version, meta_off, meta_len, sig_off, sig_len)
with open(loop_dev, 'r+b', buffering=0) as f:
    f.seek(loc_off)
    written = f.write(new_locator)
    if written != len(new_locator):
        sys.stderr.write('ERROR: short write when updating locator\n')
        sys.exit(2)
    f.flush(); os.fsync(f.fileno())
print('SUCCESS: Locator corrupted with overflow values')
# verify
with open(loop_dev, 'rb', buffering=0) as f:
    f.seek(loc_off)
    verify_data = f.read(24)
    v_magic, v_ver, v_meta_off, v_meta_len, v_sig_off, v_sig_len = struct.unpack('<IIIIII', verify_data)
    print('Verification:')
    print(f'  meta_off: {v_meta_off} (0x{v_meta_off:08x})')
    print(f'  meta_len: {v_meta_len} (0x{v_meta_len:08x})')
PY
    fi
    ;;

  buf_overflow)
    echo "==> Setting huge metadata length (correct 4-byte format)..."
    if (( DRYRUN )); then
      echo "(dry-run) would set meta_len to 0xFFFFFFFF at locator $LOCATOR_OFFSET"
    else
      sudo env LOOP="$LOOP" LOCATOR_OFFSET="$LOCATOR_OFFSET" python3 - <<'PY'
import struct, os, sys
loop_dev = os.environ['LOOP']
loc_off = int(os.environ['LOCATOR_OFFSET'])
with open(loop_dev, 'rb', buffering=0) as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    if len(locator_data) < 24:
        sys.stderr.write('ERROR: short locator read\n'); sys.exit(2)
    magic, version, meta_off, meta_len, sig_off, sig_len = struct.unpack('<IIIIII', locator_data)
    print('Before corruption:')
    print(f'  meta_off:  {meta_off} (0x{meta_off:08x})')
    print(f'  meta_len:  {meta_len} (0x{meta_len:08x})')
new_meta_len = 0xFFFFFFFF
print(f'Setting meta_len to: {new_meta_len} (0x{new_meta_len:08x})')
new_locator = struct.pack('<IIIIII', magic, version, meta_off, new_meta_len, sig_off, sig_len)
with open(loop_dev, 'r+b', buffering=0) as f:
    f.seek(loc_off)
    written = f.write(new_locator)
    if written != len(new_locator):
        sys.stderr.write('ERROR: short write when updating locator\n'); sys.exit(2)
    f.flush(); os.fsync(f.fileno())
print('SUCCESS: Locator corrupted with huge meta_len')
# Verify
with open(loop_dev, 'rb', buffering=0) as f:
    f.seek(loc_off)
    verify_data = f.read(24)
    v_magic, v_ver, v_meta_off, v_meta_len, v_sig_off, v_sig_len = struct.unpack('<IIIIII', verify_data)
    print('After corruption:')
    print(f'  meta_len: {v_meta_len} (0x{v_meta_len:08x})')
PY
    fi
    ;;

  trunc_meta)
    echo "==> Declaring longer metadata than exists (truncated metadata test)..."
    if (( DRYRUN )); then
      echo "(dry-run) would set meta_off near end and meta_len > available bytes"
    else
      sudo env LOOP="$LOOP" LOCATOR_OFFSET="$LOCATOR_OFFSET" DISK_BYTES="$DISK_BYTES" python3 - <<'PY'
import struct, os, sys
loop_dev = os.environ['LOOP']
loc_off = int(os.environ['LOCATOR_OFFSET'])
size = int(os.environ['DISK_BYTES'])
with open(loop_dev, 'rb', buffering=0) as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    if len(locator_data) < 24:
        sys.stderr.write('ERROR: short locator read\n'); sys.exit(2)
    magic, version, orig_meta_off, orig_meta_len, orig_sig_off, orig_sig_len = struct.unpack('<IIIIII', locator_data)
print(f'Disk size: {size} bytes')
meta_off = size - 100
meta_len = 4096
sig_off = orig_sig_off
sig_len = orig_sig_len
print('Truncated metadata values:')
print(f'  meta_off: {meta_off} (only {size-meta_off} bytes available)')
print(f'  meta_len: {meta_len} (but only {size-meta_off} bytes exist)')
print(f'  Would read to: {meta_off + meta_len} (beyond disk end!)')
new_locator = struct.pack('<IIIIII', magic, version, meta_off, meta_len, sig_off, sig_len)
with open(loop_dev, 'r+b', buffering=0) as f:
    f.seek(loc_off)
    written = f.write(new_locator)
    if written != len(new_locator):
        sys.stderr.write('ERROR: short write when updating locator\n'); sys.exit(2)
    f.flush(); os.fsync(f.fileno())
print('SUCCESS: Locator corrupted with truncated metadata claim')
PY
    fi
    ;;

  bad_offsets)
    echo "==> Writing locator with offsets beyond disk end (malformed fields)..."
    if (( DRYRUN )); then
      echo "(dry-run) would write offsets beyond disk end at locator $LOCATOR_OFFSET"
    else
      sudo env LOOP="$LOOP" LOCATOR_OFFSET="$LOCATOR_OFFSET" DISK_BYTES="$DISK_BYTES" python3 - <<'PY'
import struct, os, sys
loop_dev = os.environ['LOOP']
loc_off = int(os.environ['LOCATOR_OFFSET'])
size = int(os.environ['DISK_BYTES'])
with open(loop_dev, 'rb', buffering=0) as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    if len(locator_data) < 24:
        sys.stderr.write('ERROR: short locator read\n'); sys.exit(2)
    magic, version, orig_meta_off, orig_meta_len, orig_sig_off, orig_sig_len = struct.unpack('<IIIIII', locator_data)
print(f'Disk size: {size} bytes')
meta_off = size + (1 << 20)
sig_off = size + (1 << 21)
meta_len = 512
sig_len = 256
print('Bad offset values:')
print(f'  meta_off: {meta_off} ({meta_off - size} bytes beyond disk)')
print(f'  sig_off:  {sig_off} ({sig_off - size} bytes beyond disk)')
new_locator = struct.pack('<IIIIII', magic, version, meta_off, meta_len, sig_off, sig_len)
with open(loop_dev, 'r+b', buffering=0) as f:
    f.seek(loc_off)
    written = f.write(new_locator)
    if written != len(new_locator):
        sys.stderr.write('ERROR: short write when updating locator\n'); sys.exit(2)
    f.flush(); os.fsync(f.fileno())
print('SUCCESS: Locator corrupted with beyond-end offsets')
PY
    fi
    ;;

  sanitize)
    echo "==> Writing locator with random garbage fields (general input sanitation test)..."
    if (( DRYRUN )); then
      echo "(dry-run) would write random garbage to locator $LOCATOR_OFFSET"
    else
      sudo env LOOP="$LOOP" LOCATOR_OFFSET="$LOCATOR_OFFSET" python3 - <<'PY'
import struct, os, random, sys
loop_dev = os.environ['LOOP']
loc_off = int(os.environ['LOCATOR_OFFSET'])
magic = random.randint(0, 0xFFFFFFFF)
version = random.randint(0, 10)
meta_off = random.randint(0, 0xFFFFFFFF)
meta_len = random.randint(0, 0xFFFFFFFF)
sig_off = random.randint(0, 0xFFFFFFFF)
sig_len = random.randint(0, 0xFFFFFFFF)
print('Random garbage values:')
print(f'  magic:    0x{magic:08x}')
print(f'  version:  {version}')
new_locator = struct.pack('<IIIIII', magic, version, meta_off, meta_len, sig_off, sig_len)
with open(loop_dev, 'r+b', buffering=0) as f:
    f.seek(loc_off)
    written = f.write(new_locator)
    if written != len(new_locator):
        sys.stderr.write('ERROR: short write when updating locator\n'); sys.exit(2)
    f.flush(); os.fsync(f.fileno())
print('SUCCESS: Locator replaced with random garbage')
PY
    fi
    ;;

  *)
    echo "ERROR: unknown mode: $MODE" >&2
    exit 2
    ;;
esac

# Sync and detach loop, unless dry-run
if (( ! DRYRUN )); then
  sync
  sudo losetup -d "$LOOP" || true
  unset LOOP
  trap - EXIT
fi

# Post-change reporting
if [[ "$MODE" == "meta1" && -n "${BEFORE:-}" && (( ! DRYRUN )) ]]; then
  echo "Post-checksum:" 
  # compute header digest again was already printed earlier; ensure it's available
fi

cat <<EOF
Done → $BAD_IMG
Expected behavior summary:
EOF
case "$MODE" in
  meta1)
    echo "  - dm-verity metadata header changed -> metadata verification or dm table creation should fail early."
    ;;
  sig1)
    echo "  - dm-verity parameters may parse, but PKCS#7 verification should fail."
    ;;
  int_overflow)
    echo "  - parser should detect wrap-around/overflow in locator offsets and reject."
    ;;
  buf_overflow)
    echo "  - kernel should safely reject metadata length exceeding image bounds."
    ;;
  trunc_meta)
    echo "  - parser should fail cleanly on truncated metadata reads."
    ;;
  bad_offsets)
    echo "  - parser should validate offsets and reject beyond-end values."
    ;;
  sanitize)
    echo "  - parser should handle arbitrary garbage fields without panic."
    ;;
esac

if (( DRYRUN )); then
  echo "(dry-run) no changes were made."
fi

exit 0
