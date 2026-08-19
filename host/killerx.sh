#!/usr/bin/env bash
# killerx.sh — one-shot host driver for the KillerX demo over adb.
#
# it builds the native adb cores, installs the demo apk, launches it, and grades
# the four signature probes (API / SIGNINFO / APK / SVC) straight from the
# device log. works against a phone, an emulator, or a redroid container.
#
# usage: killerx.sh [apk] [--serial SERIAL] [--expect-svc-held]
#   apk                 path to the demo apk (default: newest app-debug.apk)
#   --serial SERIAL     target device (default: first connected)
#   --expect-svc-held   grade the SVC row as pass when it is HELD (apk built with
#                       the seccomp trap on); default expects SVC to leak
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
NATIVE="$HERE/native"
PKG="com.killerx.demo"

APK=""; SERIAL=""; EXPECT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --serial) SERIAL="$2"; shift 2;;
    --expect-svc-held) EXPECT="--expect-svc-held"; shift;;
    *.apk) APK="$1"; shift;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

# --- pick the apk ---
if [ -z "$APK" ]; then
  APK=$(ls -t "$ROOT"/app/build/outputs/apk/debug/*.apk 2>/dev/null | head -1)
fi
[ -z "$APK" ] || [ ! -f "$APK" ] && { echo "no apk found; build with ./gradlew :app:assembleDebug or pass one"; exit 1; }

# --- adb server + serial autodetect (redroid shows up as 127.0.0.1:5555) ---
adb start-server >/dev/null 2>&1 || true
if [ -z "$SERIAL" ]; then
  SERIAL=$(adb devices | awk 'NR>1 && $2=="device"{print $1; exit}')
fi
[ -z "$SERIAL" ] && { echo "no device. connect one (adb connect 127.0.0.1:5555 for redroid)"; exit 1; }
echo "[*] target: $SERIAL"
echo "[*] apk:    $APK"

# --- build native cores if missing ---
mkdir -p "$NATIVE"
[ -x "$NATIVE/kx_adb" ]          || cc  -O2 -o "$NATIVE/kx_adb"          "$NATIVE/kx_adb.c" "$NATIVE/adb_client.c"       || exit 1
[ -x "$NATIVE/kx_probe" ]        || c++ -O2 -o "$NATIVE/kx_probe"        "$NATIVE/kx_probe.cpp" "$NATIVE/adb_client.c"   || exit 1
[ -x "$NATIVE/kx_seccomp_test" ] || cc  -O2 -o "$NATIVE/kx_seccomp_test" "$NATIVE/kx_seccomp_test.c"                     || exit 1

# --- connection sanity via the raw client ---
echo "[*] devices (via kx_adb):"
"$NATIVE/kx_adb" devices | sed 's/^/    /'

# --- install + grade ---
echo "[*] installing"
adb -s "$SERIAL" install -r -g "$APK" 2>&1 | tail -1
echo "[*] probing"
"$NATIVE/kx_probe" -s "$SERIAL" --pkg "$PKG" $EXPECT
RC=$?

# --- bonus: prove the seccomp trap catches a direct svc syscall ---
# the trap is a KERNEL mechanism; a redroid guest shares the host kernel, so the
# host self-test exercises the same path. we run it on the host (glibc), and if an
# NDK is around we also build a bionic copy and run it on the device itself.
echo
echo "[*] seccomp/svc trap self-test (host kernel):"
if [ "$(uname -m)" = "aarch64" ]; then
  "$NATIVE/kx_seccomp_test" | sed 's/^/    /'
else
  echo "    host is not aarch64; skipping"
fi

NDK_CC=$(ls "${ANDROID_NDK:-$ANDROID_SDK_ROOT/ndk}"/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang 2>/dev/null | head -1)
ABI=$(adb -s "$SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r')
if [ -n "$NDK_CC" ] && echo "$ABI" | grep -q arm64; then
  echo "[*] seccomp/svc trap self-test (on device, bionic):"
  "$NDK_CC" -O2 -static -o "$NATIVE/kx_seccomp_test.android" "$NATIVE/kx_seccomp_test.c" 2>/dev/null \
    && adb -s "$SERIAL" push "$NATIVE/kx_seccomp_test.android" /data/local/tmp/kx_sct >/dev/null 2>&1 \
    && adb -s "$SERIAL" shell chmod 755 /data/local/tmp/kx_sct \
    && adb -s "$SERIAL" shell /data/local/tmp/kx_sct | sed 's/^/    /'
fi

exit $RC
