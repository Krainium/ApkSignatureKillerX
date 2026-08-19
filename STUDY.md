# ApkSignatureKillerX Research

Design rationale, reference analysis, and implementation notes for
ApkSignatureKillerX. For usage and deployment, see [README.md](README.md).

---

## Problem Statement

When an APK is repackaged and re-signed with a different key, any runtime
self-signature check sees the wrong certificate and terminates. A "signature
killer" intercepts those checks and returns the original certificate.

This is a runtime, in-app bypass: the app is installed with the attacker's key,
and we fake what the app's own code reads. It is not an install-time bypass
(that is CorePatch, a system/Xposed patch of PackageManagerService).

---

## ApkSignatureKillerEx Analysis

The reference implementation (`KillerApplication`) runs in the Application
static block before app code and performs two bypasses:

**killPM** (Java, PackageManager API path): replaces `PackageInfo.CREATOR` via
reflection with a wrapper that swaps `signatures[0]` and (API 28+)
`signingInfo.getApkContentsSigners()[0]` to the bundled original certificate.
Clears `PackageManager.sPackageInfoCache`, `Parcel.mCreators`, and
`Parcel.sPairedCreators`. Uses LSPosed HiddenApiBypass for hidden fields on
API 28+. Defeats `getPackageInfo(pkg, GET_SIGNATURES | GET_SIGNING_CERTIFICATES)`.

**killOpen** (native, file read path): hooks `open/open64/openat/openat64` via
xHook (iqiyi PLT/GOT hook library) across all loaded `.so` files. When code
opens the app's own APK path (resolved via `/proc/self/maps`), it is redirected
to `origin.apk`. Defeats checks that read `META-INF/*.RSA` via ZipFile.

**The SVC counter** it also ships: reads the APK with a direct `svc #0` openat
syscall (inline assembly, `__NR_openat`, x8/r7), bypassing the libc PLT entry
that xHook hooks. Sees the real re-signed APK, detects tampering. This proves
PLT/GOT hooking alone is insufficient; a stronger killer needs syscall-level
or filesystem-level interception.

---

## Signature Check Attack Surface

| Path | Method | Layer |
|---|---|---|
| PackageManager API | `getPackageInfo` with `GET_SIGNATURES` / `GET_SIGNING_CERTIFICATES` | Java/Binder |
| APK file read | `ZipFile(getPackageResourcePath())` over `META-INF/*.RSA` | libc open |
| APK Signing Block | Direct parse of v2/v3 signing block bytes | libc open/mmap |
| Native hardcoded | Hash signer bytes, compare to constant in `.so` | often direct SVC |
| Server-side | Send signature/attestation to backend | cannot fake on device |

---

## APK Signature Schemes

| Scheme | Android | Description |
|---|---|---|
| v1 (JAR) | all, rejected on 11+ for targetSdk>=30 | META-INF/MANIFEST.MF + *.SF + *.RSA, per-file digests |
| v2 | 7+ | APK Signing Block ("APK Sig Block 42"), whole-file integrity |
| v3 | 9+ | v2 + key rotation (proof-of-rotation) |
| v4 | 11+ | separate .idsig file, incremental/streaming install |

Modifying the ZIP with plain tools drops the signing block and breaks v2/v3.
Re-signing with a new key is the standard path: `zipalign -p 4` before
`apksigner sign --ks`.

---

## Bypass Toolbox

**In-app injection**: inject Application subclass via smali so kill code runs
first. apktool d -> add smali -> set `android:name` -> apktool b -> zipalign ->
apksigner. Tools: Repackman, smali-baker, APKLab.

**Java reflection**: APKKiller (aimardcr), the killPM technique.
Frida-Sign-Hook-Generator auto-builds hooks for getPackageInfo + MessageDigest.

**Frida**: hook `PackageManager.getPackageInfo` overload; return faked
signatures. Requires frida-server (root) or a gadget.

**Non-root frameworks**: LSPatch injects .dex+.so into the target APK so
Xposed modules load in-app (Local or Integrated mode; Shizuku).

**System-level**: CorePatch patches PackageManagerService to skip signature
checks + allow downgrade. Apk-Signature-Verification-Patch (Magisk/KSU).
Requires root + Xposed/Magisk.

**Smali short-circuit**: force the final boolean (`const/4 v0, 0x1`) or invert
branches at the compare site.

**Native .so patch**: replace or hex-edit the `.so` on a rooted device without
breaking the APK signature.

---

## Modern Defenses

**PairIP** (Google, 2024, `libpairipcore.so`): VM-based, native, obfuscated.
Validates install-from-Play + signature, detects frida/gdb (ptrace, prctl,
/proc/self/status, self-hashing, hooked mmap/mprotect). Bypass research: hook
RegisterNatives, dump decrypted bytecode, Unicorn emulate; LSPosed modules
pairipfix / bypass_pairipcore exist.

**Play Integrity / SafetyNet**: verdict signed by Google Play services,
verified on the app's server. Cannot forge on device. MEETS_STRONG_INTEGRITY
is hardware-backed.

**RASP (Talsec freeRASP, YinkoShield)**: continuous signature + cert-hash +
code/resource integrity, hook detection, native + server-validated. Talsec
explicitly targets ApkSignatureKiller. Detection methods: SVC direct-syscall
APK read, GOT-entry scanning, prologue hashing, statically linked libc.

---

## KillerX Design Decisions

How the research shaped the implementation, keyed to sources below:

**killPM** retained [2][3][20], rewritten in Kotlin with v3 rotation history
and ApplicationPackageManager cache handling.

**killOpen** upgraded from xHook [9] to ByteHook [5], the maintained PLT/GOT
engine from ByteDance.

**SVC gap** [1][10] addressed at three levels:
- Bind mount: `mount -o bind origin.apk base.apk`. Filesystem-level redirect;
  covers all access paths including dynamic SVC. Most reliable for VMP targets.
- SVC binary patching: scans loaded `.so` for `svc #0`, rewrites to trampoline
  stubs routing through `kx_handle_svc()`. Covers openat, newfstatat, kill,
  tgkill, exit, exit_group. Static sites only.
- Antikill seccomp: SECCOMP_RET_ERRNO for kill/tgkill targeting self with
  SIGKILL/SIGTERM/SIGABRT. Catches dynamic SVC kill attempts at kernel boundary.
- Seccomp openat redirect: SIGSYS trap on openat/newfstatat, openat2/statx
  escape. Proven on arm64, but incompatible with VMP (see below).

**LD_PRELOAD + wrap.sh**: constructor-based init, loads before any packer code.
The only way to get ahead of Ijiami 4th-gen native anti-tamper (kills re-signed
APKs in ~28ms).

**Anti-detection** layers: proc file filtering (maps, mountinfo, environ,
status), property hook (wrap.\*), artifact hiding (stat/access/readdir),
LD_PRELOAD env cleanup. Typed fd tracking with proxy_close to prevent stale
fd misclassification.

**Attestation** [18][19] implemented at the in-app layer: DeviceSpoof rewrites
`android.os.Build` to a certified fingerprint (the PlayIntegrityFix [18]
technique), and PlayIntegrityProbe runs the real verdict flow [19]. The real PIF
spoofs inside Play services (Zygisk) to move the verdict; our in-process spoof
only defeats app-side Build checks.

**Play Integrity in bind mount mode**: the original APK is installed with its
genuine signing certificate. The APK is never re-signed, so Play Integrity sees
the authentic cert and app recognition passes. This is a fundamental advantage
over standard repackage mode, where Google's server-side check detects the
attacker cert (`UNRECOGNIZED_VERSION` on the demo app with `fake.jks`).

**RASP neutralization**: exit/kill/abort/raise/tgkill/pthread_kill hooked at
both PLT and SVC levels. Seccomp antikill catches dynamic SVC termination.

**Probe evasion**: /proc/self/maps read() hook filters library names at native
level (killerx, bytehook, shadowhook all hidden).

**Out of scope**: install-time bypass [16], Xposed spoofing [17] (system/module
level, not in-app).

**Remaining gaps**: GOT inline detection (app scanning own GOT for hook stubs),
PairIP VM-based integrity.

---

## Bind Mount Mode

For VMP-packed targets (Ijiami, Bangcle) the standard repackage flow fails
because native anti-tamper checks the APK signing block before any Java code
runs. Ijiami 4th-gen (`libexec.so`) kills re-signed APKs in ~28ms via
SIGSEGV-based virtual machine execution.

Bind mount solves this: keep the original APK installed, bind-mount it over
`base.apk` so all file access sees original signatures, and inject KillerX via
LD_PRELOAD (wrap.sh). The constructor runs at process fork, before any native
library loads.

Verified against Ijiami 4th-gen VMP at level 7. All hooks active, process
stable, mmap redirect working.

### Why Seccomp Redirect Fails with VMP

Seccomp openat redirect installs a SIGSYS handler. VMP packers use
SIGSEGV-based virtual machine execution for code obfuscation. The two signal
handlers compete: SIGSYS overhead on every openat call triggers the packer's
anti-tamper SIGSEGV spinning (10K+ absorbed faults at low pc addresses
indicating VMP bytecode execution). The process self-terminates.

Moving seccomp install from the constructor to a dlopen trigger (when packer
lib is detected) does not help. The conflict is fundamental to the signal
handler mechanism.

Bind mount avoids this entirely: no signal handlers, no syscall interception.
The filesystem returns original content transparently.

---

## Anti-Detection Implementation

| Vector | Hook | Spoofed result |
|---|---|---|
| `/proc/self/maps` | `proxy_read` + `match_maps` | killerx/bytehook/shadowhook lines removed |
| `/proc/self/mountinfo` | `proxy_read` + `match_mountinfo` | bind mount entries removed |
| `/proc/self/environ` | `proxy_read` + `filter_environ` | LD_PRELOAD/LD_LIBRARY_PATH stripped |
| `/proc/self/status` | `proxy_read` + `filter_status` | Seccomp: 0, Seccomp_filters: 0 |
| `wrap.*` property | `proxy___system_property_get` | empty string |
| artifact stat/access | `proxy_stat`, `proxy_lstat`, `proxy_access` | ENOENT |
| artifact readdir | `proxy_readdir` | entries skipped |
| `LD_PRELOAD` env | constructor `unsetenv` | removed before app code |

**Typed fd tracking**: `proxy_openat` classifies paths into `KX_PROC_MAPS`,
`KX_PROC_MOUNTINFO`, `KX_PROC_ENVIRON`, `KX_PROC_STATUS`. `proxy_read`
dispatches filtering by type. `proxy_close` untracks fds to prevent false
filtering on fd reuse.

**Hidden artifacts** under `/data/local/tmp`: `origin.apk`, `libkillerx.so`,
`libbytehook.so`, `wrap.sh`, `.killerx_*`, `.kx_*`, `wrap_*`.

---

## Pitfalls

1. **Do not hook fstat.** Causes `_exit(1)` during ART init. The `fd_is_apk()`
   check does readlink on `/proc/self/fd/N` for every fstat call, overflowing
   ART's stack protection region. The RASP hook blocks `_exit(1)`, suspending
   the thread, and ActivityManager kills the process on start timeout.

2. **Do not block exit/exit_group in seccomp.** Child processes (idmap2,
   dex2oat) call exit normally. Blocking it kills them.

3. **Do not install seccomp openat redirect with VMP.** SIGSYS handler conflicts
   with SIGSEGV-based VM execution. Even from a dlopen trigger, the packer's
   anti-tamper SIGSEGV spinning kills the process. Use bind mount instead.

4. **SVC binary patching finds zero sites on VMP targets.** VMP generates SVC
   instructions dynamically at runtime. Static scanning of loaded `.so` files
   misses them. Bind mount covers these at the filesystem level.

---

## Sources

Fetched and verified while building ApkSignatureKillerX. Grouped by role;
bracket numbers show how each source informed the design.

### Signature Kill Mechanics

1. L-JINBIN/ApkSignatureKillerEx
   https://github.com/L-JINBIN/ApkSignatureKillerEx
   Canonical reference [CREATOR hook + xHook redirect + SVC counter].

2. szczecin, "Android Signature Acquisition" (2024)
   https://szczecin.github.io/2024/01/25/Android-Signature/
   Source-level walkthrough of all three read paths and cache clearing.

3. Talsec, "ApkSignatureKiller: How It Works" (2025)
   https://medium.com/@talsec/apksignaturekiller-how-it-works-and-how-talsec-protects-your-apps-c8d531e287c2
   Defender perspective on the framework-level attack.

4. aimardcr/APKKiller
   https://github.com/aimardcr/APKKiller
   Reflection-only signature/integrity bypass.

### Native Hooking

5. bytedance/bhook (ByteHook)
   https://github.com/bytedance/bhook
   PLT/GOT engine used in killerx.c. Replaces xHook.

6. bytedance/android-inline-hook (ShadowHook)
   https://github.com/bytedance/android-inline-hook
   Inline hook alternative; documents PLT vs inline trade-offs.

7. jmpews/Dobby
   https://github.com/jmpews/Dobby
   Cross-platform inline hook reference.

8. Rprop/And64InlineHook
   https://github.com/Rprop/And64InlineHook
   arm64 inline hook reference.

9. iqiyi/xHook
   https://github.com/iqiyi/xHook
   Original Ex engine; baseline replaced by ByteHook.

10. axhlzy, "Syscalls and Inline Assembly" (2025)
    https://medium.com/@axhlzy/android-reverse-engineering-basics-syscalls-and-inline-assembly-27587365f329
    Direct syscall technique [raw_syscall.c + seccomp rationale].

11. marginaldeer, "Hooking Native Libraries with Frida" (2025)
    https://www.marginaldeer.com/blog/frida-native-hooking/
    Why kernel-level interception matters.

### Signature Scheme Internals

12. AOSP APK Signature Scheme v2/v3/v4
    https://source.android.com/docs/security/features/apksigning/v2
    Ground truth on signing block bytes.

13. PTKD, "APK Signing Schemes Explained" (2026)
    https://ptkd.com/journal/apk-signing-schemes-v2-v3-v4-explained
    Concise framing of what a killer must spoof.

14. obfusk/apksigtool
    https://github.com/obfusk/apksigtool
    Pure-Python signing block parse/verify.

15. patrickfav/uber-apk-signer
    https://github.com/patrickfav/uber-apk-signer
    v1-v4 sign/zipalign/verify tooling.

### Attestation and System-Level

16. LSPosed/CorePatch
    https://github.com/LSPosed/CorePatch
    System-side PMS signature bypass (contrast: KillerX is in-app).

17. rushiiMachine/XSpoofSignatures
    https://github.com/rushiiMachine/XSpoofSignatures
    Xposed signature spoofing (2025).

18. KOWX712/PlayIntegrityFix
    https://github.com/KOWX712/PlayIntegrityFix
    Maintained PIF fork; attestation frontier.

19. m4kr0x, "Play Integrity API: How to Bypass It" (2026)
    https://m4kr0x.medium.com/play-integrity-api-how-it-works-how-to-bypass-it-f478f68cbc33
    Keybox/TrickyStore state of the art; STRONG is hardware-backed.

20. apkunpacker/FridaScripts
    https://github.com/apkunpacker/FridaScripts
    Dynamic PackageManager hooks; Frida equivalent of killPM.
