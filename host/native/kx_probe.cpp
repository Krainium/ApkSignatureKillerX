// kx_probe — drive the KillerX demo over adb and report which signature reads
// the killer held vs which leaked the real re-signed cert.
//
// It connects with the raw protocol client (adb_client), clears logcat, launches
// MainActivity, then reads the KillerXProbe log lines the app emits and prints a
// verdict table. Exit code 0 means the run matched expectations.
//
//   kx_probe [-s SERIAL] [--pkg com.killerx.demo] [--activity .MainActivity]
//            [--timeout 60] [--expect-svc-held]
//
// By default the SVC row is EXPECTED to leak (that is the whole point without the
// seccomp trap). Pass --expect-svc-held when the apk was built with the trap on.
#include "adb_client.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <map>
#include <unistd.h>

struct Row {
    std::string md5;
    bool held = false;
    bool seen = false;
};

static std::string tail_after(const std::string &line, const std::string &tag) {
    auto p = line.find(tag);
    if (p == std::string::npos) return "";
    return line.substr(p + tag.size());
}

int main(int argc, char **argv) {
    const char *serial = nullptr;
    std::string pkg = "com.killerx.demo";
    // exported launcher entry; it forwards to MainActivity which emits the probes.
    std::string activity = ".SplashActivity";
    int timeout = 60;
    bool expectSvcHeld = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-s" && i + 1 < argc) serial = argv[++i];
        else if (a == "--pkg" && i + 1 < argc) pkg = argv[++i];
        else if (a == "--activity" && i + 1 < argc) activity = argv[++i];
        else if (a == "--timeout" && i + 1 < argc) timeout = atoi(argv[++i]);
        else if (a == "--expect-svc-held") expectSvcHeld = true;
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }

    static char buf[1 << 20];
    size_t len = 0;

    // 1. clear logcat and (re)launch the activity fresh.
    if (adb_shell(serial, "logcat -c", buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "kx_probe: %s\n", adb_last_error());
        return 1;
    }
    adb_shell(serial, ("am force-stop " + pkg).c_str(), buf, sizeof(buf), &len);
    std::string start = "am start -n " + pkg + "/" + activity;
    if (adb_shell(serial, start.c_str(), buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "kx_probe: launch failed: %s\n", adb_last_error());
        return 1;
    }
    printf("[*] launched %s/%s\n", pkg.c_str(), activity.c_str());

    // 2. poll the probe log until DONE or timeout.
    std::string expected;
    std::map<std::string, Row> rows;
    bool done = false;
    for (int elapsed = 0; elapsed < timeout && !done; elapsed += 2) {
        sleep(2);
        if (adb_shell(serial, "logcat -d -s KillerXProbe:I", buf, sizeof(buf), &len) != 0)
            continue;
        std::string log(buf);
        size_t pos = 0;
        while (pos < log.size()) {
            size_t nl = log.find('\n', pos);
            std::string line = log.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
            pos = (nl == std::string::npos) ? log.size() : nl + 1;

            std::string body = tail_after(line, "KillerXProbe:");
            if (body.empty()) continue;
            // trim leading spaces
            size_t s = body.find_first_not_of(' ');
            if (s == std::string::npos) continue;
            body = body.substr(s);

            if (body.rfind("EXPECTED ", 0) == 0) {
                expected = body.substr(9);
                size_t e = expected.find_first_of(" \r");
                if (e != std::string::npos) expected = expected.substr(0, e);
            } else if (body.rfind("DONE", 0) == 0) {
                done = true;
            } else {
                // "<LABEL> <md5> <HELD|LEAKED>"
                char label[32], md5[64], verdict[16];
                if (sscanf(body.c_str(), "%31s %63s %15s", label, md5, verdict) == 3) {
                    std::string L(label);
                    if (L == "API" || L == "SIGNINFO" || L == "APK" || L == "SVC" ||
                        L == "DIGEST" || L == "MAPS" || L == "PAIRIP" || L == "HASCERT" ||
                        L == "INSTALLER" || L == "CODEINTEG") {
                        Row r;
                        r.md5 = md5;
                        r.held = (strcmp(verdict, "HELD") == 0 ||
                                  strcmp(verdict, "HIDDEN") == 0 ||
                                  strcmp(verdict, "NEUTRALIZED") == 0 ||
                                  strcmp(verdict, "NOT_PRESENT") == 0 ||
                                  strcmp(verdict, "PASS") == 0 ||
                                  strcmp(verdict, "PLAY_STORE") == 0 ||
                                  strcmp(verdict, "CACHED") == 0);
                        r.seen = true;
                        rows[L] = r;
                    }
                }
            }
        }
    }

    if (!done && rows.empty()) {
        fprintf(stderr, "kx_probe: no probe output (is the killer/demo installed and launchable?)\n");
        return 1;
    }

    // 3. verdict table.
    printf("\n  expected original md5: %s\n\n", expected.c_str());
    printf("  %-9s %-34s %s\n", "PROBE", "MD5 SEEN", "RESULT");
    printf("  %-9s %-34s %s\n", "-----", "--------", "------");
    const char *order[] = {"API", "SIGNINFO", "APK", "SVC", "DIGEST", "MAPS", "PAIRIP", "HASCERT", "INSTALLER", "CODEINTEG"};
    int failures = 0;
    for (const char *k : order) {
        auto it = rows.find(k);
        if (it == rows.end()) {
            printf("  %-9s %-34s %s\n", k, "(not seen)", "MISSING");
            failures++;
            continue;
        }
        const Row &r = it->second;
        bool wantHeld = expectSvcHeld || strcmp(k, "SVC") != 0;
        bool ok = (r.held == wantHeld);
        const char *tag = r.held ? "HELD (faked)" : "LEAKED (real)";
        printf("  %-9s %-34s %s  [%s]\n", k, r.md5.c_str(), tag, ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }
    printf("\n%s\n", failures == 0 ? "RESULT: PASS" : "RESULT: FAIL");
    return failures == 0 ? 0 : 1;
}
