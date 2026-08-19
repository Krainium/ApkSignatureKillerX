// kx_adb — tiny adb front end built on the raw protocol client.
//
//   kx_adb devices
//   kx_adb [-s SERIAL] shell <command...>
//
// Handy on its own and used by killerx.sh as the connection primitive.
#include "adb_client.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int usage(void) {
    fprintf(stderr,
        "usage:\n"
        "  kx_adb devices\n"
        "  kx_adb [-s SERIAL] shell <command...>\n");
    return 2;
}

int main(int argc, char **argv) {
    const char *serial = NULL;
    int i = 1;
    if (i < argc && strcmp(argv[i], "-s") == 0) {
        if (i + 1 >= argc) return usage();
        serial = argv[i + 1];
        i += 2;
    }
    if (i >= argc) return usage();

    if (strcmp(argv[i], "devices") == 0) {
        char out[8192];
        if (adb_devices(out, sizeof(out)) != 0) {
            fprintf(stderr, "kx_adb: %s\n", adb_last_error());
            return 1;
        }
        fputs(out, stdout);
        return 0;
    }

    if (strcmp(argv[i], "shell") == 0) {
        if (i + 1 >= argc) return usage();
        char cmd[4000] = {0};
        for (int j = i + 1; j < argc; j++) {
            if (j > i + 1) strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
            strncat(cmd, argv[j], sizeof(cmd) - strlen(cmd) - 1);
        }
        static char out[1 << 20]; // 1 MB
        size_t len = 0;
        if (adb_shell(serial, cmd, out, sizeof(out), &len) != 0) {
            fprintf(stderr, "kx_adb: %s\n", adb_last_error());
            return 1;
        }
        fputs(out, stdout);
        return 0;
    }

    return usage();
}
