// Minimal ADB smart-socket client. Speaks the adb server protocol on
// 127.0.0.1:5037 directly, so the host cores talk to a device (or a redroid
// container) without shelling out to the adb binary for every call.
//
// Protocol recap: each request is a 4-hex-digit ASCII length followed by the
// payload. The server answers OKAY or FAIL. Host services (host:devices) then
// return a 4-hex length + data and close. After a host:transport switch, a local
// service (shell:...) streams raw bytes until EOF.
#ifndef KX_ADB_CLIENT_H
#define KX_ADB_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// adb server endpoint (override with ADB_SERVER_PORT env if set).
int  adb_server_port(void);

// Ask the server for the device list (host:devices). Returns 0 on success and
// fills out[] (NUL-terminated). Non-zero on error.
int  adb_devices(char *out, size_t out_sz);

// Run `cmd` in a device shell and capture everything it prints until the shell
// closes. serial may be NULL/"" to use transport-any (first/only device).
// Returns 0 on success. out gets the (possibly truncated) NUL-terminated output;
// *out_len (if non-NULL) gets the real captured length.
int  adb_shell(const char *serial, const char *cmd,
               char *out, size_t out_sz, size_t *out_len);

// Last human-readable error from the calls above.
const char *adb_last_error(void);

#ifdef __cplusplus
}
#endif

#endif // KX_ADB_CLIENT_H
