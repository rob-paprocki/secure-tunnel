// Secure Tunnel tunnel core: C interface for the iOS packet tunnel extension.
// Strings are UTF-8. Strings returned by the core are freed with st_string_free.
#ifndef SECURETUNNEL_H
#define SECURETUNNEL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StSession StSession;

// Reads a WireGuard or AmneziaWG profile and returns JSON:
// {"ok":true,"value":{"addresses":[..],"dns":[..],"routes":[..],"mtu":1420,
//  "server":"ip:port","proxy":"","allowed_apps":[..],"disallowed_apps":[..],"protection":"..."}}
// or {"ok":false,"error":"..."}. Resolve before the tunnel is up.
char *st_plan(const char *config);

// Starts the tunnel on the utun descriptor `fd` (utun_header = true on iOS).
// `server` and `proxy` are the plan's resolved addresses. Returns NULL on
// failure with the reason in *error.
StSession *st_start(const char *config, int32_t fd, bool utun_header,
                    const char *server, const char *proxy, char **error);

// {"connected":bool,"handshake_secs":n,"tx":n,"rx":n,"loss":f,"rtt_ms":n,"uptime_secs":n,"errors":[..]}
char *st_stats(const StSession *session);

// Stops the tunnel and frees the session.
void st_stop(StSession *session);

void st_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
