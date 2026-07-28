# WebSocket security

Configuration cheatsheet for the `ws { }` block. If you followed
[Secure WebSocket endpoints](getting-started/secure-websocket-endpoints.md), you already know the
essentials — this page lists the fields and the Origin rules.

Calling `ws { }` at least once installs the upgrade guard (`wsBeforeUpgrade`). Enforcement runs
**once, at the handshake** — not per message.

## `WsSecurityConfig`

| Field / method     | Type                       | Default | Effect                                                    |
|--------------------|----------------------------|---------|-----------------------------------------------------------|
| `authentication`   | `AuthenticationStrategy?`  | `null`  | Upgrade-time authentication; `null` → anonymous.          |
| `allowedOrigins`   | `Collection<String>?`      | `null`  | Exact origins allowed; checked before authentication.     |
| `rules { … }`      | `WsSecurityRules`          | empty   | Path-only rule table (entries accumulate).                |

## `WsSecurityRules`

| Field / method                                                                | Effect                                                              |
|-------------------------------------------------------------------------------|---------------------------------------------------------------------|
| `add(pattern, rule)`                                                          | Rule for matching upgrades.                                         |
| `fallback`                                                                    | When no entry matches (`null` = **deny**).                          |
| `allow` / `deny` / `authenticated` / `hasRole` / `hasAnyRole`                 | Built-ins (`Rules.*` in Java).                                      |

Same semantics as HTTP: first match wins, deny-by-default, route roles override the table. WS
rules match on path only.

## Example

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    Javalin.create { config ->
        config.security { security ->
            security.ws { ws ->
                ws.authentication = myStrategy
                ws.allowedOrigins = listOf("https://app.example.com")
                ws.rules { r ->
                    r.add("/ws/public/*", r.allow)
                    r.add("/ws/chat", r.authenticated)
                    r.add("/ws/admin", r.hasRole(Role.ADMIN))
                    r.fallback = r.deny
                }
            }
        }
        config.routes.ws("/ws/chat") { ws ->
            ws.onConnect { ctx -> ctx.send("welcome ${ctx.authentication().identity?.name}") }
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.util.List;

    import static io.github.mzlnk.javalin.security.SecurityExtensions.authentication;

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
            ws.authentication = myStrategy;
            ws.allowedOrigins = List.of("https://app.example.com");
            ws.rules(r -> {
                r.add("/ws/public/*", Rules.allow());
                r.add("/ws/chat", Rules.authenticated());
                r.add("/ws/admin", Rules.hasRole(Role.ADMIN));
                r.fallback = Rules.deny();
            });
        })));
        config.routes.ws("/ws/chat", ws ->
            ws.onConnect(ctx -> {
                var id = authentication(ctx).getIdentity();
                ctx.send("welcome " + (id != null ? id.getName() : "?"));
            }));
    });
    ```

## Origin allow-listing

When set, missing or unlisted `Origin` values are rejected before authentication. An **empty**
collection (or blank entry) fails at startup — leave `allowedOrigins` unset to disable the check.
Origins must be exact strings (scheme + host + optional port).

## Upgrade-time only

Authentication runs during `wsBeforeUpgrade`. Denied upgrades never reach `onConnect`. Read
identity with `WsContext.authentication()` / `principal<T>()`. Mid-session expiry is not
re-checked — enforce it in your protocol if needed.

## JWT in the browser

Browsers cannot set `Authorization` on the WebSocket handshake. Carry the JWT in an `HttpOnly`,
`Secure` cookie and configure the JWT strategy to read it from there (see `JwtConfig` in the
[API reference](https://mzlnk.github.io/javalin-security/api/)). Always set `allowedOrigins`
when using cookies — otherwise the socket is open to cross-site WebSocket hijacking. Native
clients can still use `Authorization: Bearer …`.

## Related

- [Secure WebSocket endpoints](getting-started/secure-websocket-endpoints.md).
- [HTTP security](http-security.md).
