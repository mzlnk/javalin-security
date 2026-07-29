# WebSocket security

Configuration cheatsheet for `security.ws`. If you followed
[Secure endpoints](getting-started/secure-endpoints.md), you already know the
essentials — this page lists the fields and the Origin rules.

Pattern-based rules are declared on [`security.rules`](rules.md) via `rules.ws(…)`. Both HTTP
and WebSocket guards are installed as soon as the plugin is registered; declare rules on
`security.rules` or set `http.fallback` / `ws.fallback` to control access (default fallback is
deny). The WS guard runs as `wsBeforeUpgrade`. Enforcement runs **once, at the handshake** —
not per message.

## `WsSecurityConfig`

| Field / method     | Type                       | Default | Effect                                                    |
|--------------------|----------------------------|---------|-----------------------------------------------------------|
| `authentication`   | `AuthenticationStrategy?`  | `null`  | Upgrade-time authentication; `null` → anonymous.          |
| `allowedOrigins`   | `Collection<String>?`      | `null`  | Exact origins allowed; checked before authentication.     |
| `fallback`         | `Rule?`                    | `null`  | When no WS rule matches (`null` = **deny**).              |

See [Rules DSL](rules.md) for `rules.ws(…)`, built-in rules, and matching semantics. Same as
HTTP: first match wins, deny-by-default, route roles override the table. WS rules match on path
only.

## Example

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Identity
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.identity
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    Javalin.create { config ->
        config.security { security ->
            security.rules.ws("/ws/public/*", Rules.allow())
            security.rules.ws("/ws/chat", Rules.authenticated())
            security.rules.ws("/ws/admin", Rules.hasRole(Role.ADMIN))
            security.ws.authentication = myStrategy
            security.ws.allowedOrigins = listOf("https://app.example.com")
            security.ws.fallback = Rules.deny()
        }
        config.routes.ws("/ws/chat") { ws ->
            // Behind Rules.authenticated() — identity() is safe
            ws.onConnect { ctx -> ctx.send("welcome ${ctx.identity<Identity>().name}") }
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authentication.Identity;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.util.List;

    import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.ws("/ws/public/*", Rules.allow());
            security.rules.ws("/ws/chat", Rules.authenticated());
            security.rules.ws("/ws/admin", Rules.hasRole(Role.ADMIN));
            security.ws.authentication = myStrategy;
            security.ws.allowedOrigins = List.of("https://app.example.com");
            security.ws.fallback = Rules.deny();
        }));
        config.routes.ws("/ws/chat", ws ->
            // Behind Rules.authenticated() — identity() is safe
            ws.onConnect(ctx -> ctx.send("welcome " + identity(ctx, Identity.class).getName())));
    });
    ```

## Origin allow-listing

When set, missing or unlisted `Origin` values are rejected before authentication. An **empty**
collection (or blank entry) fails at startup — leave `allowedOrigins` unset to disable the check.
Origins must be exact strings (scheme + host + optional port).

## Upgrade-time only

Authentication runs during `wsBeforeUpgrade`. Denied upgrades never reach `onConnect`. Read
identity with `WsContext.authentication()` / `identity<T>()` / `identityOrNull<T>()`.
Mid-session expiry is not re-checked — enforce it in your protocol if needed.

## JWT in the browser

Browsers cannot set `Authorization` on the WebSocket handshake. Carry the JWT in an `HttpOnly`,
`Secure` cookie and configure the JWT strategy to read it from there (see `JwtConfig` in the
[API reference](https://mzlnk.github.io/javalin-security/api/)). Always set `allowedOrigins`
when using cookies — otherwise the socket is open to cross-site WebSocket hijacking. Native
clients can still use `Authorization: Bearer …`.

## Related

- [Rules DSL](rules.md).
- [Secure endpoints](getting-started/secure-endpoints.md).
- [HTTP security](http-security.md).
