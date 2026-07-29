# HTTP security

Configuration cheatsheet for `security.http`. If you followed
[Secure endpoints](getting-started/secure-endpoints.md), you already know the
essentials — this page lists the fields and common recipes.

Pattern-based rules are declared on [`security.rules`](rules.md). Both HTTP and WebSocket
guards are installed as soon as the plugin is registered; declare rules on `security.rules` or
set `http.fallback` / `ws.fallback` to control access (default fallback is deny). The HTTP
guard runs as `beforeMatched`.

## `HttpSecurityConfig`

| Field / method       | Type                      | Default | Effect                                              |
|----------------------|---------------------------|---------|-----------------------------------------------------|
| `authentication`     | `AuthenticationStrategy?` | `null`  | Resolves the caller; `null` → anonymous.            |
| `fallback`           | `Rule?`                   | `null`  | When no HTTP rule matches (`null` = **deny**).      |
| `allowCorsPreflight` | `Boolean`                 | `false` | Bypass CORS preflight `OPTIONS`.                    |

See [Rules DSL](rules.md) for verb methods, `apiBuilder`, and built-in rules. First match wins;
route-declared roles override the table. See [Authorization](concepts/authorization.md).

## Example

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/health", Rules.allow())
            security.rules.get("/api/*", Rules.authenticated())
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = myStrategy
            security.http.fallback = Rules.deny()
        }
        config.routes.get("/health") { it.result("UP") }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/health", Rules.allow());
            security.rules.get("/api/*", Rules.authenticated());
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = myStrategy;
            security.http.fallback = Rules.deny();
        }));
        config.routes.get("/health", ctx -> ctx.result("UP"));
    });
    ```

## Recipes

```kotlin
import io.github.mzlnk.javalin.security.authorization.Rules
// Public health, everything else authenticated
security.rules.get("/health", Rules.allow())
security.http.fallback = Rules.authenticated()

// Reads open, writes authenticated
security.rules.get("/api/*", Rules.allow())   // also governs HEAD
security.rules.post("/api/*", Rules.authenticated())
security.http.fallback = Rules.deny()
```

## CORS preflight

Set `allowCorsPreflight = true` so preflight `OPTIONS` (with `Access-Control-Request-Method`)
bypasses the rule table. You still need Javalin's CORS plugin for response headers. See
[CORS and preflight](guides/cors.md).

## Related

- [Rules DSL](rules.md).
- [Authorization](concepts/authorization.md).
- [Error handling](concepts/error-handling.md).
- [WebSocket security](websocket-security.md).
