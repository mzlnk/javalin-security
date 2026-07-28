# HTTP security

Configuration cheatsheet for the `http { }` block. If you followed
[Secure HTTP endpoints](getting-started/secure-http-endpoints.md), you already know the
essentials — this page lists the fields and common recipes.

Calling `http { }` at least once installs the HTTP guard (`beforeMatched`).

## `HttpSecurityConfig`

| Field / method   | Type                      | Default | Effect                                              |
|------------------|---------------------------|---------|-----------------------------------------------------|
| `authentication` | `AuthenticationStrategy?` | `null`  | Resolves the caller; `null` → anonymous.            |
| `rules { … }`    | `SecurityRules`           | empty   | Pattern rule table (entries accumulate).            |

## `SecurityRules`

| Field / method                | Effect                                                                          |
|-------------------------------|---------------------------------------------------------------------------------|
| `add(pattern, method, rule)`  | Rule for path + HTTP method.                                                    |
| `add(pattern, rule)`          | Rule for path, any method.                                                      |
| `fallback`                    | When no entry matches (`null` = **deny**).                                      |
| `allowCorsPreflight`          | Bypass CORS preflight `OPTIONS` (`false` by default).                           |
| Built-in rules                | `allow` / `deny` / `authenticated` / `hasRole` / `hasAnyRole` (`Rules.*` in Java). |

First match wins; route-declared roles override the table. See
[Authorization](concepts/authorization.md).

## Example

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.http.HandlerType.*

    Javalin.create { config ->
        config.security { security ->
            security.http { http ->
                http.authentication = myStrategy
                http.rules { r ->
                    r.add("/health", GET, r.allow)
                    r.add("/api/*", GET, r.authenticated)
                    r.add("/admin/*", r.hasRole(Role.ADMIN))
                    r.fallback = r.deny
                }
            }
        }
        config.routes.get("/health") { it.result("UP") }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    import static io.javalin.http.HandlerType.*;

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
            http.authentication = myStrategy;
            http.rules(r -> {
                r.add("/health", GET, Rules.allow());
                r.add("/api/*", GET, Rules.authenticated());
                r.add("/admin/*", Rules.hasRole(Role.ADMIN));
                r.fallback = Rules.deny();
            });
        })));
        config.routes.get("/health", ctx -> ctx.result("UP"));
    });
    ```

## Recipes

```kotlin
// Public health, everything else authenticated
http.rules { r ->
    r.add("/health", GET, r.allow)
    r.fallback = r.authenticated
}

// Reads open, writes authenticated
http.rules { r ->
    r.add("/api/*", GET, r.allow)   // also governs HEAD
    r.add("/api/*", POST, r.authenticated)
    r.fallback = r.deny
}
```

## CORS preflight

Set `allowCorsPreflight = true` so preflight `OPTIONS` (with `Access-Control-Request-Method`)
bypasses the rule table. You still need Javalin's CORS plugin for response headers. See
[CORS and preflight](guides/cors.md).

## Related

- [Authorization](concepts/authorization.md).
- [Error handling](concepts/error-handling.md).
- [WebSocket security](websocket-security.md).
