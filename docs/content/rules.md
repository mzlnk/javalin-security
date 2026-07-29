# Rules DSL

Pattern-based authorization for HTTP and WebSocket endpoints lives on a single
[`SecurityRules`](https://mzlnk.github.io/javalin-security/api/io.github.mzlnk.javalin.security/-security-rules/index.html)
table at `security.rules`. Verb methods mirror Javalin's route API; [apiBuilder](#apibuilder)
groups rules under path prefixes. Authentication, fallbacks, and CORS preflight stay on
[`security.http`](http-security.md) / [`security.ws`](websocket-security.md) — see those pages
for config cheatsheets.

If you followed [Secure endpoints](getting-started/secure-endpoints.md), you already use this
DSL — this page is the full reference.

## Verb methods

Each call registers one entry. Repeated calls accumulate; order matters (first match wins).

| Method    | Matches                              | Example                                      |
|-----------|--------------------------------------|----------------------------------------------|
| `get`     | `GET` (also governs `HEAD`)          | `rules.get("/api/*", Rules.authenticated())`         |
| `post`    | `POST`                               | `rules.post("/api/*", Rules.authenticated())`        |
| `put`     | `PUT`                                | `rules.put("/items/{id}", Rules.hasRole(Role.ADMIN))` |
| `patch`   | `PATCH`                              | `rules.patch("/items/{id}", Rules.authenticated())`  |
| `delete`  | `DELETE`                             | `rules.delete("/items/{id}", Rules.hasRole(Role.ADMIN))` |
| `head`    | `HEAD` only                          | `rules.head("/health", Rules.allow())`               |
| `options` | `OPTIONS`                            | `rules.options("/api/*", Rules.allow())`             |
| `any`     | Any HTTP method                      | `rules.any("/admin/*", Rules.hasRole(Role.ADMIN))` |
| `ws`      | WebSocket upgrade (path only)        | `rules.ws("/ws/chat", Rules.authenticated())`        |

A `GET` rule also governs `HEAD` on the same path — you rarely need a separate `head` entry.
Use `any` when method does not matter. WebSocket rules match on path only (no HTTP method).

## apiBuilder

Group rules under shared prefixes, analogous to Javalin's `routes.apiBuilder`:

=== "Kotlin"

    ```kotlin
import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*

    security.rules.apiBuilder {
        path("/api") {
            get("/*", Rules.authenticated())
            post("/*", Rules.authenticated())
            path("/admin") {
                any("/*", Rules.hasRole(Role.ADMIN))
            }
        }
        ws("/events", Rules.authenticated())
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rules;

    import static io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*;

    security.rules.apiBuilder(() -> {
        path("/api", () -> {
            get("/*", Rules.authenticated());
            post("/*", Rules.authenticated());
            path("/admin", () -> any("/*", Rules.hasRole(Role.ADMIN)));
        });
        ws("/events", Rules.authenticated());
    });
    ```

`path` accepts paths with or without a leading slash (`"/api"` and `"api"` both work). Nested
`path` blocks concatenate prefixes (`path("/a") { path("b") { get("/c", …) } }` → `/a/b/c`).
A lone `*` segment stays attached to the prefix (`path("/api") { get("*", …) }` → `/api*`).

Static `SecurityApiBuilder` methods (`get`, `post`, `path`, …) are only valid inside
`apiBuilder { }` — calling them elsewhere throws at runtime.

## Matching and fallbacks

Entries are evaluated top-to-bottom; **first match wins** per protocol (HTTP entries do not
compete with WS entries). Route-declared [RouteRoles](concepts/authorization.md) are checked
**before** the rule table — if a route declares any role, the table (including fallbacks) is
skipped for that route.

When nothing matches, the fallback on the relevant config decides:

| Config | Fallback field   | Default when unset |
|--------|------------------|--------------------|
| HTTP   | `http.fallback`  | **deny**           |
| WS     | `ws.fallback`    | **deny**           |

CORS preflight bypass is configured separately via `http.allowCorsPreflight` — see
[CORS and preflight](guides/cors.md).

Path patterns use **Javalin route syntax** (`*`, `{param}`, `<param>`). Ant-style `**` and `?`
are rejected at startup. Patterns match the path without the context-path prefix.

## Built-in rules

| Rule              | Grants when…                                     |
|-------------------|--------------------------------------------------|
| `allow`           | Always (including anonymous).                    |
| `deny`            | Never.                                           |
| `authenticated`   | Caller is logged in.                             |
| `hasRole(role)`   | Caller holds that role.                          |
| `hasAnyRole(…)`   | Caller holds at least one of the listed roles.   |

Call as `Rules.allow()`, `Rules.deny()`, `Rules.authenticated()`, `Rules.hasRole(…)`, etc.
from both Kotlin and Java.

Anonymous denials return **401**; authenticated-but-forbidden calls return **403**. See
[Authorization](concepts/authorization.md#denial-status).

## Custom rules

Implement [`Rule`](https://mzlnk.github.io/javalin-security/api/io.github.mzlnk.javalin.security.authorization/-rule/index.html)
for request-time checks (IP allowlists, tenant ownership, …). The same type works for HTTP and
WebSocket entries.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.security

    val fromTrustedIp = Rule { _, ctx -> ctx.ip() in setOf("10.0.0.10", "10.0.0.11") }

    config.security { security ->
        security.rules.any("/admin/*", fromTrustedIp)
        security.http.authentication = myStrategy
        security.http.fallback = Rules.deny()
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rule;
    import io.github.mzlnk.javalin.security.authorization.Rules;

    Rule fromTrustedIp = (auth, ctx) -> Set.of("10.0.0.10", "10.0.0.11").contains(ctx.ip());

    config.registerPlugin(new JavalinSecurityPlugin(security -> {
        security.rules.any("/admin/*", fromTrustedIp);
        security.http.authentication = myStrategy;
        security.http.fallback = Rules.deny();
    }));
    ```

Never throw from a rule — return `false` instead. See
[Custom authorization rules](guides/custom-rules.md) for patterns and testing.

## Full example

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/health", Rules.allow())
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN))
            security.rules.ws("/ws/chat", Rules.authenticated())
            security.rules.apiBuilder {
                path("/api") {
                    get("/*", Rules.authenticated())
                    post("/*", Rules.authenticated())
                }
            }
            security.http.authentication = myStrategy
            security.http.fallback = Rules.deny()
            security.http.allowCorsPreflight = true
            security.ws.authentication = myWsStrategy
            security.ws.allowedOrigins = listOf("https://app.example.com")
            security.ws.fallback = Rules.deny()
        }
        config.routes.get("/health") { it.result("UP") }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    import static io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*;

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/health", Rules.allow());
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN));
            security.rules.ws("/ws/chat", Rules.authenticated());
            security.rules.apiBuilder(() -> {
                path("/api", () -> {
                    get("/*", Rules.authenticated());
                    post("/*", Rules.authenticated());
                });
            });
            security.http.authentication = myStrategy;
            security.http.fallback = Rules.deny();
            security.http.allowCorsPreflight = true;
            security.ws.authentication = myWsStrategy;
            security.ws.allowedOrigins = List.of("https://app.example.com");
            security.ws.fallback = Rules.deny();
        }));
        config.routes.get("/health", ctx -> ctx.result("UP"));
    });
    ```

## Related

- [HTTP security](http-security.md) — authentication, fallback, CORS preflight.
- [WebSocket security](websocket-security.md) — authentication, allowedOrigins, fallback.
- [Authorization](concepts/authorization.md) — route roles, deny-by-default, path patterns.
- [Custom authorization rules](guides/custom-rules.md) — advanced `Rule` patterns.
