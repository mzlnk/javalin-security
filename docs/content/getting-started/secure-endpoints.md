# Secure endpoints

Secure HTTP routes and WebSocket upgrades from a single plugin. Pattern-based rules live on
`security.rules` — HTTP verbs and `ws(...)` entries share one table, while authentication
strategies are configured separately on `security.http` and `security.ws`.

This walkthrough uses **Basic Auth** as a concrete example. Any extension (or a custom strategy)
plugs in the same way.

!!! tip "Authentication is pluggable"
    Core provides the plugin and the rule table, not a login mechanism. Use a built-in strategy
    like [Basic Auth](../extensions/basic-auth.md), [API Key](../extensions/api-key.md),
    [Opaque Token](../extensions/opaque-token.md), [Session](../extensions/session.md),
    [JWT](../extensions/jwt/index.md), or create a
    [custom authenticator](../guides/custom-authentication.md) that fit your needs.

Install [core](installation.md) plus the
[Basic Auth extension](../extensions/basic-auth.md#installation) before you begin.

## 1. Configure authentication

Open `config.security { … }` (Kotlin) or `new JavalinSecurityPlugin(…)` (Java), set fields on
`security.http`, and assign a strategy. Both HTTP and WebSocket guards are installed as soon as
the plugin is registered; declare rules on `security.rules` or set `http.fallback` /
`ws.fallback` to control access (default fallback is deny).

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.basicauth.*
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    val users = mapOf(
        "alice" to BasicUser("alice", "secret", setOf(Role.USER)),
        "admin" to BasicUser("admin", "secret", setOf(Role.ADMIN)),
    )

    // inside Javalin.create { config ->
    config.security { security ->
        security.http.authentication = basicAuth { basic ->
            basic.userLookup = UserLookup { users[it] }
            // Demo only — use a real PasswordEncoder in production.
        }
        security.http.fallback = Rules.deny()
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.basicauth.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.security.RouteRole;
    import java.util.Map;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    Map<String, BasicUser> users = Map.of(
        "alice", new BasicUser("alice", "secret", Set.of(Role.USER)),
        "admin", new BasicUser("admin", "secret", Set.of(Role.ADMIN)));

    // inside Javalin.create(config -> {
    config.registerPlugin(new JavalinSecurityPlugin(security -> {
        security.http.authentication = BasicAuthSecurity.basicAuth(basic ->
            basic.userLookup = users::get);
        security.http.fallback = Rules.deny();
    }));
    ```

For WebSocket upgrades, set fields on `security.ws` the same way (typically with
[JWT](../extensions/jwt/index.md)) — see [WebSocket security](../websocket-security.md).

## 2. Declare who is allowed

Add rules on `security.rules`. HTTP entries match **path + method** (a GET rule also governs
HEAD). WebSocket entries match on **path only**. Entries are evaluated in order; **first match
wins**. Anything that does not match a rule falls through to `http.fallback` or `ws.fallback`
(deny-by-default when unset).

### Verb-by-verb

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules

    security.rules.get("/api/v1/*", Rules.allow())                  // public reads
    security.rules.post("/api/v1/*", Rules.authenticated())         // any logged-in user
    security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN))   // admins only
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rules;

    security.rules.get("/api/v1/*", Rules.allow());
    security.rules.post("/api/v1/*", Rules.authenticated());
    security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN));
    ```

### Grouped with `apiBuilder`

When paths share a prefix, nest rules under `apiBuilder` — analogous to Javalin's route
`apiBuilder`. HTTP and WebSocket rules can live in the same group:

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*
    import io.github.mzlnk.javalin.security.authorization.Rules

    security.rules.apiBuilder {
        path("/api/v1") {
            get("/*", Rules.allow())
            post("/*", Rules.authenticated())
            delete("/*", Rules.hasRole(Role.ADMIN))
        }
        ws("/ws/chat", Rules.authenticated())   // path-only WebSocket rule; enforced by the WS guard (installed with the plugin)
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rules;

    import static io.github.mzlnk.javalin.security.apibuilder.SecurityApiBuilder.*;

    security.rules.apiBuilder(() -> {
        path("/api/v1", () -> {
            get("/*", Rules.allow());
            post("/*", Rules.authenticated());
            delete("/*", Rules.hasRole(Role.ADMIN));
        });
        ws("/ws/chat", Rules.authenticated());  // path-only WebSocket rule; enforced by the WS guard (installed with the plugin)
    });
    ```

## 3. Register routes and run

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.basicauth.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    val app = Javalin.create { config ->
        config.security { security ->
            security.rules.get("/api/v1/*", Rules.allow())
            security.rules.post("/api/v1/*", Rules.authenticated())
            security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = basicAuth { basic ->
                basic.userLookup = UserLookup { users[it] }
            }
            security.http.fallback = Rules.deny()
        }
        config.routes.get("/api/v1/resource") { it.result("ok") }
        config.routes.post("/api/v1/resource") { it.result("created") }
        config.routes.delete("/api/v1/resource") { it.result("deleted") }
        config.routes.get("/api/v1/me") { it.result(it.identity<BasicAuthIdentity>().name) }
    }.start(7070)
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.basicauth.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;

    Javalin app = Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/api/v1/*", Rules.allow());
            security.rules.post("/api/v1/*", Rules.authenticated());
            security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = BasicAuthSecurity.basicAuth(basic ->
                basic.userLookup = users::get);
            security.http.fallback = Rules.deny();
        }));
        config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
        config.routes.post("/api/v1/resource", ctx -> ctx.result("created"));
        config.routes.delete("/api/v1/resource", ctx -> ctx.result("deleted"));
        config.routes.get("/api/v1/me", ctx ->
            ctx.result(identity(ctx, BasicAuthIdentity.class).getName()));
    }).start(7070);
    ```

## 4. Try it

```bash
curl -i localhost:7070/api/v1/resource                           # 200 — public GET
curl -i -X POST localhost:7070/api/v1/resource                   # 401 — no credentials
curl -i -X POST localhost:7070/api/v1/resource -u alice:secret   # 200
curl -i -X DELETE localhost:7070/api/v1/resource -u alice:secret # 403 — not ADMIN
curl -i -X DELETE localhost:7070/api/v1/resource -u admin:secret # 200
```

Anonymous denials return **401**; authenticated-but-forbidden calls return **403**.

## Next steps

- [Access caller identity](access-caller-identity.md) — read the authenticated user in handlers.
- [Authorization](../concepts/authorization.md) — rules, roles, and deny-by-default.
- [Authentication](../concepts/authentication.md) — strategies and outcomes.
- Prefer JWT or WebSockets? See the [JWT extension](../extensions/jwt/index.md) and
  [WebSocket security](../websocket-security.md).
