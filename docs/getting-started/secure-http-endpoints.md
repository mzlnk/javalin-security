# Secure HTTP endpoints

Secure your first HTTP routes in a few steps. This walkthrough uses **Basic Auth** as a concrete
example — any extension (or a custom strategy) plugs in the same way.

!!! tip "Authentication is pluggable"
    Core provides the plugin and the rule table, not a login mechanism. Assign a strategy from
    [Basic Auth](../extensions/basic-auth.md), [JWT](../extensions/jwt/index.md), or a
    [custom authenticator](../guides/custom-authentication.md).

Install [core](installation.md) plus the
[Basic Auth extension](../extensions/basic-auth.md#installation) before you begin.

## 1. Configure authentication

Open `config.security { … }` (Kotlin) or `new JavalinSecurityPlugin(…)` (Java), call `http { }`,
and assign a strategy.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.basicauth.*
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    val users = mapOf(
        "alice" to BasicUser("alice", "secret", setOf(Role.USER)),
        "admin" to BasicUser("admin", "secret", setOf(Role.ADMIN)),
    )

    // inside Javalin.create { config ->
    config.security { security ->
        security.http { http ->
            http.authentication = basicAuth { basic ->
                basic.userLookup = UserLookup { users[it] }
                // Demo only — use a real PasswordEncoder in production.
            }
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.basicauth.*;
    import io.javalin.security.RouteRole;
    import java.util.Map;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    Map<String, BasicUser> users = Map.of(
        "alice", new BasicUser("alice", "secret", Set.of(Role.USER)),
        "admin", new BasicUser("admin", "secret", Set.of(Role.ADMIN)));

    // inside Javalin.create(config -> {
    config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
        http.authentication = BasicAuthSecurity.basicAuth(basic ->
            basic.userLookup = users::get);
    })));
    ```

## 2. Declare who is allowed

Still inside `http { }`, add a rule table. Entries are evaluated in order; **first match wins**,
and an unset `fallback` denies.

=== "Kotlin"

    ```kotlin
    import io.javalin.http.HandlerType.*

    http.rules { r ->
        r.add("/api/v1/*", GET, r.allow)                  // public reads
        r.add("/api/v1/*", POST, r.authenticated)         // any logged-in user
        r.add("/api/v1/*", DELETE, r.hasRole(Role.ADMIN)) // admins only
        r.fallback = r.deny
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import static io.javalin.http.HandlerType.*;

    http.rules(r -> {
        r.add("/api/v1/*", GET, Rules.allow());
        r.add("/api/v1/*", POST, Rules.authenticated());
        r.add("/api/v1/*", DELETE, Rules.hasRole(Role.ADMIN));
        r.fallback = Rules.deny();
    });
    ```

## 3. Register routes and run

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    val app = Javalin.create { config ->
        config.security { security ->
            security.http { http ->
                http.authentication = basicAuth { basic ->
                    basic.userLookup = UserLookup { users[it] }
                }
                http.rules { r ->
                    r.add("/api/v1/*", GET, r.allow)
                    r.add("/api/v1/*", POST, r.authenticated)
                    r.add("/api/v1/*", DELETE, r.hasRole(Role.ADMIN))
                    r.fallback = r.deny
                }
            }
        }
        config.routes.get("/api/v1/resource") { it.result("ok") }
        config.routes.post("/api/v1/resource") { it.result("created") }
        config.routes.delete("/api/v1/resource") { it.result("deleted") }
        config.routes.get("/api/v1/me") { it.result(it.identity<BasicAuthIdentity>()!!.name) }
    }.start(7070)
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.javalin.Javalin;
    import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;

    Javalin app = Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
            http.authentication = BasicAuthSecurity.basicAuth(basic ->
                basic.userLookup = users::get);
            http.rules(r -> {
                r.add("/api/v1/*", GET, Rules.allow());
                r.add("/api/v1/*", POST, Rules.authenticated());
                r.add("/api/v1/*", DELETE, Rules.hasRole(Role.ADMIN));
                r.fallback = Rules.deny();
            });
        })));
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
- Prefer JWT? See the [JWT extension](../extensions/jwt/index.md) or
  [Secure WebSocket endpoints](secure-websocket-endpoints.md).
