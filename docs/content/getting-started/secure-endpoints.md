# Secure endpoints

Secure HTTP routes and WebSocket upgrades from a single plugin. Pattern-based rules live on
`security.rules` — HTTP verbs and `ws(...)` entries share one table, while authentication
strategies are configured separately on `security.http` and `security.ws`.

This walkthrough uses **Basic Auth** as a concrete example. Any extension (or a custom strategy)
plugs in the same way.

!!! tip "Authentication is pluggable"
    `javalin-security` provides the plugin and the rule table, not a login mechanism. Use a
    built-in strategy like [Basic Auth](../extensions/basic-auth.md),
    [API Key](../extensions/api-key.md), [Opaque Token](../extensions/opaque-token.md),
    [Session](../extensions/session.md), [JWT](../extensions/jwt/index.md), or create a
    [custom authenticator](../guides/custom-authentication.md) that fit your needs.

Install [`javalin-security`](installation.md) plus the
[Basic Auth extension](../extensions/basic-auth.md#installation) before you begin.

## 1. Create a `UserLookup`

Define roles, an `Identity`, a small in-memory user store, and a `UserLookup` that Basic Auth
will call for each request:

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Identity
    import io.github.mzlnk.javalin.security.basicauth.BasicUserDetails
    import io.github.mzlnk.javalin.security.basicauth.UserLookup
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    data class User(override val name: String) : Identity

    val users = mapOf(
        "alice" to BasicUserDetails(User("alice"), "secret", setOf(Role.USER)),
        "admin" to BasicUserDetails(User("admin"), "secret", setOf(Role.ADMIN)),
    )

    val userLookup = UserLookup { users[it] }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authentication.Identity;
    import io.github.mzlnk.javalin.security.basicauth.BasicUserDetails;
    import io.github.mzlnk.javalin.security.basicauth.UserLookup;
    import io.javalin.security.RouteRole;
    import java.util.Map;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    record User(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    Map<String, BasicUserDetails> users = Map.of(
        "alice", new BasicUserDetails(new User("alice"), "secret", Set.of(Role.USER)),
        "admin", new BasicUserDetails(new User("admin"), "secret", Set.of(Role.ADMIN)));

    UserLookup userLookup = users::get;
    ```

## 2. Configure authentication

Open `config.security { … }` (Kotlin) or `new JavalinSecurityPlugin(…)` (Java), set fields on
`security.http`, and assign a strategy. Both HTTP and WebSocket guards are installed as soon as
the plugin is registered. Declare rules on `security.rules` or set `http.fallback` /
`ws.fallback` to control access (default fallback is deny).

=== "Kotlin"

    ```kotlin
    config.security { security ->
        security.http.authentication = basicAuth { basic ->
            basic.userLookup = userLookup
            // Demo only — use a real PasswordEncoder in production.
        }
        security.http.fallback = Rules.deny()
    }
    ```

=== "Java"

    ```java
    config.registerPlugin(new JavalinSecurityPlugin(security -> {
        security.http.authentication = BasicAuthSecurity.basicAuth(basic -> {
            basic.userLookup = userLookup;
            // Demo only — use a real PasswordEncoder in production.
        });
        security.http.fallback = Rules.deny();
    }));
    ```

For WebSocket upgrades, set fields on `security.ws` the same way (typically with
[JWT](../extensions/jwt/index.md)) — see [WebSocket security](../websocket-security.md).

## 3. Declare who is allowed

Add rules on `security.rules`. HTTP entries match **path + method** (a GET rule also governs
HEAD). WebSocket entries match on **path only**. Entries are evaluated in order — **first match
wins**. Anything that does not match a rule falls through to `http.fallback` or `ws.fallback`
(deny-by-default when unset).

### Verb-by-verb

=== "Kotlin"

    ```kotlin
    security.rules.get("/api/v1/*", Rules.allow())                  // public reads
    security.rules.post("/api/v1/*", Rules.authenticated())         // any logged-in user
    security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN))   // admins only
    ```

=== "Java"

    ```java
    security.rules.get("/api/v1/*", Rules.allow());                 // public reads
    security.rules.post("/api/v1/*", Rules.authenticated());        // any logged-in user
    security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN));  // admins only
    ```

### Grouped with `apiBuilder`

When paths share a prefix, nest rules under `apiBuilder` — analogous to Javalin's route
`apiBuilder`. HTTP and WebSocket rules can live in the same group:

=== "Kotlin"

    ```kotlin
    security.rules.apiBuilder {
        path("/api/v1") {
            get("/*", Rules.allow())                                // public reads
            post("/*", Rules.authenticated())                       // any logged-in user
            delete("/*", Rules.hasRole(Role.ADMIN))                 // admins only
        }
        ws("/ws/chat", Rules.authenticated())   // path-only WebSocket rule, enforced by the WS guard
    }
    ```

=== "Java"

    ```java
    security.rules.apiBuilder(() -> {
        path("/api/v1", () -> {
            get("/*", Rules.allow());                               // public reads
            post("/*", Rules.authenticated());                      // any logged-in user
            delete("/*", Rules.hasRole(Role.ADMIN));                // admins only
        });
        ws("/ws/chat", Rules.authenticated());  // path-only WebSocket rule, enforced by the WS guard
    });
    ```

## 4. Wrap it together and run

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Identity
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.basicauth.*
    import io.github.mzlnk.javalin.security.identity
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    data class User(override val name: String) : Identity

    fun main() {
        val users = mapOf(
            "alice" to BasicUserDetails(User("alice"), "secret", setOf(Role.USER)),
            "admin" to BasicUserDetails(User("admin"), "secret", setOf(Role.ADMIN)),
        )
        val userLookup = UserLookup { users[it] }

        Javalin.create { config ->
            config.security { security ->
                security.rules.get("/api/v1/*", Rules.allow())                  // public reads
                security.rules.post("/api/v1/*", Rules.authenticated())         // any logged-in user
                security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN))   // admins only

                security.http.authentication = basicAuth { basic ->
                    basic.userLookup = userLookup
                    // Demo only — use a real PasswordEncoder in production.
                }
                security.http.fallback = Rules.deny()
            }

            config.routes.get("/api/v1/resource") { it.result("ok") }
            config.routes.post("/api/v1/resource") { it.result("created") }
            config.routes.delete("/api/v1/resource") { it.result("deleted") }
            config.routes.get("/api/v1/me") { it.result(it.identity<User>().name) }
        }.start(7070)
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authentication.Identity;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.github.mzlnk.javalin.security.basicauth.*;
    import io.javalin.Javalin;
    import io.javalin.security.RouteRole;
    import java.util.Map;
    import java.util.Set;

    import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;

    enum Role implements RouteRole { USER, ADMIN }

    record User(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    void main() {
        Map<String, BasicUserDetails> users = Map.of(
            "alice", new BasicUserDetails(new User("alice"), "secret", Set.of(Role.USER)),
            "admin", new BasicUserDetails(new User("admin"), "secret", Set.of(Role.ADMIN)));
        UserLookup userLookup = users::get;

        Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.allow());                 // public reads
                security.rules.post("/api/v1/*", Rules.authenticated());        // any logged-in user
                security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN));  // admins only

                security.http.authentication = BasicAuthSecurity.basicAuth(basic -> {
                    basic.userLookup = userLookup;
                    // Demo only — use a real PasswordEncoder in production.
                });
                security.http.fallback = Rules.deny();
            }));

            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/v1/resource", ctx -> ctx.result("created"));
            config.routes.delete("/api/v1/resource", ctx -> ctx.result("deleted"));
            config.routes.get("/api/v1/me", ctx ->
                ctx.result(identity(ctx, User.class).getName()));
        }).start(7070);
    }
    ```

## 5. Try it

=== "cURL"

    ```bash
    curl -i localhost:7070/api/v1/resource                           # 200 — public GET
    curl -i -X POST localhost:7070/api/v1/resource                   # 401 — no credentials
    curl -i -X POST localhost:7070/api/v1/resource -u alice:secret   # 200
    curl -i -X DELETE localhost:7070/api/v1/resource -u alice:secret # 403 — not ADMIN
    curl -i -X DELETE localhost:7070/api/v1/resource -u admin:secret # 200
    ```

Anonymous denials return **401**. Authenticated-but-forbidden calls return **403**.

## Next steps

- [Access caller identity](access-caller-identity.md) — read the authenticated user in handlers.
- [Authorization](../concepts/authorization.md) — rules, roles, and deny-by-default.
- [Authentication](../concepts/authentication.md) — strategies and outcomes.
- Prefer JWT or WebSockets? See the [JWT extension](../extensions/jwt/index.md) and
  [WebSocket security](../websocket-security.md).
