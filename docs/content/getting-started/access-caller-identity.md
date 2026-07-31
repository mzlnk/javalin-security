# Access caller identity

Once authentication is configured, your handlers can read *who* is calling from the Javalin
`Context` (HTTP) or `WsContext` (WebSocket). The same accessors work in both places.

!!! tip "Prerequisites"
    Follow [Secure endpoints](secure-endpoints.md) first. This page assumes an
    `authentication` strategy is already assigned.

## Accessors

| Kotlin                    | Java                           | Returns                                                                 |
| ------------------------- | ------------------------------ | ----------------------------------------------------------------------- |
| `ctx.authentication()`    | `authentication(ctx)`          | `Authentication` (identity + roles). Always non-null — anonymous callers get `isAuthenticated == false`. |
| `ctx.identity<T>()`       | `identity(ctx, T.class)`       | Typed identity. Throws `IllegalStateException` when anonymous.          |
| `ctx.identityOrNull<T>()` | `identityOrNull(ctx, T.class)` | Typed identity, or `null` when anonymous.                               |

Import them from `io.github.mzlnk.javalin.security`:

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication
    import io.github.mzlnk.javalin.security.identity
    import io.github.mzlnk.javalin.security.identityOrNull
    ```

=== "Java"

    ```java
    import static io.github.mzlnk.javalin.security.SecurityExtensions.authentication;
    import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;
    import static io.github.mzlnk.javalin.security.SecurityExtensions.identityOrNull;
    ```

## In HTTP handlers

On a successful authentication, the strategy attaches an `Identity` to the request. That is the
value you read back with `identity()` / `identityOrNull()` — typically your own domain type that
implements `Identity` (name, roles, and any extra fields you need). The cast is unchecked and
verified at runtime (like `ctx.attribute<T>()`): requesting a type other than the one the
strategy attached throws `ClassCastException`.

Prefer `identity()` on routes guarded by `authenticated` or `hasRole(...)` — the caller is
known to be authenticated, so the non-null return is safe. Use `identityOrNull()` when the
route may be hit anonymously.

=== "Kotlin"

    ```kotlin
    // User is whatever Identity type you configured your strategy with, e.g.:
    // data class User(override val name: String, override val roles: Set<RouteRole>) : Identity

    // Route behind Rules.authenticated() / hasRole(...) — identity is guaranteed
    config.routes.get("/api/v1/me") { ctx ->
        val user = ctx.identity<User>()
        ctx.result(user.name)
    }

    // Public route — caller may be anonymous
    config.routes.get("/api/v1/whoami") { ctx ->
        val user = ctx.identityOrNull<User>()
        ctx.result(user?.name ?: "anonymous")
    }
    ```

=== "Java"

    ```java
    // User is whatever Identity type you configured your strategy with, e.g.:
    // record User(String name, Set<RouteRole> roles) implements Identity { ... }

    // Route behind Rules.authenticated() / hasRole(...) — identity is guaranteed
    config.routes.get("/api/v1/me", ctx -> {
        User user = identity(ctx, User.class);
        ctx.result(user.getName());
    });

    // Public route — caller may be anonymous
    config.routes.get("/api/v1/whoami", ctx -> {
        User user = identityOrNull(ctx, User.class);
        ctx.result(user != null ? user.getName() : "anonymous");
    });
    ```

## In WebSocket handlers

Authentication resolves **once at the upgrade**. The resulting `Authentication` is attached to
every `WsContext` for the session and never re-checked per message.

=== "Kotlin"

    ```kotlin
    config.routes.ws("/ws/chat") { ws ->
        ws.onConnect { ctx ->
            // Behind Rules.authenticated() — use identity()
            val user = ctx.identity<User>()
            ctx.send("welcome ${user.name}")
        }
        ws.onMessage { ctx ->
            // Same identity for every message
            val roles = ctx.authentication().roles
            ctx.send("you have roles: $roles")
        }
    }

    config.routes.ws("/ws/public") { ws ->
        ws.onConnect { ctx ->
            // May be anonymous — use identityOrNull()
            val user = ctx.identityOrNull<User>() ?: return@onConnect
            ctx.send("welcome ${user.name}")
        }
    }
    ```

=== "Java"

    ```java
    config.routes.ws("/ws/chat", ws -> {
        ws.onConnect(ctx -> {
            // Behind Rules.authenticated() — use identity()
            User user = identity(ctx, User.class);
            ctx.send("welcome " + user.getName());
        });
        ws.onMessage(ctx -> {
            // Same identity for every message
            var roles = authentication(ctx).getRoles();
            ctx.send("you have roles: " + roles);
        });
    });

    config.routes.ws("/ws/public", ws -> {
        ws.onConnect(ctx -> {
            // May be anonymous — use identityOrNull()
            User user = identityOrNull(ctx, User.class);
            if (user == null) return;
            ctx.send("welcome " + user.getName());
        });
    });
    ```

## Working with `Authentication`

`authentication()` never returns `null` — it returns an anonymous token when no credential is
presented. Use it when you need the full picture.

| Kotlin            | Java               | Meaning                                 |
| ----------------- | ------------------ | --------------------------------------- |
| `identity`        | `getIdentity()`    | Who is calling (`null` when anonymous). |
| `roles`           | `getRoles()`       | Granted roles (empty when anonymous).   |
| `isAuthenticated` | `isAuthenticated()` | `true` when `identity != null`.        |

=== "Kotlin"

    ```kotlin
    config.routes.get("/api/v1/whoami") { ctx ->
        val auth = ctx.authentication()
        if (!auth.isAuthenticated) {
            ctx.result("anonymous")
        } else {
            ctx.result("${auth.identity!!.name} with roles ${auth.roles}")
        }
    }
    ```

=== "Java"

    ```java
    config.routes.get("/api/v1/whoami", ctx -> {
        var auth = authentication(ctx);
        if (!auth.isAuthenticated()) {
            ctx.result("anonymous");
        } else {
            ctx.result(auth.getIdentity().getName() + " with roles " + auth.getRoles());
        }
    });
    ```

## Common pitfalls

- **`identity<T>()` / `identity(ctx, T.class)` throws for anonymous callers.** Use
  `identityOrNull()` when the route may be hit without credentials. Prefer `identity()` behind
  `authenticated` / `hasRole` rules.
- **Wrong type.** Calling `identity()` with a type that doesn't match your configured strategy
  throws `ClassCastException`. Always use the identity type that matches your strategy.
- **`Context` vs `WsContext`.** Both expose the same accessors, but importing the wrong overload
  will not compile. Both live in `io.github.mzlnk.javalin.security` (`SecurityExtensions` from
  Java).
- **WebSocket identity is fixed for the session.** If you need to react to token expiry
  mid-session, enforce it in your protocol.

## Next steps

- [Authentication](../concepts/authentication.md) — identities, roles, and the three outcomes.
- [Authorization](../concepts/authorization.md) — pair identity with rules and route roles.
- [Custom authentication](../guides/custom-authentication.md) — supply your own identity type.
