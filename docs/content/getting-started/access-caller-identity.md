# Access caller identity

Once authentication is configured, your handlers can read *who* is calling from the Javalin
`Context` (HTTP) or `WsContext` (WebSocket). The same accessors work in both places.

!!! tip "Prerequisites"
    Follow [Secure endpoints](secure-endpoints.md) first. This page assumes an
    `authentication` strategy is already assigned.

## Accessors

| Extension                                               | Returns                             | Anonymous caller                                      |
|---------------------------------------------------------|-------------------------------------|-------------------------------------------------------|
| `ctx.authentication()`                                  | `Authentication` (identity + roles) | Non-null, `isAuthenticated == false`                  |
| `ctx.identity<T>()` / `ctx.identity(T.class)`           | Typed identity                      | Throws `IllegalStateException`                        |
| `ctx.identityOrNull<T>()` / `ctx.identityOrNull(T.class)` | Typed identity or `null`          | `null`                                                |

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

The identity type depends on your strategy — `BasicAuthIdentity` for Basic Auth,
`JwtIdentity` for JWT, or your own `Identity` subtype for a custom authenticator.

Prefer `identity()` on routes guarded by `authenticated` or `hasRole(...)` — the caller is
known to be authenticated, so the non-null return is safe. Use `identityOrNull()` when the
route may be hit anonymously.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.basicauth.BasicAuthIdentity

    // Route behind Rules.authenticated() / hasRole(...) — identity is guaranteed
    config.routes.get("/api/v1/me") { ctx ->
        val user = ctx.identity<BasicAuthIdentity>()
        ctx.result(user.name)
    }

    // Public route — caller may be anonymous
    config.routes.get("/api/v1/whoami") { ctx ->
        val user = ctx.identityOrNull<BasicAuthIdentity>()
        ctx.result(user?.name ?: "anonymous")
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.basicauth.BasicAuthIdentity;

    // Route behind Rules.authenticated() / hasRole(...) — identity is guaranteed
    config.routes.get("/api/v1/me", ctx -> {
        BasicAuthIdentity user = identity(ctx, BasicAuthIdentity.class);
        ctx.result(user.getName());
    });

    // Public route — caller may be anonymous
    config.routes.get("/api/v1/whoami", ctx -> {
        BasicAuthIdentity user = identityOrNull(ctx, BasicAuthIdentity.class);
        ctx.result(user != null ? user.getName() : "anonymous");
    });
    ```

## In WebSocket handlers

Authentication resolves **once at the upgrade**; the resulting `Authentication` is attached to
every `WsContext` for the session and never re-checked per message.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication
    import io.github.mzlnk.javalin.security.identity
    import io.github.mzlnk.javalin.security.identityOrNull
    import io.github.mzlnk.javalin.security.jwt.JwtIdentity

    config.routes.ws("/ws/chat") { ws ->
        ws.onConnect { ctx ->
            // Behind Rules.authenticated() — use identity()
            val user = ctx.identity<JwtIdentity>()
            ctx.send("welcome ${user.name}")
        }
        ws.onMessage { ctx ->
            val roles = ctx.authentication().roles      // same identity for every message
            ctx.send("you have roles: $roles")
        }
    }

    config.routes.ws("/ws/public") { ws ->
        ws.onConnect { ctx ->
            // May be anonymous — use identityOrNull()
            val user = ctx.identityOrNull<JwtIdentity>() ?: return@onConnect
            ctx.send("welcome ${user.name}")
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.jwt.JwtIdentity;

    config.routes.ws("/ws/chat", ws -> {
        ws.onConnect(ctx -> {
            // Behind Rules.authenticated() — use identity()
            JwtIdentity user = identity(ctx, JwtIdentity.class);
            ctx.send("welcome " + user.getName());
        });
        ws.onMessage(ctx ->
            ctx.send("you have roles: " + authentication(ctx).getRoles()));
    });

    config.routes.ws("/ws/public", ws -> {
        ws.onConnect(ctx -> {
            // May be anonymous — use identityOrNull()
            JwtIdentity user = identityOrNull(ctx, JwtIdentity.class);
            if (user == null) return;
            ctx.send("welcome " + user.getName());
        });
    });
    ```

## Working with `Authentication`

`authentication()` never returns `null` — it returns an anonymous token when no credential is
presented. Use it when you need the full picture.

| Member            | Meaning                                    |
|-------------------|--------------------------------------------|
| `identity`        | Who is calling (`null` when anonymous).    |
| `roles`           | Granted roles (empty when anonymous).      |
| `isAuthenticated` | `true` when `identity != null`.            |

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
    import io.github.mzlnk.javalin.security.authentication.Authentication;

    config.routes.get("/api/v1/whoami", ctx -> {
        Authentication auth = authentication(ctx);
        if (!auth.isAuthenticated()) {
            ctx.result("anonymous");
        } else {
            ctx.result(auth.getIdentity().getName() + " with roles " + auth.getRoles());
        }
    });
    ```

## Common pitfalls

- **`identity<T>()` throws for anonymous callers.** Use `identityOrNull()` when the route may
  be hit without credentials. Prefer `identity()` behind `authenticated` / `hasRole` rules.
- **Wrong type.** `identity(ctx, BasicAuthIdentity.class)` on a JWT-secured route throws
  `ClassCastException`. Always use the identity type that matches your strategy.
- **`Context` vs `WsContext`.** Both expose the same extensions, but importing the wrong one
  will not compile. Both live in `io.github.mzlnk.javalin.security`.
- **WebSocket identity is fixed for the session.** If you need to react to token expiry
  mid-session, enforce it in your protocol.

## Next steps

- [Authentication](../concepts/authentication.md) — identities, roles, and the three outcomes.
- [Authorization](../concepts/authorization.md) — pair identity with rules and route roles.
- [Custom authentication](../guides/custom-authentication.md) — supply your own identity type.
