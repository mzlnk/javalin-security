# Access caller identity

Once authentication is configured, your handlers can read *who* is calling from the Javalin
`Context` (HTTP) or `WsContext` (WebSocket). The same two accessors work in both places.

!!! tip "Prerequisites"
    Follow [Secure HTTP endpoints](secure-http-endpoints.md) or
    [Secure WebSocket endpoints](secure-websocket-endpoints.md) first. This page assumes an
    `authentication` strategy is already assigned.

## Two accessors

| Extension                                       | Returns                            | Anonymous caller                              |
|-------------------------------------------------|------------------------------------|-----------------------------------------------|
| `ctx.authentication()`                          | `Authentication` (identity + roles) | Non-null, `isAuthenticated == false`         |
| `ctx.identity<T>()` / `ctx.identity(T.class)` | Typed identity                    | `null`                                        |

Import them from `io.github.mzlnk.javalin.security`:

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication
    import io.github.mzlnk.javalin.security.identity
    ```

=== "Java"

    ```java
    import static io.github.mzlnk.javalin.security.SecurityExtensions.authentication;
    import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;
    ```

## In HTTP handlers

The identity type depends on your strategy — `BasicAuthIdentity` for Basic Auth,
`JwtIdentity` for JWT, or your own `Identity` subtype for a custom authenticator.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.basicauth.BasicAuthIdentity

    config.routes.get("/api/v1/me") { ctx ->
        val user = ctx.identity<BasicAuthIdentity>()   // null when anonymous
        ctx.result(user?.name ?: "anonymous")
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.basicauth.BasicAuthIdentity;

    config.routes.get("/api/v1/me", ctx -> {
        BasicAuthIdentity user = identity(ctx, BasicAuthIdentity.class);
        ctx.result(user != null ? user.getName() : "anonymous");
    });
    ```

When the route is guarded by `r.authenticated` or `r.hasRole(...)`, the identity is guaranteed
non-null inside the handler — it is safe to unwrap with `!!` (Kotlin) or without a null check
(Java).

## In WebSocket handlers

Authentication resolves **once at the upgrade**; the resulting `Authentication` is attached to
every `WsContext` for the session and never re-checked per message.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication
    import io.github.mzlnk.javalin.security.identity
    import io.github.mzlnk.javalin.security.jwt.JwtIdentity

    config.routes.ws("/ws/chat") { ws ->
        ws.onConnect { ctx ->
            val user = ctx.identity<JwtIdentity>() ?: return@onConnect
            ctx.send("welcome ${user.name}")
        }
        ws.onMessage { ctx ->
            val roles = ctx.authentication().roles      // same identity for every message
            ctx.send("you have roles: $roles")
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.jwt.JwtIdentity;

    config.routes.ws("/ws/chat", ws -> {
        ws.onConnect(ctx -> {
            JwtIdentity user = identity(ctx, JwtIdentity.class);
            if (user == null) return;
            ctx.send("welcome " + user.getName());
        });
        ws.onMessage(ctx ->
            ctx.send("you have roles: " + authentication(ctx).getRoles()));
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

- **`identity<T>()` returns `null` for anonymous callers.** Do not dereference without a null
  check unless the route is behind an `authenticated` / `hasRole` rule.
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
