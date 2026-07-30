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

Every extension attaches whichever `Identity` your lookup / mapper returns (e.g. the `User`
your `UserLookup` returns for `basicAuth { }`, the `Client` your `ApiKeyLookup` returns for
`apiKey { }`) — that's the type you read back with `identity()`. JWT defaults to its own `Jwt`
identity (wrapping the verified token), or your own type when you configure `identityMapper`.
A custom authenticator can attach any `Identity` subtype you choose. `identity<T>()` is an
unchecked cast (verified at runtime, like `ctx.attribute<T>()`): a mismatch between the type you
attached and the type you request throws `ClassCastException`.

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
    // User is whatever Identity type you configured your strategy with.

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

Authentication resolves **once at the upgrade**; the resulting `Authentication` is attached to
every `WsContext` for the session and never re-checked per message.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication
    import io.github.mzlnk.javalin.security.identity
    import io.github.mzlnk.javalin.security.identityOrNull
    import io.github.mzlnk.javalin.security.jwt.Jwt

    config.routes.ws("/ws/chat") { ws ->
        ws.onConnect { ctx ->
            // Behind Rules.authenticated() — use identity()
            val user = ctx.identity<Jwt>()
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
            val user = ctx.identityOrNull<Jwt>() ?: return@onConnect
            ctx.send("welcome ${user.name}")
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.jwt.Jwt;

    config.routes.ws("/ws/chat", ws -> {
        ws.onConnect(ctx -> {
            // Behind Rules.authenticated() — use identity()
            Jwt user = identity(ctx, Jwt.class);
            ctx.send("welcome " + user.getName());
        });
        ws.onMessage(ctx ->
            ctx.send("you have roles: " + authentication(ctx).getRoles()));
    });

    config.routes.ws("/ws/public", ws -> {
        ws.onConnect(ctx -> {
            // May be anonymous — use identityOrNull()
            Jwt user = identityOrNull(ctx, Jwt.class);
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
- **Wrong type.** Calling `identity()` / `identity(ctx, T.class)` with a type that doesn't match
  your configured strategy throws `ClassCastException`. Always use the identity type that matches
  your strategy.
- **`Context` vs `WsContext`.** Both expose the same extensions, but importing the wrong one
  will not compile. Both live in `io.github.mzlnk.javalin.security`.
- **WebSocket identity is fixed for the session.** If you need to react to token expiry
  mid-session, enforce it in your protocol.

## Next steps

- [Authentication](../concepts/authentication.md) — identities, roles, and the three outcomes.
- [Authorization](../concepts/authorization.md) — pair identity with rules and route roles.
- [Custom authentication](../guides/custom-authentication.md) — supply your own identity type.
