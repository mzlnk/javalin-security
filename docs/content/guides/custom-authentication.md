# Custom authentication

When ready-made extensions do not cover your scheme — mTLS client certificates, HMAC request
signing, or a proprietary header protocol — implement your own `Authenticator` on top of
javalin-security. No extra modules are required.

## The recipe

1. Define an `Identity` for your scheme.
2. Write an `Authenticator` that returns `Success`, `Failure`, or `NotAuthenticated`.
3. Wrap it in an `AuthenticationStrategy.Sync` (or `.Async`) and assign it.

## Example: header-based authentication

A minimal strategy that reads an `X-Api-Key` header, looks it up in an in-memory store, and
attaches a custom identity plus roles.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { SERVICE }

    // Caller-specific identity attached to the context
    class ServiceIdentity(
        override val name: String,
        val tenant: String,
    ) : Identity

    // in-memory store: key → (name, tenant, roles)
    val keys = mapOf("k-123" to Triple("orders-svc", "acme", setOf(Role.SERVICE)))

    val apiKeyAuthenticator = Authenticator { ctx ->
        when (val key = ctx.header("X-Api-Key")) {
            null -> AuthenticationResult.NotAuthenticated             // no key → anonymous
            else -> {
                val record = keys[key]
                    ?: return@Authenticator AuthenticationResult.Failure("unknown api key")
                val (name, tenant, roles) = record
                AuthenticationResult.Success(
                    Authentication.authenticated(ServiceIdentity(name, tenant), roles),
                )
            }
        }
    }

    val apiKeyStrategy = object : AuthenticationStrategy.Sync {
        override fun authenticator() = apiKeyAuthenticator
        // Optional: customize failure rendering
        override val unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
            ctx.status(401).json(mapOf("error" to "invalid_api_key"))
        }
    }

    // Assign it
    // http.authentication = apiKeyStrategy
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authentication.*;
    import io.javalin.security.RouteRole;
    import java.util.*;

    enum Role implements RouteRole { SERVICE }

    // Caller-specific identity attached to the context
    final class ServiceIdentity implements Identity {
        private final String name;
        private final String tenant;
        ServiceIdentity(String name, String tenant) {
            this.name = name;
            this.tenant = tenant;
        }
        @Override public String getName() { return name; }
        public String getTenant() { return tenant; }
    }

    // in-memory store: key → (name, tenant, roles)
    record KeyRecord(String name, String tenant, Set<RouteRole> roles) {}
    Map<String, KeyRecord> keys = Map.of("k-123",
        new KeyRecord("orders-svc", "acme", Set.of(Role.SERVICE)));

    Authenticator apiKeyAuthenticator = ctx -> {
        String key = ctx.header("X-Api-Key");
        if (key == null) return AuthenticationResult.NotAuthenticated.INSTANCE;   // no key → anonymous
        KeyRecord rec = keys.get(key);
        if (rec == null) return new AuthenticationResult.Failure("unknown api key", null);
        return new AuthenticationResult.Success(
            Authentication.authenticated(new ServiceIdentity(rec.name(), rec.tenant()), rec.roles()));
    };

    AuthenticationStrategy.Sync apiKeyStrategy = new AuthenticationStrategy.Sync() {
        @Override public Authenticator authenticator() { return apiKeyAuthenticator; }
        @Override public UnauthorizedHandler getUnauthorizedHandler() {
            return (ctx, failure) -> ctx.status(401).json(Map.of("error", "invalid_api_key"));
        }
    };

    // Assign it
    // http.authentication = apiKeyStrategy;
    ```

For production API-key auth, prefer the ready-made [API Key](../extensions/api-key.md)
extension. The example above is only a teaching sketch of the authenticator pattern.

## Rules for a well-behaved authenticator

!!! danger "Return `NotAuthenticated` — not `Failure` — when there are no credentials"
    A missing credential means *anonymous*, and the authorization layer decides. Returning
    `Failure` would 401 every anonymous request and break public routes and the `Anyone` role.
    Reserve `Failure` for credentials that are **present but invalid**.

- **Don't throw** when credentials are absent. Return `NotAuthenticated` from a sync
  authenticator. A throw is treated as a failure and becomes a 401.
- **Don't leak** why authentication failed — put the reason in `Failure.message` (logged only).
- Keep the authenticator **fast** on the request thread. If you must do remote I/O, use the
  async variant below.

## Async variant

For remote validation (introspection endpoint, database lookup), implement
`AuthenticationStrategy.Async`:

=== "Kotlin"

    ```kotlin
    val asyncStrategy = object : AuthenticationStrategy.Async {
        override fun authenticator() = AsyncAuthenticator { ctx ->
            val key = ctx.header("X-Api-Key")
                ?: return@AsyncAuthenticator CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated)
            introspectAsync(key).thenApply { record ->
                if (record == null) AuthenticationResult.Failure("unknown api key")
                else AuthenticationResult.Success(Authentication.authenticated(record.identity))
            }
        }
    }
    ```

=== "Java"

    ```java
    AuthenticationStrategy.Async asyncStrategy = new AuthenticationStrategy.Async() {
        @Override public AsyncAuthenticator authenticator() {
            return ctx -> {
                String key = ctx.header("X-Api-Key");
                if (key == null) return CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated.INSTANCE);
                return introspectAsync(key).thenApply(record -> record == null
                    ? new AuthenticationResult.Failure("unknown api key", null)
                    : new AuthenticationResult.Success(Authentication.authenticated(record.identity())));
            };
        }
    };
    ```

On HTTP, async strategies use `Context.future` so the request thread is released during I/O. On
WebSocket, the future is awaited with `join()` at upgrade time.

## Next steps

- [Error handling](../concepts/error-handling.md) — customize 401 / 403 rendering.
- [Authentication](../concepts/authentication.md) — outcomes and identity model.
- [Testing](testing.md) — assert your strategy end to end.
