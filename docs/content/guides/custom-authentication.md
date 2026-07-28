# Custom authentication

When neither Basic Auth nor JWT fits — API keys, opaque session tokens, mTLS client certs, HMAC
request signing — implement your own `Authenticator` on top of core. No extra modules required.

## The recipe

1. Define an `Identity` for your scheme.
2. Write an `Authenticator` that returns `Success`, `Failure`, or `NotAuthenticated`.
3. Wrap it in an `AuthenticationStrategy.Sync` (or `.Async`) and assign it.

## Example: API-key authentication

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { SERVICE }

    class ApiKeyIdentity(override val name: String, val tenant: String) : Identity

    // Your store: key -> (name, tenant, roles)
    val keys = mapOf("k-123" to Triple("orders-svc", "acme", setOf(Role.SERVICE)))

    val apiKeyAuthenticator = Authenticator { ctx ->
        when (val key = ctx.header("X-Api-Key")) {
            null -> AuthenticationResult.NotAuthenticated             // no key → anonymous
            else -> {
                val record = keys[key]
                    ?: return@Authenticator AuthenticationResult.Failure("unknown api key")
                val (name, tenant, roles) = record
                AuthenticationResult.Success(
                    Authentication.authenticated(ApiKeyIdentity(name, tenant), roles),
                )
            }
        }
    }

    val apiKeyStrategy = object : AuthenticationStrategy.Sync {
        override fun authenticator() = apiKeyAuthenticator
        // Optional: customize failure rendering.
        override val unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
            ctx.status(401).json(mapOf("error" to "invalid_api_key"))
        }
    }

    // Assign it:
    // http.authentication = apiKeyStrategy
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authentication.*;
    import io.javalin.security.RouteRole;
    import java.util.*;

    enum Role implements RouteRole { SERVICE }

    final class ApiKeyIdentity implements Identity {
        private final String name; private final String tenant;
        ApiKeyIdentity(String name, String tenant) { this.name = name; this.tenant = tenant; }
        @Override public String getName() { return name; }
        public String getTenant() { return tenant; }
    }

    record KeyRecord(String name, String tenant, Set<RouteRole> roles) {}
    Map<String, KeyRecord> keys = Map.of("k-123",
        new KeyRecord("orders-svc", "acme", Set.of(Role.SERVICE)));

    Authenticator apiKeyAuthenticator = ctx -> {
        String key = ctx.header("X-Api-Key");
        if (key == null) return AuthenticationResult.NotAuthenticated.INSTANCE;   // no key → anonymous
        KeyRecord rec = keys.get(key);
        if (rec == null) return new AuthenticationResult.Failure("unknown api key", null);
        return new AuthenticationResult.Success(
            Authentication.authenticated(new ApiKeyIdentity(rec.name(), rec.tenant()), rec.roles()));
    };

    AuthenticationStrategy.Sync apiKeyStrategy = new AuthenticationStrategy.Sync() {
        @Override public Authenticator authenticator() { return apiKeyAuthenticator; }
        @Override public UnauthorizedHandler getUnauthorizedHandler() {
            return (ctx, failure) -> ctx.status(401).json(Map.of("error", "invalid_api_key"));
        }
    };

    // Assign it:
    // http.authentication = apiKeyStrategy;
    ```

## Rules for a well-behaved authenticator

!!! danger "Return `NotAuthenticated` — not `Failure` — when there are no credentials"
    A missing credential means *anonymous*, and the authorization layer decides. Returning
    `Failure` would 401 every anonymous request and break public routes and the `Anyone` role.
    Reserve `Failure` for credentials that are **present but invalid**.

- **Don't throw** when credentials are absent. (A synchronous throw is treated as a failure →
  401 for async; for sync authenticators, return `NotAuthenticated`.)
- **Don't leak** why authentication failed — put the reason in `Failure.message` (logged only).
- Keep the authenticator **fast** on the request thread; if you must do remote I/O, use the
  async variant below.

## Async variant

For remote validation (introspection endpoint, DB), implement `AuthenticationStrategy.Async`:

=== "Kotlin"

    ```kotlin
    val asyncStrategy = object : AuthenticationStrategy.Async {
        override fun authenticator() = AsyncAuthenticator { ctx ->
            val key = ctx.header("X-Api-Key")
                ?: return@AsyncAuthenticator CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated)
            introspectAsync(key).thenApply { record ->
                if (record == null) AuthenticationResult.Failure("unknown api key")
                else AuthenticationResult.Success(Authentication.authenticated(record.identity, record.roles))
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
                    : new AuthenticationResult.Success(Authentication.authenticated(record.identity(), record.roles())));
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
