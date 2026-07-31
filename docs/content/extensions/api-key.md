# API Key

The `javalin-security-api-key` extension adds opaque API-key authentication to javalin-security.
A client sends a key (by default in the `X-Api-Key` header). The extension reads that value,
looks it up, and attaches your `Identity` plus roles to the request so
[authorization](../concepts/authorization.md) can decide access.

You bring your own `Identity` type and an `ApiKeyLookup` that maps a raw key to
`ApiKeyDetails` — the identity to attach and the roles to grant. Storage and comparison
(including hashing and constant-time equality) stay in your lookup.

!!! info "HTTP only"
    Assign the strategy to `http.authentication`. There is no WebSocket variant of API-key auth.

## Installation

Add the extension alongside [javalin-security](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-api-key:{{ versions.library }}")
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-api-key</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    ```

!!! danger "Store hashed keys and compare in constant time"
    The extension treats the key as an opaque string and delegates lookup entirely to your
    `ApiKeyLookup`. In production, store **hashed** API keys and compare with a constant-time
    equality check inside the lookup — never keep plaintext keys in a database. See
    [`lookup`](#lookup).

## Minimal setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Identity
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.apikey.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { SERVICE, ADMIN }

    // Client specific identity attached to context
    data class Client(override val name: String) : Identity

    // in-memory set of API keys with details
    val keys = mapOf(
        "k-alice" to ApiKeyDetails(Client("orders-svc"), setOf(Role.SERVICE)),
        "k-admin" to ApiKeyDetails(Client("admin-svc"), setOf(Role.ADMIN)),
    )

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))

            security.http.authentication = apiKey { api ->
                // Required: resolve raw key to stored details
                api.lookup = ApiKeyLookup { raw -> keys[raw] }
            }

            security.http.fallback = Rules.authenticated()
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authentication.Identity;
    import io.github.mzlnk.javalin.security.apikey.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import io.javalin.security.RouteRole;
    import java.util.Map;
    import java.util.Set;

    enum Role implements RouteRole { SERVICE, ADMIN }

    // Client specific identity attached to context
    record Client(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    // in-memory set of API keys with details
    Map<String, ApiKeyDetails> keys = Map.of(
        "k-alice", new ApiKeyDetails(new Client("orders-svc"), Set.of(Role.SERVICE)),
        "k-admin", new ApiKeyDetails(new Client("admin-svc"), Set.of(Role.ADMIN)));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));

            security.http.authentication = ApiKeySecurity.apiKey(api -> {
                // Required: resolve raw key to stored details
                api.lookup = keys::get;
            });

            security.http.fallback = Rules.authenticated();
        }));
    });
    ```

## Configuration

| Field                 | Default            | Effect                                                       |
|-----------------------|--------------------|--------------------------------------------------------------|
| `lookup`              | *required*         | Raw key → `ApiKeyDetails` (or `null`).                       |
| `resolver`            | `X-Api-Key` header | Where the key is read from.                                  |
| `unauthorizedHandler` | bare HTTP 401      | Renders failed or absent authentication.                     |
| `forbiddenHandler`    | bare HTTP 403      | Renders access denied for authenticated callers.             |

### `lookup`

Required. Called with the raw key extracted from the request. Return an `ApiKeyDetails` for
known keys, or `null` when the key is unknown — never throw.

`ApiKeyDetails` holds two pieces:

| Member     | Role                                                     |
|------------|----------------------------------------------------------|
| `identity` | Your `Identity` attached to the request on success.      |
| `roles`    | Granted on success and stored on `Authentication.roles`. |

Absent credentials yield an anonymous request. A present but unknown key is a failure (401 by
default). Hashing and constant-time comparison belong inside your lookup implementation.

### `resolver`

Locates the raw API key in the request. The default reads the `X-Api-Key` header. Return
`null` when the key is absent so the request continues as anonymous. Resolvers must not throw
when no key is present and must not validate the key themselves.

Override when the key arrives elsewhere:

| Resolver option                     | Reads key from           |
|------------------------------------- |-------------------------|
| `ApiKeyResolver.header("X-App-Key")` | HTTP header             |
| `ApiKeyResolver.query("api_key")`    | Query string parameter  |
| `ApiKeyResolver.cookie("api_key")`   | Cookie                  |

Set via `api.resolver = ...` in your configuration, for example:

=== "Kotlin"

    ```kotlin
    apiKey { api ->
        api.lookup = myLookup
        api.resolver = ApiKeyResolver.header("X-App-Key")
    }
    ```

=== "Java"

    ```java
    ApiKeySecurity.apiKey(api -> {
        api.lookup = myLookup;
        api.resolver = ApiKeyResolver.header("X-App-Key");
    });
    ```

### `unauthorizedHandler`

Renders the response for failed or absent authentication (default: bare HTTP 401). There is no
standardised `WWW-Authenticate` scheme for API keys. Override when you need a JSON body or
other rendering:

=== "Kotlin"

    ```kotlin
    apiKey { api ->
        api.lookup = myLookup
        api.unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
            ctx.status(401).result("""{"error":"invalid_api_key"}""")
        }
    }
    ```

=== "Java"

    ```java
    ApiKeySecurity.apiKey(api -> {
        api.lookup = myLookup;
        api.unauthorizedHandler = (ctx, failure) ->
            ctx.status(401).result("{\"error\":\"invalid_api_key\"}");
    });
    ```

See [Error handling](../concepts/error-handling.md) for more on customising 401 responses.

### `forbiddenHandler`

Renders the response when an **authenticated** caller is denied by authorization (default: bare
HTTP 403). Override when you need a JSON body or other rendering — see
[Error handling](../concepts/error-handling.md).

## Reading the identity

On success the strategy attaches your looked-up `Identity` directly to the request:

=== "Kotlin"

    ```kotlin
    config.routes.get("/me") { ctx ->
        ctx.result(ctx.identity<Client>().name)
    }
    ```

=== "Java"

    ```java
    config.routes.get("/me", ctx ->
        ctx.result(identity(ctx, Client.class).getName()));
    ```

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read your `Identity`
  in handlers.
- [Authorization](../concepts/authorization.md) — pair API keys with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — async / remote lookup patterns
  when `ApiKeyLookup` is not enough.
