# API Key

Opaque API-key authentication via `javalin-security-api-key`. You bring your own `Identity`
type; `ApiKeyLookup` resolves a raw key directly to your identity — there is no separate
principal type to convert.

!!! info "HTTP only"
    Assign to `http.authentication`. There is no WebSocket variant of API-key auth.

## Installation

Add the extension on top of [core](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-api-key:{{ versions.library }}")
    // plus javalin-security + Javalin + SLF4J from core
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
    The extension treats the key as an opaque string and delegates lookup entirely to
    your `ApiKeyLookup`. In production, store **hashed** API keys and compare with a
    constant-time equality check inside the lookup — never keep plaintext keys in a
    database.

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

    data class Client(override val name: String, override val roles: Set<RouteRole>) : Identity

    val keys = mapOf(
        "k-alice" to Client("orders-svc", setOf(Role.SERVICE)),
        "k-admin" to Client("admin-svc", setOf(Role.ADMIN)),
    )

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = apiKey { api ->
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
    import java.util.Map;
    import java.util.Set;

    record Client(String name, Set<RouteRole> roles) implements Identity {
        @Override public String getName() { return name; }
        @Override public Set<RouteRole> getRoles() { return roles; }
    }

    Map<String, Client> keys = Map.of(
        "k-alice", new Client("orders-svc", Set.of(Role.SERVICE)),
        "k-admin", new Client("admin-svc", Set.of(Role.ADMIN)));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = ApiKeySecurity.apiKey(api -> {
                api.lookup = keys::get;
            });
            security.http.fallback = Rules.authenticated();
        }));
    });
    ```

## Configuration

| Field                  | Default                | Effect                                                              |
|------------------------|------------------------|-----------------------------------------------------------------------|
| `lookup`               | *required*             | Raw key → `Identity` (or `null`).                                   |
| `resolver`             | `X-Api-Key` header     | Where the key is read from.                                         |
| `forbiddenHandler`     | bare HTTP 403          | Renders access denied for authenticated callers.                    |
| `unauthorizedHandler`  | bare HTTP 401          | Renders failed or absent authentication.                            |

Return `null` for unknown keys (never throw). Absent credentials yield an anonymous
request; a present-but-unknown key is a failure (401 by default).

## Where the key comes from

`ApiKeyResolver` locates the raw key in the request. The default is the `X-Api-Key`
header. Override via `resolver`:

=== "Kotlin"

    ```kotlin
    apiKey { api ->
        api.lookup = myLookup
        api.resolver = ApiKeyResolver.header("X-App-Key")   // custom header
        // api.resolver = ApiKeyResolver.query("api_key")   // query parameter
        // api.resolver = ApiKeyResolver.cookie("api_key")  // cookie
    }
    ```

=== "Java"

    ```java
    ApiKeySecurity.apiKey(api -> {
        api.lookup = myLookup;
        api.resolver = ApiKeyResolver.header("X-App-Key");   // custom header
        // api.resolver = ApiKeyResolver.query("api_key");   // query parameter
        // api.resolver = ApiKeyResolver.cookie("api_key");  // cookie
    });
    ```

!!! warning "Prefer headers over query parameters"
    Query parameters commonly appear in access logs, browser history, and `Referer`
    headers. Use `ApiKeyResolver.query(...)` only when a client cannot set custom
    headers (e.g. some webhook receivers).

## Identity

On success the strategy attaches the looked-up identity directly to the request:

```kotlin
config.routes.get("/me") { ctx ->
    ctx.result(ctx.identity<Client>().name)
}
```

## Custom 401 responses

There is no standardised `WWW-Authenticate` scheme for API keys. Override
`unauthorizedHandler` when you need a JSON body or other rendering:

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

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read your
  `Identity` in handlers.
- [Authorization](../concepts/authorization.md) — pair API keys with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — async / remote lookup
  patterns when `ApiKeyLookup` is not enough.
