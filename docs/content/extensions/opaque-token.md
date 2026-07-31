# Opaque Token

The `javalin-security-opaque-token` extension adds opaque bearer-token authentication to
javalin-security. A client sends a token (by default in the `Authorization: Bearer …` header).
The extension reads that value, looks it up, checks an optional expiry, and attaches your
`Identity` plus roles to the request so [authorization](../concepts/authorization.md) can decide
access.

You bring your own `Identity` type and an `OpaqueTokenLookup` that maps a raw token to
`OpaqueTokenDetails` — the identity to attach, an optional expiry, and the roles to grant.
Storage and comparison (including hashing and constant-time equality) stay in your lookup.

Use this for **server-issued opaque tokens** — session tokens, personal access tokens (PATs),
or any non-JWT bearer scheme where the application owns a token store. This is **not** OAuth2:
there is no grant flow, token endpoint, or RFC 7662 introspection helper.

!!! info "HTTP only"
    Assign the strategy to `http.authentication`. There is no WebSocket variant of opaque-token
    auth.

## Installation

Add the extension alongside [javalin-security](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-opaque-token:{{ versions.library }}")
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-opaque-token</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    ```

## Minimal setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Identity
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.opaquetoken.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    // User specific identity attached to context
    data class User(override val name: String) : Identity

    // in-memory set of tokens with details
    val tokens = mapOf(
        "t-alice" to OpaqueTokenDetails(User("alice"), roles = setOf(Role.USER)),
        "t-admin" to OpaqueTokenDetails(User("admin"), roles = setOf(Role.ADMIN)),
    )

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))

            security.http.authentication = opaqueToken { ot ->
                // Required: resolve raw token to stored details
                ot.lookup = OpaqueTokenLookup { raw -> tokens[raw] }
            }

            security.http.fallback = Rules.authenticated()
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authentication.Identity;
    import io.github.mzlnk.javalin.security.opaquetoken.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import io.javalin.security.RouteRole;
    import java.util.Map;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    // User specific identity attached to context
    record User(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    // in-memory set of tokens with details
    Map<String, OpaqueTokenDetails> tokens = Map.of(
        "t-alice", new OpaqueTokenDetails(new User("alice"), null, Set.of(Role.USER)),
        "t-admin", new OpaqueTokenDetails(new User("admin"), null, Set.of(Role.ADMIN)));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));

            security.http.authentication = OpaqueTokenSecurity.opaqueToken(ot -> {
                // Required: resolve raw token to stored details
                ot.lookup = tokens::get;
            });

            security.http.fallback = Rules.authenticated();
        }));
    });
    ```

## Configuration

| Field                 | Default                   | Effect                                                                 |
|-----------------------|---------------------------|------------------------------------------------------------------------|
| `lookup`              | *required*                | Raw token → `OpaqueTokenDetails` (or `null`).                          |
| `resolver`            | `Authorization: Bearer …` | Where the token is read from (`TokenResolver`).                        |
| `clock`               | `Clock.systemUTC()`       | Used to validate `OpaqueTokenDetails.expiresAt`.                       |
| `bearerChallenge`     | `false`                   | Add `WWW-Authenticate: Bearer` on 401.                                 |
| `realm`               | `"API"`                   | Realm reported in the challenge.                                       |
| `unauthorizedHandler` | bare HTTP 401             | Renders failed or absent authentication. Ignored when `bearerChallenge` is `true`. |
| `forbiddenHandler`    | bare HTTP 403             | Renders access denied for authenticated callers.                       |

### `lookup`

Required. Called with the raw token extracted from the request. Return an `OpaqueTokenDetails`
for known tokens, or `null` when the token is unknown or revoked — never throw.

`OpaqueTokenDetails` holds three pieces:

| Member      | Role                                                                 |
|-------------|----------------------------------------------------------------------|
| `identity`  | Your `Identity` attached to the request on success.                  |
| `expiresAt` | Optional expiry. Rejected when at or before the configured `clock`.  |
| `roles`     | Granted on success and stored on `Authentication.roles`.             |

Absent credentials yield an anonymous request. A present but unknown, revoked, or expired token
is a failure (401 by default). Leave `expiresAt` as `null` for non-expiring tokens. To revoke a
token early, return `null` from the lookup. Hashing and constant-time comparison belong inside
your lookup implementation.

### `resolver`

Locates the raw token in the request via javalin-security's `TokenResolver`. The default reads
the standard `Authorization: Bearer …` header. Return `null` when the token is absent so the
request continues as anonymous. Resolvers must not throw when no token is present and must not
validate the token themselves.

Override when the token arrives elsewhere:

| Resolver option                      | Reads token from        |
|--------------------------------------|-------------------------|
| `TokenResolver.bearerHeader()`       | `Authorization: Bearer` |
| `TokenResolver.bearerHeader("…")`    | Custom header, Bearer   |
| `TokenResolver.cookie("session")`    | Cookie                  |

Set via `ot.resolver = ...` in your configuration, for example:

=== "Kotlin"

    ```kotlin
    opaqueToken { ot ->
        ot.lookup = myLookup
        ot.resolver = TokenResolver.cookie("session")
    }
    ```

=== "Java"

    ```java
    OpaqueTokenSecurity.opaqueToken(ot -> {
        ot.lookup = myLookup;
        ot.resolver = TokenResolver.cookie("session");
    });
    ```

### `clock`

Clock used when validating `OpaqueTokenDetails.expiresAt`. Defaults to `Clock.systemUTC()`.
Inject a fixed clock in tests so expiry behaviour is deterministic.

### `bearerChallenge`

When `true`, failed or absent authentication includes a `WWW-Authenticate: Bearer …` header on
the 401 response (RFC 6750 style). Defaults to `false` (bare 401, or your custom
`unauthorizedHandler`).

Absent credentials produce `WWW-Authenticate: Bearer realm="…"`. Invalid or expired tokens
additionally include `error="invalid_token"`. When enabled, the challenge takes precedence over
a custom `unauthorizedHandler`.

### `realm`

Realm string reported in the `WWW-Authenticate` challenge when `bearerChallenge` is `true`.
Defaults to `"API"`. Ignored when the challenge is disabled.

=== "Kotlin"

    ```kotlin
    opaqueToken { ot ->
        ot.lookup = myLookup
        ot.bearerChallenge = true
        ot.realm = "API"
    }
    ```

=== "Java"

    ```java
    OpaqueTokenSecurity.opaqueToken(ot -> {
        ot.lookup = myLookup;
        ot.bearerChallenge = true;
        ot.realm = "API";
    });
    ```

### `unauthorizedHandler`

Renders the response for failed or absent authentication (default: bare HTTP 401). Ignored when
`bearerChallenge` is `true`. Override when you need a JSON body or other rendering and do not
want the bearer challenge:

=== "Kotlin"

    ```kotlin
    opaqueToken { ot ->
        ot.lookup = myLookup
        ot.unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
            ctx.status(401).result("""{"error":"invalid_token"}""")
        }
    }
    ```

=== "Java"

    ```java
    OpaqueTokenSecurity.opaqueToken(ot -> {
        ot.lookup = myLookup;
        ot.unauthorizedHandler = (ctx, failure) ->
            ctx.status(401).result("{\"error\":\"invalid_token\"}");
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
        ctx.result(ctx.identity<User>().name)
    }
    ```

=== "Java"

    ```java
    config.routes.get("/me", ctx ->
        ctx.result(identity(ctx, User.class).getName()));
    ```

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read your `Identity`
  in handlers.
- [Authorization](../concepts/authorization.md) — pair opaque tokens with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — async / remote lookup patterns
  when a sync `OpaqueTokenLookup` is not enough.
