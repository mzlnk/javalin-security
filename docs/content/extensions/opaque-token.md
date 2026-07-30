# Opaque Token

Opaque bearer-token authentication via `javalin-security-opaque-token`. You bring your own
`Identity` type; `OpaqueTokenLookup` resolves a raw token to a `TokenRecord` (your identity plus
an optional expiry). The extension resolves the token from the request (default:
`Authorization: Bearer …`), validates the optional expiry, and attaches your identity.

Use this for **server-issued opaque tokens** — session tokens, personal access tokens (PATs),
or any non-JWT bearer scheme where the application owns a token store. This is **not** OAuth2:
there is no grant flow, token endpoint, or RFC 7662 introspection helper.

!!! info "Opaque vs JWT"
    JWTs are self-contained and verified cryptographically (stateless). Opaque tokens are looked
    up in your store (stateful) — which also makes revocation a simple delete or `null` return
    from the lookup.

## Installation

Add the extension on top of [core](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-opaque-token:{{ versions.library }}")
    // plus javalin-security + Javalin + SLF4J from core
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-opaque-token</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    ```

!!! danger "Store hashed tokens and compare in constant time"
    The extension treats the token as an opaque string and delegates lookup entirely to your
    `OpaqueTokenLookup`. In production, store **hashed** tokens (SHA-256 is enough when tokens
    have full entropy — no salt/PBKDF2 needed) and compare with a constant-time equality check
    inside the lookup — never keep plaintext tokens in a database.

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

    data class User(override val name: String, override val roles: Set<RouteRole>) : Identity

    val tokens = mapOf(
        "t-alice" to TokenRecord(User("alice", setOf(Role.USER))),
        "t-admin" to TokenRecord(User("admin", setOf(Role.ADMIN))),
    )

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = opaqueToken { ot ->
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
    import java.util.Map;
    import java.util.Set;

    record User(String name, Set<RouteRole> roles) implements Identity {
        @Override public String getName() { return name; }
        @Override public Set<RouteRole> getRoles() { return roles; }
    }

    Map<String, TokenRecord> tokens = Map.of(
        "t-alice", new TokenRecord(new User("alice", Set.of(Role.USER))),
        "t-admin", new TokenRecord(new User("admin", Set.of(Role.ADMIN))));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = OpaqueTokenSecurity.opaqueToken(ot -> {
                ot.lookup = tokens::get;
            });
            security.http.fallback = Rules.authenticated();
        }));
    });
    ```

## Configuration

| Field                  | Default                          | Effect                                                              |
|------------------------|-----------------------------------|---------------------------------------------------------------------|
| `lookup`               | *required*                       | Raw token → `TokenRecord` (or `null`).                              |
| `resolver`             | `Authorization: Bearer …`        | Where the token is read from (`TokenResolver`).                     |
| `clock`                | `Clock.systemUTC()`              | Used to validate `TokenRecord.expiresAt`.                           |
| `bearerChallenge`      | `false`                          | When `true`, 401 responses include `WWW-Authenticate: Bearer`.      |
| `realm`                | `"API"`                          | Realm attribute for the bearer challenge.                           |
| `forbiddenHandler`     | bare HTTP 403                    | Renders access denied for authenticated callers.                    |
| `unauthorizedHandler`  | bare HTTP 401                    | Renders failed or absent authentication. Ignored when `bearerChallenge` is `true`. |

Return `null` for unknown or revoked tokens (never throw). Absent credentials yield an anonymous
request; a present-but-invalid or expired token is a failure (401 by default).

## Where the token comes from

The extension reuses core's `TokenResolver`. The default is `Authorization: Bearer <token>`.
Override via `resolver`:

=== "Kotlin"

    ```kotlin
    opaqueToken { ot ->
        ot.lookup = myLookup
        ot.resolver = TokenResolver.cookie("session")   // cookie
        // ot.resolver = TokenResolver.bearerHeader()   // default Authorization Bearer
    }
    ```

=== "Java"

    ```java
    OpaqueTokenSecurity.opaqueToken(ot -> {
        ot.lookup = myLookup;
        ot.resolver = TokenResolver.cookie("session");   // cookie
        // ot.resolver = TokenResolver.bearerHeader();   // default Authorization Bearer
    });
    ```

!!! warning "Prefer headers or cookies over query parameters"
    Query parameters commonly appear in access logs, browser history, and `Referer` headers.
    Prefer `TokenResolver.bearerHeader(...)` or `TokenResolver.cookie(...)`.

## Expiry and revocation

When `TokenRecord.expiresAt` is non-null, the authenticator rejects the token if `expiresAt` is
at-or-before the configured `clock`'s instant (`Failure("token expired")`). Leave `expiresAt` as
`null` for non-expiring tokens.

To **revoke** a token early, return `null` from the lookup (same as an unknown token).

## Identity

On success the strategy attaches the resolved `TokenRecord.identity` as the request's identity:

```kotlin
config.routes.get("/me") { ctx ->
    ctx.result(ctx.identity<User>().name)
}
```

## Bearer challenge

Enable a RFC 6750-style `WWW-Authenticate: Bearer` challenge on 401 responses:

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

Absent credentials produce `WWW-Authenticate: Bearer realm="API"`. Invalid or expired tokens
additionally include `error="invalid_token"`. When `bearerChallenge` is `true`, it takes
precedence over a custom `unauthorizedHandler`.

## Custom 401 responses

When you need a JSON body (and do not want the bearer challenge), leave `bearerChallenge = false`
and override `unauthorizedHandler`:

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

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read your
  `Identity` in handlers.
- [Authorization](../concepts/authorization.md) — pair opaque tokens with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — async / remote lookup
  patterns when a sync `OpaqueTokenLookup` is not enough.
