# Opaque Token

Opaque bearer-token authentication via `javalin-security-opaque-token`. You supply an
`OpaqueTokenLookup`; the extension resolves the token from the request (default:
`Authorization: Bearer …`), validates optional expiry, and produces an `OpaqueTokenIdentity`
with roles.

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
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.opaquetoken.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    val tokens = mapOf(
        "t-alice" to OpaqueTokenDetails(subject = "alice", roles = setOf(Role.USER)),
        "t-admin" to OpaqueTokenDetails(subject = "admin", roles = setOf(Role.ADMIN)),
    )

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = opaqueToken { ot ->
                ot.tokenLookup = OpaqueTokenLookup { raw -> tokens[raw] }
            }
            security.http.fallback = Rules.authenticated()
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.opaquetoken.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.util.Map;
    import java.util.Set;

    Map<String, OpaqueTokenDetails> tokens = Map.of(
        "t-alice", new OpaqueTokenDetails("alice", Set.of(Role.USER)),
        "t-admin", new OpaqueTokenDetails("admin", Set.of(Role.ADMIN)));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = OpaqueTokenSecurity.opaqueToken(ot -> {
                ot.tokenLookup = tokens::get;
            });
            security.http.fallback = Rules.authenticated();
        }));
    });
    ```

## Configuration

| Field                  | Default                          | Effect                                                              |
|------------------------|----------------------------------|---------------------------------------------------------------------|
| `tokenLookup`          | *required*                       | Raw token → `OpaqueTokenDetails` (or `null`).                       |
| `resolver`             | `Authorization: Bearer …`        | Where the token is read from (`TokenResolver`).                     |
| `clock`                | `Clock.systemUTC()`              | Used to validate `OpaqueTokenDetails.expiresAt`.                    |
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
        ot.tokenLookup = myLookup
        ot.resolver = TokenResolver.cookie("session")   // cookie
        // ot.resolver = TokenResolver.bearerHeader()   // default Authorization Bearer
    }
    ```

=== "Java"

    ```java
    OpaqueTokenSecurity.opaqueToken(ot -> {
        ot.tokenLookup = myLookup;
        ot.resolver = TokenResolver.cookie("session");   // cookie
        // ot.resolver = TokenResolver.bearerHeader();   // default Authorization Bearer
    });
    ```

!!! warning "Prefer headers or cookies over query parameters"
    Query parameters commonly appear in access logs, browser history, and `Referer` headers.
    Prefer `TokenResolver.bearerHeader(...)` or `TokenResolver.cookie(...)`.

## Expiry

When `OpaqueTokenDetails.expiresAt` is non-null, the authenticator rejects the token if
`expiresAt` is at-or-before the configured `clock`'s instant (`Failure("token expired")`).
Leave `expiresAt` as `null` for non-expiring tokens.

To **revoke** a token early, return `null` from the lookup (same as an unknown token).

## Identity

On success the strategy attaches an `OpaqueTokenIdentity` whose `name` is the
`OpaqueTokenDetails.subject` from the lookup:

```kotlin
config.routes.get("/me") { ctx ->
    ctx.result(ctx.identity<OpaqueTokenIdentity>().name)
}
```

## Bearer challenge

Enable a RFC 6750-style `WWW-Authenticate: Bearer` challenge on 401 responses:

=== "Kotlin"

    ```kotlin
    opaqueToken { ot ->
        ot.tokenLookup = myLookup
        ot.bearerChallenge = true
        ot.realm = "API"
    }
    ```

=== "Java"

    ```java
    OpaqueTokenSecurity.opaqueToken(ot -> {
        ot.tokenLookup = myLookup;
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
        ot.tokenLookup = myLookup
        ot.unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
            ctx.status(401).result("""{"error":"invalid_token"}""")
        }
    }
    ```

=== "Java"

    ```java
    OpaqueTokenSecurity.opaqueToken(ot -> {
        ot.tokenLookup = myLookup;
        ot.unauthorizedHandler = (ctx, failure) ->
            ctx.status(401).result("{\"error\":\"invalid_token\"}");
    });
    ```

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read
  `OpaqueTokenIdentity` in handlers.
- [Authorization](../concepts/authorization.md) — pair opaque tokens with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — async / remote lookup
  patterns when a sync `OpaqueTokenLookup` is not enough.
