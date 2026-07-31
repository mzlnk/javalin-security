# Configuration

The `javalin-security-jwt` extension authenticates callers with a verified JWT. A client sends a
token (by default in the `Authorization: Bearer …` header). The extension reads that value,
verifies the signature and claims through a **decoder adapter**, and attaches an `Identity` plus
roles to the request so [authorization](../../concepts/authorization.md) can decide access.

You pick a decoder — [Nimbus](nimbus.md) or [Auth0](auth0.md) — and a [key source](key-sources.md).
By default handlers see the built-in `Jwt` identity (wrapping the verified token). Roles come from
a `rolesMapper`. You can replace the identity with your own type via `identityMapper`.

## Installation

Add the JWT extension alongside [javalin-security](../../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:{{ versions.library }}")
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-jwt</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    ```

## Minimal setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.jwt.*
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/api/*", Rules.authenticated())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))

            security.http.authentication = jwt { jwt ->
                jwt.decoder = NimbusJwtDecoder
                jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
                jwt.issuer = "https://issuer.example.com/"
                jwt.audiences = setOf("my-api")
                jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
                    Role.entries.find { it.name == name }
                }
            }

            security.http.fallback = Rules.deny()
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.jwt.*;
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import io.javalin.security.RouteRole;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/api/*", Rules.authenticated());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));

            security.http.authentication = JwtSecurity.jwt(jwt -> {
                jwt.decoder = NimbusJwtDecoder.INSTANCE;
                jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
                jwt.issuer = "https://issuer.example.com/";
                jwt.audiences = Set.of("my-api");
                jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> {
                    try { return Role.valueOf(name); }
                    catch (IllegalArgumentException e) { return null; }
                });
            });

            security.http.fallback = Rules.deny();
        }));
    });
    ```

## Configuration

| Field              | Default                   | Effect                                              |
|--------------------|---------------------------|-----------------------------------------------------|
| `decoder`          | *required*                | Adapter that verifies tokens.                       |
| `keySource`        | *required*                | Verification key source.                            |
| `issuer`           | `null`                    | When set, require matching `iss`.                   |
| `audiences`        | empty                     | When non-empty, require matching `aud`.             |
| `clockSkewSeconds` | `60`                      | Leeway for `exp` / `nbf`.                           |
| `rolesMapper`      | `noRoles()`               | Maps token → roles — **configure when using roles**.|
| `identityMapper`   | `null`                    | Maps token → your own `Identity` (default: `Jwt`).  |
| `tokenResolver`    | `Authorization: Bearer …` | Where the token is read from.                       |
| `bearerChallenge`  | `false`                   | Add `WWW-Authenticate: Bearer` on 401.              |
| `realm`            | `"API"`                   | Realm reported in the challenge.                    |
| `forbiddenHandler` | bare HTTP 403             | Renders access denied for authenticated callers.    |

Verification failures (bad signature, expiry, issuer / audience mismatch) become **401**. The
reason is logged, never returned to the client.

### `decoder`

Required. The `JwtDecoder` verifies the signature and claims of a JWT and returns a `DecodedJwt`. You can create your own custom decoder or use one of the provided built-in adapters, which are backed by common JWT libraries:

- [`NimbusJwtDecoder`](nimbus.md) (using the [Nimbus JOSE + JWT library](https://bitbucket.org/connect2id/nimbus-jose-jwt/src/master/))
- [`Auth0JwtDecoder`](auth0.md) (using the [Auth0 Java JWT library](https://github.com/auth0/auth0-java))

### `keySource`

Required. Describes where verification keys come from (local public key, PEM, HMAC secret, or
JWKS). Consumed by the decoder adapter. See [Key sources](key-sources.md) for all factory
methods.

=== "Kotlin"

    ```kotlin
    jwt { jwt ->
        jwt.decoder = NimbusJwtDecoder
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
    }
    ```

=== "Java"

    ```java
    JwtSecurity.jwt(jwt -> {
        jwt.decoder = NimbusJwtDecoder.INSTANCE;
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
    });
    ```

### `issuer`

When set, requires the token's `iss` claim to match this value. Defaults to `null` (issuer not
checked). A different or absent issuer is rejected when set.

### `audiences`

When non-empty, requires the token's `aud` claim to contain at least one of these values.
Defaults to an empty set (audience not checked).

### `clockSkewSeconds`

Maximum acceptable clock skew in seconds for `exp` and `nbf` validation. Defaults to `60`. Set
to `0` to disable clock-skew tolerance.

### `rolesMapper`

Maps a verified `DecodedJwt` to the caller's `RouteRole`s. Those roles land on
`Authentication.roles`. Defaults to `JwtRolesMapper.noRoles()`, which always returns an empty
set.

!!! danger "Default grants no roles"
    With `noRoles()`, every role-based check fails. Authenticated callers can only satisfy
    `authenticated` / `allow`. Configure `fromClaim` or `fromScope` as soon as you use roles —
    see [Roles mapping](roles-mapping.md).

=== "Kotlin"

    ```kotlin
    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
        Role.entries.find { it.name == name }
    }
    ```

=== "Java"

    ```java
    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> {
        try { return Role.valueOf(name); }
        catch (IllegalArgumentException e) { return null; }
    });
    ```

### `identityMapper`

Maps a verified `DecodedJwt` to your own `Identity`, replacing the default `Jwt` wrapper.
Defaults to `null` (handlers see a `Jwt` identity). May be combined with `rolesMapper` — the
identity supplies “who”, the roles mapper supplies granted roles.

Returning `null` fails authentication (401). Use that when the token is cryptographically valid
but no longer maps to a real caller (for example a deleted user).

=== "Kotlin"

    ```kotlin
    data class User(override val name: String) : Identity

    jwt { jwt ->
        jwt.decoder = NimbusJwtDecoder
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
        jwt.identityMapper = JwtIdentityMapper { token ->
            usersBySubject[token.subject]?.let { User(it.name) }
        }
        jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
            Role.entries.find { it.name == name }
        }
    }
    ```

=== "Java"

    ```java
    record User(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    JwtSecurity.jwt(jwt -> {
        jwt.decoder = NimbusJwtDecoder.INSTANCE;
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
        jwt.identityMapper = token -> usersBySubject.get(token.getSubject());
        jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> Role.valueOf(name));
    });
    ```

### `tokenResolver`

Locates the raw token in the request via javalin-security's `TokenResolver`. The default reads
the standard `Authorization: Bearer …` header. Return `null` when the token is absent so the
request continues as anonymous.

Override when the token arrives elsewhere (common for browser WebSockets that cannot set
`Authorization` on the handshake):

| Resolver option                   | Reads token from        |
|-----------------------------------|-------------------------|
| `TokenResolver.bearerHeader()`    | `Authorization: Bearer` |
| `TokenResolver.bearerHeader("…")` | Custom header, Bearer   |
| `TokenResolver.cookie("access")`  | Cookie                  |

=== "Kotlin"

    ```kotlin
    jwt { jwt ->
        jwt.decoder = NimbusJwtDecoder
        jwt.keySource = myKeySource
        jwt.tokenResolver = TokenResolver.cookie("access_token")
    }
    ```

=== "Java"

    ```java
    JwtSecurity.jwt(jwt -> {
        jwt.decoder = NimbusJwtDecoder.INSTANCE;
        jwt.keySource = myKeySource;
        jwt.tokenResolver = TokenResolver.cookie("access_token");
    });
    ```

When using cookies on WebSocket upgrades, also set `ws.allowedOrigins` — see
[JWT in the browser](../../websocket-security.md#jwt-in-the-browser).

### `bearerChallenge`

When `true`, failed or absent authentication includes a `WWW-Authenticate: Bearer …` header on
the 401 response. Defaults to `false` (bare 401, no challenge).

### `realm`

Realm string reported in the `WWW-Authenticate` challenge when `bearerChallenge` is `true`.
Defaults to `"API"`. Ignored when the challenge is disabled.

=== "Kotlin"

    ```kotlin
    jwt { jwt ->
        jwt.decoder = NimbusJwtDecoder
        jwt.keySource = myKeySource
        jwt.bearerChallenge = true
        jwt.realm = "API"
    }
    ```

=== "Java"

    ```java
    JwtSecurity.jwt(jwt -> {
        jwt.decoder = NimbusJwtDecoder.INSTANCE;
        jwt.keySource = myKeySource;
        jwt.bearerChallenge = true;
        jwt.realm = "API";
    });
    ```

### `forbiddenHandler`

Renders the response when an **authenticated** caller is denied by authorization (default: bare
HTTP 403). Override when you need a JSON body or other rendering — see
[Error handling](../../concepts/error-handling.md).

## Reading the identity

By default the strategy attaches the built-in `Jwt` identity. Read claims from
`identity.token`:

=== "Kotlin"

    ```kotlin
    config.routes.get("/api/me") { ctx ->
        val jwt = ctx.identity<Jwt>().token
        ctx.json(mapOf("sub" to jwt.subject, "email" to jwt.claim<String>("email")))
    }
    ```

=== "Java"

    ```java
    config.routes.get("/api/me", ctx -> {
        DecodedJwt jwt = identity(ctx, Jwt.class).getToken();
        ctx.json(Map.of("sub", jwt.getSubject(), "email", jwt.<String>claim("email")));
    });
    ```

When you configure `identityMapper`, cast to your own type instead — see
[`identityMapper`](#identitymapper).

## Next steps

- Decoders: [Nimbus](nimbus.md) or [Auth0](auth0.md)
- [Key sources](key-sources.md) · [Roles mapping](roles-mapping.md)
- [Access caller identity](../../getting-started/access-caller-identity.md) — read the caller in
  handlers
- [Authorization](../../concepts/authorization.md) — pair JWT with the rule table
- [Error handling](../../concepts/error-handling.md) — customize 401 / 403 responses
- Browser WebSockets: [JWT in the browser](../../websocket-security.md#jwt-in-the-browser)
