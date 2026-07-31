# JWT

The `javalin-security-jwt` extension authenticates callers with a verified JWT. It provides
`jwt { }` and related SPIs; signature verification comes from a **decoder adapter** —
[Nimbus](nimbus.md) or [Auth0](auth0.md).

## Installation

Three parts, on top of [core](../../getting-started/installation.md):

1. `javalin-security-jwt` — strategy and SPI.
2. One decoder adapter — [Nimbus](nimbus.md) or [Auth0](auth0.md).
3. The matching JOSE library (not shipped by the adapter — add it yourself).

Each adapter page carries its own install snippet with the exact JOSE library and version. As a
quick reference:

=== "Nimbus"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:{{ versions.library }}")
    implementation("io.github.mzlnk:javalin-security-jwt-nimbus:{{ versions.library }}")
    implementation("com.nimbusds:nimbus-jose-jwt:{{ versions.nimbus_jose_jwt }}")
    ```

=== "Auth0"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:{{ versions.library }}")
    implementation("io.github.mzlnk:javalin-security-jwt-auth0:{{ versions.library }}")
    implementation("com.auth0:java-jwt:{{ versions.auth0_java_jwt }}")
    implementation("com.auth0:jwks-rsa:{{ versions.auth0_jwks_rsa }}")
    ```

Prefer the JOSE versions shown; they are what the adapters were built and tested against.

## Building blocks

| Type                             | Responsibility                                        |
|----------------------------------|-------------------------------------------------------|
| `JwtDecoder`                     | Verifies signature + claims; returns `DecodedJwt`.    |
| `JwtVerification`                | Spec: key source, issuer, audiences, clock skew.      |
| `JwtKeySource`                   | Public key, PEM, HMAC secret, or JWKS.                |
| `JwtRolesMapper`                 | Maps a verified token to `RouteRole`s.                |
| `DecodedJwt` / `Jwt`             | Verified token and identity (exposes claims and roles). |

By default the raw token is read from the `Authorization: Bearer …` header.

## Minimal setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.jwt.*
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

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
        config.routes.get("/api/me") { it.result(it.identity<Jwt>().name) }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.jwt.*;
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.util.Set;

    import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;

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
                    try { return Role.valueOf(name); } catch (IllegalArgumentException e) { return null; }
                });
            });
            security.http.fallback = Rules.deny();
        }));
        config.routes.get("/api/me", ctx -> ctx.result(identity(ctx, Jwt.class).getName()));
    });
    ```

Adapters are Kotlin `object`s (`NimbusJwtDecoder` / `NimbusJwtDecoder.INSTANCE`). From Java, use
`JwtSecurity.jwt(...)`.

## `JwtConfig` reference

| Field                | Type              | Default              | Effect                                      |
|----------------------|-------------------|----------------------|---------------------------------------------|
| `decoder`            | `JwtDecoder?`             | `null` (*required*)  | Adapter that verifies tokens.               |
| `keySource`          | `JwtKeySource?`           | `null` (*required*)  | Verification key source.                    |
| `issuer`             | `String?`                 | `null`               | When set, require matching `iss`.           |
| `audiences`          | `Set<String>`             | empty                | When non-empty, require matching `aud`.     |
| `clockSkewSeconds`   | `Int`                     | `60`                 | Leeway for `exp` / `nbf`.                   |
| `rolesMapper`        | `JwtRolesMapper`          | `noRoles()`          | Maps token → roles.         |
| `identityMapper`     | `JwtIdentityMapper?`      | `null`               | Maps token → your own `Identity`.           |
| `forbiddenHandler`   | `ForbiddenHandler`        | `DEFAULT`            | Renders 403.                                |
| `bearerChallenge`    | `Boolean`                 | `false`              | Add `WWW-Authenticate: Bearer` on 401.      |
| `realm`              | `String`                  | `"API"`              | Realm for the bearer challenge.             |

!!! danger "Default roles mapper grants no roles"
    With `noRoles()`, `hasRole` / role routes never match. Configure `fromClaim` / `fromScope`
    as soon as you use roles. See [Roles mapping](roles-mapping.md).

Verification failures (bad signature, expiry, issuer / audience mismatch) become **401** — the
reason is logged, never returned to the client.

## Identity mapping

By default, `jwt { }` attaches the built-in `Jwt` identity (wrapping the verified `DecodedJwt`)
— this is the zero-config path shown above. Roles always come from `rolesMapper` and land on
`Authentication.roles`. To attach your own domain identity instead — e.g. looking up a local
user record by the token's `sub` claim — set `identityMapper` on the same `jwt { }` block
(you can still use `rolesMapper` alongside it):

=== "Kotlin"

    ```kotlin
    data class User(override val name: String) : Identity

    security.http.authentication = jwt { jwt ->
        jwt.decoder = NimbusJwtDecoder
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
        jwt.identityMapper = JwtIdentityMapper { token ->
            usersBySubject[token.subject]?.let { User(it.name) }
        }
        jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
            Role.entries.find { it.name == name }
        }
    }
    config.routes.get("/api/me") { it.result(it.identity<User>().name) }
    ```

=== "Java"

    ```java
    record User(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    security.http.authentication = JwtSecurity.jwt(jwt -> {
        jwt.decoder = NimbusJwtDecoder.INSTANCE;
        jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
        jwt.identityMapper = token ->
                usersBySubject.get(token.getSubject());
        jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> Role.valueOf(name));
    });
    config.routes.get("/api/me", ctx -> ctx.result(identity(ctx, User.class).getName()));
    ```

Returning `null` from `identityMapper` fails authentication (401) — use this when the token is
cryptographically valid but no longer maps to a real caller (e.g. a deleted user).

## Reading claims

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

## Next steps

- Decoders: [Nimbus](nimbus.md) or [Auth0](auth0.md).
- [Key sources](key-sources.md) · [Roles mapping](roles-mapping.md).
- Browser WebSockets: [JWT in the browser](../../websocket-security.md#jwt-in-the-browser).
