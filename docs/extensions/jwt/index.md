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
    implementation("io.github.mzlnk:javalin-security-jwt:1.0.0-SNAPSHOT")
    implementation("io.github.mzlnk:javalin-security-jwt-nimbus:1.0.0-SNAPSHOT")
    implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")
    ```

=== "Auth0"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-jwt:1.0.0-SNAPSHOT")
    implementation("io.github.mzlnk:javalin-security-jwt-auth0:1.0.0-SNAPSHOT")
    implementation("com.auth0:java-jwt:4.6.0")
    implementation("com.auth0:jwks-rsa:0.24.1")
    ```

Prefer the JOSE versions shown; they are what the adapters were built and tested against.

## Building blocks

| Type                             | Responsibility                                        |
|----------------------------------|-------------------------------------------------------|
| `JwtDecoder`                     | Verifies signature + claims; returns `DecodedJwt`.    |
| `JwtVerification`                | Spec: key source, issuer, audiences, clock skew.      |
| `JwtKeySource`                   | Public key, PEM, HMAC secret, or JWKS.                |
| `JwtRolesMapper`                 | Maps a verified token to `RouteRole`s.                |
| `DecodedJwt` / `JwtPrincipal`    | Verified token and identity (exposes claims).         |

By default the raw token is read from the `Authorization: Bearer …` header.

## Minimal setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.jwt.*
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.http.HandlerType.GET

    Javalin.create { config ->
        config.security { security ->
            security.http { http ->
                http.authentication = jwt { jwt ->
                    jwt.decoder = NimbusJwtDecoder
                    jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
                    jwt.issuer = "https://issuer.example.com/"
                    jwt.audiences = setOf("my-api")
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
                        Role.entries.find { it.name == name }
                    }
                }
                http.rules { r ->
                    r.add("/api/*", GET, r.authenticated)
                    r.add("/admin/*", GET, r.hasRole(Role.ADMIN))
                    r.fallback = r.deny
                }
            }
        }
        config.routes.get("/api/me") { it.result(it.principal<JwtPrincipal>()!!.name) }
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

    import static io.github.mzlnk.javalin.security.SecurityExtensions.principal;
    import static io.javalin.http.HandlerType.GET;

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
            http.authentication = JwtSecurity.jwt(jwt -> {
                jwt.decoder = NimbusJwtDecoder.INSTANCE;
                jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
                jwt.issuer = "https://issuer.example.com/";
                jwt.audiences = Set.of("my-api");
                jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> {
                    try { return Role.valueOf(name); } catch (IllegalArgumentException e) { return null; }
                });
            });
            http.rules(r -> {
                r.add("/api/*", GET, Rules.authenticated());
                r.add("/admin/*", GET, Rules.hasRole(Role.ADMIN));
                r.fallback = Rules.deny();
            });
        })));
        config.routes.get("/api/me", ctx -> ctx.result(principal(ctx, JwtPrincipal.class).getName()));
    });
    ```

Adapters are Kotlin `object`s (`NimbusJwtDecoder` / `NimbusJwtDecoder.INSTANCE`). From Java, use
`JwtSecurity.jwt(...)`.

## `JwtConfig` reference

| Field                | Type              | Default              | Effect                                       |
|----------------------|-------------------|----------------------|----------------------------------------------|
| `decoder`            | `JwtDecoder?`     | `null` (*required*)  | Adapter that verifies tokens.                |
| `keySource`          | `JwtKeySource?`   | `null` (*required*)  | Verification key source.                     |
| `issuer`             | `String?`         | `null`               | When set, require matching `iss`.            |
| `audiences`          | `Set<String>`     | empty                | When non-empty, require matching `aud`.      |
| `clockSkewSeconds`   | `Int`             | `60`                 | Leeway for `exp` / `nbf`.                    |
| `rolesMapper`        | `JwtRolesMapper`  | `noRoles()`          | Maps token → roles.                          |
| `forbiddenHandler`   | `ForbiddenHandler`| `DEFAULT`            | Renders 403.                                 |
| `bearerChallenge`    | `Boolean`         | `false`              | Add `WWW-Authenticate: Bearer` on 401.       |
| `realm`              | `String`          | `"API"`              | Realm for the bearer challenge.              |

!!! danger "Default roles mapper grants no roles"
    With `noRoles()`, `hasRole` / role routes never match. Configure `fromClaim` / `fromScope`
    as soon as you use roles. See [Roles mapping](roles-mapping.md).

Verification failures (bad signature, expiry, issuer / audience mismatch) become **401** — the
reason is logged, never returned to the client.

## Reading claims

=== "Kotlin"

    ```kotlin
    config.routes.get("/api/me") { ctx ->
        val jwt = ctx.principal<JwtPrincipal>()!!.token
        ctx.json(mapOf("sub" to jwt.subject, "email" to jwt.claim<String>("email")))
    }
    ```

=== "Java"

    ```java
    config.routes.get("/api/me", ctx -> {
        DecodedJwt jwt = principal(ctx, JwtPrincipal.class).getToken();
        ctx.json(Map.of("sub", jwt.getSubject(), "email", jwt.<String>claim("email")));
    });
    ```

## Next steps

- Decoders: [Nimbus](nimbus.md) or [Auth0](auth0.md).
- [Key sources](key-sources.md) · [Roles mapping](roles-mapping.md).
- Browser WebSockets: [JWT in the browser](../../websocket-security.md#jwt-in-the-browser).
