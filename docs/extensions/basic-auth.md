# Basic Auth

HTTP Basic authentication (RFC 7617) via `javalin-security-basic-auth`. You supply a
`UserLookup`; the extension verifies the password and produces a `BasicAuthPrincipal` with roles.

!!! info "HTTP only"
    Assign to `http.authentication`. There is no WebSocket variant of Basic Auth.

## Installation

Add the extension on top of [core](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-basic-auth:1.0.0-SNAPSHOT")
    // plus javalin-security + Javalin + SLF4J from core
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-basic-auth</artifactId>
      <version>1.0.0-SNAPSHOT</version>
    </dependency>
    ```

!!! danger "Choose a real password encoder"
    The default `PasswordEncoder.noOp()` performs **no hashing**. See
    [PasswordEncoder](#passwordencoder) below before going to production.

## Minimal setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.basicauth.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.http.HandlerType.GET
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    val users = mapOf(
        "alice" to BasicUser("alice", "alice-hash", setOf(Role.USER)),
        "admin" to BasicUser("admin", "admin-hash", setOf(Role.ADMIN)),
    )

    Javalin.create { config ->
        config.security { security ->
            security.http { http ->
                http.authentication = basicAuth { basic ->
                    basic.userLookup = UserLookup { username -> users[username] }
                    basic.passwordEncoder = myBcryptEncoder
                }
                http.rules { r ->
                    r.add("/public/*", GET, r.allow)
                    r.add("/admin/*", GET, r.hasRole(Role.ADMIN))
                    r.fallback = r.authenticated
                }
            }
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.basicauth.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.util.Map;
    import java.util.Set;

    import static io.javalin.http.HandlerType.GET;

    Map<String, BasicUser> users = Map.of(
        "alice", new BasicUser("alice", "alice-hash", Set.of(Role.USER)),
        "admin", new BasicUser("admin", "admin-hash", Set.of(Role.ADMIN)));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
            http.authentication = BasicAuthSecurity.basicAuth(basic -> {
                basic.userLookup = users::get;
                basic.passwordEncoder = myBcryptEncoder;
            });
            http.rules(r -> {
                r.add("/public/*", GET, Rules.allow());
                r.add("/admin/*", GET, Rules.hasRole(Role.ADMIN));
                r.fallback = Rules.authenticated();
            });
        })));
    });
    ```

## Configuration

| Field                  | Default                      | Effect                                                            |
|------------------------|------------------------------|-------------------------------------------------------------------|
| `userLookup`           | *required*                   | Username → `BasicUser` (or `null`).                               |
| `passwordEncoder`      | `noOp()`                     | Compares raw vs. stored password — **change in production**.      |
| `credentialsResolver`  | `Authorization: Basic …`     | Where credentials are read from.                                  |
| `basicChallenge`       | `false`                      | Add `WWW-Authenticate: Basic` on 401.                             |
| `realm`                | `"API"`                      | Realm reported in the challenge.                                  |

`BasicUser.password` is the **encoded** value. Return `null` for unknown users (never throw).
Unknown-user lookups still run a dummy password comparison for timing uniformity.

## PasswordEncoder

!!! danger "Default `noOp()` performs no hashing"
    In production, plug in BCrypt, Argon2, or PBKDF2.

=== "Kotlin"

    ```kotlin
    val bcrypt = PasswordEncoder { raw, encoded ->
        at.favre.lib.crypto.bcrypt.BCrypt.verifyer()
            .verify(raw.toCharArray(), encoded).verified
    }
    basicAuth { it.userLookup = myLookup; it.passwordEncoder = bcrypt }
    ```

=== "Java"

    ```java
    PasswordEncoder bcrypt = (raw, encoded) ->
        at.favre.lib.crypto.bcrypt.BCrypt.verifyer()
            .verify(raw.toCharArray(), encoded).verified;
    BasicAuthSecurity.basicAuth(cfg -> { cfg.userLookup = myLookup; cfg.passwordEncoder = bcrypt; });
    ```

Hashing at registration is your application's responsibility; the encoder only verifies.

## Challenge and principal

```kotlin
basicAuth { basic ->
    basic.userLookup = myLookup
    basic.basicChallenge = true
    basic.realm = "My App"
}

config.routes.get("/me") { ctx -> ctx.result(ctx.principal<BasicAuthPrincipal>()!!.name) }
```

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read
  `BasicAuthPrincipal` in handlers.
- [Authorization](../concepts/authorization.md) — pair Basic Auth with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
