# Basic Auth

HTTP Basic authentication (RFC 7617) via `javalin-security-basic-auth`. You bring your own
`Identity` type; `UserLookup` resolves a username to a `BasicUserDetails` (your identity, the
encoded password to verify against, and the roles to grant). The extension parses the header,
verifies the password with timing-safe comparison, and attaches your identity and roles — the
encoded password itself never lands on the request identity, so it can't leak through
`ctx.identity<I>()`.

!!! info "HTTP only"
    Assign to `http.authentication`. There is no WebSocket variant of Basic Auth.

## Installation

Add the extension on top of [core](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-basic-auth:{{ versions.library }}")
    // plus javalin-security + Javalin + SLF4J from core
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-basic-auth</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    ```

!!! danger "Choose a real password encoder"
    The default `PasswordEncoder.noOp()` performs **no hashing**. See
    [PasswordEncoder](#passwordencoder) below before going to production.

## Minimal setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Identity
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.basicauth.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    data class User(override val name: String) : Identity

    val users = mapOf(
        "alice" to BasicUserDetails(User("alice"), "alice-hash", setOf(Role.USER)),
        "admin" to BasicUserDetails(User("admin"), "admin-hash", setOf(Role.ADMIN)),
    )

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = basicAuth { basic ->
                basic.userLookup = UserLookup { username -> users[username] }
                basic.passwordEncoder = myBcryptEncoder
            }
            security.http.fallback = Rules.authenticated()
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authentication.Identity;
    import io.github.mzlnk.javalin.security.basicauth.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.util.Map;
    import java.util.Set;

    record User(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    Map<String, BasicUserDetails> users = Map.of(
        "alice", new BasicUserDetails(new User("alice"), "alice-hash", Set.of(Role.USER)),
        "admin", new BasicUserDetails(new User("admin"), "admin-hash", Set.of(Role.ADMIN)));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = BasicAuthSecurity.basicAuth(basic -> {
                basic.userLookup = users::get;
                basic.passwordEncoder = myBcryptEncoder;
            });
            security.http.fallback = Rules.authenticated();
        }));
    });
    ```

## Configuration

| Field                  | Default                      | Effect                                                            |
|------------------------|------------------------------|--------------------------------------------------------------------|
| `userLookup`           | *required*                   | Username → `BasicUserDetails` (or `null`).                        |
| `passwordEncoder`      | `noOp()`                     | Compares raw vs. stored password — **change in production**.      |
| `credentialsResolver`  | `Authorization: Basic …`     | Where credentials are read from.                                  |
| `basicChallenge`       | `false`                      | Add `WWW-Authenticate: Basic` on 401.                             |
| `realm`                | `"API"`                      | Realm reported in the challenge.                                  |

`BasicUserDetails.encodedPassword` is the **encoded** value used for comparison; it is kept
separate from your `Identity`, so it is never reachable from handlers via `ctx.identity<I>()`.
`BasicUserDetails.roles` land on `Authentication.roles`. Return `null` for unknown users (never
throw). Unknown-user lookups still run a dummy password comparison for timing uniformity.

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

## Challenge header and identity

```kotlin
basicAuth { basic ->
    basic.userLookup = myLookup
    basic.basicChallenge = true
    basic.realm = "My App"
}

config.routes.get("/me") { ctx -> ctx.result(ctx.identity<User>().name) }
```

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read your `Identity`
  in handlers.
- [Authorization](../concepts/authorization.md) — pair Basic Auth with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
