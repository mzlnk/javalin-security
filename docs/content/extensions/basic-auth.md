# Basic Auth

The `javalin-security-basic-auth` extension adds [HTTP Basic authentication](https://datatracker.ietf.org/doc/html/rfc7617)
to javalin-security. A client sends a username and password in the `Authorization` header. The
extension parses those credentials, looks up the user, verifies the password, and attaches your
`Identity` plus roles to the request so [authorization](../concepts/authorization.md) can decide
access.

You bring your own `Identity` type and a `UserLookup` that maps a username to
`BasicUserDetails` — the identity to attach, the encoded password to verify against, and the
roles to grant. The encoded password stays on `BasicUserDetails` only, so it never reaches
handlers through `ctx.identity<I>()`.

!!! info "HTTP only"
    Assign the strategy to `http.authentication`. There is no WebSocket variant of Basic Auth.

## Installation

Add the extension alongside [javalin-security](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-basic-auth:{{ versions.library }}")
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
    [`passwordEncoder`](#passwordencoder) before going to production.

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

    // User specific identity attached to context
    data class User(override val name: String) : Identity

    // in-memory set of users with details
    val users = mapOf(
        "alice" to BasicUserDetails(User("alice"), "alice-hash", setOf(Role.USER)),
        "admin" to BasicUserDetails(User("admin"), "admin-hash", setOf(Role.ADMIN)),
    )

    Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            
            security.http.authentication = basicAuth { basic ->
                // Required: resolve username to stored credentials
                basic.userLookup = UserLookup { username -> users[username] }
                // Production: use BCrypt / Argon2 / PBKDF2 — default is noOp()
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
    import io.javalin.security.RouteRole;
    import java.util.Map;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    // User specific identity attached to context
    record User(String name) implements Identity {
        @Override public String getName() { return name; }
    }

    // in-memory set of users with details
    Map<String, BasicUserDetails> users = Map.of(
        "alice", new BasicUserDetails(new User("alice"), "alice-hash", Set.of(Role.USER)),
        "admin", new BasicUserDetails(new User("admin"), "admin-hash", Set.of(Role.ADMIN)));

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));

            security.http.authentication = BasicAuthSecurity.basicAuth(basic -> {
                // Required: resolve username to stored credentials
                basic.userLookup = users::get;
                // Production: use BCrypt / Argon2 / PBKDF2 — default is noOp()
                basic.passwordEncoder = myBcryptEncoder;
            });
            
            security.http.fallback = Rules.authenticated();
        }));
    });
    ```

## Configuration

| Field                 | Default                  | Effect                                                         |
|-----------------------|--------------------------|----------------------------------------------------------------|
| `userLookup`          | *required*               | Username → `BasicUserDetails` (or `null`).                     |
| `passwordEncoder`     | `noOp()`                 | Compares raw vs. stored password — **change in production**.   |
| `credentialsResolver` | `Authorization: Basic …` | Where credentials are read from.                               |
| `basicChallenge`      | `false`                  | Add `WWW-Authenticate: Basic` on 401.                          |
| `realm`               | `"API"`                  | Realm reported in the challenge.                               |
| `forbiddenHandler`    | bare HTTP 403            | Renders access denied for authenticated callers.               |

### `userLookup`

Required. Called with the username extracted from the request. Return a `BasicUserDetails` for
known users, or `null` when the username is unknown — never throw.

`BasicUserDetails` holds three pieces:

| Member            | Role                                                                 |
|-------------------|----------------------------------------------------------------------|
| `identity`        | Your `Identity` attached to the request on success.                  |
| `encodedPassword` | Value compared against the caller-supplied password.                 |
| `roles`           | Granted on success and stored on `Authentication.roles`.             |

Unknown-user lookups still run a dummy password comparison so timing stays roughly uniform with
a wrong-password path for a known user.

### `passwordEncoder`

Compares the raw password from the client with `BasicUserDetails.encodedPassword`. The default
`PasswordEncoder.noOp()` performs a constant-time string comparison and **no hashing**.

!!! danger "Default `noOp()` performs no hashing"
    In production, plug in BCrypt, Argon2, or PBKDF2.

=== "Kotlin"

    ```kotlin
    val bcrypt = PasswordEncoder { raw, encoded ->
        at.favre.lib.crypto.bcrypt.BCrypt.verifyer()
            .verify(raw.toCharArray(), encoded).verified
    }

    basicAuth { basic ->
        basic.userLookup = myLookup
        basic.passwordEncoder = bcrypt
    }
    ```

=== "Java"

    ```java
    PasswordEncoder bcrypt = (raw, encoded) ->
        at.favre.lib.crypto.bcrypt.BCrypt.verifyer()
            .verify(raw.toCharArray(), encoded).verified;

    BasicAuthSecurity.basicAuth(cfg -> {
        cfg.userLookup = myLookup;
        cfg.passwordEncoder = bcrypt;
    });
    ```

Hashing at registration is your application's responsibility. The encoder only verifies.

### `credentialsResolver`

Locates raw credentials in the request. The default reads the standard
`Authorization: Basic …` header (RFC 7617). Return `null` when credentials are absent so the
request continues as anonymous. Throw `IllegalArgumentException` when credentials are present
but malformed — that becomes an authentication `Failure` (401).

Override when credentials arrive in a different header:

=== "Kotlin"

    ```kotlin
    basicAuth { basic ->
        basic.userLookup = myLookup
        basic.credentialsResolver = BasicCredentialsResolver.basicHeader("X-Basic-Auth")
    }
    ```

=== "Java"

    ```java
    BasicAuthSecurity.basicAuth(cfg -> {
        cfg.userLookup = myLookup;
        cfg.credentialsResolver = BasicCredentialsResolver.basicHeader("X-Basic-Auth");
    });
    ```

### `basicChallenge`

When `true`, failed or absent authentication includes a `WWW-Authenticate: Basic …` header on
the 401 response. Browsers and some HTTP clients use that header to prompt for credentials.
Defaults to `false` (bare 401, no challenge).

### `realm`

Realm string reported in the `WWW-Authenticate` challenge when `basicChallenge` is `true`.
Defaults to `"API"`. Ignored when the challenge is disabled.

=== "Kotlin"

    ```kotlin
    basicAuth { basic ->
        basic.userLookup = myLookup
        basic.basicChallenge = true
        basic.realm = "My App"
    }
    ```

=== "Java"

    ```java
    BasicAuthSecurity.basicAuth(cfg -> {
        cfg.userLookup = myLookup;
        cfg.basicChallenge = true;
        cfg.realm = "My App";
    });
    ```

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
- [Authorization](../concepts/authorization.md) — pair Basic Auth with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Secure endpoints](../getting-started/secure-endpoints.md) — end-to-end walkthrough using
  Basic Auth.
