# Javalin Security

**Authentication and authorization for [Javalin 7](https://javalin.io/), in Java and Kotlin.**

`javalin-security` is a lightweight and straightforward community plugin dedicated to securing
Javalin applications. Its primary goal is to make adding authentication and authorization to your
app as easy as possible, without dragging in large frameworks or complicated configuration —
just register the plugin inside `Javalin.create { … }` and you are ready to go. The plugin
centers around a small set of abstractions — `AuthenticationStrategy`, `Authentication`,
`Identity`, and `Rule` — so the security workflow stays easy to follow while remaining open to
customization.

!!! warning "Pre-release version of library"
    javalin-security is still in a beta / pre-release state. Breaking changes may be introduced
    before the 1.0.0 stable release.

## How it works

Security runs as a guard before matched handlers (HTTP) or during the WebSocket upgrade. The
flow has two stages:

1. **Authentication.** An `AuthenticationStrategy` inspects the request (headers, cookies, or
  whatever your scheme uses) and produces an `Authentication` — the caller's `Identity` plus any
   granted roles. Missing credentials yield an anonymous result; invalid credentials are a
   failure (typically 401). Without a strategy assigned, every caller is anonymous.
2. **Authorization.** Once identity is known, the library checks whether that caller may proceed.
  Routes that declare `RouteRole`s are matched against the caller's roles. Routes that declare
   none fall through to a path-based rule table (`allow`, `authenticated`, `hasRole`, custom
   `Rule` predicates, or `deny`). Unmatched requests are denied by default.

On success, the resolved `Authentication` is attached to the `Context` (and to the `WsContext`
for the life of a WebSocket session) so handlers can read the caller.

## Example

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    // Define your AuthenticationStrategy implementation (or use an extension)
    val myAuthenticationStrategy = MyAuthenticationStrategy()

    val app = Javalin.create { config ->
        config.security { security ->
            // Grant access based on rules
            security.rules.get("/public/*", Rules.allow())
            security.rules.post("/api/*", Rules.authenticated())
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN))

            // Set authentication and fallback rule
            security.http.authentication = myAuthenticationStrategy
            security.http.fallback = Rules.deny()
        }

        // Define your routes
        config.routes.get("/public/info") { it.result("hello") }
    }.start(7070)
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    // Define your AuthenticationStrategy implementation (or use an extension)
    var myAuthenticationStrategy = new MyAuthenticationStrategy();

    Javalin app = Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            // Grant access based on rules
            security.rules.get("/public/*", Rules.allow());
            security.rules.post("/api/*", Rules.authenticated());
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN));

            // Set authentication and fallback rule
            security.http.authentication = myAuthenticationStrategy;
            security.http.fallback = Rules.deny();
        }));

        // Define your routes
        config.routes.get("/public/info", ctx -> ctx.result("hello"));
    }).start(7070);
    ```

## Extensions

The core itself does not provide any concrete authentication mechanism — you need to
[implement an `AuthenticationStrategy`](guides/custom-authentication.md) on your own. For most
common cases, however, ready-made extensions are available:


| Extension                                  | Description                                                     |
| ------------------------------------------ | --------------------------------------------------------------- |
| [Basic Auth](extensions/basic-auth.md)     | HTTP Basic Auth (RFC 7617)                                      |
| [API Key](extensions/api-key.md)           | Static API key authentication (`X-Api-Key` by default)          |
| [Opaque Token](extensions/opaque-token.md) | Server-issued opaque bearer tokens (sessions, PATs) with expiry |
| [Session](extensions/session.md)           | HTTP-session authentication                                     |
| [JWT](extensions/jwt/configuration.md)             | JWT authentication                                              |


## Where to start

1. [Installation](getting-started/installation.md) — add the core artifact.
2. [Secure endpoints](getting-started/secure-endpoints.md) — protect HTTP routes and WebSocket
  upgrades end to end.
3. [Access caller identity](getting-started/access-caller-identity.md) — read the authenticated
  user inside handlers.
4. [Authentication](concepts/authentication.md) and [Authorization](concepts/authorization.md) —
  the two concepts in depth.
5. Extensions — [Basic Auth](extensions/basic-auth.md), [API Key](extensions/api-key.md), [Opaque Token](extensions/opaque-token.md), [Session](extensions/session.md), [JWT](extensions/jwt/configuration.md).
6. Guides — [Custom authentication](guides/custom-authentication.md), [CORS](guides/cors.md),
  [Testing](guides/testing.md).

For the generated KDoc, see the [API reference](https://mzlnk.github.io/javalin-security/api/).