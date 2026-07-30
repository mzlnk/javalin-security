# Javalin Security

**Authentication and authorization for [Javalin 7](https://javalin.io/), in Java and Kotlin.**

`javalin-security` is a lightweight, open-source security plugin for
[Javalin](https://javalin.io/) applications. It gives you a batteries-included way to add
authentication and authorization to your app without pulling in a heavyweight framework or
learning a large new configuration surface — just register the plugin inside
`Javalin.create { … }` and you are ready to go.

The plugin is designed to be **pluggable and extensible**: authentication runs through a small
`AuthenticationStrategy` interface, so you are free to pick whichever mechanism fits your app.
Reach for a built-in strategy like [JWT](extensions/jwt/index.md),
[HTTP Basic Auth](extensions/basic-auth.md), [API Key](extensions/api-key.md), or
[Opaque Token](extensions/opaque-token.md), or [implement a fully custom strategy](guides/custom-authentication.md) —
mTLS, HMAC signing, whatever your system needs. The same is true for authorization: use
the built-in rule table and role checks, or drop in your own `Rule` predicates.

The whole library is intentionally built on a **small set of simple abstractions** —
`AuthenticationStrategy`, `Authentication`, `Identity`, `Rule` — so the mental model stays easy
to reason about, while every extension point is open for customization.

## How it works

Security runs as a guard before matched handlers (HTTP) or during the WebSocket upgrade. The
flow has two stages:

1. **Authentication.** An `AuthenticationStrategy` inspects the request (headers, cookies, or
   whatever your scheme uses) and produces an `Authentication` — the caller's identity plus any
   granted roles. Missing credentials yield an anonymous result; invalid credentials are a
   failure (typically 401). Without a strategy assigned, every caller is anonymous.
2. **Authorization.** Once identity is known, the library checks whether that caller may proceed.
   Routes that declare `RouteRole`s are matched against the caller's roles. Routes that declare
   none fall through to a path-based rule table (`allow`, `authenticated`, `hasRole`, custom
   rules, or `deny`). Unmatched requests are denied by default.

On success, the resolved `Authentication` is attached to the `Context` (and to the `WsContext`
for the life of a WebSocket session) so handlers can read the caller. Extensions such as
[Basic Auth](extensions/basic-auth.md), [API Key](extensions/api-key.md),
[Opaque Token](extensions/opaque-token.md), and [JWT](extensions/jwt/index.md) supply ready-made
strategies; you can also [write your own](guides/custom-authentication.md).

## Example

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    val app = Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.post("/api/*", Rules.authenticated())
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = myAuthenticationStrategy
            security.http.fallback = Rules.deny()
        }
        config.routes.get("/public/info") { it.result("hello") }
    }.start(7070)
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    Javalin app = Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.get("/public/*", Rules.allow());
            security.rules.post("/api/*", Rules.authenticated());
            security.rules.any("/admin/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = myAuthenticationStrategy;
            security.http.fallback = Rules.deny();
        }));
        config.routes.get("/public/info", ctx -> ctx.result("hello"));
    }).start(7070);
    ```

## Supported versions

| Component   | Version                                                       |
|-------------|---------------------------------------------------------------|
| Java        | **17+**                                                       |
| Kotlin      | **{{ versions.kotlin_family }}** (consumers may use any JVM language) |
| Javalin     | **{{ versions.javalin_family }}**                             |
| Coordinates | `io.github.mzlnk:javalin-security:{{ versions.library }}`     |

## Where to start

1. [Installation](getting-started/installation.md) — add the core artifact.
2. [Secure endpoints](getting-started/secure-endpoints.md) — protect HTTP routes and WebSocket
   upgrades end to end.
3. [Access caller identity](getting-started/access-caller-identity.md) — read the authenticated
   user inside handlers.
4. [Authentication](concepts/authentication.md) and [Authorization](concepts/authorization.md) —
   the two concepts in depth.
5. Extensions — [Basic Auth](extensions/basic-auth.md), [API Key](extensions/api-key.md), [Opaque Token](extensions/opaque-token.md), [JWT](extensions/jwt/index.md).
6. Guides — [Custom authentication](guides/custom-authentication.md), [CORS](guides/cors.md),
   [Testing](guides/testing.md).

For the generated KDoc, see the [API reference](https://mzlnk.github.io/javalin-security/api/).
