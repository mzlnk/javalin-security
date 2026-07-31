# Session

Session-based authentication via `javalin-security-session`. You bring your own `Identity` type;
the extension is built around one abstraction — `SessionManager` — that owns session **create**,
**validate**, and **invalidate** of a `SessionDetails` payload (identity + roles).
`SessionAuthenticator` delegates `validate` on every request, attaching the returned identity and
roles to the request. Session create/invalidate is your responsibility: keep a reference to your
`SessionManager` and call it from login/logout handlers.

The bundled [`HttpSessionManager`](#httpsessionmanager-default) is the servlet-session-backed
default (i.e. `ctx.sessionAttribute(...)`) and is used automatically if you don't configure one.
Plug in any other implementation (Redis, in-memory, signed cookie, …) without changing the rest
of the extension.

Use this for **cookie-backed browser sessions** — classic server-side login flows. There is
**no built-in login form**, credential validator, CSRF protection, or opinionated distributed
store: validate credentials in your own `/login` route, then call `sessions.create(ctx, SessionDetails(identity, roles))`.

!!! info "Session vs Opaque Token"
    Opaque tokens travel as bearer credentials you look up in your store. Session auth stores
    the identity via a `SessionManager` — by default in the HTTP session addressed by
    `JSESSIONID`. Prefer Session for browser apps; prefer Opaque Token for APIs and PATs.

## Architecture

```mermaid
flowchart LR
    Request --> Authenticator[SessionAuthenticator]
    Authenticator -- "validate(ctx)" --> Manager[SessionManager]
    Login[Login handler] -- "create(ctx, SessionDetails)" --> Manager
    Logout[Logout handler] -- "invalidate(ctx)" --> Manager
    Manager -- "SessionDetails or null" --> Authenticator
    Authenticator -- Success or NotAuthenticated --> Guard[Security guard]
```

There is exactly one lifecycle abstraction — the `SessionManager`. The `session { }` factory
returns an `AuthenticationStrategy.Sync` wrapping a `SessionAuthenticator` that calls `validate`
on each request. Hold onto the same `SessionManager` instance you configure so login/logout
handlers can call `create` / `invalidate`.

## Installation

Add the extension on top of [core](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-session:{{ versions.library }}")
    // plus javalin-security + Javalin + SLF4J from core
    ```

=== "Maven"

    ```xml
    <dependency>
      <groupId>io.github.mzlnk</groupId>
      <artifactId>javalin-security-session</artifactId>
      <version>{{ versions.library }}</version>
    </dependency>
    ```

## Minimal setup

Hold a `SessionManager` (defaults to `HttpSessionManager.of()`) and assign it both to
`session { }` and to your login/logout handlers. When you use `HttpSessionManager`, your
identity must implement `java.io.Serializable` — see
[`HttpSessionManager`](#httpsessionmanager-default):

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authentication.Identity
    import io.github.mzlnk.javalin.security.authorization.Rules
    import io.github.mzlnk.javalin.security.session.*
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin
    import io.javalin.security.RouteRole
    import java.io.Serializable

    enum class Role : RouteRole { USER, ADMIN }

    data class User(override val name: String) : Identity, Serializable

    val sessions = HttpSessionManager.of()

    Javalin.create { config ->
        config.security { security ->
            security.rules.post("/login", Rules.allow())
            security.rules.post("/logout", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.http.authentication = session { it.sessionManager = sessions }
            security.http.fallback = Rules.authenticated()
        }
        config.routes.post("/login") { ctx ->
            // validate credentials yourself, then:
            sessions.create(ctx, SessionDetails(User("alice"), setOf(Role.USER)))
            ctx.result("ok")
        }
        config.routes.post("/logout") { ctx ->
            sessions.invalidate(ctx)
            ctx.result("ok")
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authentication.Identity;
    import io.github.mzlnk.javalin.security.session.*;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.io.Serializable;
    import java.util.Set;

    record User(String name) implements Identity, Serializable {
        @Override public String getName() { return name; }
    }

    SessionManager sessions = HttpSessionManager.of();

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.post("/login", Rules.allow());
            security.rules.post("/logout", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
            security.http.authentication = SessionSecurity.session(cfg -> cfg.sessionManager = sessions);
            security.http.fallback = Rules.authenticated();
        }));
        config.routes.post("/login", ctx -> {
            // validate credentials yourself, then:
            sessions.create(ctx, new SessionDetails(new User("alice"), Set.of(Role.USER)));
            ctx.result("ok");
        });
        config.routes.post("/logout", ctx -> {
            sessions.invalidate(ctx);
            ctx.result("ok");
        });
    });
    ```

## Configuration

| Field                 | Default                    | Effect                                                             |
|-----------------------|-----------------------------|---------------------------------------------------------------------|
| `sessionManager`      | `HttpSessionManager.of()`  | Storage strategy for sessions.                                     |
| `forbiddenHandler`    | bare HTTP 403               | Renders access denied for authenticated callers.                   |
| `unauthorizedHandler` | bare HTTP 401               | Renders failed or absent authentication.                           |

Nothing is required for authentication alone — override `sessionManager` to change storage,
cookie name, attribute key, or session-fixation defense; see below. To create or invalidate
sessions from handlers, keep a reference to that same manager.

## `HttpSessionManager` (default)

`HttpSessionManager` is the built-in servlet-session-backed implementation. It stores a
`SessionDetails` and requires its `identity` to implement `java.io.Serializable`, since the
servlet container may serialize session attributes to disk or a replicated store. Non-serializable
identities are rejected with `IllegalArgumentException` at create time — surfacing the mistake
right away instead of at replication time.

Configure it via its builder:

=== "Kotlin"

    ```kotlin
    session { cfg ->
        cfg.sessionManager = HttpSessionManager.builder()
            .attributeKey("app.user")            // default: "javalin-security.session.principal"
            .rotateSessionIdOnCreate(true)       // default: true — session-fixation defense
            .invalidateSessionOnDestroy(true)    // default: true — HttpSession.invalidate() on logout
            .build()
    }
    ```

=== "Java"

    ```java
    SessionSecurity.session(cfg -> {
        cfg.sessionManager = HttpSessionManager.builder()
                .attributeKey("app.user")
                .rotateSessionIdOnCreate(true)
                .invalidateSessionOnDestroy(true)
                .build();
    });
    ```

`HttpSessionManager.of()` returns the same defaults, and `HttpSessionManager.of("app.user")`
is shorthand for the attribute-key-only override.

## Plug in a custom `SessionManager`

`SessionManager` is a three-method interface:

```kotlin
interface SessionManager {
    fun create(context: Context, details: SessionDetails)
    fun validate(context: Context): SessionDetails?
    fun invalidate(context: Context)
}
```

Everything else — the authenticator, the rule table, error rendering — stays the same.

=== "Kotlin"

    ```kotlin
    // Toy in-memory store keyed by an opaque cookie value.
    class InMemorySessionManager : SessionManager {
        private val store = ConcurrentHashMap<String, Identity>()

        override fun create(ctx: Context, identity: Identity) {
            val token = UUID.randomUUID().toString()
            store[token] = identity
            ctx.cookie("APPSESSION", token)
        }

        override fun validate(ctx: Context): Identity? =
            ctx.cookie("APPSESSION")?.let(store::get)

        override fun invalidate(ctx: Context) {
            ctx.cookie("APPSESSION")?.also { store.remove(it) }
            ctx.removeCookie("APPSESSION")
        }
    }

    val sessions = InMemorySessionManager()
    session { it.sessionManager = sessions }
    // call sessions.create / sessions.invalidate from your handlers
    ```

=== "Java"

    ```java
    SessionManager sessions = new SessionManager() {
        @Override public void create(Context ctx, SessionDetails details) { /* … */ }
        @Override public SessionDetails validate(Context ctx) { return /* … */; }
        @Override public void invalidate(Context ctx) { /* … */ }
    };
    SessionSecurity.session(cfg -> cfg.sessionManager = sessions);
    ```

A custom `SessionManager` does not need `SessionDetails.identity` to be `Serializable` — that constraint is
specific to `HttpSessionManager`.

## Identity

On success the strategy attaches `SessionDetails.identity` as the request's identity and
`SessionDetails.roles` as the granted roles:

```kotlin
config.routes.get("/me") { ctx ->
    ctx.result(ctx.identity<User>().name)
}
```

## Session lifetime

The extension does **not** implement application-level expiry. Session lifetime, cookie name,
and idle timeout are owned by the `SessionManager` — for the default `HttpSessionManager`
that means the servlet container (Jetty's session configuration). When the manager drops the
session, the next request authenticates as anonymous.

## Combining with credential validation

Validate passwords (or any other credential) in your `/login` handler, then call
`sessions.create`:

```kotlin
val sessions = HttpSessionManager.of()

config.routes.post("/login") { ctx ->
    val username = ctx.formParam("username") ?: throw UnauthorizedResponse()
    val password = ctx.formParam("password") ?: throw UnauthorizedResponse()
    val user = users.find(username) ?: throw UnauthorizedResponse()
    if (!passwordEncoder.matches(password, user.password)) {
        throw UnauthorizedResponse()
    }
    sessions.create(ctx, SessionDetails(User(user.username), user.roles))
    ctx.result("ok")
}
```

The [Basic Auth](basic-auth.md) extension is a separate *request-header* strategy; you can
still reuse its `PasswordEncoder` / user-lookup ideas inside a session login handler.

## Security notes

!!! warning "Hardening checklist"
    - **Session fixation** — the default `HttpSessionManager` rotates the session id on create
      (`rotateSessionIdOnCreate` defaults to `true`). Custom `SessionManager` implementations
      should provide an equivalent guarantee.
    - **Serializable identity** — `HttpSessionManager` requires `SessionDetails.identity : Serializable` (checked
      at create time). Prefer enum `RouteRole`s (enums are serializable) when sessions may be
      replicated across nodes.
    - **Cookie flags** — set `Secure`, `HttpOnly`, and `SameSite` on the container's session
      cookie (`SessionCookieConfig` / Jetty session config) or, for custom managers, on
      whichever cookie you emit. The extension does not set cookie flags on your behalf.
    - **CSRF** — not included. Browser apps that use cookie sessions typically need a CSRF
      token (or `SameSite=Strict` / `Lax` plus careful CORS). Add that in your application.

## Custom 401 responses

Override `unauthorizedHandler` when you need a JSON body:

=== "Kotlin"

    ```kotlin
    session { s ->
        s.unauthorizedHandler = UnauthorizedHandler { ctx, _ ->
            ctx.status(401).result("""{"error":"login_required"}""")
        }
    }
    ```

=== "Java"

    ```java
    SessionSecurity.session(s -> {
        s.unauthorizedHandler = (ctx, failure) ->
            ctx.status(401).result("{\"error\":\"login_required\"}");
    });
    ```

## Next steps

- [Access caller identity](../getting-started/access-caller-identity.md) — read your
  `Identity` in handlers.
- [Authorization](../concepts/authorization.md) — pair sessions with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — when even a custom
  `SessionManager` is not enough.
