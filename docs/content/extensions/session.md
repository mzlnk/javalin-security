# Session

The `javalin-security-session` extension adds session-based authentication to javalin-security.
On every request the strategy asks a `SessionManager` to validate the current session. When a
session exists, your `Identity` plus roles are attached to the request so
[authorization](../concepts/authorization.md) can decide access.

You bring your own `Identity` type. Session **create** and **invalidate** stay in your
application — keep a reference to the same `SessionManager` and call it from login/logout
handlers after you verify credentials yourself. The bundled `HttpSessionManager` is the default
(servlet session via `ctx.sessionAttribute(...)`). You can plug in Redis, in-memory storage, a
signed cookie, or any other store without changing the rest of the extension.

Use this for **cookie-backed browser sessions** — classic server-side login flows. There is no
built-in login form, credential validator, CSRF protection, or opinionated distributed store.

!!! info "HTTP only"
    Assign the strategy to `http.authentication`. There is no WebSocket variant of session auth.

## Installation

Add the extension alongside [javalin-security](../getting-started/installation.md):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    implementation("io.github.mzlnk:javalin-security-session:{{ versions.library }}")
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
identity must implement `java.io.Serializable` — see [`SessionManager`](#sessionmanager).

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

    // User specific identity attached to context (Serializable required by HttpSessionManager)
    data class User(override val name: String) : Identity, Serializable

    // Shared by the auth strategy and login/logout handlers
    val sessionManager = HttpSessionManager.of()

    Javalin.create { config ->
        config.security { security ->
            security.rules.post("/login", Rules.allow())
            security.rules.post("/logout", Rules.allow())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))

            security.http.authentication = session { session ->
                // Defaults to HttpSessionManager.of() when omitted
                session.sessionManager = sessionManager
            }

            security.http.fallback = Rules.authenticated()
        }

        config.routes.post("/login") { ctx ->
            // Validate credentials yourself, then create the session
            sessionManager.create(ctx, SessionDetails(User("alice"), setOf(Role.USER)))
            ctx.result("ok")
        }
        config.routes.post("/logout") { ctx ->
            sessionManager.invalidate(ctx)
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
    import io.javalin.security.RouteRole;
    import java.io.Serializable;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    // User specific identity attached to context (Serializable required by HttpSessionManager)
    record User(String name) implements Identity, Serializable {
        @Override public String getName() { return name; }
    }

    // Shared by the auth strategy and login/logout handlers
    SessionManager sessionManager = HttpSessionManager.of();

    Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> {
            security.rules.post("/login", Rules.allow());
            security.rules.post("/logout", Rules.allow());
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));

            security.http.authentication = SessionSecurity.session(session -> {
                // Defaults to HttpSessionManager.of() when omitted
                session.sessionManager = sessionManager;
            });

            security.http.fallback = Rules.authenticated();
        }));

        config.routes.post("/login", ctx -> {
            // Validate credentials yourself, then create the session
            sessionManager.create(ctx, new SessionDetails(new User("alice"), Set.of(Role.USER)));
            ctx.result("ok");
        });
        config.routes.post("/logout", ctx -> {
            sessionManager.invalidate(ctx);
            ctx.result("ok");
        });
    });
    ```

## Configuration

| Field                 | Default                   | Effect                                             |
|-----------------------|---------------------------|----------------------------------------------------|
| `sessionManager`      | `HttpSessionManager.of()` | Storage strategy for sessions.                     |
| `unauthorizedHandler` | bare HTTP 401             | Renders failed or absent authentication.           |
| `forbiddenHandler`    | bare HTTP 403             | Renders access denied for authenticated callers.   |

Nothing is required for authentication alone — override `sessionManager` to change storage. To
create or invalidate sessions from handlers, keep a reference to that same manager. See
[`SessionManager`](#sessionmanager) for details.

### `sessionManager`

The `SessionManager` that owns session create, validate, and invalidate. Defaults to
`HttpSessionManager.of()` (servlet-session storage). Assign your own instance when you need a
different store, a custom attribute key, or tuned session-fixation behaviour.

The `session { }` factory only wires the manager into the authenticator for **validate** on each
request. Login and logout call `create` / `invalidate` on the same instance from your handlers.

### `unauthorizedHandler`

Renders the response for failed or absent authentication (default: bare HTTP 401). Override when
you need a JSON body or other rendering:

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

See [Error handling](../concepts/error-handling.md) for more on customising 401 responses.

### `forbiddenHandler`

Renders the response when an **authenticated** caller is denied by authorization (default: bare
HTTP 403). Override when you need a JSON body or other rendering — see
[Error handling](../concepts/error-handling.md).

## SessionManager

`SessionManager` is the single lifecycle abstraction for this extension:

```kotlin
interface SessionManager {
    fun create(context: Context, details: SessionDetails)
    fun validate(context: Context): SessionDetails?
    fun invalidate(context: Context)
}
```

| Method        | Called from                         | Behaviour                                                              |
|---------------|-------------------------------------|------------------------------------------------------------------------|
| `create`      | Your login handler                  | Establishes a session for `SessionDetails`.                            |
| `validate`    | `SessionAuthenticator` every request | Returns details, or `null` when there is no valid session.            |
| `invalidate`  | Your logout handler                 | Destroys the current session. Must be safe when none exists.           |

`SessionDetails` holds two pieces:

| Member     | Role                                                     |
|------------|----------------------------------------------------------|
| `identity` | Your `Identity` attached to the request on success.      |
| `roles`    | Granted on success and stored on `Authentication.roles`. |

Implementations should not throw when no session exists: return `null` from `validate` and
no-op from `invalidate`.

### `HttpSessionManager` (default)

`HttpSessionManager` is the built-in servlet-session-backed implementation. It stores
`SessionDetails` under a session attribute and requires `identity` to implement
`java.io.Serializable`, since the servlet container may serialize session attributes. Non-serializable
identities are rejected with `IllegalArgumentException` at create time.

Configure it via its builder:

=== "Kotlin"

    ```kotlin
    session { cfg ->
        cfg.sessionManager = HttpSessionManager.builder()
            .attributeKey("app.user")
            .rotateSessionIdOnCreate(true)
            .invalidateSessionOnDestroy(true)
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

| Builder option                 | Default                              | Effect                                              |
|--------------------------------|--------------------------------------|-----------------------------------------------------|
| `attributeKey`                 | `javalin-security.session.principal` | Session attribute name for `SessionDetails`.        |
| `rotateSessionIdOnCreate`      | `true`                               | Rotates the session id on create (fixation defense).|
| `invalidateSessionOnDestroy`   | `true`                               | Calls `HttpSession.invalidate()` on logout.         |

`HttpSessionManager.of()` returns the same defaults. `HttpSessionManager.of("app.user")` is
shorthand for the attribute-key-only override.

### Custom `SessionManager`

Plug in any storage strategy. Everything else — the authenticator, the rule table, error
rendering — stays the same. A custom manager does not need `SessionDetails.identity` to be
`Serializable` — that constraint is specific to `HttpSessionManager`.

=== "Kotlin"

    ```kotlin
    // Toy in-memory store keyed by an opaque cookie value
    class InMemorySessionManager : SessionManager {
        private val store = ConcurrentHashMap<String, SessionDetails>()

        override fun create(ctx: Context, details: SessionDetails) {
            val token = UUID.randomUUID().toString()
            store[token] = details
            ctx.cookie("APPSESSION", token)
        }

        override fun validate(ctx: Context): SessionDetails? =
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

### Session lifetime

The extension does **not** implement application-level expiry. Session lifetime, cookie name,
and idle timeout are owned by the `SessionManager` — for the default `HttpSessionManager` that
means the servlet container (Jetty's session configuration). When the manager drops the session,
the next request authenticates as anonymous.

## Reading the identity

On success the strategy attaches your session `Identity` directly to the request:

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
- [Authorization](../concepts/authorization.md) — pair sessions with the rule table.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
- [Custom authentication](../guides/custom-authentication.md) — when even a custom
  `SessionManager` is not enough.
