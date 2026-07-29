# Authorization

Authorization answers **"is this caller allowed?"**. It runs *after* authentication, using the
resolved identity and roles.

## Two ways to authorize

Checked in this order:

1. **Route roles** — `RouteRole`s attached to the route itself
   (`config.routes.get("/admin", handler, Role.ADMIN)`). Checked first.
2. **Rule table** — path patterns declared on `security.rules`. Used **only**
   when the route declares no roles.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules

    security.rules.get("/public/*", Rules.allow())
    security.rules.any("/api/*", Rules.authenticated())
    security.http.fallback = Rules.deny()
    config.routes.get("/admin", { it.result("ok") }, Role.ADMIN)  // route roles win for this route
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rules;

    security.rules.get("/public/*", Rules.allow());
    security.rules.any("/api/*", Rules.authenticated());
    security.http.fallback = Rules.deny();
    config.routes.get("/admin", ctx -> ctx.result("ok"), Role.ADMIN);
    ```

If a route declares any `RouteRole`, the rule table (including `http.fallback` / `ws.fallback`) is
**skipped** for that route. Use `Anyone` as the route-role equivalent of `allow`.

## Built-in rules

| Rule              | Grants when…                                     |
|-------------------|--------------------------------------------------|
| `allow`           | Always (including anonymous).                    |
| `deny`            | Never.                                           |
| `authenticated`   | Caller is logged in.                             |
| `hasRole(role)`   | Caller holds that role.                          |
| `hasAnyRole(…)`   | Caller holds at least one of the listed roles.   |

Call as `Rules.allow()`, `Rules.deny()`, `Rules.authenticated()`, `Rules.hasRole(…)`, etc.
from both Kotlin and Java.

HTTP rules can match on path + method (`rules.get(pattern, rule)`, `rules.post(…)`, etc.) or any
method (`rules.any(…)`). WebSocket rules use `rules.ws(…)` and match on path only. A `GET` rule
also governs `HEAD`.

## Deny by default

Entries are evaluated in order; **first match wins**. If nothing matches, `http.fallback` or
`ws.fallback` decides — and when fallback is unset, access is **denied**.

```kotlin
import io.github.mzlnk.javalin.security.authorization.Rules
security.rules.get("/public/*", Rules.allow())
security.rules.any("/api/*", Rules.authenticated())
security.http.fallback = Rules.deny()   // explicit; also the default
```

Put specific patterns before broader ones (`/api/admin/*` before `/api/*`); otherwise the broad
rule shadows the specific one.

Typical fallbacks: `deny` (locked down), `authenticated` (login required by default), or — rarely
— `allow` (open by default).

## Path patterns

Use **Javalin** route syntax — the same as your routes:

| Token       | Meaning                    | Example         |
|-------------|----------------------------|-----------------|
| `*`         | Wildcard across segments   | `/api/*`        |
| `{param}`   | One segment                | `/users/{id}`   |
| `<param>`   | Slash-accepting            | `/files/<path>` |

Ant-style `**` and `?` are rejected at startup. Patterns match the path **without** the context
path prefix.

## Custom rules

A `Rule` is a lambda `(Authentication, Context) -> Boolean`. Use it for ownership checks and
similar per-request logic.

=== "Kotlin"

    ```kotlin
    val sameTenant = Rule { auth, ctx ->
        val identity = auth.identity as? JwtIdentity ?: return@Rule false
        identity.token.claim<String>("tenant") == ctx.pathParam("tenant")
    }
    security.rules.any("/tenants/{tenant}/*", sameTenant)
    ```

=== "Java"

    ```java
    Rule sameTenant = (auth, ctx) -> {
        if (!(auth.getIdentity() instanceof JwtIdentity identity)) return false;
        String tenant = identity.getToken().claim("tenant");
        return tenant != null && tenant.equals(ctx.pathParam("tenant"));
    };
    security.rules.any("/tenants/{tenant}/*", sameTenant);
    ```

Always guard against anonymous callers (`identity == null`) inside custom rules.

## Denial status

| Caller                 | Status     |
|------------------------|------------|
| Anonymous, denied      | **401**    |
| Authenticated, denied  | **403**    |

## Next steps

- [Authentication](authentication.md) — where roles come from.
- [Error handling](error-handling.md) — customize 401 / 403.
- [Rules DSL](../rules.md) — verb methods, `apiBuilder`, and the full reference.
- [HTTP security](../http-security.md) — `http.fallback`, CORS preflight.
