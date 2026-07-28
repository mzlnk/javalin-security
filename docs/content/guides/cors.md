# CORS and preflight

Cross-origin browser calls trigger a **preflight** `OPTIONS` request before the real request.
That preflight carries no credentials, so a deny-by-default rule table would block it and break
CORS. `javalin-security` has a narrow bypass for exactly this case, but it does **not** add CORS
response headers — that is still Javalin's CORS plugin's job.

## Two independent concerns

| Concern                                                          | Handled by                                                            |
|------------------------------------------------------------------|-----------------------------------------------------------------------|
| Sending `Access-Control-Allow-*` **response headers**.           | Javalin's CORS plugin (`config.bundledPlugins.enableCors`).           |
| Not **blocking** the preflight `OPTIONS` in the rule table.      | `allowCorsPreflight = true`.                                          |

You typically need **both**.

## Setup

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    Javalin.create { config ->
        // 1. CORS response headers.
        config.bundledPlugins.enableCors { cors ->
            cors.addRule { it.allowHost("https://app.example.com") }
        }

        // 2. Security: let the preflight through, protect the rest.
        config.security { security ->
            security.http { http ->
                http.authentication = myStrategy
                http.rules { r ->
                    r.allowCorsPreflight = true          // don't block CORS preflight OPTIONS
                    r.add("/api/*", r.authenticated)
                    r.fallback = r.deny
                }
            }
        }
        config.routes.get("/api/data") { it.result("data") }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;

    Javalin.create(config -> {
        // 1. CORS response headers.
        config.bundledPlugins.enableCors(cors ->
            cors.addRule(it -> it.allowHost("https://app.example.com")));

        // 2. Security: let the preflight through, protect the rest.
        config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
            http.authentication = myStrategy;
            http.rules(r -> {
                r.allowCorsPreflight = true;             // don't block CORS preflight OPTIONS
                r.add("/api/*", Rules.authenticated());
                r.fallback = Rules.deny();
            });
        })));
        config.routes.get("/api/data", ctx -> ctx.result("data"));
    });
    ```

## What the bypass exempts

`allowCorsPreflight = true` permits **only** requests that are:

- HTTP method `OPTIONS`, **and**
- carrying an `Access-Control-Request-Method` header (the preflight marker).

The check runs **before** the rule table and `fallback`, so it works even with deny-by-default.

!!! warning "It is not a general OPTIONS allow"
    Regular `OPTIONS` traffic (without the preflight header) is still governed by your rules.
    The bypass never grants access to the *actual* cross-origin request that follows — that
    request carries credentials and is authorized normally.

## Common pitfalls

- **CORS "works" locally but fails in the browser.** You enabled `allowCorsPreflight` but forgot
  the CORS plugin, so the preflight passes the guard but returns no `Access-Control-Allow-Origin`
  header. Add `config.bundledPlugins.enableCors { … }`.
- **Preflight returns 401.** You have deny-by-default but did not set
  `allowCorsPreflight = true`.
- **Credentialed CORS.** If the browser sends cookies or credentials, configure the CORS plugin
  to allow credentials and a specific origin (not `*`). Remember: the WebSocket
  [Origin allow-list](../websocket-security.md#origin-allow-listing) is a separate mechanism.

## Next steps

- [Authorization](../concepts/authorization.md) — how the rule table decides access.
- [WebSocket security](../websocket-security.md) — Origin allow-listing for upgrades.
