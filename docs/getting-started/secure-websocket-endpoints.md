# Secure WebSocket endpoints

The WebSocket model mirrors HTTP: opt into `ws { }`, plug in a strategy, and declare path rules.
Enforcement runs **once, at the upgrade** — never per message.

!!! tip "Authentication is pluggable"
    Basic Auth is HTTP-only. For WebSockets the built-in choice is
    [JWT](../extensions/jwt/index.md), but you can also use a
    [custom authenticator](../guides/custom-authentication.md).

Install [core](installation.md) plus the [JWT extension](../extensions/jwt/index.md#installation)
and a decoder adapter before you begin. HTTP and WebSocket are independent — configuring one does
not secure the other.

## 1. Configure authentication

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.jwt.*
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder
    import io.javalin.security.RouteRole

    enum class Role : RouteRole { USER, ADMIN }

    // inside Javalin.create { config ->
    config.security { security ->
        security.ws { ws ->
            ws.authentication = jwt { jwt ->
                jwt.decoder = NimbusJwtDecoder
                jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
                jwt.issuer = "https://issuer.example.com/"
                jwt.audiences = setOf("my-api")
                jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
                    Role.entries.find { it.name == name }
                }
            }
            ws.allowedOrigins = listOf("https://app.example.com")  // recommended for browsers
        }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.jwt.*;
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder;
    import io.javalin.security.RouteRole;
    import java.util.List;
    import java.util.Set;

    enum Role implements RouteRole { USER, ADMIN }

    // inside Javalin.create(config -> {
    config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
        ws.authentication = JwtSecurity.jwt(jwt -> {
            jwt.decoder = NimbusJwtDecoder.INSTANCE;
            jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
            jwt.issuer = "https://issuer.example.com/";
            jwt.audiences = Set.of("my-api");
            jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> {
                try { return Role.valueOf(name); }
                catch (IllegalArgumentException e) { return null; }
            });
        });
        ws.allowedOrigins = List.of("https://app.example.com");
    })));
    ```

By default the token is read from `Authorization: Bearer …`. Browsers cannot set that header on
the handshake — carry the JWT in a cookie instead, and always set `allowedOrigins`. See
[JWT in the browser](../websocket-security.md#jwt-in-the-browser).

## 2. Declare who is allowed

WebSocket rules match on **path only** (no HTTP method). First match wins; an unset `fallback`
denies.

=== "Kotlin"

    ```kotlin
    ws.rules { r ->
        r.add("/ws/chat", r.authenticated)
        r.add("/ws/admin", r.hasRole(Role.ADMIN))
        r.fallback = r.deny
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rules;

    ws.rules(r -> {
        r.add("/ws/chat", Rules.authenticated());
        r.add("/ws/admin", Rules.hasRole(Role.ADMIN));
        r.fallback = Rules.deny();
    });
    ```

## 3. Register WebSocket routes and run

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.jwt.*
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder
    import io.github.mzlnk.javalin.security.security
    import io.javalin.Javalin

    val app = Javalin.create { config ->
        config.security { security ->
            security.ws { ws ->
                ws.authentication = jwt { jwt ->
                    jwt.decoder = NimbusJwtDecoder
                    jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json")
                    jwt.issuer = "https://issuer.example.com/"
                    jwt.audiences = setOf("my-api")
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles") { name ->
                        Role.entries.find { it.name == name }
                    }
                }
                ws.allowedOrigins = listOf("https://app.example.com")
                ws.rules { r ->
                    r.add("/ws/chat", r.authenticated)
                    r.add("/ws/admin", r.hasRole(Role.ADMIN))
                    r.fallback = r.deny
                }
            }
        }
        config.routes.ws("/ws/chat") { ws ->
            ws.onConnect { ctx ->
                ctx.send("welcome ${ctx.principal<JwtPrincipal>()?.name}")
            }
            ws.onMessage { ctx -> ctx.send("echo: ${ctx.message()}") }
        }
        config.routes.ws("/ws/admin") { }
    }.start(7070)
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
    import io.github.mzlnk.javalin.security.jwt.*;
    import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder;
    import io.github.mzlnk.javalin.security.authorization.Rules;
    import io.javalin.Javalin;
    import java.util.List;
    import java.util.Set;

    import static io.github.mzlnk.javalin.security.SecurityExtensions.principal;

    Javalin app = Javalin.create(config -> {
        config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
            ws.authentication = JwtSecurity.jwt(jwt -> {
                jwt.decoder = NimbusJwtDecoder.INSTANCE;
                jwt.keySource = JwtKeySource.jwks("https://issuer.example.com/.well-known/jwks.json");
                jwt.issuer = "https://issuer.example.com/";
                jwt.audiences = Set.of("my-api");
                jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", name -> {
                    try { return Role.valueOf(name); }
                    catch (IllegalArgumentException e) { return null; }
                });
            });
            ws.allowedOrigins = List.of("https://app.example.com");
            ws.rules(r -> {
                r.add("/ws/chat", Rules.authenticated());
                r.add("/ws/admin", Rules.hasRole(Role.ADMIN));
                r.fallback = Rules.deny();
            });
        })));
        config.routes.ws("/ws/chat", ws -> {
            ws.onConnect(ctx -> {
                JwtPrincipal p = principal(ctx, JwtPrincipal.class);
                ctx.send("welcome " + (p != null ? p.getName() : "?"));
            });
            ws.onMessage(ctx -> ctx.send("echo: " + ctx.message()));
        });
        config.routes.ws("/ws/admin", ws -> { });
    }).start(7070);
    ```

## Next steps

- [Access caller identity](access-caller-identity.md) — read the authenticated user in handlers.
- [Authorization](../concepts/authorization.md) — same rules as HTTP, minus HTTP methods.
- [JWT](../extensions/jwt/index.md) — decoder, keys, and roles mapping.
- [Secure HTTP endpoints](secure-http-endpoints.md) — if you also need Basic Auth on routes.
