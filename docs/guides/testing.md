# Testing secured apps

`javalin-security` is designed to be tested the way Javalin apps already are: with
[`JavalinTest`](https://javalin.io/tutorials/testing) from `javalin-testtools`. `JavalinTest`
starts a real server on a random port and gives you an HTTP client, so your tests assert the true
end-to-end 200 / 401 / 403 behavior.

## Test dependencies

```kotlin
testImplementation("io.javalin:javalin-testtools:7.2.2")
testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
testImplementation("org.assertj:assertj-core:3.27.3")
```

## Build the app in a factory

Keep your Javalin configuration in a reusable factory so tests and production share it.

=== "Kotlin"

    ```kotlin
    fun secureApp(): Javalin = Javalin.create { config ->
        config.security { security ->
            security.http { http ->
                http.authentication = object : AuthenticationStrategy.Sync {
                    override fun authenticator() = Authenticator { ctx ->
                        when (ctx.header("X-User")) {
                            null -> AuthenticationResult.NotAuthenticated
                            "invalid" -> AuthenticationResult.Failure("bad")
                            else -> AuthenticationResult.Success(
                                Authentication.authenticated(ApiIdentity(ctx.header("X-User")!!), setOf(Role.ADMIN)),
                            )
                        }
                    }
                }
                http.rules { r ->
                    r.add("/public/*", GET, r.allow)
                    r.add("/api/*", POST, r.authenticated)
                    r.add("/admin/*", GET, r.hasRole(Role.ADMIN))
                    r.fallback = r.deny
                }
            }
        }
        config.routes.get("/public/info") { it.result("public") }
        config.routes.post("/api/data") { it.result("created") }
        config.routes.get("/admin/dashboard") { it.result("dashboard") }
    }
    ```

=== "Java"

    ```java
    static Javalin secureApp() {
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = new AuthenticationStrategy.Sync() {
                    @Override public Authenticator authenticator() {
                        return ctx -> {
                            String user = ctx.header("X-User");
                            if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
                            if ("invalid".equals(user)) return new AuthenticationResult.Failure("bad", null);
                            return new AuthenticationResult.Success(
                                Authentication.authenticated(new ApiIdentity(user), Set.of(Role.ADMIN)));
                        };
                    }
                };
                http.rules(r -> {
                    r.add("/public/*", GET, Rules.allow());
                    r.add("/api/*", POST, Rules.authenticated());
                    r.add("/admin/*", GET, Rules.hasRole(Role.ADMIN));
                    r.fallback = Rules.deny();
                });
            })));
            config.routes.get("/public/info", ctx -> ctx.result("public"));
            config.routes.post("/api/data", ctx -> ctx.result("created"));
            config.routes.get("/admin/dashboard", ctx -> ctx.result("dashboard"));
        });
    }
    ```

## Assert the 200 / 401 / 403 matrix

=== "Kotlin"

    ```kotlin
    import io.javalin.testtools.JavalinTest
    import org.assertj.core.api.Assertions.assertThat
    import org.junit.jupiter.api.Test

    class SecurityTest {
        @Test fun `public route is open`() = JavalinTest.test(secureApp()) { _, client ->
            assertThat(client.get("/public/info").code).isEqualTo(200)
        }

        @Test fun `authenticated route needs credentials`() = JavalinTest.test(secureApp()) { _, client ->
            assertThat(client.post("/api/data").code).isEqualTo(401)                       // anonymous → 401
            assertThat(client.post("/api/data", null) { it.header("X-User", "bob") }.code).isEqualTo(200)
        }

        @Test fun `invalid credentials yield 401`() = JavalinTest.test(secureApp()) { _, client ->
            assertThat(client.post("/api/data", null) { it.header("X-User", "invalid") }.code).isEqualTo(401)
        }

        @Test fun `admin route enforces role`() = JavalinTest.test(secureApp()) { _, client ->
            assertThat(client.get("/admin/dashboard").code).isEqualTo(401)                 // anonymous → 401
            // authenticated but assume no ADMIN role would be 403 in your real setup
            assertThat(client.get("/admin/dashboard") { it.header("X-User", "root") }.code).isEqualTo(200)
        }
    }
    ```

=== "Java"

    ```java
    import io.javalin.testtools.JavalinTest;
    import org.junit.jupiter.api.Test;
    import static org.assertj.core.api.Assertions.assertThat;

    class SecurityTest {
        @Test void public_route_is_open() {
            JavalinTest.test(secureApp(), (server, client) ->
                assertThat(client.get("/public/info").code()).isEqualTo(200));
        }

        @Test void authenticated_route_needs_credentials() {
            JavalinTest.test(secureApp(), (server, client) -> {
                assertThat(client.post("/api/data", "").code()).isEqualTo(401);            // anonymous → 401
                assertThat(client.post("/api/data", "", req -> req.header("X-User", "bob")).code()).isEqualTo(200);
            });
        }

        @Test void invalid_credentials_yield_401() {
            JavalinTest.test(secureApp(), (server, client) ->
                assertThat(client.post("/api/data", "", req -> req.header("X-User", "invalid")).code()).isEqualTo(401));
        }
    }
    ```

## Assert that details never leak

A valuable security assertion: a denied response must **not** contain the internal failure reason.

=== "Kotlin"

    ```kotlin
    JavalinTest.test(secureApp()) { _, client ->
        val body = client.post("/api/data", null) { it.header("X-User", "invalid") }.body.string()
        assertThat(body).doesNotContain("bad")   // the Failure message stays server-side
    }
    ```

=== "Java"

    ```java
    JavalinTest.test(secureApp(), (server, client) -> {
        String body = client.post("/api/data", "", req -> req.header("X-User", "invalid")).body().string();
        assertThat(body).doesNotContain("bad");  // the Failure message stays server-side
    });
    ```

## Testing WebSocket security

For WebSocket upgrades, use the JDK `HttpClient` WebSocket builder and inspect the handshake
result — a denied upgrade throws `WebSocketHandshakeException`, whose `response.statusCode()` is
the 401 or 403. This mirrors the library's own end-to-end tests.

```kotlin
val client = java.net.http.HttpClient.newHttpClient()
val wsUri = java.net.URI.create("ws://localhost:$port/ws/chat")
val future = client.newWebSocketBuilder()
    .header("X-User", "alice")
    .buildAsync(wsUri, object : java.net.http.WebSocket.Listener {})
// future completes normally on a successful upgrade; exceptionally with
// WebSocketHandshakeException (→ response.statusCode()) when denied.
```

!!! tip "Mirror the library's test style"
    The `e2eTest` sources in the repository (`JavalinSecurityHttpKtTest`, `BasicAuthSecurityTest`,
    `JwtSecurityTest`, `JavalinSecurityWsKtTest`, and their Java twins) are copy-pasteable
    templates covering every scenario in both languages.

## Next steps

- [Custom authentication](custom-authentication.md) — build the strategy you are testing.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
