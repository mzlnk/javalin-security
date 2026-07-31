# Testing secured apps

javalin-security is designed to be tested the way Javalin apps already are: with
[`JavalinTest`](https://javalin.io/tutorials/testing) from `javalin-testtools`. `JavalinTest`
starts a real server on a random port and gives you an HTTP client, so your tests assert the true
end-to-end 200 / 401 / 403 behavior.

## Test dependencies

```kotlin
testImplementation("io.javalin:javalin-testtools:{{ versions.javalin }}")
testImplementation("org.junit.jupiter:junit-jupiter:{{ versions.junit_bom }}")
testImplementation("org.assertj:assertj-core:{{ versions.assertj }}")
```

## Build the app in a factory

Keep your Javalin configuration in a reusable factory so tests and production share it.

=== "Kotlin"

    ```kotlin
    import io.github.mzlnk.javalin.security.authorization.Rules

    val testAuthenticator = Authenticator { ctx ->
        when (ctx.header("X-User")) {
            null -> AuthenticationResult.NotAuthenticated
            "invalid" -> AuthenticationResult.Failure("bad")
            else -> AuthenticationResult.Success(
                Authentication.authenticated(ApiIdentity(ctx.header("X-User")!!, setOf(Role.ADMIN))),
            )
        }
    }

    fun secureApp(): Javalin = Javalin.create { config ->
        config.security { security ->
            security.rules.get("/public/*", Rules.allow())
            security.rules.post("/api/*", Rules.authenticated())
            security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN))
            security.rules.ws("/ws/chat", Rules.authenticated())

            security.http.authentication = AuthenticationStrategy.sync(testAuthenticator)
            security.http.fallback = Rules.deny()
            security.ws.authentication = AuthenticationStrategy.sync(testAuthenticator)
            security.ws.fallback = Rules.deny()
        }

        config.routes.get("/public/info") { it.result("public") }
        config.routes.post("/api/data") { it.result("created") }
        config.routes.get("/admin/dashboard") { it.result("dashboard") }
        config.routes.ws("/ws/chat") { }
    }
    ```

=== "Java"

    ```java
    import io.github.mzlnk.javalin.security.authorization.Rules;

    static Authenticator testAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        if ("invalid".equals(user)) return new AuthenticationResult.Failure("bad", null);
        return new AuthenticationResult.Success(
            Authentication.authenticated(new ApiIdentity(user, Set.of(Role.ADMIN))));
    };

    static Javalin secureApp() {
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/public/*", Rules.allow());
                security.rules.post("/api/*", Rules.authenticated());
                security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
                security.rules.ws("/ws/chat", Rules.authenticated());

                security.http.authentication = AuthenticationStrategy.sync(testAuthenticator);
                security.http.fallback = Rules.deny();
                security.ws.authentication = AuthenticationStrategy.sync(testAuthenticator);
                security.ws.fallback = Rules.deny();
            }));

            config.routes.get("/public/info", ctx -> ctx.result("public"));
            config.routes.post("/api/data", ctx -> ctx.result("created"));
            config.routes.get("/admin/dashboard", ctx -> ctx.result("dashboard"));
            config.routes.ws("/ws/chat", ws -> {});
        });
    }
    ```

## Write a test

Point `JavalinTest` at your factory and assert status codes like any other Javalin app:

=== "Kotlin"

    ```kotlin
    import io.javalin.testtools.JavalinTest
    import org.assertj.core.api.Assertions.assertThat
    import org.junit.jupiter.api.Test

    class SecurityTest {
        @Test fun `secured routes enforce authentication`() = JavalinTest.test(secureApp()) { _, client ->
            assertThat(client.get("/public/info").code).isEqualTo(200)
            assertThat(client.post("/api/data").code).isEqualTo(401)
            assertThat(client.post("/api/data", null) { it.header("X-User", "bob") }.code).isEqualTo(200)
        }
    }
    ```

=== "Java"

    ```java
    import io.javalin.testtools.JavalinTest;
    import org.junit.jupiter.api.Test;
    import static org.assertj.core.api.Assertions.assertThat;

    class SecurityTest {
        @Test void secured_routes_enforce_authentication() {
            JavalinTest.test(secureApp(), (server, client) -> {
                assertThat(client.get("/public/info").code()).isEqualTo(200);
                assertThat(client.post("/api/data", "").code()).isEqualTo(401);
                assertThat(client.post("/api/data", "", req -> req.header("X-User", "bob")).code()).isEqualTo(200);
            });
        }
    }
    ```

## Testing WebSocket security

WebSocket authorization is enforced at upgrade time. Start the app with `JavalinTest` as
usual, then assert the handshake status with any WebSocket client — the snippets below use
the JDK `HttpClient` as an example.

A denied upgrade completes exceptionally with `WebSocketHandshakeException`. Read
`response.statusCode()` for the 401 or 403:

=== "Kotlin"

    ```kotlin
    import io.javalin.testtools.JavalinTest
    import java.net.URI
    import java.net.http.HttpClient
    import java.net.http.WebSocket
    import java.net.http.WebSocketHandshakeException
    import java.util.concurrent.CompletionException
    import org.assertj.core.api.Assertions.assertThat
    import org.junit.jupiter.api.Test

    @Test
    fun `anonymous upgrade is rejected`() = JavalinTest.test(secureApp()) { _, client ->
        val wsUri = URI.create("ws://127.0.0.1:${client.app.port()}/ws/chat")
        val future = HttpClient.newHttpClient()
            .newWebSocketBuilder()
            .buildAsync(wsUri, object : WebSocket.Listener {})

        val cause = runCatching { future.join() }.exceptionOrNull()
            .let { if (it is CompletionException) it.cause else it }

        assertThat(cause).isInstanceOf(WebSocketHandshakeException::class.java)
        assertThat((cause as WebSocketHandshakeException).response.statusCode()).isEqualTo(401)
    }
    ```

=== "Java"

    ```java
    import io.javalin.testtools.JavalinTest;
    import java.net.URI;
    import java.net.http.HttpClient;
    import java.net.http.WebSocket;
    import java.net.http.WebSocketHandshakeException;
    import java.util.concurrent.CompletionException;
    import org.junit.jupiter.api.Test;

    import static org.assertj.core.api.Assertions.assertThat;

    @Test
    void anonymous_upgrade_is_rejected() {
        JavalinTest.test(secureApp(), (server, client) -> {
            URI wsUri = URI.create("ws://127.0.0.1:" + client.getApp().port() + "/ws/chat");
            var future = HttpClient.newHttpClient()
                .newWebSocketBuilder()
                .buildAsync(wsUri, new WebSocket.Listener() {});

            Throwable error = null;
            try {
                future.join();
            } catch (CompletionException e) {
                error = e.getCause() != null ? e.getCause() : e;
            }

            assertThat(error).isInstanceOf(WebSocketHandshakeException.class);
            assertThat(((WebSocketHandshakeException) error).getResponse().statusCode()).isEqualTo(401);
        });
    }
    ```

## Next steps

- [Custom authentication](custom-authentication.md) — build the strategy you are testing.
- [Error handling](../concepts/error-handling.md) — customize 401 / 403 responses.
