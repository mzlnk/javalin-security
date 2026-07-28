package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.github.mzlnk.javalin.security.E2EJavaTestSupport.authenticationStrategy;
import static io.github.mzlnk.javalin.security.WsTestClient.rawUpgradeStatusCode;
import static io.github.mzlnk.javalin.security.WsTestClient.tryConnect;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityWsAllowedOriginsJavaTest {

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        return user == null
                ? AuthenticationResult.NotAuthenticated.INSTANCE
                : new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity(user)));
    };

    @Test
    void should_reject_the_upgrade_with_403_when_the_Origin_is_not_in_the_allowedOrigins_list() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.fallback = Rules.allow());
                ws.allowedOrigins = java.util.List.of("https://allowed.example.com");
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            int code = rawUpgradeStatusCode(
                    "localhost", server.port(), "/ws/chat", Map.of("Origin", "https://evil.example.com"));

            // then
            assertThat(code).isEqualTo(403);
        });
    }

    @Test
    void should_reject_the_upgrade_with_403_when_the_Origin_header_is_absent_and_allowedOrigins_is_set() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.fallback = Rules.allow());
                ws.allowedOrigins = java.util.List.of("https://allowed.example.com");
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            int code = rawUpgradeStatusCode("localhost", server.port(), "/ws/chat", Map.of());

            // then
            assertThat(code).isEqualTo(403);
        });
    }

    @Test
    void should_accept_the_upgrade_when_the_Origin_is_in_the_allowedOrigins_list() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.fallback = Rules.allow());
                ws.allowedOrigins = java.util.List.of("https://allowed.example.com");
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            int code = rawUpgradeStatusCode(
                    "localhost", server.port(), "/ws/chat", Map.of("Origin", "https://allowed.example.com"));

            // then
            assertThat(code).isEqualTo(101);
        });
    }

    @Test
    void should_accept_any_Origin_when_allowedOrigins_is_not_configured() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.rules(rules -> rules.fallback = Rules.allow()))));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_reject_a_disallowed_Origin_before_authentication_is_even_attempted() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.fallback = Rules.authenticated());
                ws.allowedOrigins = java.util.List.of("https://allowed.example.com");
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            int code = rawUpgradeStatusCode(
                    "localhost", server.port(), "/ws/chat",
                    Map.of("Origin", "https://evil.example.com", "X-User", "alice"));

            // then
            assertThat(code).isEqualTo(403);
        });
    }

    @Test
    void should_invoke_a_custom_forbiddenHandler_when_the_Origin_is_disallowed() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.fallback = Rules.allow());
                ws.allowedOrigins = java.util.List.of("https://allowed.example.com");
                ws.authentication = E2EJavaTestSupport.authenticationStrategy(
                        ctx -> AuthenticationResult.NotAuthenticated.INSTANCE,
                        io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler.getDEFAULT(),
                        (ctx, auth) -> ctx.status(403).result("custom-origin-denied")
                );
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            int code = rawUpgradeStatusCode(
                    "localhost", server.port(), "/ws/chat", Map.of("Origin", "https://evil.example.com"));

            // then
            assertThat(code).isEqualTo(403);
        });
    }
}
