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

class JavalinSecurityWsPathNormalizationJavaTest {

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        return user == null
                ? AuthenticationResult.NotAuthenticated.INSTANCE
                : new AuthenticationResult.Success(Authentication.authenticated(new TestPrincipal(user)));
    };

    @Test
    void should_keep_denying_an_upgrade_when_a_trailing_slash_is_added_to_the_path() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.rules(rules -> rules.add("/ws/admin", Rules.deny())))));
            config.routes.ws("/ws/admin", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/admin/", Map.of());

            // then
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_keep_denying_an_upgrade_when_the_path_contains_duplicate_slashes() {
        // given
        Javalin app = Javalin.create(config -> {
            config.router.treatMultipleSlashesAsSingleSlash = true;
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.rules(rules -> rules.add("/ws/admin", Rules.deny())))));
            config.routes.ws("/ws/admin", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            int code = rawUpgradeStatusCode("localhost", server.port(), "/ws//admin", Map.of());

            // then
            assertThat(code).isEqualTo(401);
        });
    }

    @Test
    void should_match_the_authorization_rule_after_the_context_path_is_stripped() {
        // given
        Javalin app = Javalin.create(config -> {
            config.router.contextPath = "/ctx";
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.authenticated()));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when / then
            var anonAttempt = tryConnect(client.getOrigin(), "/ctx/ws/chat", Map.of());
            assertThat(anonAttempt.statusCode()).isEqualTo(401);

            // when / then
            var authAttempt = tryConnect(client.getOrigin(), "/ctx/ws/chat", Map.of("X-User", "alice"));
            assertThat(authAttempt.connected()).isTrue();
        });
    }
}
