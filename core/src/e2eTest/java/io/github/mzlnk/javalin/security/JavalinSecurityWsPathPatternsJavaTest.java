package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.github.mzlnk.javalin.security.WsTestClient.tryConnect;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityWsPathPatternsJavaTest {

    @Test
    void should_match_a_concrete_request_path_when_the_rule_pattern_declares_a_path_parameter() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security ->
                    security.rules.ws("/ws/room/{id}", Rules.allow())));
            config.routes.ws("/ws/room/{id}", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/room/5", Map.of());

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_match_a_concrete_request_path_when_the_rule_pattern_declares_a_wildcard() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security ->
                    security.rules.ws("/ws/room/*", Rules.allow())));
            config.routes.ws("/ws/room/{id}", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/room/5", Map.of());

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }
}
