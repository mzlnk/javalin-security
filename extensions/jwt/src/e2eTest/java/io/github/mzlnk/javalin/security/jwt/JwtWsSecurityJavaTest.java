package io.github.mzlnk.javalin.security.jwt;

import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.github.mzlnk.javalin.security.common.token.TokenResolver;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class JwtWsSecurityJavaTest {
    private enum Role implements RouteRole { ADMIN, USER }

    private final JwtDecoder testDecoder = (token, verification) -> {
        if (!token.startsWith("valid|")) {
            throw new IllegalArgumentException("bad token");
        }
        String[] parts = token.split("\\|", 3);
        String subject = parts.length > 1 ? parts[1] : "";
        List<String> roles = parts.length > 2 && !parts[2].isEmpty()
                ? Arrays.stream(parts[2].split(",")).filter(s -> !s.isEmpty()).collect(Collectors.toList())
                : List.of();
        return new SimpleDecodedJwt(subject, Map.of("sub", subject, "roles", roles));
    };

    @Test
    void should_reject_an_anonymous_upgrade_when_the_ws_route_requires_authentication() {
        // given
        Javalin app = bearerApp();

        JavalinTest.test(app, (server, client) -> {
            // when
            WsTestClient.UpgradeAttempt attempt = WsTestClient.tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_allow_the_upgrade_when_a_valid_bearer_token_is_provided() {
        // given
        Javalin app = bearerApp();

        JavalinTest.test(app, (server, client) -> {
            // when
            WsTestClient.UpgradeAttempt attempt = WsTestClient.tryConnect(
                    client.getOrigin(), "/ws/chat", Map.of("Authorization", "Bearer " + token("alice")));

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_allow_the_upgrade_when_the_caller_holds_the_required_role() {
        // given
        Javalin app = bearerApp();

        JavalinTest.test(app, (server, client) -> {
            // when
            WsTestClient.UpgradeAttempt attempt = WsTestClient.tryConnect(
                    client.getOrigin(), "/ws/admin", Map.of("Authorization", "Bearer " + token("admin", List.of("ADMIN"))));

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_reject_the_upgrade_with_403_when_the_authenticated_caller_lacks_the_required_role() {
        // given
        Javalin app = bearerApp();

        JavalinTest.test(app, (server, client) -> {
            // when
            WsTestClient.UpgradeAttempt attempt = WsTestClient.tryConnect(
                    client.getOrigin(), "/ws/admin", Map.of("Authorization", "Bearer " + token("bob", List.of("USER"))));

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(403);
        });
    }

    @Test
    void should_reject_the_upgrade_with_401_when_the_bearer_token_is_malformed() {
        // given
        Javalin app = bearerApp();

        JavalinTest.test(app, (server, client) -> {
            // when
            WsTestClient.UpgradeAttempt attempt = WsTestClient.tryConnect(
                    client.getOrigin(), "/ws/chat", Map.of("Authorization", "Bearer not-a-jwt"));

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_allow_the_upgrade_when_a_valid_token_is_carried_in_a_cookie() {
        // given
        Javalin app = cookieApp();

        JavalinTest.test(app, (server, client) -> {
            // when
            WsTestClient.UpgradeAttempt attempt = WsTestClient.tryConnect(
                    client.getOrigin(), "/ws/chat", Map.of("Cookie", "access_token=" + token("alice")));

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_reject_the_upgrade_with_401_when_the_cookie_is_absent() {
        // given
        Javalin app = cookieApp();

        JavalinTest.test(app, (server, client) -> {
            // when
            WsTestClient.UpgradeAttempt attempt = WsTestClient.tryConnect(
                    client.getOrigin(), "/ws/chat", Map.of("Authorization", "Bearer " + token("alice")));

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    private static RouteRole roleOf(String name) {
        for (Role role : Role.values()) {
            if (role.name().equals(name)) return role;
        }
        return null;
    }

    private String token(String subject, List<String> roles) {
        return "valid|" + subject + "|" + String.join(",", roles);
    }

    private String token(String subject) {
        return token(subject, List.of());
    }

    private Javalin bearerApp() {
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.authentication = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = testDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret");
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", JwtWsSecurityJavaTest::roleOf);
                });
                ws.rules(rules -> {
                    rules.add("/ws/chat", Rules.authenticated());
                    rules.add("/ws/admin", Rules.hasRole(Role.ADMIN));
                });
            })));
            config.routes.ws("/ws/chat", ws -> { });
            config.routes.ws("/ws/admin", ws -> { });
        });
    }

    private Javalin cookieApp() {
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.authentication = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = testDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret");
                    jwt.tokenResolver = TokenResolver.cookie("access_token");
                });
                ws.rules(rules -> rules.add("/ws/chat", Rules.authenticated()));
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });
    }
}
