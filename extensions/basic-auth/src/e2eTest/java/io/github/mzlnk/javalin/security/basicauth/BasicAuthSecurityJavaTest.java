package io.github.mzlnk.javalin.security.basicauth;

import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy;
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler;
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Set;

import static io.github.mzlnk.javalin.security.SecurityExtensions.principal;
import static io.javalin.http.HandlerType.GET;
import static io.javalin.http.HandlerType.POST;
import static org.assertj.core.api.Assertions.assertThat;

class BasicAuthSecurityJavaTest {
    private enum Role implements RouteRole { USER, ADMIN }

    private final UserLookup testUserLookup = username -> switch (username) {
        case "alice" -> new BasicUser("alice", "alice-pw", Set.of(Role.USER));
        case "admin" -> new BasicUser("admin", "admin-pw", Set.of(Role.ADMIN));
        default -> null;
    };

    @Test
    void should_allow_anonymous_access_when_route_is_allow() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.get("/public/info").code()).isEqualTo(200);
        });
    }

    @Test
    void should_return_401_when_authenticated_route_is_hit_without_credentials() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.post("/protected/data", "").code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_401_when_a_denied_route_is_hit_even_without_credentials() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.get("/admin/dashboard").code()).isEqualTo(401);
        });
    }

    @Test
    void should_allow_access_when_authenticated_route_is_hit_with_valid_credentials() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post(
                    "/protected/data", "", req -> req.header("Authorization", basicHeader("alice", "alice-pw")));

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_return_401_when_username_is_unknown() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post(
                    "/protected/data", "", req -> req.header("Authorization", basicHeader("nobody", "whatever")));

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_401_when_password_is_wrong() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post(
                    "/protected/data", "", req -> req.header("Authorization", basicHeader("alice", "wrong-pw")));

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_401_when_credentials_are_malformed() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post(
                    "/protected/data", "", req -> req.header("Authorization", "Basic not-valid-base64!!!"));

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_403_when_authenticated_caller_lacks_required_role() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/admin/dashboard", req -> req.header("Authorization", basicHeader("alice", "alice-pw")));

            // then
            assertThat(response.code()).isEqualTo(403);
        });
    }

    @Test
    void should_allow_access_when_caller_holds_required_role() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/admin/dashboard", req -> req.header("Authorization", basicHeader("admin", "admin-pw")));

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_expose_BasicAuthPrincipal_on_the_context_when_the_caller_is_authenticated() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = BasicAuthSecurity.basicAuth(basic -> basic.userLookup = testUserLookup);
                http.rules(rules -> rules.fallback = Rules.authenticated());
            })));
            config.routes.get("/me", ctx -> ctx.result(principal(ctx, BasicAuthPrincipal.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("Authorization", basicHeader("alice", "alice-pw")));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice");
        });
    }

    @Test
    void should_include_WWW_Authenticate_header_when_basicChallenge_is_enabled_and_credentials_are_absent() {
        // given
        Javalin app = app(true);

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/protected/data", "");

            // then
            assertThat(response.code()).isEqualTo(401);
            var wwwAuth = response.headers().get("WWW-Authenticate");
            assertThat(wwwAuth).isNotNull().isNotEmpty();
            assertThat(wwwAuth.get(0)).startsWith("Basic realm=\"TestAPI\"");
        });
    }

    @Test
    void should_include_WWW_Authenticate_header_when_basicChallenge_is_enabled_and_credentials_are_invalid() {
        // given
        Javalin app = app(true);

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/protected/data", "", req -> req.header("Authorization", basicHeader("alice", "wrong-pw")));

            // then
            assertThat(response.code()).isEqualTo(401);
            var wwwAuth = response.headers().get("WWW-Authenticate");
            assertThat(wwwAuth).isNotNull().isNotEmpty();
            assertThat(wwwAuth.get(0)).startsWith("Basic realm=\"TestAPI\"");
        });
    }

    @Test
    void should_NOT_include_WWW_Authenticate_header_when_basicChallenge_is_disabled() {
        // given
        Javalin app = app(false);

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/protected/data", "");

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.headers().get("WWW-Authenticate")).isNull();
        });
    }

    @Test
    void should_authenticate_from_a_custom_header_when_credentialsResolver_is_set_to_a_custom_header() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = BasicAuthSecurity.basicAuth(basic -> {
                    basic.userLookup = testUserLookup;
                    basic.credentialsResolver = BasicCredentialsResolver.basicHeader("X-Custom-Auth");
                });
                http.rules(rules -> rules.fallback = Rules.authenticated());
            })));
            config.routes.get("/me", ctx -> ctx.result(principal(ctx, BasicAuthPrincipal.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("X-Custom-Auth", basicHeader("alice", "alice-pw")));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice");
        });
    }

    @Test
    void should_enforce_rules_end_to_end_when_a_plugin_is_registered_with_a_built_BasicAuthenticator() {
        // given
        // a custom AuthenticationStrategy rather than the basicAuth( ) one-stop factory
        BasicAuthenticator authenticator = BasicAuthenticator.builder(testUserLookup)
                .passwordEncoder(PasswordEncoder.noOp())
                .build();
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = authenticationStrategy(authenticator);
                http.rules(rules -> {
                    rules.add("/api/*", GET, Rules.allow());
                    rules.add("/api/*", POST, Rules.authenticated());
                    rules.fallback = Rules.deny();
                });
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/resource", ctx -> ctx.result("created"));
        });

        JavalinTest.test(app, (server, client) -> {
            // allow — anonymous GET allowed
            assertThat(client.get("/api/resource").code()).isEqualTo(200);
            // authenticated — no credentials
            assertThat(client.post("/api/resource", "").code()).isEqualTo(401);
            // authenticated — with valid credentials
            assertThat(client.post("/api/resource", "", req -> req.header("Authorization", basicHeader("alice", "alice-pw"))).code())
                    .isEqualTo(200);
            // authenticated — with wrong password -> 401
            assertThat(client.post("/api/resource", "", req -> req.header("Authorization", basicHeader("alice", "wrong-pw"))).code())
                    .isEqualTo(401);
        });
    }

    private static String basicHeader(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }

    private static AuthenticationStrategy.Sync authenticationStrategy(Authenticator authenticator) {
        return authenticationStrategy(authenticator, UnauthorizedHandler.getDEFAULT(), ForbiddenHandler.getDEFAULT());
    }

    private static AuthenticationStrategy.Sync authenticationStrategy(
            Authenticator authenticator,
            UnauthorizedHandler unauthorizedHandler,
            ForbiddenHandler forbiddenHandler
    ) {
        return new AuthenticationStrategy.Sync() {
            @Override
            public Authenticator authenticator() {
                return authenticator;
            }

            @Override
            public UnauthorizedHandler getUnauthorizedHandler() {
                return unauthorizedHandler;
            }

            @Override
            public ForbiddenHandler getForbiddenHandler() {
                return forbiddenHandler;
            }
        };
    }

    private Javalin app(boolean basicChallenge) {
        BasicAuthenticator authenticator = BasicAuthenticator.builder(testUserLookup).build();
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = BasicAuthSecurity.basicAuth(basic -> {
                    basic.userLookup = testUserLookup;
                    basic.basicChallenge = basicChallenge;
                    basic.realm = "TestAPI";
                });
                http.rules(rules -> {
                    rules.add("/public/*", GET, Rules.allow());
                    rules.add("/protected/*", POST, Rules.authenticated());
                    rules.add("/admin/*", GET, Rules.hasRole(Role.ADMIN));
                    rules.fallback = Rules.deny();
                });
            })));
            config.routes.get("/public/info", ctx -> ctx.result("public"));
            config.routes.post("/protected/data", ctx -> ctx.result("created"));
            config.routes.get("/admin/dashboard", ctx -> ctx.result("dashboard"));
        });
    }

    private Javalin app() {
        return app(false);
    }
}
