package io.github.mzlnk.javalin.security.jwt;

import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.github.mzlnk.javalin.security.common.token.TokenResolver;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.github.mzlnk.javalin.security.ExtensionsKt.principal;
import static io.javalin.http.HandlerType.GET;
import static io.javalin.http.HandlerType.POST;
import static org.assertj.core.api.Assertions.assertThat;

class JwtSecurityJavaTest {
    private enum Role implements RouteRole { ADMIN, USER }

    private final JwtDecoder testDecoder = (token, verification) -> {
        if ("INVALID".equals(token)) throw new IllegalArgumentException("bad token");
        return new SimpleDecodedJwt(token, Map.of("sub", token, "roles", List.of("USER")));
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
    void should_return_401_when_authenticated_route_is_hit_without_a_token() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.post("/protected/data", "").code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_401_when_a_denied_route_is_hit_even_without_a_token() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.get("/admin/dashboard").code()).isEqualTo(401);
        });
    }

    @Test
    void should_allow_access_when_authenticated_route_is_hit_with_a_valid_bearer_token() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/protected/data", "", req -> req.header("Authorization", "Bearer alice"));

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_return_401_when_the_decoder_throws_for_an_invalid_token() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/protected/data", "", req -> req.header("Authorization", "Bearer INVALID"));

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
            var response = client.get("/admin/dashboard", req -> req.header("Authorization", "Bearer bob"));

            // then
            assertThat(response.code()).isEqualTo(403);
        });
    }

    @Test
    void should_allow_access_when_caller_holds_required_role() {
        // given
        JwtDecoder adminDecoder = (token, verification) -> new SimpleDecodedJwt(token, Map.of("roles", List.of("ADMIN")));
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authenticationStrategy = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = adminDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret");
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", JwtSecurityJavaTest::roleOf);
                });
                http.rules(rules -> rules.add("/admin/*", GET, Rules.hasRole(Role.ADMIN)));
            })));
            config.routes.get("/admin/dashboard", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/admin/dashboard", req -> req.header("Authorization", "Bearer admin-user"));

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_expose_JwtPrincipal_on_the_context_when_the_caller_is_authenticated() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authenticationStrategy = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = testDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret");
                });
                http.rules(rules -> rules.fallback = Rules.authenticated());
            })));
            config.routes.get("/me", ctx -> ctx.result(principal(ctx, JwtPrincipal.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("Authorization", "Bearer alice"));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice");
        });
    }

    @Test
    void should_include_WWW_Authenticate_header_when_bearerChallenge_is_enabled_and_token_is_absent() {
        // given
        Javalin app = app(true);

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/protected/data", "");

            // then
            assertThat(response.code()).isEqualTo(401);
            var wwwAuth = response.headers().get("WWW-Authenticate");
            assertThat(wwwAuth).isNotNull().isNotEmpty();
            assertThat(wwwAuth.get(0)).startsWith("Bearer realm=\"TestAPI\"");
        });
    }

    @Test
    void should_include_an_error_attribute_in_WWW_Authenticate_when_the_token_is_invalid() {
        // given
        Javalin app = app(true);

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/protected/data", "", req -> req.header("Authorization", "Bearer INVALID"));

            // then
            assertThat(response.code()).isEqualTo(401);
            var wwwAuth = response.headers().get("WWW-Authenticate");
            assertThat(wwwAuth).isNotNull().isNotEmpty();
            assertThat(wwwAuth.get(0)).contains("error=\"invalid_token\"");
        });
    }

    @Test
    void should_NOT_include_WWW_Authenticate_header_when_bearerChallenge_is_disabled() {
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
    void should_authenticate_from_a_cookie_when_tokenResolver_is_set_to_cookie_based_resolution() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authenticationStrategy = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = testDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret");
                    jwt.tokenResolver = TokenResolver.cookie("access_token");
                });
                http.rules(rules -> rules.fallback = Rules.authenticated());
            })));
            config.routes.get("/me", ctx -> ctx.result(principal(ctx, JwtPrincipal.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("Cookie", "access_token=alice"));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice");
        });
    }

    @Test
    void should_return_401_when_tokenResolver_is_cookie_based_and_the_cookie_is_absent() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authenticationStrategy = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = testDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret");
                    jwt.tokenResolver = TokenResolver.cookie("access_token");
                });
                http.rules(rules -> rules.fallback = Rules.authenticated());
            })));
            config.routes.get("/me", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("Authorization", "Bearer alice"));

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_enforce_rules_end_to_end_when_a_plugin_is_registered_with_a_built_JwtAuthenticator() {
        // given
        // a custom AuthenticationStrategy rather than the jwt( ) one-stop factory
        JwtVerification verification = JwtVerification.of(JwtKeySource.secret("test-secret"));
        JwtAuthenticator authenticator = JwtAuthenticator.builder(testDecoder, verification)
                .rolesMapper(JwtRolesMapper.fromClaim("roles", JwtSecurityJavaTest::roleOf))
                .build();
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authenticationStrategy = authenticationStrategy(authenticator);
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
            // authenticated — no token
            assertThat(client.post("/api/resource", "").code()).isEqualTo(401);
            // authenticated — with valid token
            assertThat(client.post("/api/resource", "", req -> req.header("Authorization", "Bearer alice")).code())
                    .isEqualTo(200);
            // authenticated — with invalid token -> 401
            assertThat(client.post("/api/resource", "", req -> req.header("Authorization", "Bearer INVALID")).code())
                    .isEqualTo(401);
        });
    }

    private static RouteRole roleOf(String name) {
        for (Role role : Role.values()) {
            if (role.name().equals(name)) return role;
        }
        return null;
    }

    /** Wraps a plain {@link Authenticator} (e.g. a built {@link JwtAuthenticator}) in a minimal {@link AuthenticationStrategy.Sync}. */
    private static AuthenticationStrategy.Sync authenticationStrategy(Authenticator authenticator) {
        return new AuthenticationStrategy.Sync() {
            @Override
            public Authenticator authenticator() {
                return authenticator;
            }
        };
    }

    private Javalin app(boolean bearerChallenge) {
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authenticationStrategy = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = testDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret-not-actually-used-by-test-double");
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", JwtSecurityJavaTest::roleOf);
                    jwt.bearerChallenge = bearerChallenge;
                    jwt.realm = "TestAPI";
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
