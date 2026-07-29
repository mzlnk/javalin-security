package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static io.github.mzlnk.javalin.security.E2EJavaTestSupport.authenticationStrategy;
import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;
import static io.github.mzlnk.javalin.security.SecurityExtensions.identityOrNull;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityHttpJavaTest {
    private enum Role implements RouteRole { ADMIN, USER }

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        if ("invalid".equals(user)) return new AuthenticationResult.Failure("bad credentials", null);
        String rolesHeader = ctx.header("X-Roles");
        Set<RouteRole> roles = rolesHeader == null
                ? Set.of()
                : Arrays.stream(rolesHeader.split(","))
                        .map(name -> (RouteRole) Role.valueOf(name))
                        .collect(Collectors.toSet());
        return new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity(user), roles));
    };

    @Test
    void should_allow_anonymous_access_when_rule_is_allow() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource");

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("ok");
        });
    }

    @Test
    void should_return_401_when_authenticated_rule_is_hit_without_credentials() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/api/v1/resource", "");

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_allow_access_when_authenticated_rule_is_hit_with_credentials() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/api/v1/resource", "", req -> req.header("X-User", "bob"));

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_return_401_when_role_protected_rule_is_hit_anonymously() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.delete("/api/v1/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_403_when_role_protected_rule_is_hit_without_the_role() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.delete("/api/v1/resource", null, req -> {
                req.header("X-User", "bob");
                req.header("X-Roles", "USER");
            });

            // then
            assertThat(response.code()).isEqualTo(403);
        });
    }

    @Test
    void should_allow_access_when_role_protected_rule_is_hit_with_the_role() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.delete("/api/v1/resource", null, req -> {
                req.header("X-User", "admin");
                req.header("X-Roles", "ADMIN");
            });

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("deleted");
        });
    }

    @Test
    void should_return_401_when_the_authenticator_reports_a_failure() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post("/api/v1/resource", "", req -> req.header("X-User", "invalid"));

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_expose_the_authenticated_identity_on_the_context_when_the_caller_is_authenticated() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/me", req -> req.header("X-User", "bob"));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("bob");
        });
    }

    @Test
    void should_deny_by_default_when_no_rule_matches_the_route() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.allow());
                security.http.authentication = authenticationStrategy(headerAuthenticator);
            }));
            config.routes.get("/internal", ctx -> ctx.result("secret"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/internal");

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_treat_every_request_as_anonymous_when_no_authenticator_is_configured() {
        // given
        Javalin app = app(null);

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.get("/api/v1/resource").code()).isEqualTo(200);
            assertThat(client.post("/api/v1/resource", "").code()).isEqualTo(401);
        });
    }

    @Test
    void should_deny_http_routes_by_default_when_only_ws_is_configured() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws.fallback = Rules.deny()));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_deny_http_routes_by_default_when_security_has_no_further_configuration() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> { }));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_grant_access_to_anonymous_callers_when_route_declares_the_anyone_role() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http.fallback = Rules.deny()));
            config.routes.get("/public", ctx -> ctx.result("ok"), Anyone.INSTANCE);
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/public");

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_grant_access_when_route_declares_roles_and_the_caller_holds_a_matching_role() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.http.authentication = authenticationStrategy(headerAuthenticator);
                security.http.fallback = Rules.deny(); // rule table must NOT be consulted
            }));
            config.routes.get("/admin", ctx -> ctx.result("admin-ok"), Role.ADMIN);
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/admin", req -> {
                req.header("X-User", "alice");
                req.header("X-Roles", "ADMIN");
            });

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("admin-ok");
        });
    }

    @Test
    void should_deny_access_when_route_declares_roles_and_the_caller_holds_no_matching_role() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.http.authentication = authenticationStrategy(headerAuthenticator);
                security.http.fallback = Rules.allow(); // even a permissive fallback must not apply
            }));
            config.routes.get("/admin", ctx -> ctx.result("admin-ok"), Role.ADMIN);
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/admin", req -> {
                req.header("X-User", "alice");
                req.header("X-Roles", "USER");
            });

            // then
            assertThat(response.code()).isEqualTo(403);
        });
    }

    @Test
    void should_fall_through_to_the_pattern_rule_table_when_route_declares_no_roles() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/plain", Rules.deny());
                security.http.authentication = authenticationStrategy(ctx -> new AuthenticationResult.Success(
                        Authentication.authenticated(new TestIdentity("alice"), Role.ADMIN)));
            }));
            config.routes.get("/plain", ctx -> ctx.result("ok")); // no roles declared
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/plain");

            // then
            assertThat(response.code()).isEqualTo(403);
        });
    }

    @Test
    void should_return_null_from_identityOrNull_when_the_caller_is_anonymous() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.allow());
                security.http.authentication = authenticationStrategy(headerAuthenticator);
            }));
            config.routes.get("/api/v1/me", ctx -> {
                TestIdentity caller = identityOrNull(ctx, TestIdentity.class);
                ctx.result(caller != null ? caller.getName() : "anonymous");
            });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/me");

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("anonymous");
        });
    }

    @Test
    void should_return_the_identity_from_identityOrNull_when_the_caller_is_authenticated() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.allow());
                security.http.authentication = authenticationStrategy(headerAuthenticator);
            }));
            config.routes.get("/api/v1/me", ctx -> {
                TestIdentity caller = identityOrNull(ctx, TestIdentity.class);
                ctx.result(caller != null ? caller.getName() : "anonymous");
            });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/me", req -> req.header("X-User", "bob"));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("bob");
        });
    }

    private Javalin app(Authenticator authenticator) {
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.allow());
                security.rules.post("/api/v1/*", Rules.authenticated());
                security.rules.delete("/api/v1/*", Rules.hasRole(Role.ADMIN));
                if (authenticator != null) {
                    security.http.authentication = authenticationStrategy(authenticator);
                }
            }));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/v1/resource", ctx -> ctx.result("created"));
            config.routes.delete("/api/v1/resource", ctx -> ctx.result("deleted"));
            config.routes.get("/api/v1/me", ctx -> ctx.result(identity(ctx, TestIdentity.class).getName()));
        });
    }

    private Javalin app() {
        return app(headerAuthenticator);
    }
}
