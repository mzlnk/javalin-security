package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.http.ForbiddenResponse;
import io.javalin.http.UnauthorizedResponse;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import static io.github.mzlnk.javalin.security.E2EJavaTestSupport.authenticationStrategy;
import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityCustomHandlersJavaTest {

    private enum Role implements RouteRole { ADMIN }

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        if ("invalid".equals(user)) return new AuthenticationResult.Failure("super secret internal reason", null);
        return new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity(user)));
    };

    @Test
    void should_authenticate_with_a_custom_authenticator_when_one_is_provided() {
        // given
        Authenticator alwaysBob = ctx ->
                new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity("bob")));
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.authenticated());
                security.http.authentication = authenticationStrategy(alwaysBob);
            }));
            config.routes.get("/api/v1/me", ctx -> ctx.result(identity(ctx, TestIdentity.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/me");

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("bob");
        });
    }

    @Test
    void should_emit_a_custom_challenge_when_a_custom_unauthorizedHandler_is_configured() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.authenticated());
                security.http.authentication = E2EJavaTestSupport.authenticationStrategy(headerAuthenticator, (ctx, failure) -> {
                    ctx.header("WWW-Authenticate", "Bearer");
                    throw new UnauthorizedResponse();
                }, io.github.mzlnk.javalin.security.authorization.ForbiddenHandler.getDEFAULT());
            }));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.headers().get("WWW-Authenticate")).contains("Bearer");
        });
    }

    @Test
    void should_render_a_custom_response_when_a_custom_forbiddenHandler_is_configured() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.hasRole(Role.ADMIN));
                security.http.authentication = E2EJavaTestSupport.authenticationStrategy(
                        headerAuthenticator,
                        io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler.getDEFAULT(),
                        (ctx, auth) -> { throw new ForbiddenResponse("custom denied"); }
                );
            }));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource", req -> req.header("X-User", "bob"));

            // then
            assertThat(response.code()).isEqualTo(403);
            assertThat(response.body().string()).contains("custom denied");
        });
    }

    @Test
    void should_not_leak_the_authenticator_failure_message_when_authentication_fails() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.allow());
                security.http.authentication = authenticationStrategy(headerAuthenticator);
            }));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource", req -> req.header("X-User", "invalid"));

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.body().string()).doesNotContain("super secret internal reason");
        });
    }

    @Test
    void should_not_run_the_route_handler_when_a_custom_unauthorizedHandler_renders_without_throwing() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.authenticated());
                security.http.authentication = E2EJavaTestSupport.authenticationStrategy(
                        ctx -> AuthenticationResult.NotAuthenticated.INSTANCE,
                        (ctx, failure) -> ctx.status(401).result("denied-without-throwing"),
                        io.github.mzlnk.javalin.security.authorization.ForbiddenHandler.getDEFAULT()
                );
            }));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("protected-content"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
            String body = response.body().string();
            assertThat(body).isEqualTo("denied-without-throwing");
            assertThat(body).doesNotContain("protected-content");
        });
    }

    @Test
    void should_not_run_the_route_handler_when_a_custom_forbiddenHandler_renders_without_throwing() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.hasRole(Role.ADMIN));
                security.http.authentication = E2EJavaTestSupport.authenticationStrategy(
                        headerAuthenticator,
                        io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler.getDEFAULT(),
                        (ctx, auth) -> ctx.status(403).result("forbidden-without-throwing")
                );
            }));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("protected-content"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource", req -> req.header("X-User", "bob"));

            // then
            assertThat(response.code()).isEqualTo(403);
            String body = response.body().string();
            assertThat(body).isEqualTo("forbidden-without-throwing");
            assertThat(body).doesNotContain("protected-content");
        });
    }

    @Test
    void should_run_the_route_handler_after_the_guard_grants_access_to_an_authenticated_caller() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/*", Rules.authenticated());
                security.http.authentication = authenticationStrategy(headerAuthenticator);
            }));
            config.routes.get("/api/v1/resource", ctx -> {
                // Route handler: only reachable when the security guard grants access
                Authentication authentication = ctx.with(JavalinSecurityPlugin.class).authentication();
                ctx.result(authentication.getIdentity().getName());
            });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/resource", req -> req.header("X-User", "alice"));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice");
        });
    }
}
