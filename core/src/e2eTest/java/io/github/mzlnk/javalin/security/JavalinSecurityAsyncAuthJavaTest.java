package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;

import static io.github.mzlnk.javalin.security.E2EJavaTestSupport.asyncAuthenticationStrategy;
import static io.javalin.http.HandlerType.GET;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityAsyncAuthJavaTest {

    @Test
    void should_authenticate_and_allow_access_when_an_async_authenticator_succeeds() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> rules.add("/api/*", GET, Rules.authenticated()));
                http.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx -> CompletableFuture.supplyAsync(() -> {
                    String user = ctx.header("X-User");
                    return user != null
                            ? new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity(user)))
                            : AuthenticationResult.NotAuthenticated.INSTANCE;
                }));
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.get("/api/resource").code()).isEqualTo(401);
            assertThat(client.get("/api/resource", req -> req.header("X-User", "alice")).code()).isEqualTo(200);
        });
    }

    @Test
    void should_deny_access_when_an_async_authenticator_reports_a_failure() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> rules.add("/api/*", GET, Rules.allow()));
                http.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx ->
                        CompletableFuture.completedFuture(new AuthenticationResult.Failure("async credential failure", null)));
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.body().string()).doesNotContain("async credential failure");
        });
    }

    @Test
    void should_not_run_the_route_handler_when_an_async_authenticator_denies_the_request() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> rules.add("/api/*", GET, Rules.authenticated()));
                http.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx ->
                        CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated.INSTANCE));
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("protected-content"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.body().string()).doesNotContain("protected-content");
        });
    }

    @Test
    void should_deny_with_401_when_an_async_authenticator_future_completes_exceptionally() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> rules.add("/api/*", GET, Rules.allow()));
                http.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx ->
                        CompletableFuture.failedFuture(new RuntimeException("internal IdP error")));
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("protected-content"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.body().string()).doesNotContain("protected-content");
            assertThat(response.body().string()).doesNotContain("internal IdP error");
        });
    }

    @Test
    void should_deny_with_401_when_an_async_authenticator_throws_synchronously() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> rules.add("/api/*", GET, Rules.allow()));
                http.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx -> {
                    throw new IllegalStateException("sync crash in authenticator");
                });
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("protected-content"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/resource");

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.body().string()).doesNotContain("protected-content");
            assertThat(response.body().string()).doesNotContain("sync crash in authenticator");
        });
    }
}
