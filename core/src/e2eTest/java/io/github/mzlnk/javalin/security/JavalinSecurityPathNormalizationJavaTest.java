package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import static io.github.mzlnk.javalin.security.E2EJavaTestSupport.authenticationStrategy;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityPathNormalizationJavaTest {

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        if ("invalid".equals(user)) return new AuthenticationResult.Failure("super secret internal reason", null);
        return new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity(user)));
    };

    @Test
    void should_keep_denying_a_path_when_a_trailing_slash_is_added() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/admin", Rules.deny());
                security.rules.get("/api/v1/*", Rules.allow());
            }));
            config.routes.get("/api/v1/admin", ctx -> ctx.result("admin"));
            config.routes.get("/api/v1/public", ctx -> ctx.result("public"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.get("/api/v1/admin").code()).isEqualTo(401);
            assertThat(client.get("/api/v1/admin/").code()).isEqualTo(401);
            // and a genuinely permitted sibling still works
            assertThat(client.get("/api/v1/public").code()).isEqualTo(200);
        });
    }

    @Test
    void should_authorize_a_parameterized_route_against_the_concrete_request_path() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/v1/users/{id}", Rules.deny());
                security.http.authentication = authenticationStrategy(headerAuthenticator);
            }));
            config.routes.get("/api/v1/users/{id}", ctx -> ctx.result("user-" + ctx.pathParam("id")));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/api/v1/users/42", req -> req.header("X-User", "bob"));

            // then
            assertThat(response.code()).isEqualTo(403);
            assertThat(response.body().string()).doesNotContain("user-42");
        });
    }
}
