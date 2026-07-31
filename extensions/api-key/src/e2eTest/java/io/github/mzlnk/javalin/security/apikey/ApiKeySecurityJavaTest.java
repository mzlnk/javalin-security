package io.github.mzlnk.javalin.security.apikey;

import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy;
import io.github.mzlnk.javalin.security.authentication.Identity;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;
import static org.assertj.core.api.Assertions.assertThat;

class ApiKeySecurityJavaTest {
    private enum Role implements RouteRole { USER, ADMIN }

    static class Client implements Identity {
        private final String name;

        Client(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    private final ApiKeyLookup testApiKeyLookup = rawKey -> switch (rawKey) {
        case "k-alice" -> new ApiKeyDetails(new Client("alice-svc"), Set.of(Role.USER));
        case "k-admin" -> new ApiKeyDetails(new Client("admin-svc"), Set.of(Role.ADMIN));
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
    void should_return_401_when_authenticated_route_is_hit_without_api_key() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.post("/protected/data", "").code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_401_when_a_denied_route_is_hit_even_without_api_key() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when / then
            assertThat(client.get("/admin/dashboard").code()).isEqualTo(401);
        });
    }

    @Test
    void should_allow_access_when_authenticated_route_is_hit_with_valid_api_key() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post(
                    "/protected/data", "", req -> req.header("X-Api-Key", "k-alice"));

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_return_401_when_api_key_is_unknown() {
        // given
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.post(
                    "/protected/data", "", req -> req.header("X-Api-Key", "k-nobody"));

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
            var response = client.get("/admin/dashboard", req -> req.header("X-Api-Key", "k-alice"));

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
            var response = client.get("/admin/dashboard", req -> req.header("X-Api-Key", "k-admin"));

            // then
            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_expose_the_user_defined_identity_on_the_context_when_the_caller_is_authenticated() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.http.authentication = ApiKeySecurity.apiKey(api -> api.lookup = testApiKeyLookup);
                security.http.fallback = Rules.authenticated();
            }));
            config.routes.get("/me", ctx -> ctx.result(identity(ctx, Client.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("X-Api-Key", "k-alice"));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice-svc");
        });
    }

    @Test
    void should_authenticate_from_a_custom_header_when_resolver_is_set_to_a_custom_header() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.http.authentication = ApiKeySecurity.apiKey(api -> {
                    api.lookup = testApiKeyLookup;
                    api.resolver = ApiKeyResolver.header("X-App-Key");
                });
                security.http.fallback = Rules.authenticated();
            }));
            config.routes.get("/me", ctx -> ctx.result(identity(ctx, Client.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("X-App-Key", "k-alice"));

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice-svc");
        });
    }

    @Test
    void should_authenticate_from_a_query_parameter_when_resolver_is_set_to_query() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.http.authentication = ApiKeySecurity.apiKey(api -> {
                    api.lookup = testApiKeyLookup;
                    api.resolver = ApiKeyResolver.query("api_key");
                });
                security.http.fallback = Rules.authenticated();
            }));
            config.routes.get("/me", ctx -> ctx.result(identity(ctx, Client.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me?api_key=k-alice");

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice-svc");
        });
    }

    @Test
    void should_use_custom_unauthorizedHandler_when_configured() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.http.authentication = ApiKeySecurity.apiKey(api -> {
                    api.lookup = testApiKeyLookup;
                    api.unauthorizedHandler = (ctx, failure) ->
                            ctx.status(401).result("{\"error\":\"invalid_api_key\"}");
                });
                security.http.fallback = Rules.authenticated();
            }));
            config.routes.get("/me", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/me", req -> req.header("X-Api-Key", "k-nobody"));

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.body().string()).contains("invalid_api_key");
        });
    }

    @Test
    void should_enforce_rules_end_to_end_when_a_plugin_is_registered_with_a_built_ApiKeyAuthenticator() {
        // given
        // a custom AuthenticationStrategy rather than the apiKey( ) one-stop factory
        ApiKeyAuthenticator authenticator = new ApiKeyAuthenticator(testApiKeyLookup, ApiKeyResolver.getDEFAULT());
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/api/*", Rules.allow());
                security.rules.post("/api/*", Rules.authenticated());
                security.http.authentication = AuthenticationStrategy.sync(authenticator);
                security.http.fallback = Rules.deny();
            }));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/resource", ctx -> ctx.result("created"));
        });

        JavalinTest.test(app, (server, client) -> {
            // allow — anonymous GET allowed
            assertThat(client.get("/api/resource").code()).isEqualTo(200);
            // authenticated — no credentials
            assertThat(client.post("/api/resource", "").code()).isEqualTo(401);
            // authenticated — with valid api key
            assertThat(client.post("/api/resource", "", req -> req.header("X-Api-Key", "k-alice")).code())
                    .isEqualTo(200);
            // authenticated — with unknown key -> 401
            assertThat(client.post("/api/resource", "", req -> req.header("X-Api-Key", "k-nobody")).code())
                    .isEqualTo(401);
        });
    }

    private Javalin app() {
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/public/*", Rules.allow());
                security.rules.post("/protected/*", Rules.authenticated());
                security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
                security.http.authentication = ApiKeySecurity.apiKey(api -> {
                    api.lookup = testApiKeyLookup;
                });
                security.http.fallback = Rules.deny();
            }));
            config.routes.get("/public/info", ctx -> ctx.result("public"));
            config.routes.post("/protected/data", ctx -> ctx.result("created"));
            config.routes.get("/admin/dashboard", ctx -> ctx.result("dashboard"));
        });
    }
}
