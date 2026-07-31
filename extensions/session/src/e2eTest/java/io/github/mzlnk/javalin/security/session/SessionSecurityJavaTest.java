package io.github.mzlnk.javalin.security.session;

import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
import io.github.mzlnk.javalin.security.authentication.Identity;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.HttpClient;
import io.javalin.testtools.JavalinTest;
import io.javalin.testtools.Response;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.util.List;
import java.util.Set;

import static io.github.mzlnk.javalin.security.SecurityExtensions.identity;
import static org.assertj.core.api.Assertions.assertThat;

class SessionSecurityJavaTest {
    private enum Role implements RouteRole { USER, ADMIN }

    static class Principal implements Identity, Serializable {
        private final String name;

        Principal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    @Test
    void should_allow_anonymous_access_when_route_is_allow() {
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            assertThat(client.get("/public/info").code()).isEqualTo(200);
        });
    }

    @Test
    void should_return_401_when_authenticated_route_is_hit_without_login() {
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            assertThat(client.post("/protected/data", "").code()).isEqualTo(401);
        });
    }

    @Test
    void should_allow_access_when_authenticated_route_is_hit_after_login() {
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            String cookie = login(client, "alice", Role.USER);

            var response = client.post("/protected/data", "", req -> req.header("Cookie", cookie));

            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_return_401_after_logout() {
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            String cookie = login(client, "alice", Role.USER);

            assertThat(client.post("/logout", "", req -> req.header("Cookie", cookie)).code())
                    .isEqualTo(200);

            var response = client.post("/protected/data", "", req -> req.header("Cookie", cookie));
            assertThat(response.code()).isEqualTo(401);
        });
    }

    @Test
    void should_return_403_when_authenticated_caller_lacks_required_role() {
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            String cookie = login(client, "alice", Role.USER);

            var response = client.get("/admin/dashboard", req -> req.header("Cookie", cookie));

            assertThat(response.code()).isEqualTo(403);
        });
    }

    @Test
    void should_allow_access_when_caller_holds_required_role() {
        Javalin app = app();

        JavalinTest.test(app, (server, client) -> {
            String cookie = login(client, "admin", Role.ADMIN);

            var response = client.get("/admin/dashboard", req -> req.header("Cookie", cookie));

            assertThat(response.code()).isEqualTo(200);
        });
    }

    @Test
    void should_expose_the_user_defined_identity_on_the_context_when_the_caller_is_authenticated() {
        SessionManager sessions = HttpSessionManager.of();
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.http.authentication = SessionSecurity.session(cfg -> cfg.sessionManager = sessions);
                security.rules.post("/login", Rules.allow());
                security.http.fallback = Rules.authenticated();
            }));
            config.routes.post("/login", ctx -> {
                sessions.create(ctx, new SessionDetails(new Principal("alice"), Set.of(Role.USER)));
                ctx.result("ok");
            });
            config.routes.get("/me", ctx ->
                    ctx.result(identity(ctx, Principal.class).getName()));
        });

        JavalinTest.test(app, (server, client) -> {
            String cookie = sessionCookie(client.post("/login", ""));
            assertThat(cookie).isNotNull();

            var response = client.get("/me", req -> req.header("Cookie", cookie));

            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("alice");
        });
    }

    private Javalin app() {
        SessionManager sessions = HttpSessionManager.of();
        return Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> {
                security.rules.get("/public/*", Rules.allow());
                security.rules.post("/login", Rules.allow());
                security.rules.post("/logout", Rules.allow());
                security.rules.post("/protected/*", Rules.authenticated());
                security.rules.get("/admin/*", Rules.hasRole(Role.ADMIN));
                security.http.authentication = SessionSecurity.session(cfg -> cfg.sessionManager = sessions);
                security.http.fallback = Rules.deny();
            }));
            config.routes.get("/public/info", ctx -> ctx.result("public"));
            config.routes.post("/login", ctx -> {
                String username = ctx.queryParam("user") != null ? ctx.queryParam("user") : "alice";
                Role role = "ADMIN".equals(ctx.queryParam("role")) ? Role.ADMIN : Role.USER;
                sessions.create(ctx, new SessionDetails(new Principal(username), Set.of(role)));
                ctx.result("ok");
            });
            config.routes.post("/logout", ctx -> {
                sessions.invalidate(ctx);
                ctx.result("ok");
            });
            config.routes.post("/protected/data", ctx -> ctx.result("created"));
            config.routes.get("/admin/dashboard", ctx -> ctx.result("dashboard"));
        });
    }

    private static String login(HttpClient client, String username, Role role) {
        Response response = client.post("/login?user=" + username + "&role=" + role.name(), "");
        assertThat(response.code()).isEqualTo(200);
        String cookie = sessionCookie(response);
        assertThat(cookie).isNotNull();
        return cookie;
    }

    private static String sessionCookie(Response response) {
        List<String> setCookies = response.headers().get("Set-Cookie");
        if (setCookies == null || setCookies.isEmpty()) {
            return null;
        }
        String session = setCookies.stream()
                .filter(c -> c.regionMatches(true, 0, "JSESSIONID=", 0, "JSESSIONID=".length()))
                .findFirst()
                .orElse(setCookies.get(0));
        int semicolon = session.indexOf(';');
        return semicolon >= 0 ? session.substring(0, semicolon) : session;
    }
}
