package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator;
import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy;
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler;
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler;
import io.github.mzlnk.javalin.security.authorization.Rule;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import static io.javalin.http.HandlerType.*;
import static org.assertj.core.api.Assertions.*;

/**
 * Verifies that the Java API produces configurations identical to the Kotlin DSL — the same
 * {@code JavalinSecurityPlugin} + {@code Consumer}-configured sub-configs, no Kotlin-only
 * indirection. This test is the guardrail that keeps the Java ergonomics from regressing: it must
 * compile with no {@code Unit.INSTANCE}, no {@code .INSTANCE.getX()} for common operations, and
 * no raw casts.
 */
class JavaInteropIT {

    private enum Role implements RouteRole { ADMIN, READ, WRITE }

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
        return new AuthenticationResult.Success(
                Authentication.authenticated(new TestPrincipal(user), roles)
        );
    };

    /**
     * Builds an {@link AuthenticationStrategy.Sync} directly from Java — the way a custom
     * authentication mechanism (not provided by a companion library's {@code jwt { }} /
     * {@code basicAuth { }} factory) is wired up.
     */
    private static AuthenticationStrategy.Sync scheme(Authenticator authenticator) {
        return scheme(authenticator, UnauthorizedHandler.getDEFAULT(), ForbiddenHandler.getDEFAULT());
    }

    private static AuthenticationStrategy.Sync scheme(
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

    // ── plugin registration produces no Unit.INSTANCE / INSTANCE.getX() ───────

    @Test
    void plugin_registers_without_unit_instance_or_kotlin_singleton_getters() {
        // No Unit.INSTANCE, no .INSTANCE.getX() — compiles cleanly from Java
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authenticationStrategy = scheme(headerAuthenticator);
                http.rules(rules -> {
                    rules.add("/api/*", GET, Rules.allow());
                    rules.add("/admin/*", POST, Rules.hasRole(Role.ADMIN));
                    rules.fallback = Rules.deny();
                });
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
        });

        assertThat(app).isNotNull();
    }

    // ── all built-in rules ────────────────────────────────────────────────────

    @Test
    void all_builtin_rules_are_accessible_as_static_methods() {
        assertThat(Rules.allow()).isNotNull();
        assertThat(Rules.deny()).isNotNull();
        assertThat(Rules.authenticated()).isNotNull();
        assertThat(Rules.hasRole(Role.READ)).isNotNull();
        assertThat(Rules.hasAnyRole(Role.READ, Role.WRITE)).isNotNull();
    }

    // ── custom Rule as lambda ──────────────────────────────────────────────────

    @Test
    void custom_rule_as_java_lambda() {
        // Rule is a fun interface — Java lambda works directly
        Rule customRule = (auth, ctx) -> auth.isAuthenticated();

        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                        http.rules(rules -> rules.fallback = customRule)))));

        assertThat(app).isNotNull();
    }

    // ── custom Authenticator as lambda ───────────────────────────────────────

    @Test
    void custom_authenticator_as_java_lambda() {
        Authenticator alwaysBob = ctx ->
                new AuthenticationResult.Success(
                        Authentication.authenticated(new TestPrincipal("bob")));

        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.fallback = Rules.authenticated());
                    http.authenticationStrategy = scheme(alwaysBob);
                }))));

        assertThat(app).isNotNull();
    }

    // ── custom unauthorizedHandler / forbiddenHandler ─────────────────────────

    @Test
    void custom_unauthorized_and_forbidden_handlers() {
        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.fallback = Rules.hasRole(Role.ADMIN));
                    http.authenticationStrategy = scheme(
                            headerAuthenticator,
                            (ctx, failure) -> ctx.status(401).result("custom-401"),
                            (ctx, auth) -> ctx.status(403).result("custom-403")
                    );
                }))));

        assertThat(app).isNotNull();
    }

    // ── sync/async are mutually exclusive by construction ─────────────────────

    @Test
    void async_scheme_can_be_built_directly_from_java() {
        // AuthenticationStrategy.Async has a single abstract method — a Java lambda cannot
        // implement it directly (the interface also declares defaulted properties that are
        // abstract at the JVM level), so a small anonymous class is used, mirroring `scheme(...)`.
        AuthenticationStrategy.Async async = new AuthenticationStrategy.Async() {
            @Override
            public AsyncAuthenticator authenticator() {
                return ctx -> CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated.INSTANCE);
            }

            @Override
            public UnauthorizedHandler getUnauthorizedHandler() {
                return UnauthorizedHandler.getDEFAULT();
            }

            @Override
            public ForbiddenHandler getForbiddenHandler() {
                return ForbiddenHandler.getDEFAULT();
            }
        };

        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.fallback = Rules.allow());
                    http.authenticationStrategy = async;
                }))));

        assertThat(app).isNotNull();
    }

    // ── full integration ──────────────────────────────────────────────────────

    @Test
    void registered_plugin_enforces_rules_end_to_end() {
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> {
                    rules.add("/api/*", GET, Rules.allow());
                    rules.add("/api/*", POST, Rules.authenticated());
                    rules.fallback = Rules.deny();
                });
                http.authenticationStrategy = scheme(headerAuthenticator);
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/resource", ctx -> ctx.result("created"));
        });

        JavalinTest.test(app, (server, client) -> {
            // allow — anonymous allowed
            assertThat(client.get("/api/resource").code()).isEqualTo(200);

            // authenticated — anonymous rejected
            assertThat(client.post("/api/resource", "").code()).isEqualTo(401);

            // authenticated — with header allowed
            assertThat(client.post("/api/resource", "", req -> req.header("X-User", "bob")).code()).isEqualTo(200);
        });
    }

    // ── forbidden handler integration ────────────────────────────────────────

    @Test
    void custom_forbidden_handler_renders_custom_response() {
        ForbiddenHandler denied = (ctx, auth) -> ctx.status(403).result("java-denied");

        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> rules.add("/api/*", GET, Rules.hasRole(Role.ADMIN)));
                http.authenticationStrategy = scheme(headerAuthenticator, UnauthorizedHandler.getDEFAULT(), denied);
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            var response = client.get("/api/resource", req -> req.header("X-User", "bob"));
            assertThat(response.code()).isEqualTo(403);
            assertThat(response.body().string()).isEqualTo("java-denied");
        });
    }

    // ── ctx.with(...) context extension access ────────────────────────────────

    @Test
    void context_extension_exposes_authentication_from_java() {
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> rules.fallback = Rules.authenticated());
                http.authenticationStrategy = scheme(headerAuthenticator);
            })));
            config.routes.get("/api/me", ctx -> {
                Authentication authentication = ctx.with(JavalinSecurityPlugin.class).authentication();
                ctx.result(authentication.getIdentity().getName());
            });
        });

        JavalinTest.test(app, (server, client) -> {
            var response = client.get("/api/me", req -> req.header("X-User", "bob"));
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("bob");
        });
    }

    // ── RouteRole-first authorization from Java ───────────────────────────────

    @Test
    void route_declared_roles_are_granted_directly_from_authentication_roles_from_java() {
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                    http.authenticationStrategy = scheme(headerAuthenticator)
            )));
            config.routes.get("/admin", ctx -> ctx.result("admin-ok"), Role.ADMIN);
        });

        JavalinTest.test(app, (server, client) -> {
            assertThat(client.get("/admin").code()).isEqualTo(401);

            var response = client.get("/admin", req -> {
                req.header("X-User", "alice");
                req.header("X-Roles", "ADMIN");
            });
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("admin-ok");
        });
    }
}
