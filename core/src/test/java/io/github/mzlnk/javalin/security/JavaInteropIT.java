package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler;
import io.github.mzlnk.javalin.security.authorization.Rule;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;

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

    private enum Role implements RouteRole { ADMIN }

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        if ("invalid".equals(user)) return new AuthenticationResult.Failure("bad credentials", null);
        String authoritiesHeader = ctx.header("X-Authorities");
        java.util.Set<String> authorities = authoritiesHeader == null
                ? java.util.Set.of()
                : java.util.Set.of(authoritiesHeader.split(","));
        return new AuthenticationResult.Success(
                Authentication.authenticated(new TestPrincipal(user), authorities)
        );
    };

    // ── plugin registration produces no Unit.INSTANCE / INSTANCE.getX() ───────

    @Test
    void plugin_registers_without_unit_instance_or_kotlin_singleton_getters() {
        // No Unit.INSTANCE, no .INSTANCE.getX() — compiles cleanly from Java
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.setAuthenticator(headerAuthenticator);
                http.rules(rules -> {
                    rules.add("/api/*", GET, Rules.allow());
                    rules.add("/admin/*", POST, Rules.hasAuthority("ADMIN"));
                    rules.setFallback(Rules.deny());
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
        assertThat(Rules.hasAuthority("READ")).isNotNull();
        assertThat(Rules.hasAnyAuthority("READ", "WRITE")).isNotNull();
    }

    // ── custom Rule as lambda ──────────────────────────────────────────────────

    @Test
    void custom_rule_as_java_lambda() {
        // Rule is a fun interface — Java lambda works directly
        Rule customRule = (auth, ctx) -> auth.isAuthenticated();

        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                        http.rules(rules -> rules.setFallback(customRule))))));

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
                    http.rules(rules -> rules.setFallback(Rules.authenticated()));
                    http.setAuthenticator(alwaysBob);
                }))));

        assertThat(app).isNotNull();
    }

    // ── custom unauthorizedHandler / forbiddenHandler ─────────────────────────

    @Test
    void custom_unauthorized_and_forbidden_handlers() {
        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.setFallback(Rules.hasAuthority("ADMIN")));
                    http.setAuthenticator(headerAuthenticator);
                    http.setUnauthorizedHandler((ctx, failure) -> ctx.status(401).result("custom-401"));
                    http.setForbiddenHandler((ctx, auth) -> ctx.status(403).result("custom-403"));
                }))));

        assertThat(app).isNotNull();
    }

    // ── mutual exclusion: sync + async authenticators rejected ────────────────

    @Test
    void plugin_rejects_both_sync_and_async_authenticator() {
        // JavalinSecurityPlugin.onStart runs during Javalin.create(...) itself (plugins are
        // started once the whole create block has been applied, before create() returns), so the
        // validation failure surfaces there rather than at a later app.start() call.
        assertThatThrownBy(() -> Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.setFallback(Rules.allow()));
                    http.setAuthenticator(ctx -> AuthenticationResult.NotAuthenticated.INSTANCE);
                    http.setAsyncAuthenticator(ctx -> CompletableFuture.completedFuture(
                            AuthenticationResult.NotAuthenticated.INSTANCE));
                })))))
                .isInstanceOf(SecurityConfigurationException.class)
                .hasMessageContaining("mutually exclusive");
    }

    // ── full integration ──────────────────────────────────────────────────────

    @Test
    void registered_plugin_enforces_rules_end_to_end() {
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.rules(rules -> {
                    rules.add("/api/*", GET, Rules.allow());
                    rules.add("/api/*", POST, Rules.authenticated());
                    rules.setFallback(Rules.deny());
                });
                http.setAuthenticator(headerAuthenticator);
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
                http.rules(rules -> rules.add("/api/*", GET, Rules.hasAuthority("ADMIN")));
                http.setAuthenticator(headerAuthenticator);
                http.setForbiddenHandler(denied);
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
                http.rules(rules -> rules.setFallback(Rules.authenticated()));
                http.setAuthenticator(headerAuthenticator);
            })));
            config.routes.get("/api/me", ctx -> {
                Authentication authentication = ctx.with(JavalinSecurityPlugin.class).authentication();
                ctx.result(authentication.getPrincipal().getName());
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
    void route_declared_roles_are_resolved_via_roleMapper_from_java() {
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.setAuthenticator(headerAuthenticator);
                http.setRoleMapper((authentication, ctx) -> {
                    if (authentication.getAuthorities().contains("ADMIN")) {
                        return java.util.Set.of(Role.ADMIN);
                    }
                    return java.util.Set.of();
                });
            })));
            config.routes.get("/admin", ctx -> ctx.result("admin-ok"), Role.ADMIN);
        });

        JavalinTest.test(app, (server, client) -> {
            assertThat(client.get("/admin").code()).isEqualTo(401);

            var response = client.get("/admin", req -> {
                req.header("X-User", "alice");
                req.header("X-Authorities", "ADMIN");
            });
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).isEqualTo("admin-ok");
        });
    }
}
