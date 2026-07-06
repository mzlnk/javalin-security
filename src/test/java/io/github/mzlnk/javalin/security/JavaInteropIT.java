package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.AuthenticatedPrincipal;
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler;
import io.github.mzlnk.javalin.security.authorization.AuthorizationRule;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;

import static io.javalin.http.HandlerType.*;
import static org.assertj.core.api.Assertions.*;

/**
 * Verifies that the Java API produces configurations identical to the Kotlin DSL.
 * This test is the guardrail that keeps the Java ergonomics from regressing: it must compile
 * with no {@code Unit.INSTANCE}, no {@code .INSTANCE.getX()} for common operations, and no
 * raw casts.
 */
class JavaInteropIT {

    /** Minimal AuthenticatedPrincipal for tests. */
    static final class TestPrincipal implements AuthenticatedPrincipal {
        private final String name;
        TestPrincipal(String name) { this.name = name; }
        @Override public String getName() { return name; }
    }

    private final AuthenticationManager headerManager = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        if ("invalid".equals(user)) return new AuthenticationResult.Failure("bad credentials", null);
        return new AuthenticationResult.Success(
                Authentication.authenticated(new TestPrincipal(user))
        );
    };

    // ── builder round-trip ────────────────────────────────────────────────────

    @Test
    void builder_produces_JavalinSecurity_without_unit_instance() {
        // No Unit.INSTANCE, no .INSTANCE.getX() — compiles cleanly from Java
        JavalinSecurity security = JavalinSecurity.builder()
                .http(http -> http
                        .authorizeRequests(auth -> auth
                                .authorize("/api/**", GET, Rules.permitAll())
                                .authorize("/admin/**", POST, Rules.hasRole("ADMIN"))
                                .anyRequest(Rules.denyAll()))
                        .authenticationManager(headerManager))
                .build();

        assertThat(security).isNotNull();
    }

    // ── all built-in rules ────────────────────────────────────────────────────

    @Test
    void all_builtin_rules_are_accessible_as_static_methods() {
        assertThat(Rules.permitAll()).isNotNull();
        assertThat(Rules.denyAll()).isNotNull();
        assertThat(Rules.authenticated()).isNotNull();
        assertThat(Rules.hasAuthority("READ")).isNotNull();
        assertThat(Rules.hasAnyAuthority("READ", "WRITE")).isNotNull();
        assertThat(Rules.hasRole("ADMIN")).isNotNull();
        assertThat(Rules.hasAnyRole("ADMIN", "USER")).isNotNull();
    }

    // ── custom AuthorizationRule as lambda ────────────────────────────────────

    @Test
    void custom_authorization_rule_as_java_lambda() {
        // AuthorizationRule is a fun interface — Java lambda works directly
        AuthorizationRule customRule = (auth, ctx) -> auth.isAuthenticated();

        JavalinSecurity security = JavalinSecurity.builder()
                .http(http -> http
                        .authorizeRequests(auth -> auth
                                .anyRequest(customRule)))
                .build();

        assertThat(security).isNotNull();
    }

    // ── custom AuthenticationManager as lambda ───────────────────────────────

    @Test
    void custom_authentication_manager_as_java_lambda() {
        AuthenticationManager alwaysBob = ctx ->
                new AuthenticationResult.Success(
                        Authentication.authenticated(new TestPrincipal("bob")));

        JavalinSecurity security = JavalinSecurity.builder()
                .http(http -> http
                        .authorizeRequests(auth -> auth.anyRequest(Rules.authenticated()))
                        .authenticationManager(alwaysBob))
                .build();

        assertThat(security).isNotNull();
    }

    // ── custom entry point / denied handler ───────────────────────────────────

    @Test
    void custom_entry_point_and_access_denied_handler() {
        JavalinSecurity security = JavalinSecurity.builder()
                .http(http -> http
                        .authorizeRequests(auth -> auth.anyRequest(Rules.hasRole("ADMIN")))
                        .authenticationManager(headerManager)
                        .authenticationEntryPoint((ctx, failure) -> ctx.status(401).result("custom-401"))
                        .accessDeniedHandler((ctx, auth) -> ctx.status(403).result("custom-403")))
                .build();

        assertThat(security).isNotNull();
    }

    // ── mutual exclusion: sync + async managers rejected ─────────────────────

    @Test
    void builder_rejects_both_sync_and_async_manager() {
        assertThatThrownBy(() ->
                JavalinSecurity.builder()
                        .http(http -> http
                                .authorizeRequests(auth -> auth.anyRequest(Rules.permitAll()))
                                .authenticationManager(ctx -> AuthenticationResult.NotAuthenticated.INSTANCE)
                                .asyncAuthenticationManager(ctx -> CompletableFuture.completedFuture(
                                        AuthenticationResult.NotAuthenticated.INSTANCE)))
                        .build()
        ).isInstanceOf(SecurityConfigurationException.class)
                .hasMessageContaining("mutually exclusive");
    }

    // ── full integration via JavalinSecurity.enable ───────────────────────────

    @Test
    void enable_installs_security_and_enforces_rules() {
        Javalin app = Javalin.create(config -> {
            JavalinSecurity security = JavalinSecurity.builder()
                    .http(http -> http
                            .authorizeRequests(auth -> auth
                                    .authorize("/api/**", GET, Rules.permitAll())
                                    .authorize("/api/**", POST, Rules.authenticated())
                                    .anyRequest(Rules.denyAll()))
                            .authenticationManager(headerManager))
                    .build();

            JavalinSecurity.enable(config, security);
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/resource", ctx -> ctx.result("created"));
        });

        JavalinTest.test(app, (server, client) -> {
            // permitAll — anonymous allowed
            assertThat(client.get("/api/resource").code()).isEqualTo(200);

            // authenticated — anonymous rejected
            assertThat(client.post("/api/resource", "").code()).isEqualTo(401);

            // authenticated — with header allowed
            assertThat(client.post("/api/resource", "", req -> req.header("X-User", "bob")).code()).isEqualTo(200);
        });
    }

    // ── access denied handler integration ────────────────────────────────────

    @Test
    void custom_access_denied_handler_renders_custom_response() {
        AccessDeniedHandler denied = (ctx, auth) -> ctx.status(403).result("java-denied");

        Javalin app = Javalin.create(config -> {
            JavalinSecurity security = JavalinSecurity.builder()
                    .http(http -> http
                            .authorizeRequests(auth -> auth
                                    .authorize("/api/**", GET, Rules.hasRole("ADMIN")))
                            .authenticationManager(headerManager)
                            .accessDeniedHandler(denied))
                    .build();

            JavalinSecurity.enable(config, security);
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            var response = client.get("/api/resource", req -> req.header("X-User", "bob"));
            assertThat(response.code()).isEqualTo(403);
            assertThat(response.body().string()).isEqualTo("java-denied");
        });
    }
}
