package io.github.mzlnk.javalin.security.basicauth;

import io.github.mzlnk.javalin.security.JavalinSecurity;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Set;

import static io.javalin.http.HandlerType.GET;
import static io.javalin.http.HandlerType.POST;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the basic-auth addon provides a clean Java API:
 * - {@link BasicAuthAuthenticationManager} built via its {@link BasicAuthAuthenticationManager.Builder},
 * - {@link UserLookup} and {@link PasswordEncoder} usable as Java lambdas/static factories,
 * - {@link BasicChallengeUnauthorizedHandler} instantiable without generics or {@code Unit.INSTANCE}.
 *
 * This test is the Java-ergonomics guardrail: it must compile without raw casts, {@code Unit.INSTANCE}
 * leaking into lookup usage, or verbose Kotlin-object indirection.
 */
class BasicAuthJavaInteropIT {

    private final UserLookup testUserLookup = username ->
            "alice".equals(username) ? new BasicUser("alice", "alice-pw", Set.of("USER")) : null;

    private static String basicHeader(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }

    // ── BasicAuthAuthenticationManager builder ────────────────────────────────

    @Test
    void manager_builder_is_fluent_from_java() {
        BasicAuthAuthenticationManager manager = BasicAuthAuthenticationManager.builder(testUserLookup)
                .passwordEncoder(PasswordEncoder.noOp())
                .build();

        assertThat(manager).isNotNull();
    }

    @Test
    void manager_of_factory_works_from_java() {
        BasicAuthAuthenticationManager manager = BasicAuthAuthenticationManager.of(testUserLookup);
        assertThat(manager).isNotNull();
    }

    // ── PasswordEncoder ────────────────────────────────────────────────────────

    @Test
    void no_op_password_encoder_is_accessible_as_static_method() {
        PasswordEncoder encoder = PasswordEncoder.noOp();
        assertThat(encoder.matches("secret", "secret")).isTrue();
        assertThat(encoder.matches("secret", "other")).isFalse();
    }

    @Test
    void password_encoder_can_be_expressed_as_java_lambda() {
        PasswordEncoder encoder = (raw, encoded) -> raw.equals(encoded);
        assertThat(encoder.matches("pw", "pw")).isTrue();
    }

    // ── UserLookup as Java lambda ──────────────────────────────────────────────

    @Test
    void user_lookup_can_be_expressed_as_java_lambda() {
        UserLookup lookup = username -> new BasicUser(username, "pw", Set.of("ROLE_USER"));
        BasicUser user = lookup.lookup("bob");
        assertThat(user.getUsername()).isEqualTo("bob");
        assertThat(user.getAuthorities()).containsExactly("ROLE_USER");
    }

    // ── BasicCredentialsResolver factories ─────────────────────────────────────

    @Test
    void credentials_resolver_factories_are_accessible_as_static_methods() {
        assertThat(BasicCredentialsResolver.basicHeader()).isNotNull();
        assertThat(BasicCredentialsResolver.basicHeader("X-Custom-Auth")).isNotNull();
        assertThat(BasicCredentialsResolver.getDEFAULT()).isNotNull();
    }

    // ── BasicChallengeUnauthorizedHandler ──────────────────────────────────────

    @Test
    void basic_challenge_handler_is_instantiable_from_java() {
        BasicChallengeUnauthorizedHandler handler = BasicChallengeUnauthorizedHandler.withRealm("MyAPI");
        assertThat(handler).isNotNull();

        BasicChallengeUnauthorizedHandler defaultHandler = BasicChallengeUnauthorizedHandler.withRealm();
        assertThat(defaultHandler).isNotNull();
    }

    // ── Full integration: JavalinSecurity.builder() + BasicAuthAuthenticationManager ─

    @Test
    void full_integration_via_builder_works_from_java() {
        BasicAuthAuthenticationManager manager = BasicAuthAuthenticationManager.builder(testUserLookup)
                .passwordEncoder(PasswordEncoder.noOp())
                .build();

        Javalin app = Javalin.create(config -> {
            JavalinSecurity security = JavalinSecurity.builder()
                    .http(http -> http
                            .authenticationManager(manager)
                            .authorizeRequests(auth -> auth
                                    .authorize("/api/**", GET, Rules.permitAll())
                                    .authorize("/api/**", POST, Rules.authenticated())
                                    .anyRequest(Rules.denyAll())))
                    .build();

            JavalinSecurity.enable(config, security);
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/resource", ctx -> ctx.result("created"));
        });

        JavalinTest.test(app, (server, client) -> {
            // permitAll — anonymous GET allowed
            assertThat(client.get("/api/resource").code()).isEqualTo(200);

            // authenticated — no credentials
            assertThat(client.post("/api/resource", "").code()).isEqualTo(401);

            // authenticated — with valid credentials
            assertThat(
                    client.post("/api/resource", "", req -> req.header("Authorization", basicHeader("alice", "alice-pw"))).code()
            ).isEqualTo(200);

            // authenticated — with wrong password -> 401
            assertThat(
                    client.post("/api/resource", "", req -> req.header("Authorization", basicHeader("alice", "wrong-pw"))).code()
            ).isEqualTo(401);
        });
    }

    // ── BasicChallengeUnauthorizedHandler in builder ──────────────────────────

    @Test
    void basic_challenge_handler_wires_via_builder() {
        BasicAuthAuthenticationManager manager = BasicAuthAuthenticationManager.of(testUserLookup);
        BasicChallengeUnauthorizedHandler challenge = BasicChallengeUnauthorizedHandler.withRealm("Test");

        Javalin app = Javalin.create(config -> {
            JavalinSecurity security = JavalinSecurity.builder()
                    .http(http -> http
                            .authenticationManager(manager)
                            .unauthorizedHandler(challenge)
                            .authorizeRequests(auth -> auth.anyRequest(Rules.authenticated())))
                    .build();

            JavalinSecurity.enable(config, security);
            config.routes.get("/secured", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            var response = client.get("/secured");
            assertThat(response.code()).isEqualTo(401);
            var wwwAuth = response.headers().get("WWW-Authenticate");
            assertThat(wwwAuth).isNotNull().isNotEmpty();
            assertThat(wwwAuth.get(0)).startsWith("Basic realm=\"Test\"");
        });
    }
}
