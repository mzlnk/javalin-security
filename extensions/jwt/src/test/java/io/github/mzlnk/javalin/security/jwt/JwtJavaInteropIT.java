package io.github.mzlnk.javalin.security.jwt;

import io.github.mzlnk.javalin.security.JavalinSecurity;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.javalin.http.HandlerType.GET;
import static io.javalin.http.HandlerType.POST;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the JWT addon provides a clean Java API:
 * - {@link JwtAuthenticationManager} built via its {@link JwtAuthenticationManager.Builder},
 * - {@link JwtKeySource} and {@link JwtVerification} factory methods/builders callable from Java,
 * - {@link JwtAuthoritiesMapper} factory methods callable as static methods,
 * - {@link BearerChallengeUnauthorizedHandler} instantiable without generics or {@code Unit.INSTANCE},
 * - the {@code NimbusJwtDecoder} Kotlin object usable from Java as {@code NimbusJwtDecoder.INSTANCE}.
 *
 * This test is the Java-ergonomics guardrail: it must compile without raw casts, {@code Unit.INSTANCE}
 * leaking into decoder usage, or verbose Kotlin-object indirection.
 */
class JwtJavaInteropIT {

    private final JwtDecoder testDecoder = (token, verification) -> {
        if ("INVALID".equals(token)) throw new IllegalArgumentException("bad token");
        return new SimpleDecodedJwt(token, Map.of("sub", token, "roles", List.of("USER")));
    };

    private final JwtVerification testVerification = JwtVerification.of(JwtKeySource.secret("test-secret"));

    // ── JwtAuthenticationManager builder ─────────────────────────────────────

    @Test
    void manager_builder_is_fluent_from_java() {
        JwtAuthenticationManager manager = JwtAuthenticationManager.builder(testDecoder, testVerification)
                .authoritiesMapper(JwtAuthoritiesMapper.fromClaim("roles"))
                .build();

        assertThat(manager).isNotNull();
    }

    @Test
    void manager_of_factory_works_from_java() {
        JwtAuthenticationManager manager = JwtAuthenticationManager.of(testDecoder, testVerification);
        assertThat(manager).isNotNull();
    }

    // ── JwtKeySource / JwtVerification factories ──────────────────────────────

    @Test
    void key_source_factories_are_accessible_as_static_methods() {
        assertThat(JwtKeySource.secret("some-secret")).isNotNull();
        assertThat(JwtKeySource.secretBytes("some-secret".getBytes(), "HS256")).isNotNull();
        assertThat(JwtKeySource.jwks("https://auth.example.com/jwks.json")).isNotNull();
    }

    @Test
    void verification_builder_is_fluent_from_java() {
        JwtVerification verification = JwtVerification.builder(JwtKeySource.secret("some-secret"))
                .issuer("https://auth.example.com")
                .audience("my-api")
                .clockSkew(30)
                .build();

        assertThat(verification).isNotNull();
    }

    // ── NimbusJwtDecoder as a stateless Java-usable object ────────────────────

    @Test
    void nimbus_decoder_object_is_usable_from_java() {
        JwtDecoder decoder = NimbusJwtDecoder.INSTANCE;
        assertThat(decoder).isNotNull();
    }

    // ── JwtAuthoritiesMapper static factories ─────────────────────────────────

    @Test
    void all_mapper_factories_are_accessible_as_static_methods() {
        assertThat(JwtAuthoritiesMapper.noAuthorities()).isNotNull();
        assertThat(JwtAuthoritiesMapper.fromClaim("roles")).isNotNull();
        assertThat(JwtAuthoritiesMapper.fromScope()).isNotNull();
    }

    // ── BearerChallengeUnauthorizedHandler ────────────────────────────────────

    @Test
    void bearer_challenge_handler_is_instantiable_from_java() {
        BearerChallengeUnauthorizedHandler handler = BearerChallengeUnauthorizedHandler.withRealm("MyAPI");
        assertThat(handler).isNotNull();

        BearerChallengeUnauthorizedHandler defaultHandler = BearerChallengeUnauthorizedHandler.withRealm();
        assertThat(defaultHandler).isNotNull();
    }

    // ── JwtDecoder as Java lambda ─────────────────────────────────────────────

    @Test
    void jwt_decoder_can_be_expressed_as_java_lambda() {
        JwtDecoder decoder = (token, verification) -> new SimpleDecodedJwt(token, Map.of("sub", token));
        assertThat(decoder).isNotNull();
    }

    // ── JwtAuthoritiesMapper as Java lambda ───────────────────────────────────

    @Test
    void authorities_mapper_can_be_expressed_as_java_lambda() {
        JwtAuthoritiesMapper mapper = token -> java.util.Set.of("ROLE_USER");
        assertThat(mapper.map(new SimpleDecodedJwt("sub", Map.of()))).containsExactly("ROLE_USER");
    }

    // ── Full integration: JavalinSecurity.builder() + JwtAuthenticationManager ─

    @Test
    void full_integration_via_builder_works_from_java() {
        JwtAuthenticationManager manager = JwtAuthenticationManager.builder(testDecoder, testVerification)
                .authoritiesMapper(JwtAuthoritiesMapper.fromClaim("roles"))
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

            // authenticated — no token
            assertThat(client.post("/api/resource", "").code()).isEqualTo(401);

            // authenticated — with valid token
            assertThat(
                    client.post("/api/resource", "", req -> req.header("Authorization", "Bearer alice")).code()
            ).isEqualTo(200);

            // authenticated — with invalid token -> 401
            assertThat(
                    client.post("/api/resource", "", req -> req.header("Authorization", "Bearer INVALID")).code()
            ).isEqualTo(401);
        });
    }

    // ── BearerChallengeUnauthorizedHandler in builder ─────────────────────────

    @Test
    void bearer_challenge_handler_wires_via_builder() {
        JwtAuthenticationManager manager = JwtAuthenticationManager.of(testDecoder, testVerification);
        BearerChallengeUnauthorizedHandler challenge = BearerChallengeUnauthorizedHandler.withRealm("Test");

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
            assertThat(wwwAuth.get(0)).startsWith("Bearer realm=\"Test\"");
        });
    }
}
