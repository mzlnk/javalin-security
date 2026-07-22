package io.github.mzlnk.javalin.security.jwt;

import io.github.mzlnk.javalin.security.JavalinSecurityPlugin;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authentication.AuthenticationScheme;
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler;
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.github.mzlnk.javalin.security.jwt.nimbus.NimbusJwtDecoder;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.javalin.http.HandlerType.GET;
import static io.javalin.http.HandlerType.POST;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the JWT addon provides a clean Java API:
 * - {@link JwtAuthenticator} built via its {@link JwtAuthenticator.Builder},
 * - {@link JwtKeySource} and {@link JwtVerification} factory methods/builders callable from Java,
 * - {@link JwtRolesMapper} factory methods callable as static methods,
 * - {@link BearerChallengeUnauthorizedHandler} instantiable without generics or {@code Unit.INSTANCE},
 * - the {@code NimbusJwtDecoder} Kotlin object usable from Java as {@code NimbusJwtDecoder.INSTANCE}.
 *
 * This test is the Java-ergonomics guardrail: it must compile without raw casts, {@code Unit.INSTANCE}
 * leaking into decoder usage, or verbose Kotlin-object indirection.
 */
class JwtJavaInteropIT {

    private enum Role implements RouteRole { ADMIN, USER }

    private static RouteRole roleOf(String name) {
        for (Role role : Role.values()) {
            if (role.name().equals(name)) return role;
        }
        return null;
    }

    private final JwtDecoder testDecoder = (token, verification) -> {
        if ("INVALID".equals(token)) throw new IllegalArgumentException("bad token");
        return new SimpleDecodedJwt(token, Map.of("sub", token, "roles", List.of("USER")));
    };

    private final JwtVerification testVerification = JwtVerification.of(JwtKeySource.secret("test-secret"));

    /** Wraps a plain {@link Authenticator} (e.g. a built {@link JwtAuthenticator}) in a minimal {@link AuthenticationScheme.Sync}. */
    private static AuthenticationScheme.Sync scheme(Authenticator authenticator) {
        return scheme(authenticator, UnauthorizedHandler.getDEFAULT(), ForbiddenHandler.getDEFAULT());
    }

    private static AuthenticationScheme.Sync scheme(
            Authenticator authenticator,
            UnauthorizedHandler unauthorizedHandler,
            ForbiddenHandler forbiddenHandler
    ) {
        return new AuthenticationScheme.Sync() {
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

    // ── JwtAuthenticator builder ──────────────────────────────────────────────

    @Test
    void authenticator_builder_is_fluent_from_java() {
        JwtAuthenticator authenticator = JwtAuthenticator.builder(testDecoder, testVerification)
                .rolesMapper(JwtRolesMapper.fromClaim("roles", JwtJavaInteropIT::roleOf))
                .build();

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_of_factory_works_from_java() {
        JwtAuthenticator authenticator = JwtAuthenticator.of(testDecoder, testVerification);
        assertThat(authenticator).isNotNull();
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

    // ── JwtRolesMapper static factories ───────────────────────────────────────

    @Test
    void all_mapper_factories_are_accessible_as_static_methods() {
        assertThat(JwtRolesMapper.noRoles()).isNotNull();
        assertThat(JwtRolesMapper.fromClaim("roles", JwtJavaInteropIT::roleOf)).isNotNull();
        assertThat(JwtRolesMapper.fromScope(JwtJavaInteropIT::roleOf)).isNotNull();
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

    // ── JwtRolesMapper as Java lambda ─────────────────────────────────────────

    @Test
    void roles_mapper_can_be_expressed_as_java_lambda() {
        JwtRolesMapper mapper = token -> java.util.Set.of(Role.USER);
        assertThat(mapper.map(new SimpleDecodedJwt("sub", Map.of()))).containsExactly(Role.USER);
    }

    // ── Full integration: JavalinSecurityPlugin + JwtAuthenticator ─────────────

    @Test
    void full_integration_via_plugin_works_from_java() {
        JwtAuthenticator authenticator = JwtAuthenticator.builder(testDecoder, testVerification)
                .rolesMapper(JwtRolesMapper.fromClaim("roles", JwtJavaInteropIT::roleOf))
                .build();

        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = scheme(authenticator);
                http.rules(rules -> {
                    rules.add("/api/*", GET, Rules.allow());
                    rules.add("/api/*", POST, Rules.authenticated());
                    rules.fallback = Rules.deny();
                });
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
            config.routes.post("/api/resource", ctx -> ctx.result("created"));
        });

        JavalinTest.test(app, (server, client) -> {
            // allow — anonymous GET allowed
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

    // ── one-stop jwt config via the JwtSecurity static method ─────────────────

    @Test
    void one_stop_jwt_config_is_callable_from_java_via_static_method() {
        // The same Consumer-based `jwt { }` block Kotlin uses — surfaced to Java as a static
        // factory method returning an AuthenticationScheme.Sync — including the bearerChallenge
        // side-effect that a standalone authenticator alone could not wire.
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = JwtSecurity.jwt(jwt -> {
                    jwt.decoder = testDecoder;
                    jwt.keySource = JwtKeySource.secret("test-secret");
                    jwt.rolesMapper = JwtRolesMapper.fromClaim("roles", JwtJavaInteropIT::roleOf);
                    jwt.bearerChallenge = true;
                    jwt.realm = "JavaTest";
                });
                http.rules(rules -> rules.fallback = Rules.authenticated());
            })));
            config.routes.get("/secured", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // anonymous → 401 with the auto-wired bearer challenge
            var unauthorized = client.get("/secured");
            assertThat(unauthorized.code()).isEqualTo(401);
            var wwwAuth = unauthorized.headers().get("WWW-Authenticate");
            assertThat(wwwAuth).isNotNull().isNotEmpty();
            assertThat(wwwAuth.get(0)).startsWith("Bearer realm=\"JavaTest\"");

            // valid token → 200
            var ok = client.get("/secured", req -> req.header("Authorization", "Bearer alice"));
            assertThat(ok.code()).isEqualTo(200);
        });
    }

    // ── BearerChallengeUnauthorizedHandler wired via plugin ────────────────────

    @Test
    void bearer_challenge_handler_wires_via_plugin() {
        JwtAuthenticator authenticator = JwtAuthenticator.of(testDecoder, testVerification);
        BearerChallengeUnauthorizedHandler challenge = BearerChallengeUnauthorizedHandler.withRealm("Test");

        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = scheme(authenticator, challenge, ForbiddenHandler.getDEFAULT());
                http.rules(rules -> rules.fallback = Rules.authenticated());
            })));
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
