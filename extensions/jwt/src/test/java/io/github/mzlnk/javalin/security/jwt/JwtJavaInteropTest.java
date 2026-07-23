package io.github.mzlnk.javalin.security.jwt;

import io.javalin.security.RouteRole;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtJavaInteropTest {
    private enum Role implements RouteRole { ADMIN, USER }

    private final JwtDecoder testDecoder = (token, verification) ->
            new SimpleDecodedJwt(token, Map.of("sub", token, "roles", List.of("USER")));

    private final JwtVerification testVerification = JwtVerification.of(JwtKeySource.secret("test-secret"));

    @Test
    void authenticator_builder_is_fluent_from_java() {
        JwtAuthenticator authenticator = JwtAuthenticator.builder(testDecoder, testVerification)
                .rolesMapper(JwtRolesMapper.fromClaim("roles", JwtJavaInteropTest::roleOf))
                .build();

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_of_factory_works_from_java() {
        JwtAuthenticator authenticator = JwtAuthenticator.of(testDecoder, testVerification);
        assertThat(authenticator).isNotNull();
    }

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

    @Test
    void all_mapper_factories_are_accessible_as_static_methods() {
        assertThat(JwtRolesMapper.noRoles()).isNotNull();
        assertThat(JwtRolesMapper.fromClaim("roles", JwtJavaInteropTest::roleOf)).isNotNull();
        assertThat(JwtRolesMapper.fromScope(JwtJavaInteropTest::roleOf)).isNotNull();
    }

    @Test
    void bearer_challenge_handler_is_instantiable_from_java() {
        BearerChallengeUnauthorizedHandler handler = BearerChallengeUnauthorizedHandler.withRealm("MyAPI");
        assertThat(handler).isNotNull();

        BearerChallengeUnauthorizedHandler defaultHandler = BearerChallengeUnauthorizedHandler.withRealm();
        assertThat(defaultHandler).isNotNull();
    }

    @Test
    void jwt_decoder_can_be_expressed_as_java_lambda() {
        JwtDecoder decoder = (token, verification) -> new SimpleDecodedJwt(token, Map.of("sub", token));
        assertThat(decoder).isNotNull();
    }

    @Test
    void roles_mapper_can_be_expressed_as_java_lambda() {
        JwtRolesMapper mapper = token -> java.util.Set.of(Role.USER);
        assertThat(mapper.map(new SimpleDecodedJwt("sub", Map.of()))).containsExactly(Role.USER);
    }

    private static Role roleOf(String name) {
        for (Role role : Role.values()) {
            if (role.name().equals(name)) return role;
        }
        return null;
    }
}
