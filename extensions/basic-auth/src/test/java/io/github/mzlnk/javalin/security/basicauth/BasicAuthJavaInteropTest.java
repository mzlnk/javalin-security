package io.github.mzlnk.javalin.security.basicauth;

import io.github.mzlnk.javalin.security.authentication.Identity;
import org.junit.jupiter.api.Test;


import static org.assertj.core.api.Assertions.assertThat;

class BasicAuthJavaInteropTest {

    static class TestUser implements Identity {
        private final String name;

        TestUser(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    @Test
    void authenticator_builder_is_fluent_from_java() {
        UserLookup testUserLookup = username ->
                "alice".equals(username) ? new BasicUserDetails(new TestUser("alice"), "alice-pw") : null;

        BasicAuthenticator authenticator = BasicAuthenticator.builder(testUserLookup)
                .passwordEncoder(PasswordEncoder.noOp())
                .build();

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_of_factory_works_from_java() {
        UserLookup testUserLookup = username ->
                "alice".equals(username) ? new BasicUserDetails(new TestUser("alice"), "alice-pw") : null;

        BasicAuthenticator authenticator = BasicAuthenticator.of(testUserLookup);
        assertThat(authenticator).isNotNull();
    }

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

    @Test
    void user_lookup_can_be_expressed_as_java_lambda() {
        UserLookup lookup = username -> new BasicUserDetails(new TestUser(username), "pw");
        BasicUserDetails credentials = lookup.lookup("bob");
        assertThat(credentials.getIdentity().getName()).isEqualTo("bob");
    }

    @Test
    void credentials_resolver_factories_are_accessible_as_static_methods() {
        assertThat(BasicCredentialsResolver.basicHeader()).isNotNull();
        assertThat(BasicCredentialsResolver.basicHeader("X-Custom-Auth")).isNotNull();
        assertThat(BasicCredentialsResolver.getDEFAULT()).isNotNull();
    }

    @Test
    void basic_challenge_handler_is_instantiable_from_java() {
        BasicChallengeUnauthorizedHandler handler = BasicChallengeUnauthorizedHandler.withRealm("MyAPI");
        assertThat(handler).isNotNull();

        BasicChallengeUnauthorizedHandler defaultHandler = BasicChallengeUnauthorizedHandler.withRealm();
        assertThat(defaultHandler).isNotNull();
    }
}
