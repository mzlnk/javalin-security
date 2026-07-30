package io.github.mzlnk.javalin.security.opaquetoken;

import io.github.mzlnk.javalin.security.authentication.Identity;
import io.javalin.security.RouteRole;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class OpaqueTokenJavaInteropTest {

    static class Principal implements Identity {
        private final String name;
        private final Set<RouteRole> roles;

        Principal(String name) {
            this(name, Set.of());
        }

        Principal(String name, Set<RouteRole> roles) {
            this.name = name;
            this.roles = roles;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Set<RouteRole> getRoles() {
            return roles;
        }
    }

    @Test
    void authenticator_builder_is_fluent_from_java() {
        OpaqueTokenLookup testLookup = rawToken ->
                "t-valid".equals(rawToken) ? new TokenRecord(new Principal("alice"), null) : null;

        OpaqueTokenAuthenticator authenticator = OpaqueTokenAuthenticator.builder(testLookup)
                .resolver(io.github.mzlnk.javalin.security.common.token.TokenResolver.getDEFAULT())
                .clock(Clock.systemUTC())
                .build();

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_of_factory_works_from_java() {
        OpaqueTokenLookup testLookup = rawToken ->
                "t-valid".equals(rawToken) ? new TokenRecord(new Principal("alice"), null) : null;

        OpaqueTokenAuthenticator authenticator = OpaqueTokenAuthenticator.of(testLookup);
        assertThat(authenticator).isNotNull();
    }

    @Test
    void opaque_token_lookup_can_be_expressed_as_java_lambda() {
        OpaqueTokenLookup lookup = rawToken -> new TokenRecord(new Principal("svc"), null);
        TokenRecord record = lookup.lookup("any");
        assertThat(record.getIdentity().getName()).isEqualTo("svc");
    }

    @Test
    void token_record_defaults_optional_fields() {
        TokenRecord record = new TokenRecord(new Principal("sub"), null);
        assertThat(record.getIdentity().getName()).isEqualTo("sub");
        assertThat(record.getIdentity().getRoles()).isEmpty();
        assertThat(record.getExpiresAt()).isNull();
    }

    @Test
    void token_record_accepts_expiry() {
        Instant expires = Instant.parse("2026-06-01T00:00:00Z");
        TokenRecord record = new TokenRecord(new Principal("alice"), expires);
        assertThat(record.getIdentity().getName()).isEqualTo("alice");
        assertThat(record.getExpiresAt()).isEqualTo(expires);
    }

    @Test
    void bearer_challenge_handler_factory_is_accessible() {
        assertThat(BearerChallengeUnauthorizedHandler.withRealm()).isNotNull();
        assertThat(BearerChallengeUnauthorizedHandler.withRealm("MyAPI")).isNotNull();
    }

    @Test
    void fixed_clock_can_be_injected_from_java() {
        Clock fixed = Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC);
        OpaqueTokenLookup testLookup = rawToken -> new TokenRecord(new Principal("alice"), null);

        OpaqueTokenAuthenticator authenticator = OpaqueTokenAuthenticator.builder(testLookup)
                .clock(fixed)
                .build();

        assertThat(authenticator).isNotNull();
    }
}
