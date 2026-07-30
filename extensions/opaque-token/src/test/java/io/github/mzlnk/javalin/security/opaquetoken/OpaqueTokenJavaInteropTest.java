package io.github.mzlnk.javalin.security.opaquetoken;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class OpaqueTokenJavaInteropTest {

    @Test
    void authenticator_builder_is_fluent_from_java() {
        OpaqueTokenLookup testLookup = rawToken ->
                "t-valid".equals(rawToken) ? new OpaqueTokenDetails("alice", Set.of()) : null;

        OpaqueTokenAuthenticator authenticator = OpaqueTokenAuthenticator.builder(testLookup)
                .resolver(io.github.mzlnk.javalin.security.common.token.TokenResolver.getDEFAULT())
                .clock(Clock.systemUTC())
                .build();

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_of_factory_works_from_java() {
        OpaqueTokenLookup testLookup = rawToken ->
                "t-valid".equals(rawToken) ? new OpaqueTokenDetails("alice", Set.of()) : null;

        OpaqueTokenAuthenticator authenticator = OpaqueTokenAuthenticator.of(testLookup);
        assertThat(authenticator).isNotNull();
    }

    @Test
    void opaque_token_lookup_can_be_expressed_as_java_lambda() {
        OpaqueTokenLookup lookup = rawToken -> new OpaqueTokenDetails("svc", Set.of());
        OpaqueTokenDetails details = lookup.lookup("any");
        assertThat(details.getSubject()).isEqualTo("svc");
    }

    @Test
    void opaque_token_details_defaults_optional_fields() {
        OpaqueTokenDetails details = new OpaqueTokenDetails("sub");
        assertThat(details.getSubject()).isEqualTo("sub");
        assertThat(details.getRoles()).isEmpty();
        assertThat(details.getExpiresAt()).isNull();
    }

    @Test
    void opaque_token_details_accepts_full_constructor() {
        Instant expires = Instant.parse("2026-06-01T00:00:00Z");
        OpaqueTokenDetails details = new OpaqueTokenDetails("alice", Set.of(), expires);
        assertThat(details.getSubject()).isEqualTo("alice");
        assertThat(details.getExpiresAt()).isEqualTo(expires);
    }

    @Test
    void opaque_token_identity_exposes_name() {
        OpaqueTokenIdentity identity = new OpaqueTokenIdentity("alice");
        assertThat(identity.getName()).isEqualTo("alice");
    }

    @Test
    void bearer_challenge_handler_factory_is_accessible() {
        assertThat(BearerChallengeUnauthorizedHandler.withRealm()).isNotNull();
        assertThat(BearerChallengeUnauthorizedHandler.withRealm("MyAPI")).isNotNull();
    }

    @Test
    void fixed_clock_can_be_injected_from_java() {
        Clock fixed = Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC);
        OpaqueTokenLookup testLookup = rawToken -> new OpaqueTokenDetails("alice");

        OpaqueTokenAuthenticator authenticator = OpaqueTokenAuthenticator.builder(testLookup)
                .clock(fixed)
                .build();

        assertThat(authenticator).isNotNull();
    }
}
