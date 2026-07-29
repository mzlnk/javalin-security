package io.github.mzlnk.javalin.security.apikey;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ApiKeyJavaInteropTest {

    @Test
    void authenticator_builder_is_fluent_from_java() {
        ApiKeyLookup testLookup = rawKey ->
                "k-valid".equals(rawKey) ? new ApiKeyPrincipal("orders-svc", Set.of()) : null;

        ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.builder(testLookup)
                .resolver(ApiKeyResolver.getDEFAULT())
                .build();

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_of_factory_works_from_java() {
        ApiKeyLookup testLookup = rawKey ->
                "k-valid".equals(rawKey) ? new ApiKeyPrincipal("orders-svc", Set.of()) : null;

        ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.of(testLookup);
        assertThat(authenticator).isNotNull();
    }

    @Test
    void api_key_lookup_can_be_expressed_as_java_lambda() {
        ApiKeyLookup lookup = rawKey -> new ApiKeyPrincipal("svc", Set.of());
        ApiKeyPrincipal principal = lookup.lookup("any");
        assertThat(principal.getName()).isEqualTo("svc");
    }

    @Test
    void resolver_factories_are_accessible_as_static_methods() {
        assertThat(ApiKeyResolver.header()).isNotNull();
        assertThat(ApiKeyResolver.header("X-App-Key")).isNotNull();
        assertThat(ApiKeyResolver.query("api_key")).isNotNull();
        assertThat(ApiKeyResolver.cookie("api_key")).isNotNull();
        assertThat(ApiKeyResolver.getDEFAULT()).isNotNull();
    }

    @Test
    void api_key_principal_defaults_roles_to_empty_set() {
        ApiKeyPrincipal principal = new ApiKeyPrincipal("svc");
        assertThat(principal.getName()).isEqualTo("svc");
        assertThat(principal.getRoles()).isEmpty();
    }
}
