package io.github.mzlnk.javalin.security.apikey;

import io.github.mzlnk.javalin.security.authentication.Identity;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ApiKeyJavaInteropTest {

    static class Client implements Identity {
        private final String name;

        Client(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    @Test
    void authenticator_constructor_with_resolver_works_from_java() {
        ApiKeyLookup testLookup = rawKey ->
                "k-valid".equals(rawKey) ? new ApiKeyDetails(new Client("orders-svc")) : null;

        ApiKeyAuthenticator authenticator = new ApiKeyAuthenticator(testLookup, ApiKeyResolver.getDEFAULT());

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_single_arg_constructor_works_from_java() {
        ApiKeyLookup testLookup = rawKey ->
                "k-valid".equals(rawKey) ? new ApiKeyDetails(new Client("orders-svc")) : null;

        ApiKeyAuthenticator authenticator = new ApiKeyAuthenticator(testLookup);
        assertThat(authenticator).isNotNull();
    }

    @Test
    void api_key_lookup_can_be_expressed_as_java_lambda() {
        ApiKeyLookup lookup = rawKey -> new ApiKeyDetails(new Client("svc"), Set.of());
        ApiKeyDetails details = lookup.lookup("any");
        assertThat(details.getIdentity().getName()).isEqualTo("svc");
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
    void user_defined_identity_defaults_roles_to_empty_set() {
        Client client = new Client("svc");
        assertThat(client.getName()).isEqualTo("svc");
        assertThat(new ApiKeyDetails(client).getRoles()).isEmpty();
    }
}
