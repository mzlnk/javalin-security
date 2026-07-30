package io.github.mzlnk.javalin.security.apikey;

import io.github.mzlnk.javalin.security.authentication.Identity;
import io.javalin.security.RouteRole;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ApiKeyJavaInteropTest {

    static class Client implements Identity {
        private final String name;
        private final Set<RouteRole> roles;

        Client(String name) {
            this(name, Set.of());
        }

        Client(String name, Set<RouteRole> roles) {
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
    void authenticator_constructor_with_resolver_works_from_java() {
        ApiKeyLookup testLookup = rawKey ->
                "k-valid".equals(rawKey) ? new Client("orders-svc") : null;

        ApiKeyAuthenticator authenticator = new ApiKeyAuthenticator(testLookup, ApiKeyResolver.getDEFAULT());

        assertThat(authenticator).isNotNull();
    }

    @Test
    void authenticator_single_arg_constructor_works_from_java() {
        ApiKeyLookup testLookup = rawKey ->
                "k-valid".equals(rawKey) ? new Client("orders-svc") : null;

        ApiKeyAuthenticator authenticator = new ApiKeyAuthenticator(testLookup);
        assertThat(authenticator).isNotNull();
    }

    @Test
    void api_key_lookup_can_be_expressed_as_java_lambda() {
        ApiKeyLookup lookup = rawKey -> new Client("svc");
        Identity client = lookup.lookup("any");
        assertThat(client.getName()).isEqualTo("svc");
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
        assertThat(client.getRoles()).isEmpty();
    }
}
