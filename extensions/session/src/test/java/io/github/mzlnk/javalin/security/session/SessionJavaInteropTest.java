package io.github.mzlnk.javalin.security.session;

import io.github.mzlnk.javalin.security.authentication.Identity;
import io.javalin.http.Context;
import io.javalin.security.RouteRole;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SessionJavaInteropTest {

    private enum Role implements RouteRole { USER, ADMIN }

    static class Principal implements Identity, Serializable {
        private final String name;

        Principal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    @Test
    void authenticator_builder_requires_a_session_manager() {
        SessionManager manager = HttpSessionManager.of();
        SessionAuthenticator authenticator = SessionAuthenticator.builder(manager).build();

        assertThat(authenticator).isNotNull();
        assertThat(authenticator.getSessionManager()).isSameAs(manager);
    }

    @Test
    void authenticator_of_factory_takes_a_session_manager() {
        SessionManager manager = HttpSessionManager.of();
        SessionAuthenticator authenticator = SessionAuthenticator.of(manager);

        assertThat(authenticator).isNotNull();
        assertThat(authenticator.getSessionManager()).isSameAs(manager);
    }

    @Test
    void http_session_manager_builder_is_fluent_from_java() {
        HttpSessionManager manager = HttpSessionManager.builder()
                .attributeKey("custom.key")
                .rotateSessionIdOnCreate(false)
                .invalidateSessionOnDestroy(false)
                .build();

        assertThat(manager).isNotNull();
    }

    @Test
    void http_session_manager_of_factory_works_from_java() {
        assertThat(HttpSessionManager.of()).isNotNull();
        assertThat(HttpSessionManager.of("custom.key")).isNotNull();
    }

    @Test
    void session_manager_can_be_implemented_as_a_java_class() {
        SessionManager custom = new SessionManager() {
            @Override
            public void create(Context context, SessionDetails details) { /* stub */ }

            @Override
            public SessionDetails validate(Context context) {
                return new SessionDetails(new Principal("alice"), Set.of(Role.USER));
            }

            @Override
            public void invalidate(Context context) { /* stub */ }
        };

        assertThat(custom.validate(null).getIdentity().getName()).isEqualTo("alice");
        assertThat(custom.validate(null).getRoles()).containsExactly(Role.USER);
    }

    @Test
    void user_defined_identity_implements_serializable_and_round_trips() {
        Principal principal = new Principal("alice");
        assertThat(principal).isInstanceOf(Serializable.class);

        byte[] bytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(principal);
            bytes = baos.toByteArray();
        } catch (Exception e) {
            throw new AssertionError(e);
        }

        Principal restored;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            restored = (Principal) ois.readObject();
        } catch (Exception e) {
            throw new AssertionError(e);
        }

        assertThat(restored.getName()).isEqualTo("alice");
    }

    @Test
    void session_details_round_trips_through_java_serialization() {
        SessionDetails details = new SessionDetails(new Principal("alice"), Set.of(Role.USER));

        byte[] bytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(details);
            bytes = baos.toByteArray();
        } catch (Exception e) {
            throw new AssertionError(e);
        }

        SessionDetails restored;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            restored = (SessionDetails) ois.readObject();
        } catch (Exception e) {
            throw new AssertionError(e);
        }

        assertThat(restored.getIdentity().getName()).isEqualTo("alice");
        assertThat(restored.getRoles()).containsExactly(Role.USER);
    }

    @Test
    void session_factory_returns_a_sync_strategy() {
        SessionManager manager = HttpSessionManager.of();
        var strategy = SessionSecurity.session(cfg -> cfg.sessionManager = manager);

        assertThat(strategy).isNotNull();
        assertThat(((SessionAuthenticator) strategy.authenticator()).getSessionManager()).isSameAs(manager);
    }
}
