package io.github.mzlnk.javalin.security.session;

import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy;
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
            public void create(Context context, SessionPrincipal principal) { /* stub */ }

            @Override
            public SessionPrincipal validate(Context context) {
                return new SessionPrincipal("alice", Set.of(Role.USER));
            }

            @Override
            public void invalidate(Context context) { /* stub */ }
        };

        assertThat(custom.validate(null).getSubject()).isEqualTo("alice");
    }

    @Test
    void session_principal_defaults_optional_fields() {
        SessionPrincipal principal = new SessionPrincipal("alice");
        assertThat(principal.getSubject()).isEqualTo("alice");
        assertThat(principal.getRoles()).isEmpty();
    }

    @Test
    void session_principal_accepts_full_constructor() {
        SessionPrincipal principal = new SessionPrincipal("alice", Set.of(Role.USER, Role.ADMIN));
        assertThat(principal.getSubject()).isEqualTo("alice");
        assertThat(principal.getRoles()).containsExactlyInAnyOrder(Role.USER, Role.ADMIN);
    }

    @Test
    void session_principal_implements_Serializable() {
        SessionPrincipal principal = new SessionPrincipal("alice", Set.of(Role.USER));
        assertThat(principal).isInstanceOf(Serializable.class);

        byte[] bytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(principal);
            bytes = baos.toByteArray();
        } catch (Exception e) {
            throw new AssertionError(e);
        }

        SessionPrincipal restored;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            restored = (SessionPrincipal) ois.readObject();
        } catch (Exception e) {
            throw new AssertionError(e);
        }

        assertThat(restored.getSubject()).isEqualTo("alice");
        assertThat(restored.getRoles()).containsExactly(Role.USER);
    }

    @Test
    void session_identity_exposes_name() {
        SessionIdentity identity = new SessionIdentity("alice");
        assertThat(identity.getName()).isEqualTo("alice");
    }

    @Test
    void session_factory_returns_a_plain_AuthenticationStrategy_Sync() {
        SessionManager manager = HttpSessionManager.of();
        AuthenticationStrategy.Sync strategy = SessionSecurity.session(cfg -> cfg.sessionManager = manager);

        assertThat(strategy).isNotNull();
        assertThat(((SessionAuthenticator) strategy.authenticator()).getSessionManager()).isSameAs(manager);
    }
}
