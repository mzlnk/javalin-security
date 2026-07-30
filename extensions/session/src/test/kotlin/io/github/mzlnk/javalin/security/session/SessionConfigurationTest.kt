package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.Serializable

class SessionConfigurationTest {

    @Test
    fun `should throw SecurityConfigurationException when sessionManager is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http.authentication = session {
                        // sessionManager not set — should fail
                    }
                    security.http.fallback = Rules.allow()
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("sessionManager")
    }

    @Test
    fun `session factory wires the supplied SessionManager into the authenticator`() {
        val custom: SessionManager = mockk(relaxed = true)

        val strategy = session { cfg -> cfg.sessionManager = custom }
        val authenticator = strategy.authenticator() as SessionAuthenticator

        assertThat(authenticator.sessionManager).isSameAs(custom)
    }

    @Test
    fun `session factory picks up custom handlers`() {
        val customUnauthorized = UnauthorizedHandler { ctx, _ -> ctx.status(401).result("nope") }
        val customForbidden = ForbiddenHandler { ctx, _ -> ctx.status(403).result("denied") }

        val strategy = session { cfg ->
            cfg.sessionManager = HttpSessionManager.of()
            cfg.unauthorizedHandler = customUnauthorized
            cfg.forbiddenHandler = customForbidden
        }

        assertThat(strategy.unauthorizedHandler).isSameAs(customUnauthorized)
        assertThat(strategy.forbiddenHandler).isSameAs(customForbidden)
    }

    @Test
    fun `session factory can be assigned to http authentication`() {
        val strategy = session { it.sessionManager = HttpSessionManager.of() }

        Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = strategy
                security.http.fallback = Rules.allow()
            }
        }
    }

    @Test
    fun `SessionPrincipal is Serializable and round-trips`() {
        val principal = SessionPrincipal(subject = "alice")
        assertThat(principal).isInstanceOf(Serializable::class.java)

        val bytes = ByteArrayOutputStream().use { baos ->
            ObjectOutputStream(baos).use { it.writeObject(principal) }
            baos.toByteArray()
        }
        val restored = ObjectInputStream(ByteArrayInputStream(bytes)).use {
            it.readObject() as SessionPrincipal
        }
        assertThat(restored.subject).isEqualTo("alice")
        assertThat(restored.roles).isEmpty()
    }

}
