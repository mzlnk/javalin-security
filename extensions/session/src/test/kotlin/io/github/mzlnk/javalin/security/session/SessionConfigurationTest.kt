package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SessionConfigurationTest {

    @Test
    fun `session factory defaults to an HttpSessionManager when sessionManager is not configured`() {
        val strategy = session { }
        val authenticator = strategy.authenticator() as SessionAuthenticator

        assertThat(authenticator.sessionManager).isInstanceOf(HttpSessionManager::class.java)
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
            cfg.unauthorizedHandler = customUnauthorized
            cfg.forbiddenHandler = customForbidden
        }

        assertThat(strategy.unauthorizedHandler).isSameAs(customUnauthorized)
        assertThat(strategy.forbiddenHandler).isSameAs(customForbidden)
    }

    @Test
    fun `session factory can be assigned to http authentication`() {
        val strategy = session { }

        Javalin.create { cfg ->
            cfg.security { security ->
                security.http.authentication = strategy
                security.http.fallback = Rules.allow()
            }
        }
    }

}
