package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpSession
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.io.Serializable

class HttpSessionManagerTest {
    private enum class Role : RouteRole { USER }

    private data class Principal(
        override val name: String,
    ) : Identity, Serializable

    private data class NonSerializablePrincipal(
        override val name: String,
    ) : Identity

    @Test
    fun `validate returns null when no session details attribute exists`() {
        val context: Context = mockk {
            every { sessionAttribute<SessionDetails>(HttpSessionManager.DEFAULT_ATTRIBUTE_KEY) } returns null
        }

        val manager = HttpSessionManager.of()

        assertThat(manager.validate(context)).isNull()
    }

    @Test
    fun `validate returns the stored session details`() {
        val details = SessionDetails(Principal(name = "alice"), roles = setOf(Role.USER))
        val context: Context = mockk {
            every { sessionAttribute<SessionDetails>(HttpSessionManager.DEFAULT_ATTRIBUTE_KEY) } returns details
        }

        val manager = HttpSessionManager.of()

        assertThat(manager.validate(context)).isSameAs(details)
    }

    @Test
    fun `validate reads from custom attributeKey`() {
        val details = SessionDetails(Principal(name = "bob"))
        val context: Context = mockk {
            every { sessionAttribute<SessionDetails>("custom.principal") } returns details
        }

        val manager = HttpSessionManager.builder().attributeKey("custom.principal").build()

        assertThat(manager.validate(context)).isSameAs(details)
    }

    @Test
    fun `create ensures a session, rotates the id, and writes the session details attribute`() {
        val details = SessionDetails(Principal(name = "alice"))
        val request: HttpServletRequest = mockk {
            every { getSession(true) } returns mockk()
            every { changeSessionId() } returns "new-id"
        }
        val context: Context = mockk {
            every { req() } returns request
            justRun { sessionAttribute(HttpSessionManager.DEFAULT_ATTRIBUTE_KEY, details) }
        }

        val manager = HttpSessionManager.of()

        manager.create(context, details)

        verify(exactly = 1) { request.getSession(true) }
        verify(exactly = 1) { request.changeSessionId() }
        verify(exactly = 1) {
            context.sessionAttribute(HttpSessionManager.DEFAULT_ATTRIBUTE_KEY, details)
        }
    }

    @Test
    fun `create does not rotate the session id when rotateSessionIdOnCreate is disabled`() {
        val details = SessionDetails(Principal(name = "alice"))
        val request: HttpServletRequest = mockk {
            every { getSession(true) } returns mockk()
        }
        val context: Context = mockk {
            every { req() } returns request
            justRun { sessionAttribute("k", details) }
        }

        val manager = HttpSessionManager.builder()
            .attributeKey("k")
            .rotateSessionIdOnCreate(false)
            .build()

        manager.create(context, details)

        verify(exactly = 0) { request.changeSessionId() }
    }

    @Test
    fun `create rejects a non-Serializable identity with a descriptive error`() {
        val manager = HttpSessionManager.of()
        val context: Context = mockk()

        assertThatThrownBy {
            manager.create(context, SessionDetails(NonSerializablePrincipal("alice")))
        }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("Serializable")
    }

    @Test
    fun `invalidate is a no-op when there is no active session`() {
        val request: HttpServletRequest = mockk {
            every { getSession(false) } returns null
        }
        val context: Context = mockk {
            every { req() } returns request
        }

        val manager = HttpSessionManager.of()

        manager.invalidate(context)

        verify(exactly = 1) { request.getSession(false) }
    }

    @Test
    fun `invalidate clears the attribute and invalidates the session by default`() {
        val session: HttpSession = mockk {
            justRun { removeAttribute(HttpSessionManager.DEFAULT_ATTRIBUTE_KEY) }
            justRun { invalidate() }
        }
        val request: HttpServletRequest = mockk {
            every { getSession(false) } returns session
        }
        val context: Context = mockk {
            every { req() } returns request
        }

        val manager = HttpSessionManager.of()

        manager.invalidate(context)

        verify(exactly = 1) { session.removeAttribute(HttpSessionManager.DEFAULT_ATTRIBUTE_KEY) }
        verify(exactly = 1) { session.invalidate() }
    }

    @Test
    fun `invalidate does not call invalidate() when invalidateSessionOnDestroy is disabled`() {
        val session: HttpSession = mockk {
            justRun { removeAttribute("k") }
        }
        val request: HttpServletRequest = mockk {
            every { getSession(false) } returns session
        }
        val context: Context = mockk {
            every { req() } returns request
        }

        val manager = HttpSessionManager.builder()
            .attributeKey("k")
            .invalidateSessionOnDestroy(false)
            .build()

        manager.invalidate(context)

        verify(exactly = 1) { session.removeAttribute("k") }
        verify(exactly = 0) { session.invalidate() }
    }

    @Test
    fun `invalidate swallows IllegalStateException when the session is already invalidated`() {
        val session: HttpSession = mockk {
            every { removeAttribute(HttpSessionManager.DEFAULT_ATTRIBUTE_KEY) } throws IllegalStateException("already invalidated")
        }
        val request: HttpServletRequest = mockk {
            every { getSession(false) } returns session
        }
        val context: Context = mockk {
            every { req() } returns request
        }

        val manager = HttpSessionManager.of()

        manager.invalidate(context)
    }
}
