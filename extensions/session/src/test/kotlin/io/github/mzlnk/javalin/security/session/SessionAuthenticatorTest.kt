package io.github.mzlnk.javalin.security.session

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Identity
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SessionAuthenticatorTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private data class Principal(
        override val name: String,
        override val roles: Set<RouteRole> = emptySet(),
    ) : Identity

    @Test
    fun `should return NotAuthenticated when SessionManager returns null`() {
        val context: Context = mockk()
        val manager: SessionManager = mockk {
            every { validate(context) } returns null
        }

        val authenticator = SessionAuthenticator.of(manager)
        val result = authenticator.authenticate(context)

        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
        verify(exactly = 1) { manager.validate(context) }
    }

    @Test
    fun `should return Success with the session identity when SessionManager returns one`() {
        val principal = Principal(name = "alice", roles = setOf(Role.USER, Role.ADMIN))
        val context: Context = mockk()
        val manager: SessionManager = mockk {
            every { validate(context) } returns principal
        }

        val authenticator = SessionAuthenticator.of(manager)
        val result = authenticator.authenticate(context)

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
        val success = result as AuthenticationResult.Success
        assertThat(success.authentication.isAuthenticated).isTrue()
        assertThat(success.authentication.identity).isInstanceOf(Principal::class.java)

        val identity = success.authentication.identity as Principal
        assertThat(identity.name).isEqualTo("alice")
        assertThat(success.authentication.roles).containsExactlyInAnyOrder(Role.USER, Role.ADMIN)
    }

    @Test
    fun `should return empty roles when the session has none`() {
        val context: Context = mockk()
        val manager: SessionManager = mockk {
            every { validate(context) } returns Principal(name = "anon")
        }

        val authenticator = SessionAuthenticator.of(manager)
        val result = authenticator.authenticate(context) as AuthenticationResult.Success

        assertThat(result.authentication.roles).isEmpty()
    }

    @Test
    fun `builder produces a functional authenticator that delegates to the given SessionManager`() {
        val principal = Principal(name = "alice", roles = setOf(Role.USER))
        val context: Context = mockk()
        val manager: SessionManager = mockk {
            every { validate(context) } returns principal
        }

        val authenticator = SessionAuthenticator.builder(manager).build()

        val result = authenticator.authenticate(context)
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should expose the SessionManager it was built with`() {
        val manager: SessionManager = mockk()
        val authenticator = SessionAuthenticator.of(manager)
        assertThat(authenticator.sessionManager).isSameAs(manager)
    }
}
