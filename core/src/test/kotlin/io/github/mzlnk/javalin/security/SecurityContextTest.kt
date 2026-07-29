package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class SecurityContextTest {

    @Test
    fun `identity returns the authenticated identity`() {
        // given
        val context = securityContext(Authentication.authenticated(TestIdentity("bob")))

        // when / then
        assertThat(context.identity<TestIdentity>().name).isEqualTo("bob")
        assertThat(context.identity(TestIdentity::class.java).name).isEqualTo("bob")
    }

    @Test
    fun `identity throws when the caller is unauthenticated`() {
        // given
        val context = securityContext(Authentication.unauthenticated())

        // when / then
        assertThatThrownBy { context.identity<TestIdentity>() }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining("identityOrNull")
        assertThatThrownBy { context.identity(TestIdentity::class.java) }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining("identityOrNull")
    }

    @Test
    fun `identityOrNull returns null when the caller is unauthenticated`() {
        // given
        val context = securityContext(Authentication.unauthenticated())

        // when / then
        assertThat(context.identityOrNull<TestIdentity>()).isNull()
        assertThat(context.identityOrNull(TestIdentity::class.java)).isNull()
    }

    @Test
    fun `identityOrNull returns the authenticated identity`() {
        // given
        val context = securityContext(Authentication.authenticated(TestIdentity("alice")))

        // when / then
        assertThat(context.identityOrNull<TestIdentity>()!!.name).isEqualTo("alice")
        assertThat(context.identityOrNull(TestIdentity::class.java)!!.name).isEqualTo("alice")
    }

    @Test
    fun `identity throws ClassCastException when the identity type does not match`() {
        // given
        val context = securityContext(Authentication.authenticated(TestIdentity("bob")))

        // when / then
        assertThatThrownBy { context.identity(OtherIdentity::class.java) }
            .isInstanceOf(ClassCastException::class.java)
    }

    private fun securityContext(authentication: Authentication): SecurityContext {
        val ctx = mockk<Context>()
        every { ctx.attribute<Authentication>(JavalinSecurityPlugin.AUTHENTICATION_ATTRIBUTE) } returns authentication
        return SecurityContext(ctx)
    }

    private data class OtherIdentity(override val name: String) : io.github.mzlnk.javalin.security.authentication.Identity
}
