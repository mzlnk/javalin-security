package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Base64

class BasicAuthenticatorTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private val alice = BasicUser(username = "alice", password = "correct-password", roles = setOf(Role.USER, Role.ADMIN))

    private val userLookup = UserLookup { username -> if (username == "alice") alice else null }

    @Test
    fun `should return NotAuthenticated when Authorization header is absent`() {
        val manager = BasicAuthenticator.of(userLookup)
        val result = manager.authenticate(ctx(null))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return NotAuthenticated when Authorization header has no Basic scheme`() {
        val manager = BasicAuthenticator.of(userLookup)
        val result = manager.authenticate(ctx("Bearer some.jwt.token"))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return Failure when Basic credentials are not valid Base64`() {
        val manager = BasicAuthenticator.of(userLookup)
        val result = manager.authenticate(ctx("Basic not-valid-base64!!!"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should return Failure when decoded credentials have no colon separator`() {
        val manager = BasicAuthenticator.of(userLookup)
        val noColon = Base64.getEncoder().encodeToString("aliceandpassword".toByteArray())
        val result = manager.authenticate(ctx("Basic $noColon"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should return Failure when username is unknown`() {
        val manager = BasicAuthenticator.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("unknown", "whatever")))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should return Failure when password does not match`() {
        val manager = BasicAuthenticator.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("alice", "wrong-password")))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should return Success with BasicAuthIdentity when credentials are valid`() {
        val manager = BasicAuthenticator.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("alice", "correct-password")))

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
        val success = result as AuthenticationResult.Success
        assertThat(success.authentication.isAuthenticated).isTrue()
        assertThat(success.authentication.identity).isInstanceOf(BasicAuthIdentity::class.java)

        val identity = success.authentication.identity as BasicAuthIdentity
        assertThat(identity.name).isEqualTo("alice")
    }

    @Test
    fun `should populate roles from the looked-up user`() {
        val manager = BasicAuthenticator.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("alice", "correct-password"))) as AuthenticationResult.Success

        assertThat(result.authentication.roles).containsExactlyInAnyOrder(Role.USER, Role.ADMIN)
    }

    @Test
    fun `should return empty roles when the looked-up user has none`() {
        val noRolesLookup = UserLookup { username -> BasicUser(username = username, password = "pw") }
        val manager = BasicAuthenticator.of(noRolesLookup)
        val result = manager.authenticate(ctx(basicHeader("bob", "pw"))) as AuthenticationResult.Success

        assertThat(result.authentication.roles).isEmpty()
    }

    @Test
    fun `builder produces a functional manager`() {
        val manager = BasicAuthenticator.builder(userLookup)
            .passwordEncoder(PasswordEncoder.noOp())
            .build()

        val result = manager.authenticate(ctx(basicHeader("alice", "correct-password")))
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should use the configured passwordEncoder for comparison`() {
        val alwaysMatches = PasswordEncoder { _, _ -> true }
        val manager = BasicAuthenticator.builder(userLookup)
            .passwordEncoder(alwaysMatches)
            .build()

        val result = manager.authenticate(ctx(basicHeader("alice", "literally-anything")))
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should authenticate from a custom header when a custom credentialsResolver is configured`() {
        val manager = BasicAuthenticator.builder(userLookup)
            .credentialsResolver(BasicCredentialsResolver.basicHeader("X-Custom-Auth"))
            .build()

        val customCtx: Context = mockk {
            every { header("X-Custom-Auth") } returns basicHeader("alice", "correct-password")
        }

        val result = manager.authenticate(customCtx)
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should return NotAuthenticated when custom credentialsResolver finds no header`() {
        val manager = BasicAuthenticator.builder(userLookup)
            .credentialsResolver(BasicCredentialsResolver.basicHeader("X-Custom-Auth"))
            .build()

        val customCtx: Context = mockk {
            every { header("X-Custom-Auth") } returns null
        }

        val result = manager.authenticate(customCtx)
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `BasicAuthIdentity name is the username`() {
        val identity = BasicAuthIdentity("carol")
        assertThat(identity.name).isEqualTo("carol")
    }

    private fun basicHeader(username: String, password: String): String =
        "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())

    private fun ctx(authHeader: String?): Context = mockk {
        every { header("Authorization") } returns authHeader
    }
}
