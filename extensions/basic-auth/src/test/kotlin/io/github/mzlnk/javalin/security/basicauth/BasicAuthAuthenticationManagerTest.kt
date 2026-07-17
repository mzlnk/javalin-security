package io.github.mzlnk.javalin.security.basicauth

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.javalin.http.Context
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Base64

class BasicAuthAuthenticationManagerTest {

    private val alice = BasicUser(username = "alice", password = "correct-password", authorities = setOf("USER", "ADMIN"))
    private val userLookup = UserLookup { username -> if (username == "alice") alice else null }

    private fun basicHeader(username: String, password: String): String =
        "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())

    private fun ctx(authHeader: String?): Context = mockk {
        every { header("Authorization") } returns authHeader
    }

    // ── NotAuthenticated ──────────────────────────────────────────────────────

    @Test
    fun `should return NotAuthenticated when Authorization header is absent`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val result = manager.authenticate(ctx(null))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return NotAuthenticated when Authorization header has no Basic scheme`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val result = manager.authenticate(ctx("Bearer some.jwt.token"))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    // ── Failure: malformed credentials ────────────────────────────────────────

    @Test
    fun `should return Failure when Basic credentials are not valid Base64`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val result = manager.authenticate(ctx("Basic not-valid-base64!!!"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should return Failure when decoded credentials have no colon separator`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val noColon = Base64.getEncoder().encodeToString("aliceandpassword".toByteArray())
        val result = manager.authenticate(ctx("Basic $noColon"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    // ── Failure: unknown user / wrong password ────────────────────────────────

    @Test
    fun `should return Failure when username is unknown`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("unknown", "whatever")))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    @Test
    fun `should return Failure when password does not match`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("alice", "wrong-password")))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
    }

    // ── Success ───────────────────────────────────────────────────────────────

    @Test
    fun `should return Success with BasicAuthPrincipal when credentials are valid`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("alice", "correct-password")))

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
        val success = result as AuthenticationResult.Success
        assertThat(success.authentication.isAuthenticated).isTrue()
        assertThat(success.authentication.principal).isInstanceOf(BasicAuthPrincipal::class.java)

        val principal = success.authentication.principal as BasicAuthPrincipal
        assertThat(principal.name).isEqualTo("alice")
    }

    @Test
    fun `should populate authorities from the looked-up user`() {
        val manager = BasicAuthAuthenticationManager.of(userLookup)
        val result = manager.authenticate(ctx(basicHeader("alice", "correct-password"))) as AuthenticationResult.Success

        assertThat(result.authentication.authorities).containsExactlyInAnyOrder("USER", "ADMIN")
    }

    @Test
    fun `should return empty authorities when the looked-up user has none`() {
        val noAuthoritiesLookup = UserLookup { username -> BasicUser(username = username, password = "pw") }
        val manager = BasicAuthAuthenticationManager.of(noAuthoritiesLookup)
        val result = manager.authenticate(ctx(basicHeader("bob", "pw"))) as AuthenticationResult.Success

        assertThat(result.authentication.authorities).isEmpty()
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    @Test
    fun `builder produces a functional manager`() {
        val manager = BasicAuthAuthenticationManager.builder(userLookup)
            .passwordEncoder(PasswordEncoder.noOp())
            .build()

        val result = manager.authenticate(ctx(basicHeader("alice", "correct-password")))
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    // ── custom passwordEncoder ────────────────────────────────────────────────

    @Test
    fun `should use the configured passwordEncoder for comparison`() {
        val alwaysMatches = PasswordEncoder { _, _ -> true }
        val manager = BasicAuthAuthenticationManager.builder(userLookup)
            .passwordEncoder(alwaysMatches)
            .build()

        val result = manager.authenticate(ctx(basicHeader("alice", "literally-anything")))
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    // ── custom credentialsResolver ────────────────────────────────────────────

    @Test
    fun `should authenticate from a custom header when a custom credentialsResolver is configured`() {
        val manager = BasicAuthAuthenticationManager.builder(userLookup)
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
        val manager = BasicAuthAuthenticationManager.builder(userLookup)
            .credentialsResolver(BasicCredentialsResolver.basicHeader("X-Custom-Auth"))
            .build()

        val customCtx: Context = mockk {
            every { header("X-Custom-Auth") } returns null
        }

        val result = manager.authenticate(customCtx)
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    // ── BasicAuthPrincipal ────────────────────────────────────────────────────

    @Test
    fun `BasicAuthPrincipal name is the username`() {
        val principal = BasicAuthPrincipal("carol")
        assertThat(principal.name).isEqualTo("carol")
    }

}
