package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtAuthenticatorTest {

    private enum class Role : RouteRole { ADMIN, USER }

    private val roleOf: (String) -> RouteRole? = { name -> Role.entries.find { it.name == name } }

    private val validToken = "valid.jwt.token"
    private val decodedJwt = SimpleDecodedJwt(subject = "alice", claims = mapOf("sub" to "alice"))
    private val verification = JwtVerification.of(JwtKeySource.secret("test-secret"))

    private val successDecoder = JwtDecoder { _, _ -> decodedJwt }
    private val failingDecoder = JwtDecoder { _, _ -> throw IllegalArgumentException("expired token") }

    private fun ctx(authHeader: String?): Context = mockk {
        every { header("Authorization") } returns authHeader
    }

    // ── NotAuthenticated ──────────────────────────────────────────────────────

    @Test
    fun `should return NotAuthenticated when Authorization header is absent`() {
        val manager = JwtAuthenticator.of(successDecoder, verification)
        val result = manager.authenticate(ctx(null))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return NotAuthenticated when Authorization header has no Bearer scheme`() {
        val manager = JwtAuthenticator.of(successDecoder, verification)
        val result = manager.authenticate(ctx("Basic dXNlcjpwYXNz"))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    // ── Success ───────────────────────────────────────────────────────────────

    @Test
    fun `should return Success with JwtPrincipal when decoder succeeds`() {
        val manager = JwtAuthenticator.of(successDecoder, verification)
        val result = manager.authenticate(ctx("Bearer $validToken"))

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
        val success = result as AuthenticationResult.Success
        assertThat(success.authentication.isAuthenticated).isTrue()
        assertThat(success.authentication.identity).isInstanceOf(JwtPrincipal::class.java)

        val principal = success.authentication.identity as JwtPrincipal
        assertThat(principal.name).isEqualTo("alice")
        assertThat(principal.token).isEqualTo(decodedJwt)
    }

    @Test
    fun `should populate roles from mapper`() {
        val rolesJwt = SimpleDecodedJwt(subject = "bob", claims = mapOf("roles" to listOf("ADMIN", "USER")))
        val decoderWithRoles = JwtDecoder { _, _ -> rolesJwt }

        val managerWithRoles = JwtAuthenticator.builder(decoderWithRoles, verification)
            .rolesMapper(JwtRolesMapper.fromClaim("roles", roleOf))
            .build()

        val result = managerWithRoles.authenticate(ctx("Bearer $validToken")) as AuthenticationResult.Success
        assertThat(result.authentication.roles).containsExactlyInAnyOrder(Role.ADMIN, Role.USER)
    }

    @Test
    fun `should return empty roles when no mapper is configured`() {
        val manager = JwtAuthenticator.of(successDecoder, verification)
        val result = manager.authenticate(ctx("Bearer $validToken")) as AuthenticationResult.Success
        assertThat(result.authentication.roles).isEmpty()
    }

    // ── Failure ───────────────────────────────────────────────────────────────

    @Test
    fun `should return Failure when decoder throws`() {
        val manager = JwtAuthenticator.of(failingDecoder, verification)
        val result = manager.authenticate(ctx("Bearer $validToken"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
        val failure = result as AuthenticationResult.Failure
        assertThat(failure.message).isEqualTo("expired token")
        assertThat(failure.cause).isInstanceOf(IllegalArgumentException::class.java)
    }

    // ── JwtPrincipal ──────────────────────────────────────────────────────────

    @Test
    fun `JwtPrincipal name is the token subject`() {
        val principal = JwtPrincipal(SimpleDecodedJwt(subject = "carol", claims = emptyMap()))
        assertThat(principal.name).isEqualTo("carol")
    }

    @Test
    fun `JwtPrincipal name is blank string when subject is empty`() {
        val principal = JwtPrincipal(SimpleDecodedJwt(subject = "", claims = emptyMap()))
        assertThat(principal.name).isBlank()
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    @Test
    fun `builder produces a functional manager`() {
        val manager = JwtAuthenticator.builder(successDecoder, verification)
            .rolesMapper(JwtRolesMapper.fromScope(roleOf))
            .build()

        val result = manager.authenticate(ctx("Bearer $validToken"))
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    // ── tokenResolver ─────────────────────────────────────────────────────────

    @Test
    fun `should authenticate from a cookie when a custom tokenResolver is configured`() {
        val manager = JwtAuthenticator.builder(successDecoder, verification)
            .tokenResolver(TokenResolver.cookie("access_token"))
            .build()

        val cookieCtx: Context = mockk {
            every { cookie("access_token") } returns validToken
        }

        val result = manager.authenticate(cookieCtx)
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should return NotAuthenticated when custom tokenResolver finds no token`() {
        val manager = JwtAuthenticator.builder(successDecoder, verification)
            .tokenResolver(TokenResolver.cookie("access_token"))
            .build()

        val cookieCtx: Context = mockk {
            every { cookie("access_token") } returns null
        }

        val result = manager.authenticate(cookieCtx)
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

}
