package io.github.mzlnk.javalin.security.opaquetoken

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.Identity
import io.github.mzlnk.javalin.security.common.token.TokenResolver
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class OpaqueTokenAuthenticatorTest {
    private enum class Role : RouteRole { USER, ADMIN }

    private data class Principal(
        override val name: String,
        override val roles: Set<RouteRole> = emptySet(),
    ) : Identity

    private val now = Instant.parse("2026-01-15T12:00:00Z")
    private val fixedClock = Clock.fixed(now, ZoneOffset.UTC)

    private val alice = TokenRecord(
        identity = Principal(name = "alice", roles = setOf(Role.USER, Role.ADMIN)),
        expiresAt = now.plusSeconds(3600),
    )

    private val tokenLookup = OpaqueTokenLookup { rawToken ->
        when (rawToken) {
            "t-valid" -> alice
            "t-expired" -> alice.copy(expiresAt = now.minusSeconds(1))
            "t-exact" -> alice.copy(expiresAt = now)
            "t-no-expiry" -> alice.copy(expiresAt = null)
            "t-noroles" -> TokenRecord(identity = Principal(name = "anon"))
            else -> null
        }
    }

    @Test
    fun `should return NotAuthenticated when Authorization header is absent`() {
        val authenticator = OpaqueTokenAuthenticator.of(tokenLookup)
        val result = authenticator.authenticate(ctx(null))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return NotAuthenticated when Authorization header is blank`() {
        val authenticator = OpaqueTokenAuthenticator.of(tokenLookup)
        val result = authenticator.authenticate(ctx("   "))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return NotAuthenticated when Authorization header is missing Bearer prefix`() {
        val authenticator = OpaqueTokenAuthenticator.of(tokenLookup)
        val result = authenticator.authenticate(ctx("Basic d-user:pass"))
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    @Test
    fun `should return Failure when token is unknown`() {
        val authenticator = OpaqueTokenAuthenticator.of(tokenLookup)
        val result = authenticator.authenticate(ctx("Bearer t-unknown"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
        assertThat((result as AuthenticationResult.Failure).message).isEqualTo("invalid token")
    }

    @Test
    fun `should return Failure when token is expired`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .clock(fixedClock)
            .build()
        val result = authenticator.authenticate(ctx("Bearer t-expired"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
        assertThat((result as AuthenticationResult.Failure).message).isEqualTo("token expired")
    }

    @Test
    fun `should return Failure when expiresAt equals clock instant`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .clock(fixedClock)
            .build()
        val result = authenticator.authenticate(ctx("Bearer t-exact"))

        assertThat(result).isInstanceOf(AuthenticationResult.Failure::class.java)
        assertThat((result as AuthenticationResult.Failure).message).isEqualTo("token expired")
    }

    @Test
    fun `should return Success with the looked-up identity when token is valid`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .clock(fixedClock)
            .build()
        val result = authenticator.authenticate(ctx("Bearer t-valid"))

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
        val success = result as AuthenticationResult.Success
        assertThat(success.authentication.isAuthenticated).isTrue()
        assertThat(success.authentication.identity).isInstanceOf(Principal::class.java)

        val identity = success.authentication.identity as Principal
        assertThat(identity.name).isEqualTo("alice")
    }

    @Test
    fun `should return Success when expiresAt is null`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .clock(fixedClock)
            .build()
        val result = authenticator.authenticate(ctx("Bearer t-no-expiry"))

        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should populate roles from the looked-up details`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .clock(fixedClock)
            .build()
        val result = authenticator.authenticate(ctx("Bearer t-valid")) as AuthenticationResult.Success

        assertThat(result.authentication.roles).containsExactlyInAnyOrder(Role.USER, Role.ADMIN)
    }

    @Test
    fun `should return empty roles when the looked-up details have none`() {
        val authenticator = OpaqueTokenAuthenticator.of(tokenLookup)
        val result = authenticator.authenticate(ctx("Bearer t-noroles")) as AuthenticationResult.Success

        assertThat(result.authentication.roles).isEmpty()
    }

    @Test
    fun `builder produces a functional authenticator`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .resolver(TokenResolver.DEFAULT)
            .clock(fixedClock)
            .build()

        val result = authenticator.authenticate(ctx("Bearer t-valid"))
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should authenticate from a cookie when a cookie resolver is configured`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .resolver(TokenResolver.cookie("session"))
            .clock(fixedClock)
            .build()

        val cookieCtx: Context = mockk {
            every { cookie("session") } returns "t-valid"
        }

        val result = authenticator.authenticate(cookieCtx)
        assertThat(result).isInstanceOf(AuthenticationResult.Success::class.java)
    }

    @Test
    fun `should return NotAuthenticated when cookie resolver finds no cookie`() {
        val authenticator = OpaqueTokenAuthenticator.builder(tokenLookup)
            .resolver(TokenResolver.cookie("session"))
            .build()

        val cookieCtx: Context = mockk {
            every { cookie("session") } returns null
        }

        val result = authenticator.authenticate(cookieCtx)
        assertThat(result).isEqualTo(AuthenticationResult.NotAuthenticated)
    }

    private fun ctx(authorizationHeader: String?): Context = mockk {
        every { header("Authorization") } returns authorizationHeader
    }
}
