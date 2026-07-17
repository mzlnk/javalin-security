package io.github.mzlnk.javalin.security.jwt

import io.javalin.http.Context
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtTokenResolverTest {

    // ── bearerHeader() ────────────────────────────────────────────────────────

    private fun ctxWithHeader(authHeader: String?): Context = mockk {
        every { header("Authorization") } returns authHeader
    }

    @Test
    fun `bearerHeader should return token when Authorization header is present with Bearer scheme`() {
        val token = JwtTokenResolver.bearerHeader().resolve(ctxWithHeader("Bearer my.jwt.token"))
        assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `bearerHeader should be case-insensitive for Bearer scheme`() {
        val resolver = JwtTokenResolver.bearerHeader()
        assertThat(resolver.resolve(ctxWithHeader("BEARER my.jwt.token"))).isEqualTo("my.jwt.token")
        assertThat(resolver.resolve(ctxWithHeader("bearer my.jwt.token"))).isEqualTo("my.jwt.token")
        assertThat(resolver.resolve(ctxWithHeader("Bearer my.jwt.token"))).isEqualTo("my.jwt.token")
    }

    @Test
    fun `bearerHeader should trim whitespace from the token`() {
        val token = JwtTokenResolver.bearerHeader().resolve(ctxWithHeader("Bearer   my.jwt.token   "))
        assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `bearerHeader should return null when Authorization header is absent`() {
        val token = JwtTokenResolver.bearerHeader().resolve(ctxWithHeader(null))
        assertThat(token).isNull()
    }

    @Test
    fun `bearerHeader should return null when scheme is not Bearer`() {
        val resolver = JwtTokenResolver.bearerHeader()
        assertThat(resolver.resolve(ctxWithHeader("Basic dXNlcjpwYXNz"))).isNull()
        assertThat(resolver.resolve(ctxWithHeader("Digest abc123"))).isNull()
    }

    @Test
    fun `bearerHeader should return null when token portion is blank`() {
        val resolver = JwtTokenResolver.bearerHeader()
        assertThat(resolver.resolve(ctxWithHeader("Bearer "))).isNull()
        assertThat(resolver.resolve(ctxWithHeader("Bearer    "))).isNull()
    }

    @Test
    fun `bearerHeader should read from a custom header name when configured`() {
        val ctx: Context = mockk {
            every { header("X-Auth-Token") } returns "Bearer my.jwt.token"
        }
        val token = JwtTokenResolver.bearerHeader("X-Auth-Token").resolve(ctx)
        assertThat(token).isEqualTo("my.jwt.token")
    }

    // ── cookie(name) ──────────────────────────────────────────────────────────

    private fun ctxWithCookie(name: String, value: String?): Context = mockk {
        every { cookie(name) } returns value
    }

    @Test
    fun `cookie should return the trimmed cookie value when present`() {
        val token = JwtTokenResolver.cookie("access_token").resolve(ctxWithCookie("access_token", "  my.jwt.token  "))
        assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `cookie should return null when the cookie is absent`() {
        val token = JwtTokenResolver.cookie("access_token").resolve(ctxWithCookie("access_token", null))
        assertThat(token).isNull()
    }

    @Test
    fun `cookie should return null when the cookie value is blank`() {
        val token = JwtTokenResolver.cookie("access_token").resolve(ctxWithCookie("access_token", "   "))
        assertThat(token).isNull()
    }

    @Test
    fun `cookie should not read a differently-named cookie`() {
        val ctx: Context = mockk {
            every { cookie("access_token") } returns "my.jwt.token"
            every { cookie("other_cookie") } returns null
        }
        val token = JwtTokenResolver.cookie("other_cookie").resolve(ctx)
        assertThat(token).isNull()
    }

    // ── DEFAULT ───────────────────────────────────────────────────────────────

    @Test
    fun `DEFAULT should behave like bearerHeader`() {
        val token = JwtTokenResolver.DEFAULT.resolve(ctxWithHeader("Bearer my.jwt.token"))
        assertThat(token).isEqualTo("my.jwt.token")
    }

}
