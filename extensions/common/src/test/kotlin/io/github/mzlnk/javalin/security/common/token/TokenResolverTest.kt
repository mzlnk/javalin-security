package io.github.mzlnk.javalin.security.common.token

import io.javalin.http.Context
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

class TokenResolverTest {
    @Test
    fun `bearerHeader should return token when Authorization header is present with Bearer scheme`() {
        val token = TokenResolver.bearerHeader().resolve(ctxWithHeader("Bearer my.jwt.token"))
        Assertions.assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `bearerHeader should be case-insensitive for Bearer scheme`() {
        val resolver = TokenResolver.bearerHeader()
        Assertions.assertThat(resolver.resolve(ctxWithHeader("BEARER my.jwt.token"))).isEqualTo("my.jwt.token")
        Assertions.assertThat(resolver.resolve(ctxWithHeader("bearer my.jwt.token"))).isEqualTo("my.jwt.token")
        Assertions.assertThat(resolver.resolve(ctxWithHeader("Bearer my.jwt.token"))).isEqualTo("my.jwt.token")
    }

    @Test
    fun `bearerHeader should trim whitespace from the token`() {
        val token = TokenResolver.bearerHeader().resolve(ctxWithHeader("Bearer   my.jwt.token   "))
        Assertions.assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `bearerHeader should return null when Authorization header is absent`() {
        val token = TokenResolver.bearerHeader().resolve(ctxWithHeader(null))
        Assertions.assertThat(token).isNull()
    }

    @Test
    fun `bearerHeader should return null when scheme is not Bearer`() {
        val resolver = TokenResolver.bearerHeader()
        Assertions.assertThat(resolver.resolve(ctxWithHeader("Basic dXNlcjpwYXNz"))).isNull()
        Assertions.assertThat(resolver.resolve(ctxWithHeader("Digest abc123"))).isNull()
    }

    @Test
    fun `bearerHeader should return null when token portion is blank`() {
        val resolver = TokenResolver.bearerHeader()
        Assertions.assertThat(resolver.resolve(ctxWithHeader("Bearer "))).isNull()
        Assertions.assertThat(resolver.resolve(ctxWithHeader("Bearer    "))).isNull()
    }

    @Test
    fun `bearerHeader should read from a custom header name when configured`() {
        val ctx: Context = mockk {
            every { header("X-Auth-Token") } returns "Bearer my.jwt.token"
        }
        val token = TokenResolver.bearerHeader("X-Auth-Token").resolve(ctx)
        Assertions.assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `cookie should return the trimmed cookie value when present`() {
        val token = TokenResolver.cookie("access_token").resolve(ctxWithCookie("access_token", "  my.jwt.token  "))
        Assertions.assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `cookie should return null when the cookie is absent`() {
        val token = TokenResolver.cookie("access_token").resolve(ctxWithCookie("access_token", null))
        Assertions.assertThat(token).isNull()
    }

    @Test
    fun `cookie should return null when the cookie value is blank`() {
        val token = TokenResolver.cookie("access_token").resolve(ctxWithCookie("access_token", "   "))
        Assertions.assertThat(token).isNull()
    }

    @Test
    fun `cookie should not read a differently-named cookie`() {
        val ctx: Context = mockk {
            every { cookie("access_token") } returns "my.jwt.token"
            every { cookie("other_cookie") } returns null
        }
        val token = TokenResolver.cookie("other_cookie").resolve(ctx)
        Assertions.assertThat(token).isNull()
    }

    @Test
    fun `DEFAULT should behave like bearerHeader`() {
        val token = TokenResolver.DEFAULT.resolve(ctxWithHeader("Bearer my.jwt.token"))
        Assertions.assertThat(token).isEqualTo("my.jwt.token")
    }

    private fun ctxWithHeader(authHeader: String?): Context = mockk {
        every { header("Authorization") } returns authHeader
    }

    private fun ctxWithCookie(name: String, value: String?): Context = mockk {
        every { cookie(name) } returns value
    }
}
