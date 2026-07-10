package io.github.mzlnk.javalin.security.jwt

import io.javalin.http.Context
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class BearerTokenResolverTest {

    private fun ctx(authHeader: String?): Context = mockk {
        every { header("Authorization") } returns authHeader
    }

    @Test
    fun `should return token when Authorization header is present with Bearer scheme`() {
        val token = BearerTokenResolver.resolve(ctx("Bearer my.jwt.token"))
        assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `should be case-insensitive for Bearer scheme`() {
        assertThat(BearerTokenResolver.resolve(ctx("BEARER my.jwt.token"))).isEqualTo("my.jwt.token")
        assertThat(BearerTokenResolver.resolve(ctx("bearer my.jwt.token"))).isEqualTo("my.jwt.token")
        assertThat(BearerTokenResolver.resolve(ctx("Bearer my.jwt.token"))).isEqualTo("my.jwt.token")
    }

    @Test
    fun `should trim whitespace from the token`() {
        val token = BearerTokenResolver.resolve(ctx("Bearer   my.jwt.token   "))
        assertThat(token).isEqualTo("my.jwt.token")
    }

    @Test
    fun `should return null when Authorization header is absent`() {
        val token = BearerTokenResolver.resolve(ctx(null))
        assertThat(token).isNull()
    }

    @Test
    fun `should return null when scheme is not Bearer`() {
        assertThat(BearerTokenResolver.resolve(ctx("Basic dXNlcjpwYXNz"))).isNull()
        assertThat(BearerTokenResolver.resolve(ctx("Digest abc123"))).isNull()
    }

    @Test
    fun `should return null when token portion is blank`() {
        assertThat(BearerTokenResolver.resolve(ctx("Bearer "))).isNull()
        assertThat(BearerTokenResolver.resolve(ctx("Bearer    "))).isNull()
    }
}
