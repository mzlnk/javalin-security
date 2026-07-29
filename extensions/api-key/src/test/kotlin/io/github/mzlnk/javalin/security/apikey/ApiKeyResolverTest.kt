package io.github.mzlnk.javalin.security.apikey

import io.javalin.http.Context
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ApiKeyResolverTest {

    @Test
    fun `header DEFAULT extracts from X-Api-Key`() {
        val ctx: Context = mockk {
            every { header("X-Api-Key") } returns "k-123"
        }
        assertThat(ApiKeyResolver.DEFAULT.resolve(ctx)).isEqualTo("k-123")
    }

    @Test
    fun `header returns null when header is absent`() {
        val ctx: Context = mockk {
            every { header("X-Api-Key") } returns null
        }
        assertThat(ApiKeyResolver.header().resolve(ctx)).isNull()
    }

    @Test
    fun `header returns null when header is blank`() {
        val ctx: Context = mockk {
            every { header("X-Api-Key") } returns "   "
        }
        assertThat(ApiKeyResolver.header().resolve(ctx)).isNull()
    }

    @Test
    fun `header trims surrounding whitespace`() {
        val ctx: Context = mockk {
            every { header("X-Api-Key") } returns "  k-123  "
        }
        assertThat(ApiKeyResolver.header().resolve(ctx)).isEqualTo("k-123")
    }

    @Test
    fun `header extracts from a custom header name`() {
        val ctx: Context = mockk {
            every { header("X-App-Key") } returns "k-custom"
        }
        assertThat(ApiKeyResolver.header("X-App-Key").resolve(ctx)).isEqualTo("k-custom")
    }

    @Test
    fun `query extracts from the named query parameter`() {
        val ctx: Context = mockk {
            every { queryParam("api_key") } returns "k-query"
        }
        assertThat(ApiKeyResolver.query("api_key").resolve(ctx)).isEqualTo("k-query")
    }

    @Test
    fun `query returns null when parameter is absent`() {
        val ctx: Context = mockk {
            every { queryParam("api_key") } returns null
        }
        assertThat(ApiKeyResolver.query("api_key").resolve(ctx)).isNull()
    }

    @Test
    fun `query returns null when parameter is blank`() {
        val ctx: Context = mockk {
            every { queryParam("api_key") } returns "  "
        }
        assertThat(ApiKeyResolver.query("api_key").resolve(ctx)).isNull()
    }

    @Test
    fun `query trims surrounding whitespace`() {
        val ctx: Context = mockk {
            every { queryParam("api_key") } returns "  k-query  "
        }
        assertThat(ApiKeyResolver.query("api_key").resolve(ctx)).isEqualTo("k-query")
    }

    @Test
    fun `cookie extracts from the named cookie`() {
        val ctx: Context = mockk {
            every { cookie("api_key") } returns "k-cookie"
        }
        assertThat(ApiKeyResolver.cookie("api_key").resolve(ctx)).isEqualTo("k-cookie")
    }

    @Test
    fun `cookie returns null when cookie is absent`() {
        val ctx: Context = mockk {
            every { cookie("api_key") } returns null
        }
        assertThat(ApiKeyResolver.cookie("api_key").resolve(ctx)).isNull()
    }

    @Test
    fun `cookie returns null when cookie is blank`() {
        val ctx: Context = mockk {
            every { cookie("api_key") } returns "  "
        }
        assertThat(ApiKeyResolver.cookie("api_key").resolve(ctx)).isNull()
    }

    @Test
    fun `cookie trims surrounding whitespace`() {
        val ctx: Context = mockk {
            every { cookie("api_key") } returns "  k-cookie  "
        }
        assertThat(ApiKeyResolver.cookie("api_key").resolve(ctx)).isEqualTo("k-cookie")
    }
}
