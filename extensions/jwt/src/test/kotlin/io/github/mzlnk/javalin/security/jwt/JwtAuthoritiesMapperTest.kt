package io.github.mzlnk.javalin.security.jwt

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtAuthoritiesMapperTest {

    private fun jwt(claims: Map<String, Any?>) = SimpleDecodedJwt(subject = "user", claims = claims)

    // ── noAuthorities ─────────────────────────────────────────────────────────

    @Test
    fun `noAuthorities returns empty set for any token`() {
        val mapper = JwtAuthoritiesMapper.noAuthorities()
        assertThat(mapper.map(jwt(mapOf("roles" to listOf("ADMIN"))))).isEmpty()
        assertThat(mapper.map(jwt(emptyMap()))).isEmpty()
    }

    // ── fromClaim (single string) ─────────────────────────────────────────────

    @Test
    fun `fromClaim returns single-element set when claim is a string`() {
        val mapper = JwtAuthoritiesMapper.fromClaim("role")
        assertThat(mapper.map(jwt(mapOf("role" to "ADMIN")))).containsExactly("ADMIN")
    }

    @Test
    fun `fromClaim returns set when claim is a list of strings`() {
        val mapper = JwtAuthoritiesMapper.fromClaim("roles")
        assertThat(mapper.map(jwt(mapOf("roles" to listOf("ADMIN", "USER"))))).containsExactlyInAnyOrder("ADMIN", "USER")
    }

    @Test
    fun `fromClaim returns empty set when claim is absent`() {
        val mapper = JwtAuthoritiesMapper.fromClaim("roles")
        assertThat(mapper.map(jwt(emptyMap()))).isEmpty()
    }

    @Test
    fun `fromClaim returns empty set when claim is of unexpected type`() {
        val mapper = JwtAuthoritiesMapper.fromClaim("roles")
        assertThat(mapper.map(jwt(mapOf("roles" to 42)))).isEmpty()
    }

    @Test
    fun `fromClaim filters null elements from list`() {
        val mapper = JwtAuthoritiesMapper.fromClaim("roles")
        assertThat(mapper.map(jwt(mapOf("roles" to listOf("ADMIN", null, "USER"))))).containsExactlyInAnyOrder("ADMIN", "USER")
    }

    // ── fromScope ─────────────────────────────────────────────────────────────

    @Test
    fun `fromScope splits space-delimited scope claim`() {
        val mapper = JwtAuthoritiesMapper.fromScope()
        assertThat(mapper.map(jwt(mapOf("scope" to "read:orders write:orders"))))
            .containsExactlyInAnyOrder("read:orders", "write:orders")
    }

    @Test
    fun `fromScope returns empty set when scope claim is absent`() {
        val mapper = JwtAuthoritiesMapper.fromScope()
        assertThat(mapper.map(jwt(emptyMap()))).isEmpty()
    }

    @Test
    fun `fromScope returns empty set when scope is blank`() {
        val mapper = JwtAuthoritiesMapper.fromScope()
        assertThat(mapper.map(jwt(mapOf("scope" to "   ")))).isEmpty()
    }

    @Test
    fun `fromScope handles single scope token`() {
        val mapper = JwtAuthoritiesMapper.fromScope()
        assertThat(mapper.map(jwt(mapOf("scope" to "admin")))).containsExactly("admin")
    }
}
