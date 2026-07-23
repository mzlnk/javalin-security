package io.github.mzlnk.javalin.security.jwt

import io.javalin.security.RouteRole
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtRolesMapperTest {
    private enum class Role : RouteRole { ADMIN, USER }

    private val roleOf: (String) -> RouteRole? = { name -> Role.entries.find { it.name == name } }

    @Test
    fun `noRoles returns empty set for any token`() {
        val mapper = JwtRolesMapper.noRoles()
        assertThat(mapper.map(jwt(mapOf("roles" to listOf("ADMIN"))))).isEmpty()
        assertThat(mapper.map(jwt(emptyMap()))).isEmpty()
    }

    @Test
    fun `fromClaim returns single-element set when claim is a string`() {
        val mapper = JwtRolesMapper.fromClaim("role", roleOf)
        assertThat(mapper.map(jwt(mapOf("role" to "ADMIN")))).containsExactly(Role.ADMIN)
    }

    @Test
    fun `fromClaim returns set when claim is a list of strings`() {
        val mapper = JwtRolesMapper.fromClaim("roles", roleOf)
        assertThat(mapper.map(jwt(mapOf("roles" to listOf("ADMIN", "USER"))))).containsExactlyInAnyOrder(Role.ADMIN, Role.USER)
    }

    @Test
    fun `fromClaim returns empty set when claim is absent`() {
        val mapper = JwtRolesMapper.fromClaim("roles", roleOf)
        assertThat(mapper.map(jwt(emptyMap()))).isEmpty()
    }

    @Test
    fun `fromClaim returns empty set when claim is of unexpected type`() {
        val mapper = JwtRolesMapper.fromClaim("roles", roleOf)
        assertThat(mapper.map(jwt(mapOf("roles" to 42)))).isEmpty()
    }

    @Test
    fun `fromClaim filters null elements from list`() {
        val mapper = JwtRolesMapper.fromClaim("roles", roleOf)
        assertThat(mapper.map(jwt(mapOf("roles" to listOf("ADMIN", null, "USER"))))).containsExactlyInAnyOrder(Role.ADMIN, Role.USER)
    }

    @Test
    fun `fromClaim drops names for which roleOf returns null`() {
        val mapper = JwtRolesMapper.fromClaim("roles", roleOf)
        assertThat(mapper.map(jwt(mapOf("roles" to listOf("ADMIN", "UNKNOWN"))))).containsExactly(Role.ADMIN)
    }

    @Test
    fun `fromScope splits space-delimited scope claim`() {
        val scopeRoleOf: (String) -> RouteRole? = { scope ->
            when (scope) {
                "read:orders" -> Role.USER
                "write:orders" -> Role.ADMIN
                else -> null
            }
        }
        val mapper = JwtRolesMapper.fromScope(scopeRoleOf)
        assertThat(mapper.map(jwt(mapOf("scope" to "read:orders write:orders"))))
            .containsExactlyInAnyOrder(Role.USER, Role.ADMIN)
    }

    @Test
    fun `fromScope returns empty set when scope claim is absent`() {
        val mapper = JwtRolesMapper.fromScope(roleOf)
        assertThat(mapper.map(jwt(emptyMap()))).isEmpty()
    }

    @Test
    fun `fromScope returns empty set when scope is blank`() {
        val mapper = JwtRolesMapper.fromScope(roleOf)
        assertThat(mapper.map(jwt(mapOf("scope" to "   ")))).isEmpty()
    }

    @Test
    fun `fromScope handles single scope token`() {
        val mapper = JwtRolesMapper.fromScope { scope -> if (scope == "admin") Role.ADMIN else null }
        assertThat(mapper.map(jwt(mapOf("scope" to "admin")))).containsExactly(Role.ADMIN)
    }

    private fun jwt(claims: Map<String, Any?>) = SimpleDecodedJwt(subject = "user", claims = claims)
}
