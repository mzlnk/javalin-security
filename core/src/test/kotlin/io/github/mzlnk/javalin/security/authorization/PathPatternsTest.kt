package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.javalin.config.RouterConfig
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

/**
 * Tests [compilePattern], the shared bridge from a security rule pattern to Javalin's own
 * [io.javalin.router.matcher.PathParser] - the same primitive Javalin's router uses for its own
 * routes.
 */
class PathPatternsTest {

    private val router = RouterConfig()

    @Test
    fun `should match nested segments with a single star, since Javalin wildcards cross path segments`() {
        // given: unlike the legacy Ant-style matcher, a single "*" already crosses "/" boundaries
        val parser = compilePattern("/api/v1/*", router)

        // when / then
        assertThat(parser.matches("/api/v1/users")).isTrue()
        assertThat(parser.matches("/api/v1/users/1")).isTrue()
        assertThat(parser.matches("/api/v2/users")).isFalse()
    }

    @Test
    fun `should match a no-slash path parameter`() {
        // given
        val parser = compilePattern("/api/users/{id}", router)

        // when / then
        assertThat(parser.matches("/api/users/42")).isTrue()
        assertThat(parser.matches("/api/users/42/extra")).isFalse()
    }

    @Test
    fun `should match a slash-accepting path parameter across segments`() {
        // given
        val parser = compilePattern("/files/<path>", router)

        // when / then
        assertThat(parser.matches("/files/a/b/c.txt")).isTrue()
    }

    @Test
    fun `should reject Ant-style double star with migration guidance`() {
        assertThatThrownBy { compilePattern("/api/v1/**", router) }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("**")
            .hasMessageContaining("*")
    }

    @Test
    fun `should reject Ant-style single-character wildcard with migration guidance`() {
        assertThatThrownBy { compilePattern("/user/?", router) }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("?")
    }

    @Test
    fun `should honor case-insensitive routing when configured on the router`() {
        // given
        val caseInsensitiveRouter = RouterConfig().apply { caseInsensitiveRoutes = true }
        val parser = compilePattern("/api/admin/*", caseInsensitiveRouter)

        // when / then
        assertThat(parser.matches("/API/ADMIN/x")).isTrue()
    }

    @Test
    fun `should honor ignoreTrailingSlashes when configured on the router`() {
        // given: default RouterConfig has ignoreTrailingSlashes = true
        val parser = compilePattern("/api/admin", router)

        // when / then
        assertThat(parser.matches("/api/admin")).isTrue()
        assertThat(parser.matches("/api/admin/")).isTrue()
    }

    @Test
    fun `should honor treatMultipleSlashesAsSingleSlash when configured on the router`() {
        // given
        val lenientRouter = RouterConfig().apply { treatMultipleSlashesAsSingleSlash = true }
        val parser = compilePattern("/api/admin", lenientRouter)

        // when / then
        assertThat(parser.matches("/api//admin")).isTrue()
    }
}
