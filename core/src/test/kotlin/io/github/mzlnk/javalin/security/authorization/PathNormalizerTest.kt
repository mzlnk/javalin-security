package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.PathNormalizer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * [PathNormalizer] now only strips the router's context path and fixes up the leading slash;
 * trailing-slash/duplicate-slash/case-insensitivity handling all live inside Javalin's own
 * [io.javalin.router.matcher.PathParser], driven by [io.javalin.config.RouterConfig] — see
 * [PathPatternsTest] for coverage of that behaviour.
 */
class PathNormalizerTest {

    @Test
    fun `should leave a path with no context path unchanged`() {
        val normalizer = PathNormalizer(contextPath = "")

        assertThat(normalizer.normalize("/api/v1/users")).isEqualTo("/api/v1/users")
    }

    @Test
    fun `should preserve the root path`() {
        val normalizer = PathNormalizer(contextPath = "")

        assertThat(normalizer.normalize("/")).isEqualTo("/")
    }

    @Test
    fun `should strip the runtime context path`() {
        val normalizer = PathNormalizer(contextPath = "/blog")

        assertThat(normalizer.normalize("/blog/api/v1/users")).isEqualTo("/api/v1/users")
    }

    @Test
    fun `should normalize the bare context path to the root path`() {
        val normalizer = PathNormalizer(contextPath = "/blog")

        assertThat(normalizer.normalize("/blog")).isEqualTo("/")
    }

    @Test
    fun `should preserve a leading slash when the remaining path would otherwise lose it`() {
        val normalizer = PathNormalizer(contextPath = "/blog")

        assertThat(normalizer.normalize("/blogusers")).isEqualTo("/users")
    }
}
