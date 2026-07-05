package io.github.mzlnk.javalin.security.authorization

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PathNormalizerTest {

    @Test
    fun `should strip a trailing slash when configured`() {
        val normalizer = PathNormalizer(ignoreTrailingSlashes = true, treatMultipleSlashesAsSingleSlash = false)

        assertThat(normalizer.normalize("/api/v1/users/", "")).isEqualTo("/api/v1/users")
        assertThat(normalizer.normalize("/api/v1/users", "")).isEqualTo("/api/v1/users")
    }

    @Test
    fun `should keep the trailing slash when not configured to ignore it`() {
        val normalizer = PathNormalizer(ignoreTrailingSlashes = false, treatMultipleSlashesAsSingleSlash = false)

        assertThat(normalizer.normalize("/api/v1/users/", "")).isEqualTo("/api/v1/users/")
    }

    @Test
    fun `should preserve the root path`() {
        val normalizer = PathNormalizer(ignoreTrailingSlashes = true, treatMultipleSlashesAsSingleSlash = false)

        assertThat(normalizer.normalize("/", "")).isEqualTo("/")
    }

    @Test
    fun `should collapse multiple slashes when configured`() {
        val normalizer = PathNormalizer(ignoreTrailingSlashes = true, treatMultipleSlashesAsSingleSlash = true)

        assertThat(normalizer.normalize("/api//v1///users", "")).isEqualTo("/api/v1/users")
    }

    @Test
    fun `should not collapse multiple slashes by default`() {
        val normalizer = PathNormalizer(ignoreTrailingSlashes = true, treatMultipleSlashesAsSingleSlash = false)

        assertThat(normalizer.normalize("/api//v1", "")).isEqualTo("/api//v1")
    }

    @Test
    fun `should strip the runtime context path`() {
        val normalizer = PathNormalizer(ignoreTrailingSlashes = true, treatMultipleSlashesAsSingleSlash = false)

        assertThat(normalizer.normalize("/blog/api/v1/users", "/blog")).isEqualTo("/api/v1/users")
        assertThat(normalizer.normalize("/blog", "/blog")).isEqualTo("/")
    }
}
