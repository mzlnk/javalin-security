package io.github.mzlnk.javalin.security.authorization

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AntPathMatcherTest {

    @Test
    fun `should match nested segments when pattern ends with double star`() {
        // given
        val matcher = AntPathMatcher("/api/v1/**")

        // when / then
        assertThat(matcher.matches("/api/v1/users")).isTrue()
        assertThat(matcher.matches("/api/v1/users/1")).isTrue()
    }

    @Test
    fun `should match the base path when pattern ends with double star and no trailing segment`() {
        // given
        val matcher = AntPathMatcher("/api/v1/**")

        // when / then
        assertThat(matcher.matches("/api/v1")).isTrue()
        assertThat(matcher.matches("/api/v1/")).isTrue()
    }

    @Test
    fun `should not match when prefix differs from double star pattern`() {
        // given
        val matcher = AntPathMatcher("/api/v1/**")

        // when / then
        assertThat(matcher.matches("/api/v2/users")).isFalse()
    }

    @Test
    fun `should match a single segment when using single star`() {
        // given
        val matcher = AntPathMatcher("/api/*/users")

        // when / then
        assertThat(matcher.matches("/api/v1/users")).isTrue()
    }

    @Test
    fun `should not cross segment boundaries when using single star`() {
        // given
        val matcher = AntPathMatcher("/api/*/users")

        // when / then
        assertThat(matcher.matches("/api/v1/v2/users")).isFalse()
    }

    @Test
    fun `should match within a segment when star is combined with a suffix`() {
        // given
        val matcher = AntPathMatcher("/files/*.html")

        // when / then
        assertThat(matcher.matches("/files/index.html")).isTrue()
        assertThat(matcher.matches("/files/index.htm")).isFalse()
    }

    @Test
    fun `should match exactly one character when using question mark`() {
        // given
        val matcher = AntPathMatcher("/user/?")

        // when / then
        assertThat(matcher.matches("/user/a")).isTrue()
        assertThat(matcher.matches("/user/ab")).isFalse()
    }

    @Test
    fun `should match everything when pattern is root double star`() {
        // given
        val matcher = AntPathMatcher("/**")

        // when / then
        assertThat(matcher.matches("/")).isTrue()
        assertThat(matcher.matches("/anything/at/all")).isTrue()
    }
}
