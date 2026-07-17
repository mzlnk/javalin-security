package io.github.mzlnk.javalin.security.basicauth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PasswordEncoderTest {

    private val encoder = PasswordEncoder.noOp()

    @Test
    fun `should return true when raw and encoded passwords are equal`() {
        assertThat(encoder.matches("secret", "secret")).isTrue()
    }

    @Test
    fun `should return false when raw and encoded passwords differ`() {
        assertThat(encoder.matches("secret", "other")).isFalse()
    }

    @Test
    fun `should return false when raw password is a prefix of the encoded one`() {
        assertThat(encoder.matches("secret", "secret-extra")).isFalse()
    }

    @Test
    fun `should be case-sensitive`() {
        assertThat(encoder.matches("Secret", "secret")).isFalse()
    }

    @Test
    fun `should return true for empty passwords when both sides are empty`() {
        assertThat(encoder.matches("", "")).isTrue()
    }

}
