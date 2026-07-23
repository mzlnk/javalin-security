package io.github.mzlnk.javalin.security.jwt

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.security
import io.javalin.Javalin
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class JwtConfigurationTest {

    private val testDecoder = JwtDecoder { token, _ -> SimpleDecodedJwt(subject = token, claims = emptyMap()) }

    @Test
    fun `should throw SecurityConfigurationException when decoder is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http { http ->
                        http.authenticationStrategy = jwt { jwt ->
                            jwt.keySource = JwtKeySource.secret("test-secret")
                            // decoder not set — should fail
                        }
                        http.rules { r -> r.fallback = r.allow }
                    }
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("decoder")
    }

    @Test
    fun `should throw SecurityConfigurationException when keySource is not configured`() {
        assertThatThrownBy {
            Javalin.create { cfg ->
                cfg.security { security ->
                    security.http { http ->
                        http.authenticationStrategy = jwt { jwt ->
                            jwt.decoder = testDecoder
                            // keySource not set — should fail
                        }
                        http.rules { r -> r.fallback = r.allow }
                    }
                }
            }
        }.isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("keySource")
    }

}
