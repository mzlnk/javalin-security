package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

class JavalinSecurityConfigurationTest {

    @Test
    fun `should fail fast when both a sync and async manager are configured`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    authenticationManager = { AuthenticationResult.NotAuthenticated }
                    asyncAuthenticationManager = { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("mutually exclusive")
    }

    @Test
    fun `should allow a sync manager on its own`() {
        assertThatCode {
            javalinSecurity {
                http {
                    authenticationManager = { AuthenticationResult.NotAuthenticated }
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should allow an async manager on its own`() {
        assertThatCode {
            javalinSecurity {
                http {
                    asyncAuthenticationManager = { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                }
            }
        }.doesNotThrowAnyException()
    }
}
