package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

class JavalinSecurityConfigurationTest {

    @Test
    fun `should fail fast when both a provider and a custom manager are configured`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    authenticationProvider { AuthenticationResult.NotAuthenticated }
                    authenticationManager { AuthenticationResult.NotAuthenticated }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("mutually exclusive")
    }

    @Test
    fun `should fail fast when both an async provider and a custom manager are configured`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    asyncAuthenticationProvider { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                    authenticationManager { AuthenticationResult.NotAuthenticated }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("mutually exclusive")
    }

    @Test
    fun `should fail fast when both sync and async providers are configured`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    authenticationProvider { AuthenticationResult.NotAuthenticated }
                    asyncAuthenticationProvider { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("mutually exclusive")
    }

    @Test
    fun `should allow a custom manager on its own`() {
        assertThatCode {
            javalinSecurity {
                http {
                    authenticationManager { AuthenticationResult.NotAuthenticated }
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should allow one or more providers on their own`() {
        assertThatCode {
            javalinSecurity {
                http {
                    authenticationProvider { AuthenticationResult.NotAuthenticated }
                    authenticationProvider { AuthenticationResult.NotAuthenticated }
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should allow one or more async providers on their own`() {
        assertThatCode {
            javalinSecurity {
                http {
                    asyncAuthenticationProvider { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                }
            }
        }.doesNotThrowAnyException()
    }
}
