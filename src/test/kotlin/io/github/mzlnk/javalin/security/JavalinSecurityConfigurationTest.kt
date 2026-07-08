package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.http.authorization.AuthorizationRules
import io.javalin.http.HandlerType.GET
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

class JavalinSecurityConfigurationTest {

    // ── sync/async mutual exclusion (existing) ────────────────────────────────

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

    // ── fail-fast on double-configured single-valued slots ────────────────────

    @Test
    fun `should fail fast when authenticationManager is set twice`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    authenticationManager = { AuthenticationResult.NotAuthenticated }
                    authenticationManager = { AuthenticationResult.NotAuthenticated }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("authenticationManager")
    }

    @Test
    fun `should fail fast when unauthorizedHandler is set twice`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    unauthorizedHandler = UnauthorizedHandler.DEFAULT
                    unauthorizedHandler = UnauthorizedHandler.DEFAULT
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("unauthorizedHandler")
    }

    @Test
    fun `should fail fast when anyRequest is set twice`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    authorizeRequests {
                        anyRequest = AuthorizationRules.permitAll
                        anyRequest = AuthorizationRules.denyAll
                    }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("anyRequest")
    }

    @Test
    fun `should fail fast when the top-level http block is configured twice`() {
        assertThatThrownBy {
            javalinSecurity {
                http {
                    authorizeRequests { authorize("/api/**", GET, AuthorizationRules.permitAll) }
                }
                http {
                    authorizeRequests { authorize("/api/**", GET, AuthorizationRules.denyAll) }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("http")
    }
}
