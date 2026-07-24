package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.javalin.config.JavalinState
import io.javalin.http.HandlerType.GET
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

class JavalinSecurityConfigurationTest {
    @Test
    fun `should allow a sync authentication strategy on its own`() {
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authentication = authenticationStrategy(Authenticator { AuthenticationResult.NotAuthenticated })
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should allow an async authentication strategy on its own`() {
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authentication = asyncAuthenticationStrategy(
                        { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) },
                    )
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should keep only the last assigned authentication strategy, with no exception`() {
        var lastAuthenticatorInvoked: String? = null
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authentication = authenticationStrategy(
                        Authenticator {
                            lastAuthenticatorInvoked = "first"
                            AuthenticationResult.NotAuthenticated
                        },
                    )
                    http.authentication = authenticationStrategy(
                        Authenticator {
                            lastAuthenticatorInvoked = "second"
                            AuthenticationResult.NotAuthenticated
                        },
                    )
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should keep only the last assigned unauthorizedHandler, with no exception`() {
        val first = UnauthorizedHandler.DEFAULT
        val second = UnauthorizedHandler { _, _ -> }
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authentication = authenticationStrategy(unauthorizedHandler = first)
                    http.authentication = authenticationStrategy(unauthorizedHandler = second)
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should keep only the last assigned fallback rule, with no exception`() {
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.rules { r ->
                        r.fallback = Rules.allow()
                        r.fallback = Rules.deny()
                    }
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should accumulate rule entries across repeated rules calls`() {
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.rules { r -> r.add("/api/one", GET, Rules.allow()) }
                    http.rules { r -> r.add("/api/two", GET, Rules.allow()) }
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should accumulate configuration across repeated calls to the top-level http block`() {
        assertThatCode {
            start { security ->
                security.http { http -> http.rules { r -> r.add("/api/one", GET, Rules.allow()) } }
                security.http { http -> http.rules { r -> r.add("/api/two", GET, Rules.allow()) } }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should reject an empty allowedOrigins collection at startup`() {
        assertThatThrownBy {
            start { security ->
                security.ws { ws -> ws.allowedOrigins = emptyList() }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("empty")
    }

    @Test
    fun `should reject an allowedOrigins collection containing blank entries at startup`() {
        assertThatThrownBy {
            start { security ->
                security.ws { ws -> ws.allowedOrigins = listOf("https://ok.example.com", "  ") }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("blank")
    }

    @Test
    fun `should keep only the last assigned allowedOrigins value, with no exception`() {
        assertThatCode {
            start { security ->
                security.ws { ws ->
                    ws.allowedOrigins = listOf("https://first.example.com")
                    ws.allowedOrigins = listOf("https://second.example.com")
                }
            }
        }.doesNotThrowAnyException()
    }

    /** Builds a fresh [JavalinSecurityPlugin] and runs its startup wiring/validation without booting a real server. */
    private fun start(configure: (JavalinSecurityPlugin.Config) -> Unit) {
        JavalinSecurityPlugin { configure(it) }.onStart(JavalinState())
    }
}
