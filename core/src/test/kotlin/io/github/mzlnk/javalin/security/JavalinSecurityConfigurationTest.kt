package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.javalin.config.JavalinState
import io.javalin.http.HandlerType.GET
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

/**
 * Startup validation and last-write-wins semantics of [SecurityConfig] and its sub-configs.
 *
 * All fields are plain `var`s with no set-once guards: assigning a field more than once simply
 * keeps the last value, matching Javalin's own subconfigs. Only genuine cross-field invariants
 * (mutually-exclusive authenticators, non-empty [io.github.mzlnk.javalin.security.ws.WsSecurityConfig.allowedOrigins])
 * are validated - and only once the plugin starts, since [SecurityConfig] itself performs no
 * validation while being mutated.
 */
class JavalinSecurityConfigurationTest {

    /** Builds a fresh [JavalinSecurityPlugin] and runs its startup wiring/validation without booting a real server. */
    private fun start(configure: (SecurityConfig) -> Unit) {
        JavalinSecurityPlugin { configure(it) }.onStart(JavalinState())
    }

    // ── sync/async mutual exclusion ────────────────────────────────────────────

    @Test
    fun `should fail fast when both a sync and async authenticator are configured for http`() {
        assertThatThrownBy {
            start { security ->
                security.http { http ->
                    http.authenticator = { AuthenticationResult.NotAuthenticated }
                    http.asyncAuthenticator = { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("mutually exclusive")
    }

    @Test
    fun `should fail fast when both a sync and async authenticator are configured for ws`() {
        assertThatThrownBy {
            start { security ->
                security.ws { ws ->
                    ws.authenticator = { AuthenticationResult.NotAuthenticated }
                    ws.asyncAuthenticator = { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                }
            }
        }
            .isInstanceOf(SecurityConfigurationException::class.java)
            .hasMessageContaining("mutually exclusive")
    }

    @Test
    fun `should allow a sync authenticator on its own`() {
        assertThatCode {
            start { security ->
                security.http { http -> http.authenticator = { AuthenticationResult.NotAuthenticated } }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should allow an async authenticator on its own`() {
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.asyncAuthenticator = { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) }
                }
            }
        }.doesNotThrowAnyException()
    }

    // ── last-write-wins: no set-once guards ────────────────────────────────────

    @Test
    fun `should keep only the last assigned authenticator, with no exception`() {
        var lastAuthenticatorInvoked: String? = null
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authenticator = { lastAuthenticatorInvoked = "first"; AuthenticationResult.NotAuthenticated }
                    http.authenticator = { lastAuthenticatorInvoked = "second"; AuthenticationResult.NotAuthenticated }
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
                    http.unauthorizedHandler = first
                    http.unauthorizedHandler = second
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
}
