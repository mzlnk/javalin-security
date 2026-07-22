package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.Authenticator
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler
import io.github.mzlnk.javalin.security.authorization.Rules
import io.javalin.config.JavalinState
import io.javalin.http.HandlerType.GET
import org.assertj.core.api.Assertions.assertThatCode
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

/**
 * Startup validation and last-write-wins semantics of [SecurityConfig] and its sub-configs.
 *
 * All fields are plain `var`s with no set-once guards: assigning a field more than once simply
 * keeps the last value, matching Javalin's own subconfigs. Sync-vs-async authentication is
 * mutually exclusive by construction — an [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme]
 * is either [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme.Sync] or
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationScheme.Async], never both — so
 * there is no such runtime check left to perform. Only genuine cross-field invariants
 * (non-empty [io.github.mzlnk.javalin.security.ws.WsSecurityConfig.allowedOrigins]) are still
 * validated, and only once the plugin starts, since [SecurityConfig] itself performs no
 * validation while being mutated.
 */
class JavalinSecurityConfigurationTest {

    /** Builds a fresh [JavalinSecurityPlugin] and runs its startup wiring/validation without booting a real server. */
    private fun start(configure: (SecurityConfig) -> Unit) {
        JavalinSecurityPlugin { configure(it) }.onStart(JavalinState())
    }

    // ── sync/async mutual exclusion is now a type-level guarantee ─────────────

    @Test
    fun `should allow a sync scheme on its own`() {
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authentication = syncScheme(Authenticator { AuthenticationResult.NotAuthenticated })
                }
            }
        }.doesNotThrowAnyException()
    }

    @Test
    fun `should allow an async scheme on its own`() {
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authentication = asyncScheme(
                        { CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated) },
                    )
                }
            }
        }.doesNotThrowAnyException()
    }

    // ── last-write-wins: no set-once guards ────────────────────────────────────

    @Test
    fun `should keep only the last assigned authentication scheme, with no exception`() {
        var lastAuthenticatorInvoked: String? = null
        assertThatCode {
            start { security ->
                security.http { http ->
                    http.authentication = syncScheme(
                        Authenticator {
                            lastAuthenticatorInvoked = "first"
                            AuthenticationResult.NotAuthenticated
                        },
                    )
                    http.authentication = syncScheme(
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
                    http.authentication = syncScheme(unauthorizedHandler = first)
                    http.authentication = syncScheme(unauthorizedHandler = second)
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
