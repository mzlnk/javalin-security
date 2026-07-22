package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.http.HttpSecurityConfig
import io.github.mzlnk.javalin.security.ws.WsSecurityConfig
import java.util.function.Consumer

/**
 * The mutable security configuration consumed by [JavalinSecurityPlugin].
 *
 * A single field-assignment config, the same shape as every other Javalin plugin config (compare
 * `RateLimitPluginConfig`, `JavalinVueConfig`): install with
 * `config.registerPlugin(JavalinSecurityPlugin { security -> ... })` and configure inline.
 *
 * **Both guards are opt-in.** The HTTP guard is installed only when [http] was called at least
 * once; the WS guard is installed only when [ws] was called at least once. If neither is called,
 * no guards are installed and all routes remain unprotected. This keeps the two protocols
 * symmetric and prevents silent over-protection of routes when only one protocol is in use.
 */
class SecurityConfig internal constructor() {

    private var httpConfig: HttpSecurityConfig? = null
    private var wsConfig: WsSecurityConfig? = null

    internal val http: HttpSecurityConfig? get() = httpConfig
    internal val ws: WsSecurityConfig? get() = wsConfig

    /**
     * Configures the HTTP security block. May be called more than once; later calls configure the
     * same [HttpSecurityConfig] instance (fields are last-write-wins, [HttpSecurityConfig.rules]
     * entries accumulate).
     */
    fun http(configure: Consumer<HttpSecurityConfig>) {
        val config = httpConfig ?: HttpSecurityConfig().also { httpConfig = it }
        configure.accept(config)
    }

    /**
     * Configures the WebSocket security block. May be called more than once; later calls configure
     * the same [WsSecurityConfig] instance (fields are last-write-wins, [WsSecurityConfig.rules]
     * entries accumulate).
     */
    fun ws(configure: Consumer<WsSecurityConfig>) {
        val config = wsConfig ?: WsSecurityConfig().also { wsConfig = it }
        configure.accept(config)
    }

}
