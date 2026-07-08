package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.http.HttpConfig
import io.github.mzlnk.javalin.security.ws.WsConfig
import io.javalin.config.JavalinConfig
import java.util.function.Consumer

/**
 * The immutable, fully-built security configuration.
 *
 * Construct via [builder] (Java) or the `javalinSecurity { }` DSL function (Kotlin).
 * Install into a Javalin application via [enable] (Java) or the `config.security { }` extension
 * function (Kotlin).
 */
class JavalinSecurity internal constructor(
    internal val httpConfig: HttpConfig,
    internal val wsConfig: WsConfig?,
) {

    class Builder {

        private var httpConfig: HttpConfig = HttpConfig.Builder().build()
        private var wsConfig: WsConfig? = null
        private var httpSet = false
        private var wsSet = false

        /**
         * Configures the HTTP security block.
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun http(configure: Consumer<HttpConfig.Builder>): Builder {
            if (httpSet) {
                throw SecurityConfigurationException(
                    "http was already configured; it may only be set once.",
                )
            }
            httpSet = true
            val builder = HttpConfig.Builder()
            configure.accept(builder)
            this.httpConfig = builder.build()
            return this
        }

        internal fun http(config: HttpConfig): Builder {
            if (httpSet) {
                throw SecurityConfigurationException(
                    "http was already configured; it may only be set once.",
                )
            }
            httpSet = true
            this.httpConfig = config
            return this
        }

        /**
         * Configures the WebSocket security block.
         *
         * May only be called once; a second call throws [SecurityConfigurationException].
         */
        fun ws(configure: Consumer<WsConfig.Builder>): Builder {
            if (wsSet) {
                throw SecurityConfigurationException(
                    "ws was already configured; it may only be set once.",
                )
            }
            wsSet = true
            val builder = WsConfig.Builder()
            configure.accept(builder)
            this.wsConfig = builder.build()
            return this
        }

        internal fun ws(config: WsConfig): Builder {
            if (wsSet) {
                throw SecurityConfigurationException(
                    "ws was already configured; it may only be set once.",
                )
            }
            wsSet = true
            this.wsConfig = config
            return this
        }

        fun build(): JavalinSecurity = JavalinSecurity(httpConfig = httpConfig, wsConfig = wsConfig)

    }

    companion object {

        /**
         * Returns a new [Builder] for constructing a [JavalinSecurity] configuration from Java
         * using a fluent, Consumer-based API. Call [build] at the end and pass the result to
         * [enable].
         */
        @JvmStatic
        fun builder(): Builder = Builder()

        /**
         * Installs the given [security] configuration into the Javalin application being built.
         *
         * Equivalent to the Kotlin `config.security { }` extension when the [JavalinSecurity]
         * object has already been constructed (e.g. by a [builder]).
         *
         * The security guard always runs before the matched route handler — this is enforced by
         * Javalin's own `beforeMatched` lifecycle. The plugin runs at
         * [io.javalin.plugin.PluginPriority.EARLY], which orders the guard ahead of `beforeMatched`
         * handlers added by other plugins (`NORMAL` or `LATE` priority). However, `beforeMatched`
         * handlers registered directly via `cfg.routes.beforeMatched()` inside `Javalin.create { }`
         * are added before any plugin's `onStart`, so they run before the guard and will not yet
         * see a populated [io.github.mzlnk.javalin.security.authentication.Authentication].
         * To observe the resolved authentication, add handlers on the Javalin instance after
         * creation (`app.beforeMatched { }`) or read it inside the matched route handler itself.
         */
        @JvmStatic
        fun enable(config: JavalinConfig, security: JavalinSecurity) {
            config.registerPlugin(JavalinSecurityPlugin(security))
        }

    }

}
