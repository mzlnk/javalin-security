package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.http.HttpConfig
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
) {

    class Builder {

        private var httpConfig: HttpConfig = HttpConfig.Builder().build()

        /** Configures the HTTP security block. */
        fun http(configure: Consumer<HttpConfig.Builder>): Builder {
            val builder = HttpConfig.Builder()
            configure.accept(builder)
            this.httpConfig = builder.build()
            return this
        }

        internal fun http(config: HttpConfig): Builder {
            this.httpConfig = config
            return this
        }

        fun build(): JavalinSecurity = JavalinSecurity(httpConfig = httpConfig)

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
         * The security guard runs at [io.javalin.plugin.PluginPriority.EARLY], so it is the first
         * `beforeMatched` handler and every subsequent handler observes a populated
         * [io.github.mzlnk.javalin.security.authentication.Authentication] on the context.
         */
        @JvmStatic
        fun enable(config: JavalinConfig, security: JavalinSecurity) {
            config.registerPlugin(JavalinSecurityPlugin(security))
        }

    }

}
