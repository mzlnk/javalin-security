package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authentication.AuthenticationProvider
import io.github.mzlnk.javalin.security.http.authorize.AuthorizeRequestsConfig

/**
 * The `http { }` security configuration: request authorization rules and the authentication
 * provider.
 *
 * The [Dsl] is the public receiver that companion libraries extend (via Kotlin extension functions)
 * to contribute their own configuration, ultimately calling [Dsl.authenticationProvider].
 */
class HttpConfig internal constructor(
    val authorizeRequestsConfig: AuthorizeRequestsConfig,
    internal val authenticationProvider: AuthenticationProvider,
) {

    class Dsl {

        private var authorizeRequestsConfig: AuthorizeRequestsConfig = AuthorizeRequestsConfig.Dsl().build()
        private var authenticationProvider: AuthenticationProvider = AuthenticationProvider.NONE

        /** Configures the request authorization rules. */
        fun authorizeRequests(init: AuthorizeRequestsConfig.Dsl.() -> Unit) {
            this.authorizeRequestsConfig = AuthorizeRequestsConfig.Dsl().apply(init).build()
        }

        /**
         * Registers the single [AuthenticationProvider].
         *
         * This is the hook that companion libraries call from their own DSL extension functions
         * (for example, a future `jwt { }` block).
         */
        fun authenticationProvider(provider: AuthenticationProvider) {
            this.authenticationProvider = provider
        }

        fun build(): HttpConfig =
            HttpConfig(
                authorizeRequestsConfig = authorizeRequestsConfig,
                authenticationProvider = authenticationProvider,
            )

    }

}
