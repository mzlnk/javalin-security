package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.authentication.AuthenticationEntryPoint
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationProvider
import io.github.mzlnk.javalin.security.authentication.ProviderAuthenticationManager
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.http.authorize.AuthorizeRequestsConfig

/**
 * The `http { }` security configuration: request authorization rules, authentication orchestration
 * and how authentication/authorization failures are rendered.
 *
 * The [Dsl] is the public receiver that companion libraries extend (via Kotlin extension functions)
 * to contribute their own configuration, ultimately calling [Dsl.authenticationProvider] or
 * [Dsl.authenticationManager].
 */
class HttpConfig internal constructor(
    val authorizeRequestsConfig: AuthorizeRequestsConfig,
    internal val authenticationManager: AuthenticationManager,
    internal val authenticationEntryPoint: AuthenticationEntryPoint,
    internal val accessDeniedHandler: AccessDeniedHandler,
) {

    class Dsl {

        private var authorizeRequestsConfig: AuthorizeRequestsConfig = AuthorizeRequestsConfig.Dsl().build()
        private val authenticationProviders = mutableListOf<AuthenticationProvider>()
        private var authenticationManager: AuthenticationManager? = null
        private var authenticationEntryPoint: AuthenticationEntryPoint = AuthenticationEntryPoint.DEFAULT
        private var accessDeniedHandler: AccessDeniedHandler = AccessDeniedHandler.DEFAULT

        /** Configures the request authorization rules. */
        fun authorizeRequests(init: AuthorizeRequestsConfig.Dsl.() -> Unit) {
            this.authorizeRequestsConfig = AuthorizeRequestsConfig.Dsl().apply(init).build()
        }

        /**
         * Registers an [AuthenticationProvider].
         *
         * This is the hook that companion libraries call from their own DSL extension functions
         * (for example, a future `jwt { }` block). It may be called multiple times; providers are
         * tried in registration order by the default [AuthenticationManager], so several strategies
         * (JWT, API key, ...) can coexist without clobbering one another.
         *
         * Ignored when a custom [authenticationManager] is supplied.
         */
        fun authenticationProvider(provider: AuthenticationProvider) {
            this.authenticationProviders += provider
        }

        /**
         * Registers a fully custom [AuthenticationManager], taking complete control of how requests
         * are authenticated. When set, it takes precedence over any registered
         * [authenticationProvider]s.
         */
        fun authenticationManager(manager: AuthenticationManager) {
            this.authenticationManager = manager
        }

        /** Overrides how failed/absent authentication is rendered (HTTP 401 by default). */
        fun authenticationEntryPoint(entryPoint: AuthenticationEntryPoint) {
            this.authenticationEntryPoint = entryPoint
        }

        /** Overrides how access-denied for an authenticated caller is rendered (HTTP 403 by default). */
        fun accessDeniedHandler(handler: AccessDeniedHandler) {
            this.accessDeniedHandler = handler
        }

        fun build(): HttpConfig =
            HttpConfig(
                authorizeRequestsConfig = authorizeRequestsConfig,
                authenticationManager = authenticationManager ?: ProviderAuthenticationManager(authenticationProviders.toList()),
                authenticationEntryPoint = authenticationEntryPoint,
                accessDeniedHandler = accessDeniedHandler,
            )

    }

}
