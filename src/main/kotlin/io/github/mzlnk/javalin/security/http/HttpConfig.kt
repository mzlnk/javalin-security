package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationProvider
import io.github.mzlnk.javalin.security.authentication.AsyncProviderAuthenticationManager
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
 * to contribute their own configuration, ultimately calling [Dsl.authenticationProvider],
 * [Dsl.asyncAuthenticationProvider], or [Dsl.authenticationManager].
 *
 * **Sync vs async authentication.** The default, zero-overhead path uses blocking [AuthenticationProvider]s.
 * For providers that perform remote I/O (JWKS endpoint, database), the opt-in
 * [asyncAuthenticationProvider] path releases the request thread while authentication is in flight.
 * With `config.useVirtualThreads = true`, blocking providers are usually sufficient; async is an
 * advanced option.
 */
class HttpConfig internal constructor(
    val authorizeRequestsConfig: AuthorizeRequestsConfig,
    internal val authenticationManager: AuthenticationManager?,
    internal val asyncAuthenticationManager: AsyncAuthenticationManager?,
    internal val authenticationEntryPoint: AuthenticationEntryPoint,
    internal val accessDeniedHandler: AccessDeniedHandler,
) {

    class Dsl {

        private var authorizeRequestsConfig: AuthorizeRequestsConfig = AuthorizeRequestsConfig.Dsl().build()
        private val authenticationProviders = mutableListOf<AuthenticationProvider>()
        private val asyncAuthenticationProviders = mutableListOf<AsyncAuthenticationProvider>()
        private var authenticationManager: AuthenticationManager? = null
        private var authenticationEntryPoint: AuthenticationEntryPoint = AuthenticationEntryPoint.DEFAULT
        private var accessDeniedHandler: AccessDeniedHandler = AccessDeniedHandler.DEFAULT

        /** Configures the request authorization rules. */
        fun authorizeRequests(init: AuthorizeRequestsConfig.Dsl.() -> Unit) {
            this.authorizeRequestsConfig = AuthorizeRequestsConfig.Dsl().apply(init).build()
        }

        /**
         * Registers a blocking [AuthenticationProvider].
         *
         * This is the hook that companion libraries call from their own DSL extension functions
         * (for example, a future `jwt { }` block). It may be called multiple times; providers are
         * tried in registration order by the default manager, so several strategies (JWT, API key,
         * ...) can coexist without clobbering one another.
         *
         * Mutually exclusive with [authenticationManager] and [asyncAuthenticationProvider].
         */
        fun authenticationProvider(provider: AuthenticationProvider) {
            this.authenticationProviders += provider
        }

        /**
         * Registers an opt-in async [AsyncAuthenticationProvider] for I/O-bound authentication.
         *
         * The security guard integrates with Javalin's async machinery ([io.javalin.http.Context.future])
         * to release the request thread while authentication is in flight. All fail-closed
         * semantics, CRLF-sanitized logging and no-message-leak behaviour are preserved across
         * the async boundary.
         *
         * Mutually exclusive with [authenticationManager] and blocking [authenticationProvider]s.
         * For `config.useVirtualThreads = true` applications, the blocking path is typically
         * preferred — virtual threads make blocking I/O cheap.
         */
        fun asyncAuthenticationProvider(provider: AsyncAuthenticationProvider) {
            this.asyncAuthenticationProviders += provider
        }

        /**
         * Registers a fully custom [AuthenticationManager], taking complete control of how requests
         * are authenticated synchronously.
         *
         * Mutually exclusive with [authenticationProvider] and [asyncAuthenticationProvider]:
         * a custom manager already owns provider orchestration, so configuring both is a
         * contradiction and is rejected at [build] time with a [SecurityConfigurationException].
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

        fun build(): HttpConfig {
            val customManager = authenticationManager
            val hasProviders = authenticationProviders.isNotEmpty()
            val hasAsyncProviders = asyncAuthenticationProviders.isNotEmpty()

            if (customManager != null && (hasProviders || hasAsyncProviders)) {
                throw SecurityConfigurationException(
                    "Both a custom authenticationManager and authentication provider(s) were " +
                        "configured, but they are mutually exclusive: a custom manager takes full " +
                        "control of authentication and would ignore the providers. Register either " +
                        "a custom authenticationManager or one or more provider(s), not both.",
                )
            }
            if (hasProviders && hasAsyncProviders) {
                throw SecurityConfigurationException(
                    "Both blocking authenticationProvider(s) and asyncAuthenticationProvider(s) " +
                        "were configured, but they are mutually exclusive: choose one authentication " +
                        "path (blocking or async) per security configuration.",
                )
            }

            val syncManager: AuthenticationManager? = when {
                customManager != null -> customManager
                hasProviders -> ProviderAuthenticationManager(authenticationProviders.toList())
                else -> null
            }
            val asyncManager: AsyncAuthenticationManager? = when {
                hasAsyncProviders -> AsyncProviderAuthenticationManager(asyncAuthenticationProviders.toList())
                else -> null
            }

            return HttpConfig(
                authorizeRequestsConfig = authorizeRequestsConfig,
                authenticationManager = syncManager,
                asyncAuthenticationManager = asyncManager,
                authenticationEntryPoint = authenticationEntryPoint,
                accessDeniedHandler = accessDeniedHandler,
            )
        }

    }

}
