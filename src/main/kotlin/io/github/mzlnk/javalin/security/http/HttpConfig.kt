package io.github.mzlnk.javalin.security.http

import io.github.mzlnk.javalin.security.SecurityConfigurationException
import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationEntryPoint
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.http.authorize.AuthorizeRequestsConfig
import java.util.function.Consumer

/**
 * The HTTP security configuration: request authorization rules, authentication orchestration,
 * and how authentication/authorization failures are rendered.
 *
 * Use [Builder] to construct an instance. Companion libraries contribute their authentication
 * strategy by calling [Builder.authenticationManager] or [Builder.asyncAuthenticationManager].
 *
 * **Sync vs async authentication.** The default, zero-overhead path uses a blocking [AuthenticationManager].
 * For authentication that performs remote I/O (JWKS endpoint, database), the opt-in
 * [Builder.asyncAuthenticationManager] path releases the request thread while authentication is
 * in flight. With `config.useVirtualThreads = true`, the blocking manager is usually sufficient;
 * async is an advanced option.
 */
class HttpConfig internal constructor(
    val authorizeRequestsConfig: AuthorizeRequestsConfig,
    internal val authenticationManager: AuthenticationManager?,
    internal val asyncAuthenticationManager: AsyncAuthenticationManager?,
    internal val authenticationEntryPoint: AuthenticationEntryPoint,
    internal val accessDeniedHandler: AccessDeniedHandler,
) {

    class Builder {

        private var authorizeRequestsConfig: AuthorizeRequestsConfig = AuthorizeRequestsConfig.Builder().build()
        private var authenticationManager: AuthenticationManager? = null
        private var asyncAuthenticationManager: AsyncAuthenticationManager? = null
        private var authenticationEntryPoint: AuthenticationEntryPoint = AuthenticationEntryPoint.DEFAULT
        private var accessDeniedHandler: AccessDeniedHandler = AccessDeniedHandler.DEFAULT

        /** Configures the request authorization rules. */
        fun authorizeRequests(configure: Consumer<AuthorizeRequestsConfig.Builder>): Builder {
            val builder = AuthorizeRequestsConfig.Builder()
            configure.accept(builder)
            this.authorizeRequestsConfig = builder.build()
            return this
        }

        internal fun authorizeRequests(config: AuthorizeRequestsConfig): Builder {
            this.authorizeRequestsConfig = config
            return this
        }

        /**
         * Registers a blocking [AuthenticationManager].
         *
         * This is the hook that companion libraries call from their own configuration extension
         * functions. Mutually exclusive with [asyncAuthenticationManager].
         */
        fun authenticationManager(manager: AuthenticationManager): Builder {
            this.authenticationManager = manager
            return this
        }

        /**
         * Registers an opt-in async [AsyncAuthenticationManager] for I/O-bound authentication.
         *
         * The security guard integrates with Javalin's async machinery ([io.javalin.http.Context.future])
         * to release the request thread while authentication is in flight. All fail-closed
         * semantics and no-message-leak behaviour are preserved across the async boundary.
         *
         * Mutually exclusive with [authenticationManager]. For `config.useVirtualThreads = true`
         * applications, the blocking path is typically preferred — virtual threads make blocking
         * I/O cheap.
         */
        fun asyncAuthenticationManager(manager: AsyncAuthenticationManager): Builder {
            this.asyncAuthenticationManager = manager
            return this
        }

        /** Overrides how failed/absent authentication is rendered (HTTP 401 by default). */
        fun authenticationEntryPoint(entryPoint: AuthenticationEntryPoint): Builder {
            this.authenticationEntryPoint = entryPoint
            return this
        }

        /** Overrides how access-denied for an authenticated caller is rendered (HTTP 403 by default). */
        fun accessDeniedHandler(handler: AccessDeniedHandler): Builder {
            this.accessDeniedHandler = handler
            return this
        }

        fun build(): HttpConfig {
            if (authenticationManager != null && asyncAuthenticationManager != null) {
                throw SecurityConfigurationException(
                    "Both a blocking authenticationManager and an asyncAuthenticationManager were " +
                        "configured, but they are mutually exclusive: choose one authentication " +
                        "path (blocking or async) per security configuration.",
                )
            }

            return HttpConfig(
                authorizeRequestsConfig = authorizeRequestsConfig,
                authenticationManager = authenticationManager,
                asyncAuthenticationManager = asyncAuthenticationManager,
                authenticationEntryPoint = authenticationEntryPoint,
                accessDeniedHandler = accessDeniedHandler,
            )
        }

    }

}
