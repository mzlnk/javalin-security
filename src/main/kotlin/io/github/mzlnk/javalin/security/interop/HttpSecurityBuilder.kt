package io.github.mzlnk.javalin.security.interop

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticationProvider
import io.github.mzlnk.javalin.security.authentication.AuthenticationEntryPoint
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationProvider
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.http.HttpConfig
import java.util.function.Consumer

/**
 * Fluent Java builder for the `http { }` security block.
 *
 * Each method returns `this` so calls chain without `return Unit.INSTANCE`. Internally it records
 * configuration as a sequence of actions that are replayed onto an [HttpConfig.Dsl] when [build]
 * is called, keeping validation (e.g. provider-vs-manager mutual exclusion) in the Kotlin DSL as
 * the single source of truth.
 *
 * Obtain an instance via [JavalinSecurityBuilder.http].
 */
class HttpSecurityBuilder {

    private val actions = mutableListOf<HttpConfig.Dsl.() -> Unit>()

    /**
     * Configures the request authorization rules.
     *
     * The [configure] consumer receives an [AuthorizeRequestsBuilder] and must not return a value
     * (Java `Consumer<AuthorizeRequestsBuilder>`).
     */
    fun authorizeRequests(configure: Consumer<AuthorizeRequestsBuilder>): HttpSecurityBuilder {
        val builder = AuthorizeRequestsBuilder()
        configure.accept(builder)
        actions += { authorizeRequests { builder.applyTo(this) } }
        return this
    }

    /**
     * Registers an [AuthenticationProvider].
     *
     * This is the hook that companion libraries use to contribute their authentication strategy.
     * May be called multiple times; providers are tried in registration order. Mutually exclusive
     * with [authenticationManager].
     *
     * [AuthenticationProvider] is a SAM interface so a Java lambda works directly:
     * `authenticationProvider(ctx -> AuthenticationResult.NotAuthenticated.INSTANCE)`
     */
    fun authenticationProvider(provider: AuthenticationProvider): HttpSecurityBuilder {
        actions += { authenticationProvider(provider) }
        return this
    }

    /**
     * Registers an opt-in async [AsyncAuthenticationProvider] for I/O-bound authentication.
     *
     * The security guard releases the request thread while the [java.util.concurrent.CompletableFuture]
     * is in flight. Mutually exclusive with [authenticationManager] and blocking [authenticationProvider]s.
     */
    fun asyncAuthenticationProvider(provider: AsyncAuthenticationProvider): HttpSecurityBuilder {
        actions += { asyncAuthenticationProvider(provider) }
        return this
    }

    /**
     * Registers a fully custom [AuthenticationManager], taking complete control of authentication.
     *
     * Mutually exclusive with [authenticationProvider]. Passing both is rejected at [build] time
     * with a [io.github.mzlnk.javalin.security.SecurityConfigurationException].
     */
    fun authenticationManager(manager: AuthenticationManager): HttpSecurityBuilder {
        actions += { authenticationManager(manager) }
        return this
    }

    /** Overrides how failed/absent authentication is rendered (HTTP 401 by default). */
    fun authenticationEntryPoint(entryPoint: AuthenticationEntryPoint): HttpSecurityBuilder {
        actions += { authenticationEntryPoint(entryPoint) }
        return this
    }

    /** Overrides how access-denied for an authenticated caller is rendered (HTTP 403 by default). */
    fun accessDeniedHandler(handler: AccessDeniedHandler): HttpSecurityBuilder {
        actions += { accessDeniedHandler(handler) }
        return this
    }

    internal fun applyTo(dsl: HttpConfig.Dsl) = actions.forEach { dsl.it() }

    internal fun build(): HttpConfig = HttpConfig.Dsl().also { applyTo(it) }.build()
}
