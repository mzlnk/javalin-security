package io.github.mzlnk.javalin.security.interop

import io.github.mzlnk.javalin.security.authorization.AuthorizationRule
import io.github.mzlnk.javalin.security.http.authorize.AuthorizeRequestsConfig
import io.javalin.http.HandlerType

/**
 * Fluent Java builder for the `authorizeRequests { }` block.
 *
 * Each method returns `this` so calls chain without `return Unit.INSTANCE`. Internally it records
 * the configuration as a sequence of actions that are replayed onto an
 * [AuthorizeRequestsConfig.Dsl] when [build] is called, so the Kotlin DSL remains the single
 * source of truth for the rule-entry model.
 *
 * Obtain an instance via [HttpSecurityBuilder.authorizeRequests].
 */
class AuthorizeRequestsBuilder {

    private val actions = mutableListOf<AuthorizeRequestsConfig.Dsl.() -> Unit>()

    /**
     * Registers a rule for requests matching [pattern] with the given HTTP [method].
     *
     * A custom [AuthorizationRule] may be passed as a lambda (SAM from Java):
     * `authorize("/x", GET, (auth, ctx) -> ...)`
     */
    fun authorize(pattern: String, method: HandlerType, rule: AuthorizationRule): AuthorizeRequestsBuilder {
        actions += { authorize(pattern, method, rule) }
        return this
    }

    /**
     * Registers a rule for requests matching [pattern] for any HTTP method.
     *
     * A custom [AuthorizationRule] may be passed as a lambda.
     */
    fun authorize(pattern: String, rule: AuthorizationRule): AuthorizeRequestsBuilder {
        actions += { authorize(pattern, rule) }
        return this
    }

    /**
     * Registers a terminal catch-all rule applied to every request (any path, any method).
     *
     * Because matching is first-match-wins, call this last to mirror the Kotlin `anyRequest()` DSL
     * member and reduce the risk of leaving routes uncovered.
     */
    fun anyRequest(rule: AuthorizationRule): AuthorizeRequestsBuilder {
        actions += { anyRequest(rule) }
        return this
    }

    /**
     * Permits CORS preflight `OPTIONS` requests identified by the presence of the
     * `Access-Control-Request-Method` request header.
     *
     * See [HttpSecurityBuilder] and the CORS plugin documentation for ordering guidance.
     */
    fun permitCorsPreflight(): AuthorizeRequestsBuilder {
        actions += { permitCorsPreflight() }
        return this
    }

    internal fun applyTo(dsl: AuthorizeRequestsConfig.Dsl) = actions.forEach { dsl.it() }

    internal fun build(): AuthorizeRequestsConfig = AuthorizeRequestsConfig.Dsl().also { applyTo(it) }.build()
}
