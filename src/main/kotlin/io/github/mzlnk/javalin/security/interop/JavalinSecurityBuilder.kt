package io.github.mzlnk.javalin.security.interop

import io.github.mzlnk.javalin.security.JavalinSecurity
import java.util.function.Consumer

/**
 * Fluent Java builder for a [JavalinSecurity] configuration.
 *
 * Obtain an instance via [JavalinSecuritySupport.builder]; do not instantiate directly. Each method
 * returns `this` so the whole configuration reads as a single chained expression without
 * `return Unit.INSTANCE`. Call [build] at the end and pass the result to
 * [JavalinSecuritySupport.enable].
 */
class JavalinSecurityBuilder {

    private val actions = mutableListOf<JavalinSecurity.Dsl.() -> Unit>()

    /**
     * Configures the HTTP security block.
     *
     * The [configure] consumer receives an [HttpSecurityBuilder] and must not return a value
     * (Java `Consumer<HttpSecurityBuilder>`).
     */
    fun http(configure: Consumer<HttpSecurityBuilder>): JavalinSecurityBuilder {
        val builder = HttpSecurityBuilder()
        configure.accept(builder)
        actions += { http { builder.applyTo(this) } }
        return this
    }

    /** Builds the immutable [JavalinSecurity] from the accumulated configuration. */
    fun build(): JavalinSecurity = JavalinSecurity.Dsl().also { dsl -> actions.forEach { dsl.it() } }.build()
}
