package io.github.mzlnk.javalin.security.interop

import io.github.mzlnk.javalin.security.JavalinSecurity
import io.github.mzlnk.javalin.security.JavalinSecurityPlugin
import io.javalin.config.JavalinConfig

/**
 * Java-friendly facade for installing `javalin-security` into a Javalin application.
 *
 * Kotlin users use the `config.security { }` extension function instead. Java users build a
 * [JavalinSecurity] via [builder] and install it via [enable] — both static, no [Unit] returned.
 */
object JavalinSecuritySupport {

    /**
     * Returns a new [JavalinSecurityBuilder] for constructing a [JavalinSecurity] configuration
     * from Java using a fluent API.
     */
    @JvmStatic
    fun builder(): JavalinSecurityBuilder = JavalinSecurityBuilder()

    /**
     * Installs the given [security] configuration into the Javalin application being built.
     *
     * Equivalent to the Kotlin `config.security { }` extension when the [JavalinSecurity] object
     * has already been constructed (e.g. by a [JavalinSecurityBuilder] or
     * [io.github.mzlnk.javalin.security.javalinSecurity]).
     *
     * The security guard runs at [io.javalin.plugin.PluginPriority.EARLY], so it is the first
     * `beforeMatched` handler and every subsequent handler observes a populated
     * [io.github.mzlnk.javalin.security.Authentication] on the context.
     */
    @JvmStatic
    fun enable(config: JavalinConfig, security: JavalinSecurity) {
        config.registerPlugin(JavalinSecurityPlugin(security))
    }
}
