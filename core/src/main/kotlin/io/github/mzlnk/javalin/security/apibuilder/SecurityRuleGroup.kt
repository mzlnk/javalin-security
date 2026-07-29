package io.github.mzlnk.javalin.security.apibuilder

/**
 * Functional group of security-rule declarations for [SecurityApiBuilder].
 *
 * Analogous to Javalin's [io.javalin.apibuilder.EndpointGroup]. Invoked inside
 * [io.github.mzlnk.javalin.security.SecurityRules.apiBuilder].
 */
fun interface SecurityRuleGroup {

    /** Registers rules via the static [SecurityApiBuilder] methods. */
    fun addRules()

}
