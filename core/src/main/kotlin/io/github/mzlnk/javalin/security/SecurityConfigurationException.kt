package io.github.mzlnk.javalin.security

/**
 * Raised at build time when the security configuration is invalid or ambiguous.
 *
 * The framework favours failing fast over silently applying a surprising default, so a
 * misconfiguration surfaces immediately when the [javalinSecurity] DSL is built rather than as a
 * hard-to-diagnose gap in protection at runtime.
 */
class SecurityConfigurationException(message: String) : RuntimeException(message)
