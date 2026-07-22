package io.github.mzlnk.javalin.security

/**
 * Raised at startup when the security configuration is invalid or ambiguous - for example, a
 * missing required field on a companion library's scheme config (`jwt { }`, `basicAuth { }`), an
 * empty `allowedOrigins` collection, or a rule pattern using unsupported legacy Ant-style syntax.
 *
 * The framework favours failing fast over silently applying a surprising default, so a
 * misconfiguration surfaces immediately when [JavalinSecurityPlugin] starts rather than as a
 * hard-to-diagnose gap in protection at runtime.
 */
class SecurityConfigurationException(message: String) : RuntimeException(message)
