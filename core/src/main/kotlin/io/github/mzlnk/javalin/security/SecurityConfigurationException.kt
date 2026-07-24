package io.github.mzlnk.javalin.security

/**
 * Thrown at startup when the security configuration is invalid or ambiguous.
 *
 * Examples include a missing required field on a companion scheme config, an empty `allowedOrigins` collection, or a rule pattern using unsupported Ant-style tokens (`**`, `?`). Raised when [JavalinSecurityPlugin] starts rather than at request time.
 */
class SecurityConfigurationException(message: String) : RuntimeException(message)
