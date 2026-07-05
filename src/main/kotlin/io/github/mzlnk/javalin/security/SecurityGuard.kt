package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authentication.AuthenticationEntryPoint
import io.github.mzlnk.javalin.security.authentication.AuthenticationManager
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult
import io.github.mzlnk.javalin.security.authorization.AccessDeniedHandler
import io.github.mzlnk.javalin.security.authorization.AuthorizationManager
import io.github.mzlnk.javalin.security.authorization.PathNormalizer
import io.javalin.http.Context
import org.slf4j.LoggerFactory

/**
 * The request-time pipeline and the sole bridge between the framework and Javalin.
 *
 * It authenticates, publishes the [Authentication] on the [Context], then authorizes. Failures are
 * delegated to the configured [AuthenticationEntryPoint] (401) and [AccessDeniedHandler] (403); the
 * guard itself contains no interception, reflection or thread-locals.
 */
internal class SecurityGuard(
    private val authenticationManager: AuthenticationManager,
    private val authorizationManager: AuthorizationManager,
    private val pathNormalizer: PathNormalizer,
    private val authenticationEntryPoint: AuthenticationEntryPoint,
    private val accessDeniedHandler: AccessDeniedHandler,
) {

    fun handle(context: Context) {
        val method = context.method()
        val path = pathNormalizer.normalize(context.path())

        val authentication = when (val result = authenticationManager.authenticate(context)) {
            is AuthenticationResult.Success -> result.authentication
            is AuthenticationResult.NotAuthenticated -> Authentication.unauthenticated()
            is AuthenticationResult.Failure -> {
                // The failure message/cause is logged but never forwarded to the client, to avoid
                // leaking why authentication failed.
                log.warn("Authentication failed for {} {}: {}", method, path, result.message ?: "no detail", result.cause)
                authenticationEntryPoint.commence(context, result)
                return
            }
        }

        context.attribute(AUTHENTICATION_ATTRIBUTE, authentication)

        if (authorizationManager.isGranted(method, path, authentication, context)) {
            if (log.isDebugEnabled) {
                log.debug("Access granted to {} for {} {}", principalName(authentication), method, path)
            }
            return
        }

        if (authentication.isAuthenticated) {
            log.warn("Access denied to {} for {} {}", principalName(authentication), method, path)
            accessDeniedHandler.handle(context, authentication)
        } else {
            log.warn("Access denied to anonymous caller for {} {}", method, path)
            authenticationEntryPoint.commence(context, null)
        }
    }

    private fun principalName(authentication: Authentication): String =
        (authentication.principal as? AuthenticatedPrincipal)?.name ?: "anonymous"

    private companion object {
        val log = LoggerFactory.getLogger(SecurityGuard::class.java)
    }

}
