package io.github.mzlnk.javalin.security.http.authorization

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context

/**
 * A single access decision applied to a request that matched a configured pattern.
 *
 * Implementations receive the current [Authentication] and the request [Context] and return
 * whether access is granted. Custom rules can be supplied as lambdas thanks to the SAM conversion.
 */
fun interface AuthorizationRule {

    fun isGranted(authentication: Authentication, context: Context): Boolean

}
