package io.github.mzlnk.javalin.security.authorization

import io.github.mzlnk.javalin.security.authentication.Authentication
import io.javalin.http.Context

/**
 * Access decision for a request that matched a configured pattern.
 *
 * Returns whether access is granted for the given [Authentication] and [Context]. Custom rules
 * may be supplied as lambdas (SAM conversion).
 */
fun interface Rule {

    /** Returns `true` when access is granted for [authentication] on [context]. */
    fun isGranted(authentication: Authentication, context: Context): Boolean

}
