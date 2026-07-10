package io.github.mzlnk.javalin.security

import io.javalin.http.Context

/** Request attribute key under which the resolved [authentication.Authentication] is stored on the [Context]. */
internal const val AUTHENTICATION_ATTRIBUTE = "io.github.mzlnk.javalin.security.Authentication"