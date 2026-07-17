package io.github.mzlnk.javalin.security.basicauth

/** The username/password pair extracted from an incoming request's `Basic` credentials. */
data class BasicCredentials(val username: String, val password: String)
