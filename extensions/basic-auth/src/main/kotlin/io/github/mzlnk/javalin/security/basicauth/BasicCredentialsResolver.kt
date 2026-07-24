package io.github.mzlnk.javalin.security.basicauth

import io.javalin.http.Context
import java.util.Base64

/**
 * Locates [BasicCredentials] within an incoming request.
 *
 * Returns decoded credentials, or `null` when absent so the request proceeds as anonymous.
 * Malformed credentials (invalid Base64 or missing `:` separator) must throw
 * [IllegalArgumentException] so [BasicAuthenticator] can surface
 * [io.github.mzlnk.javalin.security.authentication.AuthenticationResult.Failure].
 */
fun interface BasicCredentialsResolver {

    /**
     * Returns the [BasicCredentials] extracted from [context], or `null` when absent.
     *
     * Throws [IllegalArgumentException] when credentials are present but malformed.
     */
    fun resolve(context: Context): BasicCredentials?

    companion object {

        private const val BASIC_PREFIX = "basic "

        /**
         * Extracts credentials from the `Basic` scheme of [headerName] (defaults to `Authorization`).
         *
         * Recognises `Basic` case-insensitively. Returns `null` when the header is absent or does
         * not start with `Basic `. When the scheme is present, the remainder is Base64-decoded and
         * split on the first `:`; malformed Base64 or a missing separator throws
         * [IllegalArgumentException].
         */
        @JvmStatic
        @JvmOverloads
        fun basicHeader(headerName: String = "Authorization"): BasicCredentialsResolver = BasicCredentialsResolver { context ->
            val header = context.header(headerName) ?: return@BasicCredentialsResolver null
            if (!header.lowercase().startsWith(BASIC_PREFIX)) return@BasicCredentialsResolver null

            val encoded = header.substring(BASIC_PREFIX.length).trim()
            val decoded = try {
                Base64.getDecoder().decode(encoded).toString(Charsets.UTF_8)
            } catch (ex: IllegalArgumentException) {
                throw IllegalArgumentException("Basic credentials are not valid Base64", ex)
            }

            val separatorIndex = decoded.indexOf(':')
            if (separatorIndex < 0) {
                throw IllegalArgumentException("Basic credentials are missing the ':' separator between username and password")
            }

            BasicCredentials(
                username = decoded.substring(0, separatorIndex),
                password = decoded.substring(separatorIndex + 1),
            )
        }

        /** The default resolver: [basicHeader] with the standard `Authorization` header. */
        @JvmStatic
        val DEFAULT: BasicCredentialsResolver = basicHeader()

    }

}
