package io.github.mzlnk.javalin.security

/**
 * Sanitizes attacker-influenced values before they are written to the log.
 *
 * Replaces control characters with `_` and truncates values longer than [MAX_LOGGED_LENGTH]. Used by [SecurityGuard] and [io.github.mzlnk.javalin.security.ws.WsSecurityGuard].
 */
internal object LogSanitizer {

    /** Matches ASCII control characters (including CR, LF and TAB). */
    private val CONTROL_CHARS = Regex("\\p{Cntrl}")

    /** Upper bound on the length of any single value written to the log. */
    private const val MAX_LOGGED_LENGTH = 256

    /** Returns [value] with control characters replaced by `_` and length capped at [MAX_LOGGED_LENGTH]. */
    fun sanitize(value: String): String {
        val cleaned = CONTROL_CHARS.replace(value, "_")
        return if (cleaned.length > MAX_LOGGED_LENGTH) {
            cleaned.substring(0, MAX_LOGGED_LENGTH) + "..."
        } else {
            cleaned
        }
    }

}
