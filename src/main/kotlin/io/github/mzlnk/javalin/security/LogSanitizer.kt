package io.github.mzlnk.javalin.security

/**
 * Sanitizes attacker-influenced values (request paths, principal names, provider messages)
 * before they are written to the log.
 *
 * Control characters are replaced with `_` to prevent CRLF log-injection attacks where a crafted
 * value could forge additional log lines. Overly long values are truncated to keep log lines
 * bounded.
 *
 * Shared by [SecurityGuard] and [io.github.mzlnk.javalin.security.ws.WsSecurityGuard] to ensure
 * consistent sanitization from a single implementation.
 */
internal object LogSanitizer {

    /** Matches ASCII control characters (including CR, LF and TAB). */
    private val CONTROL_CHARS = Regex("\\p{Cntrl}")

    /** Upper bound on the length of any single value written to the log. */
    private const val MAX_LOGGED_LENGTH = 256

    fun sanitize(value: String): String {
        val cleaned = CONTROL_CHARS.replace(value, "_")
        return if (cleaned.length > MAX_LOGGED_LENGTH) {
            cleaned.substring(0, MAX_LOGGED_LENGTH) + "..."
        } else {
            cleaned
        }
    }

}
