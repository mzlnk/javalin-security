package io.github.mzlnk.javalin.security.authorization

/**
 * A lightweight ant-style path matcher, decoupled from Javalin routing so that authorization
 * patterns behave predictably regardless of how routes are declared.
 *
 * Supported wildcards:
 * - `?` matches exactly one character within a path segment (not `/`)
 * - `*` matches zero or more characters within a single path segment (not `/`)
 * - `**` matches zero or more path segments (crosses `/`)
 *
 * The compiled [Regex] is built once per pattern so matching stays cheap on the request path.
 */
internal class AntPathMatcher(val pattern: String) {

    private val regex: Regex = compile(pattern)

    fun matches(path: String): Boolean = regex.matches(path)

    private companion object {

        fun compile(pattern: String): Regex {
            val sb = StringBuilder()
            var i = 0
            while (i < pattern.length) {
                val c = pattern[i]
                when (c) {
                    '*' -> {
                        val doubleStar = i + 1 < pattern.length && pattern[i + 1] == '*'
                        if (doubleStar) {
                            // Collapse a preceding literal '/' into the wildcard so that e.g.
                            // "/api/**" also matches "/api" (zero trailing segments).
                            if (sb.isNotEmpty() && sb.last() == '/') {
                                sb.setLength(sb.length - 1)
                                sb.append("(?:/.*)?")
                            } else {
                                sb.append(".*")
                            }
                            i += 2
                            continue
                        } else {
                            sb.append("[^/]*")
                        }
                    }
                    '?' -> sb.append("[^/]")
                    '.', '\\', '(', ')', '[', ']', '{', '}', '+', '^', '$', '|' -> {
                        sb.append('\\')
                        sb.append(c)
                    }
                    else -> sb.append(c)
                }
                i++
            }
            return Regex(sb.toString())
        }

    }

}
