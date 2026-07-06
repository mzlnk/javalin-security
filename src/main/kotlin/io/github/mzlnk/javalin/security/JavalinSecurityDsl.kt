package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.http.HttpConfigDsl

/**
 * Kotlin DSL receiver for the top-level security configuration block.
 *
 * Used as the receiver type for the `javalinSecurity { }` function and the `config.security { }`
 * extension — both ultimately delegate to [JavalinSecurity.Builder] so the immutable config and
 * validation logic live in one place.
 */
class JavalinSecurityDsl internal constructor() {

    private val builder = JavalinSecurity.builder()

    /** Configures the HTTP security block. */
    fun http(init: HttpConfigDsl.() -> Unit) {
        builder.http(HttpConfigDsl().apply(init).build())
    }

    internal fun build(): JavalinSecurity = builder.build()

}

/** Builds a [JavalinSecurity] configuration using the Kotlin DSL. */
fun javalinSecurity(init: JavalinSecurityDsl.() -> Unit): JavalinSecurity =
    JavalinSecurityDsl().apply(init).build()
