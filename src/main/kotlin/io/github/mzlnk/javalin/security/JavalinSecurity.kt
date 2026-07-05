package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.http.HttpConfig

/**
 * The immutable, fully-built security configuration produced by the [javalinSecurity] DSL.
 */
class JavalinSecurity internal constructor(
    internal val httpConfig: HttpConfig,
) {

    class Dsl {

        private var httpConfig: HttpConfig = HttpConfig.Dsl().build()

        fun http(init: HttpConfig.Dsl.() -> Unit) {
            this.httpConfig = HttpConfig.Dsl().apply(init).build()
        }

        fun build(): JavalinSecurity = JavalinSecurity(httpConfig = httpConfig)

    }

}

/** Builds a [JavalinSecurity] configuration using the DSL. */
fun javalinSecurity(init: JavalinSecurity.Dsl.() -> Unit): JavalinSecurity =
    JavalinSecurity.Dsl().apply(init).build()
