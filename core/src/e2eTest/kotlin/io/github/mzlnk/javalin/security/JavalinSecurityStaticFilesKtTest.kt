package io.github.mzlnk.javalin.security

import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.http.staticfiles.Location
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JavalinSecurityStaticFilesKtTest {

    @Test
    fun `should deny a static file by default when no rule permits it`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.staticFiles.add("/public", Location.CLASSPATH)
            cfg.security { security ->
                security.http { http -> http.rules { r -> r.add("/api/v1/*", GET, r.allow) } }
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/secret.txt")

            // then
            assertThat(response.code).isEqualTo(401)
            assertThat(response.body.string()).doesNotContain("top secret static content")
        }
    }

    @Test
    fun `should serve a static file when a rule explicitly permits it`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.staticFiles.add("/public", Location.CLASSPATH)
            cfg.security { security ->
                security.http { http -> http.rules { r -> r.add("/*", GET, r.allow) } }
            }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val response = client.get("/secret.txt")

            // then
            assertThat(response.code).isEqualTo(200)
            assertThat(response.body.string()).contains("top secret static content")
        }
    }
}
