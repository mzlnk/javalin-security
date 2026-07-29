package io.github.mzlnk.javalin.security

import io.github.mzlnk.javalin.security.authorization.Rules
import io.javalin.Javalin
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.HttpResponse
import java.net.http.HttpClient as JdkHttpClient
import java.net.http.HttpRequest as JdkHttpRequest

class JavalinSecurityHttpMethodsKtTest {

    @Test
    fun `should treat HEAD like GET when the route is guarded by an allow GET rule`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.rules.get("/api/v1/*", Rules.allow())
            }
            cfg.routes.get("/api/v1/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val request = JdkHttpRequest.newBuilder(URI.create(client.origin + "/api/v1/resource"))
                .method("HEAD", JdkHttpRequest.BodyPublishers.noBody())
                .build()
            val response = JdkHttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())

            // then
            assertThat(response.statusCode()).isEqualTo(200)
        }
    }
}
