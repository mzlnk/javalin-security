package io.github.mzlnk.javalin.security

import io.javalin.Javalin
import io.javalin.http.HandlerType.GET
import io.javalin.plugin.bundled.CorsPlugin
import io.javalin.testtools.JavalinTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.HttpResponse
import java.net.http.HttpClient as JdkHttpClient
import java.net.http.HttpRequest as JdkHttpRequest

class JavalinSecurityCorsPreflightKtTest {

    @Test
    fun `should allow a CORS preflight request when allowCorsPreflight is enabled`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.registerPlugin(CorsPlugin { cors ->
                cors.addRule { it.anyHost() }
            })
            cfg.security { security ->
                security.http { http ->
                    http.rules { r ->
                        r.allowCorsPreflight = true
                        r.add("/api/*", GET, r.allow)
                        r.fallback = r.deny
                    }
                }
            }
            cfg.routes.get("/api/resource") { it.result("ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val preflightRequest = JdkHttpRequest.newBuilder(URI.create(client.origin + "/api/resource"))
                .method("OPTIONS", JdkHttpRequest.BodyPublishers.noBody())
                .header("Origin", "https://example.com")
                .header("Access-Control-Request-Method", "GET")
                .build()
            val preflightResponse = JdkHttpClient.newHttpClient().send(preflightRequest, HttpResponse.BodyHandlers.discarding())

            // then
            assertThat(preflightResponse.statusCode()).isNotEqualTo(401)
            assertThat(preflightResponse.statusCode()).isNotEqualTo(403)
            assertThat(client.get("/api/resource").code).isEqualTo(200)
        }
    }

    @Test
    fun `should deny an OPTIONS request when it is not a CORS preflight`() {
        // given
        val app = Javalin.create { cfg ->
            cfg.security { security ->
                security.http { http ->
                    http.rules { r ->
                        r.allowCorsPreflight = true
                        r.add("/api/*", GET, r.allow)
                        r.fallback = r.deny
                    }
                }
            }
            cfg.routes.options("/api/resource") { it.result("options-ok") }
        }

        JavalinTest.test(app) { _, client ->
            // when
            val request = JdkHttpRequest.newBuilder(URI.create(client.origin + "/api/resource"))
                .method("OPTIONS", JdkHttpRequest.BodyPublishers.noBody())
                .build()
            val response = JdkHttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())

            // then
            assertThat(response.statusCode()).isIn(401, 403)
        }
    }
}
