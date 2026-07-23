package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.plugin.bundled.CorsPlugin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static io.javalin.http.HandlerType.GET;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityCorsPreflightJavaTest {

    @Test
    void should_allow_a_cors_preflight_request_when_allowCorsPreflight_is_enabled() throws Exception {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new CorsPlugin(cors -> cors.addRule(it -> it.anyHost())));
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                    http.rules(rules -> {
                        rules.allowCorsPreflight = true;
                        rules.add("/api/*", GET, Rules.allow());
                        rules.fallback = Rules.deny();
                    }))));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            HttpRequest preflightRequest = HttpRequest.newBuilder(URI.create(client.getOrigin() + "/api/resource"))
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "GET")
                    .build();
            HttpResponse<Void> preflightResponse =
                    HttpClient.newHttpClient().send(preflightRequest, HttpResponse.BodyHandlers.discarding());

            // then
            assertThat(preflightResponse.statusCode()).isNotEqualTo(401);
            assertThat(preflightResponse.statusCode()).isNotEqualTo(403);
            assertThat(client.get("/api/resource").code()).isEqualTo(200);
        });
    }

    @Test
    void should_deny_an_options_request_when_it_is_not_a_cors_preflight() throws Exception {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                    http.rules(rules -> {
                        rules.allowCorsPreflight = true;
                        rules.add("/api/*", GET, Rules.allow());
                        rules.fallback = Rules.deny();
                    }))));
            config.routes.options("/api/resource", ctx -> ctx.result("options-ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            HttpRequest request = HttpRequest.newBuilder(URI.create(client.getOrigin() + "/api/resource"))
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            // then
            assertThat(response.statusCode()).isIn(401, 403);
        });
    }
}
