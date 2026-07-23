package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static io.javalin.http.HandlerType.GET;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityHttpMethodsJavaTest {

    @Test
    void should_treat_head_like_get_when_the_route_is_guarded_by_an_allow_get_rule() throws Exception {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                    http.rules(rules -> rules.add("/api/v1/*", GET, Rules.allow())))));
            config.routes.get("/api/v1/resource", ctx -> ctx.result("ok"));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            HttpRequest request = HttpRequest.newBuilder(URI.create(client.getOrigin() + "/api/v1/resource"))
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            // then
            assertThat(response.statusCode()).isEqualTo(200);
        });
    }
}
