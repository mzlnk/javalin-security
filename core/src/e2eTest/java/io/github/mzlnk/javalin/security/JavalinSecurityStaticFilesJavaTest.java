package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import static io.javalin.http.HandlerType.GET;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityStaticFilesJavaTest {

    @Test
    void should_deny_a_static_file_by_default_when_no_rule_permits_it() {
        // given
        Javalin app = Javalin.create(config -> {
            config.staticFiles.add("/public", Location.CLASSPATH);
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                    http.rules(rules -> rules.add("/api/v1/*", GET, Rules.allow())))));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/secret.txt");

            // then
            assertThat(response.code()).isEqualTo(401);
            assertThat(response.body().string()).doesNotContain("top secret static content");
        });
    }

    @Test
    void should_serve_a_static_file_when_a_rule_explicitly_permits_it() {
        // given
        Javalin app = Javalin.create(config -> {
            config.staticFiles.add("/public", Location.CLASSPATH);
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                    http.rules(rules -> rules.add("/*", GET, Rules.allow())))));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var response = client.get("/secret.txt");

            // then
            assertThat(response.code()).isEqualTo(200);
            assertThat(response.body().string()).contains("top secret static content");
        });
    }
}
