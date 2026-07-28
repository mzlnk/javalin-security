package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import io.javalin.testtools.JavalinTest;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static io.github.mzlnk.javalin.security.E2EJavaTestSupport.asyncAuthenticationStrategy;
import static io.github.mzlnk.javalin.security.E2EJavaTestSupport.authenticationStrategy;
import static io.github.mzlnk.javalin.security.WsTestClient.tryConnect;
import static io.github.mzlnk.javalin.security.WsTestClient.upgradeRejectionBody;
import static org.assertj.core.api.Assertions.assertThat;

class JavalinSecurityWsJavaTest {

    private enum Role implements RouteRole { ADMIN }

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        if ("invalid".equals(user)) return new AuthenticationResult.Failure("super secret internal reason", null);
        String rolesHeader = ctx.header("X-Roles");
        var roles = rolesHeader == null
                ? java.util.Set.<RouteRole>of()
                : java.util.Arrays.stream(rolesHeader.split(","))
                        .map(name -> (RouteRole) Role.valueOf(name))
                        .collect(java.util.stream.Collectors.toSet());
        return new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity(user), roles));
    };

    @Test
    void should_reject_anonymous_upgrade_when_the_route_requires_authentication() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.authenticated()));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_deny_an_anonymous_upgrade_by_default_when_no_rule_matches_the_path() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.authentication = authenticationStrategy(headerAuthenticator))));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_deny_an_authenticated_upgrade_by_default_when_no_rule_matches_the_path() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/other/*", Rules.authenticated()));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of("X-User", "alice"));

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(403);
        });
    }

    @Test
    void should_permit_an_anonymous_upgrade_when_rule_is_allow() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.rules(rules -> rules.add("/ws/*", Rules.allow())))));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_allow_the_upgrade_when_authenticated_rule_is_hit_with_credentials() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.authenticated()));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of("X-User", "alice"));

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_allow_the_upgrade_when_the_authenticated_caller_holds_the_required_role() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.hasRole(Role.ADMIN)));
                ws.authentication = authenticationStrategy(ctx -> new AuthenticationResult.Success(
                        Authentication.authenticated(new TestIdentity("alice"), Role.ADMIN)));
            })));
            config.routes.ws("/ws/admin", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/admin", Map.of());

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_reject_the_upgrade_with_403_when_the_authenticated_caller_lacks_the_required_role() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.hasRole(Role.ADMIN)));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/admin", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/admin", Map.of("X-User", "bob"));

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(403);
        });
    }

    @Test
    void should_not_run_onConnect_when_the_upgrade_is_denied() {
        // given
        AtomicBoolean onConnectRan = new AtomicBoolean(false);
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.rules(rules -> rules.add("/ws/*", Rules.deny())))));
            config.routes.ws("/ws/chat", ws -> ws.onConnect(ctx -> onConnectRan.set(true)));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            Thread.sleep(200); // give the server time to potentially invoke onConnect (it must not)
            assertThat(onConnectRan.get()).isFalse();
        });
    }

    @Test
    void should_reject_the_upgrade_with_401_when_credentials_are_invalid() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of("X-User", "invalid"));

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_not_leak_the_internal_authenticator_message_when_authentication_fails() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            String body = upgradeRejectionBody(client.getOrigin(), "/ws/chat", Map.of("X-User", "invalid"));

            // then
            assertThat(body).doesNotContain("super secret internal reason");
        });
    }

    @Test
    void should_invoke_a_custom_unauthorizedHandler_when_the_upgrade_is_anonymously_denied() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.authenticated()));
                ws.authentication = E2EJavaTestSupport.authenticationStrategy(
                        ctx -> AuthenticationResult.NotAuthenticated.INSTANCE,
                        (ctx, failure) -> ctx.status(401).result("custom-ws-401"),
                        io.github.mzlnk.javalin.security.authorization.ForbiddenHandler.getDEFAULT()
                );
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_invoke_a_custom_forbiddenHandler_when_the_upgrade_is_forbidden() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.hasRole(Role.ADMIN)));
                ws.authentication = E2EJavaTestSupport.authenticationStrategy(
                        headerAuthenticator,
                        io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler.getDEFAULT(),
                        (ctx, auth) -> ctx.status(403).result("custom-ws-403")
                );
            })));
            config.routes.ws("/ws/admin", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/admin", Map.of("X-User", "bob"));

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(403);
        });
    }

    @Test
    void should_deny_upgrades_not_matched_by_a_specific_rule_when_a_fallback_deny_rule_is_set() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.rules(rules -> {
                        rules.add("/ws/public/*", Rules.allow());
                        rules.fallback = Rules.deny();
                    }))));
            config.routes.ws("/ws/public/chat", ws -> { });
            config.routes.ws("/ws/secret", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when / then
            var publicAttempt = tryConnect(client.getOrigin(), "/ws/public/chat", Map.of());
            assertThat(publicAttempt.connected()).isTrue();

            // when / then
            var secretAttempt = tryConnect(client.getOrigin(), "/ws/secret", Map.of());
            assertThat(secretAttempt.connected()).isFalse();
            assertThat(secretAttempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_deny_anonymous_and_allow_authenticated_upgrade_when_using_an_async_authenticator() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.authenticated()));
                ws.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx -> CompletableFuture.supplyAsync(() -> {
                    String user = ctx.header("X-User");
                    return user != null
                            ? new AuthenticationResult.Success(Authentication.authenticated(new TestIdentity(user)))
                            : AuthenticationResult.NotAuthenticated.INSTANCE;
                }));
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when / then
            var anonAttempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());
            assertThat(anonAttempt.connected()).isFalse();
            assertThat(anonAttempt.statusCode()).isEqualTo(401);

            // when / then
            var authAttempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of("X-User", "alice"));
            assertThat(authAttempt.connected()).isTrue();
        });
    }

    @Test
    void should_deny_the_upgrade_when_an_async_authenticator_future_completes_with_Failure() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx ->
                        CompletableFuture.completedFuture(new AuthenticationResult.Failure("async credential failure", null)));
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_not_leak_the_failure_message_when_an_async_authenticator_future_completes_with_Failure() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx ->
                        CompletableFuture.completedFuture(new AuthenticationResult.Failure("async credential failure", null)));
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            String body = upgradeRejectionBody(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(body).doesNotContain("async credential failure");
        });
    }

    @Test
    void should_deny_the_upgrade_when_an_async_authenticator_future_completes_exceptionally() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx ->
                        CompletableFuture.failedFuture(new RuntimeException("internal IdP crash")));
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_not_leak_the_cause_when_an_async_authenticator_future_completes_exceptionally() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx ->
                        CompletableFuture.failedFuture(new RuntimeException("internal IdP crash")));
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            String body = upgradeRejectionBody(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(body).doesNotContain("internal IdP crash");
        });
    }

    @Test
    void should_deny_the_upgrade_when_an_async_authenticator_throws_synchronously() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx -> {
                    throw new IllegalStateException("sync crash in async ws authenticator");
                });
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(attempt.connected()).isFalse();
            assertThat(attempt.statusCode()).isEqualTo(401);
        });
    }

    @Test
    void should_not_leak_the_cause_when_an_async_authenticator_throws_synchronously() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.allow()));
                ws.authentication = E2EJavaTestSupport.asyncAuthenticationStrategy(ctx -> {
                    throw new IllegalStateException("sync crash in async ws authenticator");
                });
            })));
            config.routes.ws("/ws/chat", ws -> { });
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            String body = upgradeRejectionBody(client.getOrigin(), "/ws/chat", Map.of());

            // then
            assertThat(body).doesNotContain("sync crash in async ws authenticator");
        });
    }

    @Test
    void should_expose_the_authentication_set_during_upgrade_from_WsContext_in_onConnect() throws Exception {
        // given
        AtomicReference<String> identityName = new AtomicReference<>(null);
        CountDownLatch connectLatch = new CountDownLatch(1);
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.rules(rules -> rules.add("/ws/*", Rules.authenticated()));
                ws.authentication = authenticationStrategy(headerAuthenticator);
            })));
            config.routes.ws("/ws/chat", ws -> ws.onConnect(ctx -> {
                Authentication authentication = SecurityExtensions.authentication(ctx);
                identityName.set(authentication.getIdentity() instanceof TestIdentity p ? p.getName() : null);
                connectLatch.countDown();
            }));
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            tryConnect(client.getOrigin(), "/ws/chat", Map.of("X-User", "alice"));

            // then
            assertThat(connectLatch.await(3, TimeUnit.SECONDS)).isTrue();
            assertThat(identityName.get()).isEqualTo("alice");
        });
    }

    @Test
    void should_permit_an_anonymous_upgrade_when_the_WS_endpoint_declares_the_Anyone_role() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws ->
                    ws.rules(rules -> rules.fallback = Rules.deny()))));
            config.routes.ws("/ws/public", ws -> { }, Anyone.INSTANCE);
        });

        JavalinTest.test(app, (server, client) -> {
            // when
            var attempt = tryConnect(client.getOrigin(), "/ws/public", Map.of());

            // then
            assertThat(attempt.connected()).isTrue();
        });
    }

    @Test
    void should_grant_the_upgrade_when_the_WS_endpoint_declares_roles_and_the_caller_holds_a_matching_role() {
        // given
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.ws(ws -> {
                ws.authentication = authenticationStrategy(headerAuthenticator);
                ws.rules(rules -> rules.fallback = Rules.deny()); // rule table must NOT be consulted
            })));
            config.routes.ws("/ws/admin", ws -> { }, Role.ADMIN);
        });

        JavalinTest.test(app, (server, client) -> {
            // when / then
            var anonAttempt = tryConnect(client.getOrigin(), "/ws/admin", Map.of());
            assertThat(anonAttempt.statusCode()).isEqualTo(401);

            // when / then
            var forbiddenAttempt = tryConnect(client.getOrigin(), "/ws/admin", Map.of("X-User", "bob"));
            assertThat(forbiddenAttempt.statusCode()).isEqualTo(403);

            // when / then
            var grantedAttempt = tryConnect(client.getOrigin(), "/ws/admin", Map.of("X-User", "alice", "X-Roles", "ADMIN"));
            assertThat(grantedAttempt.connected()).isTrue();
        });
    }
}
