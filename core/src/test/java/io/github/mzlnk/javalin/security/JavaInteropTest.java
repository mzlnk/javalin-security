package io.github.mzlnk.javalin.security;

import io.github.mzlnk.javalin.security.authentication.AsyncAuthenticator;
import io.github.mzlnk.javalin.security.authentication.Authentication;
import io.github.mzlnk.javalin.security.authentication.Authenticator;
import io.github.mzlnk.javalin.security.authentication.AuthenticationResult;
import io.github.mzlnk.javalin.security.authentication.AuthenticationStrategy;
import io.github.mzlnk.javalin.security.authentication.UnauthorizedHandler;
import io.github.mzlnk.javalin.security.authorization.ForbiddenHandler;
import io.github.mzlnk.javalin.security.authorization.Rule;
import io.github.mzlnk.javalin.security.authorization.Rules;
import io.javalin.Javalin;
import io.javalin.security.RouteRole;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;

import static io.javalin.http.HandlerType.*;
import static org.assertj.core.api.Assertions.*;

class JavaInteropTest {
    private enum Role implements RouteRole { ADMIN, READ, WRITE }

    private final Authenticator headerAuthenticator = ctx -> {
        String user = ctx.header("X-User");
        if (user == null) return AuthenticationResult.NotAuthenticated.INSTANCE;
        return new AuthenticationResult.Success(
                Authentication.authenticated(new TestPrincipal(user))
        );
    };

    @Test
    void plugin_registers_without_unit_instance_or_kotlin_singleton_getters() {
        // No Unit.INSTANCE, no .INSTANCE.getX() — compiles cleanly from Java
        Javalin app = Javalin.create(config -> {
            config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                http.authentication = authenticationStrategy(headerAuthenticator);
                http.rules(rules -> {
                    rules.add("/api/*", GET, Rules.allow());
                    rules.add("/admin/*", POST, Rules.hasRole(Role.ADMIN));
                    rules.fallback = Rules.deny();
                });
            })));
            config.routes.get("/api/resource", ctx -> ctx.result("ok"));
        });

        assertThat(app).isNotNull();
    }

    @Test
    void all_builtin_rules_are_accessible_as_static_methods() {
        assertThat(Rules.allow()).isNotNull();
        assertThat(Rules.deny()).isNotNull();
        assertThat(Rules.authenticated()).isNotNull();
        assertThat(Rules.hasRole(Role.READ)).isNotNull();
        assertThat(Rules.hasAnyRole(Role.READ, Role.WRITE)).isNotNull();
    }

    @Test
    void custom_rule_as_java_lambda() {
        // Rule is a fun interface — Java lambda works directly
        Rule customRule = (auth, ctx) -> auth.isAuthenticated();

        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http ->
                        http.rules(rules -> rules.fallback = customRule)))));

        assertThat(app).isNotNull();
    }

    @Test
    void custom_authenticator_as_java_lambda() {
        Authenticator alwaysBob = ctx ->
                new AuthenticationResult.Success(
                        Authentication.authenticated(new TestPrincipal("bob")));

        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.fallback = Rules.authenticated());
                    http.authentication = authenticationStrategy(alwaysBob);
                }))));

        assertThat(app).isNotNull();
    }

    @Test
    void custom_unauthorized_and_forbidden_handlers() {
        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.fallback = Rules.hasRole(Role.ADMIN));
                    http.authentication = new AuthenticationStrategy.Sync() {
                        @Override
                        public Authenticator authenticator() {
                            return headerAuthenticator;
                        }

                        @Override
                        public UnauthorizedHandler getUnauthorizedHandler() {
                            return (ctx, failure) -> ctx.status(401).result("custom-401");
                        }

                        @Override
                        public ForbiddenHandler getForbiddenHandler() {
                            return (ctx, auth) -> ctx.status(403).result("custom-403");
                        }
                    };
                }))));

        assertThat(app).isNotNull();
    }

    @Test
    void async_authenticationStrategy_can_be_built_directly_from_java() {
        // AuthenticationStrategy.Async has a single abstract method — a Java lambda cannot
        // implement it directly (the interface also declares defaulted properties that are
        // abstract at the JVM level), so a small anonymous class is used, mirroring `authenticationStrategy(...)`.
        AuthenticationStrategy.Async async = new AuthenticationStrategy.Async() {
            @Override
            public AsyncAuthenticator authenticator() {
                return ctx -> CompletableFuture.completedFuture(AuthenticationResult.NotAuthenticated.INSTANCE);
            }

            @Override
            public UnauthorizedHandler getUnauthorizedHandler() {
                return UnauthorizedHandler.getDEFAULT();
            }

            @Override
            public ForbiddenHandler getForbiddenHandler() {
                return ForbiddenHandler.getDEFAULT();
            }
        };

        Javalin app = Javalin.create(config ->
                config.registerPlugin(new JavalinSecurityPlugin(security -> security.http(http -> {
                    http.rules(rules -> rules.fallback = Rules.allow());
                    http.authentication = async;
                }))));

        assertThat(app).isNotNull();
    }

    /**
     * Builds an {@link AuthenticationStrategy.Sync} directly from Java — the way a custom
     * authentication mechanism (not provided by a companion library's {@code jwt { }} /
     * {@code basicAuth { }} factory) is wired up.
     */
    private static AuthenticationStrategy.Sync authenticationStrategy(Authenticator authenticator) {
        return new AuthenticationStrategy.Sync() {
            @Override
            public Authenticator authenticator() {
                return authenticator;
            }
        };
    }
}
