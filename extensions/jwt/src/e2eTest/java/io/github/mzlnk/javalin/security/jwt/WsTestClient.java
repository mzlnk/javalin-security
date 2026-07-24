package io.github.mzlnk.javalin.security.jwt;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Shared WebSocket upgrade helpers for JWT e2e tests. */
final class WsTestClient {

    private WsTestClient() {
    }

    /** Result of a WebSocket upgrade attempt. */
    record UpgradeAttempt(boolean connected, Integer statusCode) {
    }

    /** Attempts a WebSocket upgrade; on HTTP rejection, {@code statusCode} holds the response status. */
    static UpgradeAttempt tryConnect(String origin, String path, Map<String, String> headers) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean connected = new AtomicBoolean(false);
        AtomicReference<Integer> statusCode = new AtomicReference<>(null);

        URI wsUri = URI.create(origin.replace("http://", "ws://") + path);
        WebSocket.Builder builder = HttpClient.newHttpClient().newWebSocketBuilder();
        headers.forEach(builder::header);

        builder.buildAsync(wsUri, new WebSocket.Listener() {
            @Override
            public void onOpen(WebSocket webSocket) {
                connected.set(true);
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "").thenRun(latch::countDown);
            }
        }).exceptionally(t -> {
            Throwable cause = (t instanceof CompletionException && t.getCause() != null) ? t.getCause() : t;
            if (cause instanceof WebSocketHandshakeException handshakeException) {
                statusCode.set(handshakeException.getResponse().statusCode());
            }
            latch.countDown();
            return null;
        });

        awaitQuietly(latch, 3, TimeUnit.SECONDS);
        return new UpgradeAttempt(connected.get(), statusCode.get());
    }

    private static void awaitQuietly(CountDownLatch latch, long timeout, TimeUnit unit) {
        try {
            latch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
