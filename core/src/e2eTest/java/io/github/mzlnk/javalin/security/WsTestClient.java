package io.github.mzlnk.javalin.security;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Java-side counterpart of the WebSocket test helpers duplicated across the Kotlin e2e WS test
 * classes — attempts a WebSocket upgrade and reports whether it succeeded or was rejected by the
 * security guard before the handshake completed.
 */
final class WsTestClient {

    private WsTestClient() {
    }

    /** The outcome of a WebSocket upgrade attempt. */
    record UpgradeAttempt(boolean connected, Integer statusCode) {
    }

    /**
     * Attempts a WebSocket upgrade and returns whether it connected, and — on HTTP-level
     * rejection — the server's status code (extracted from {@link WebSocketHandshakeException}).
     */
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

    /**
     * Attempts a WebSocket upgrade and returns the rejection response body as a String. Used only
     * to verify that no internal detail is present in a denial response.
     */
    static String upgradeRejectionBody(String origin, String path, Map<String, String> headers) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> body = new AtomicReference<>("");

        URI wsUri = URI.create(origin.replace("http://", "ws://") + path);
        WebSocket.Builder builder = HttpClient.newHttpClient().newWebSocketBuilder();
        headers.forEach(builder::header);

        builder.buildAsync(wsUri, new WebSocket.Listener() {
            @Override
            public void onOpen(WebSocket webSocket) {
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "").thenRun(latch::countDown);
            }
        }).exceptionally(t -> {
            Throwable cause = (t instanceof CompletionException && t.getCause() != null) ? t.getCause() : t;
            if (cause instanceof WebSocketHandshakeException handshakeException) {
                Object responseBody = handshakeException.getResponse().body();
                body.set(responseBody == null ? "" : responseBody.toString());
            }
            latch.countDown();
            return null;
        });

        awaitQuietly(latch, 3, TimeUnit.SECONDS);
        return body.get();
    }

    /**
     * Sends a raw HTTP WebSocket upgrade request via a plain TCP socket, giving full control over
     * which headers are included (or omitted) — used for headers the JDK WebSocket client manages
     * automatically, such as {@code Origin}.
     *
     * Returns the HTTP response status code from the server's status line (e.g. 101, 401, 403).
     */
    static int rawUpgradeStatusCode(String host, int port, String path, Map<String, String> extraHeaders) {
        try (Socket socket = new Socket(host, port)) {
            socket.setSoTimeout(5_000);
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.ISO_8859_1));
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));

            out.write("GET " + path + " HTTP/1.1\r\n");
            out.write("Host: " + host + ":" + port + "\r\n");
            out.write("Upgrade: websocket\r\n");
            out.write("Connection: Upgrade\r\n");
            out.write("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
            out.write("Sec-WebSocket-Version: 13\r\n");
            for (Map.Entry<String, String> header : extraHeaders.entrySet()) {
                out.write(header.getKey() + ": " + header.getValue() + "\r\n");
            }
            out.write("\r\n");
            out.flush();

            String statusLine = in.readLine();
            if (statusLine == null) return -1;
            String[] parts = statusLine.split(" ");
            return parts.length > 1 ? Integer.parseInt(parts[1]) : -1;
        } catch (IOException e) {
            return -1;
        }
    }

    private static void awaitQuietly(CountDownLatch latch, long timeout, TimeUnit unit) {
        try {
            latch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
