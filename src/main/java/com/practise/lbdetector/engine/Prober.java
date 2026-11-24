package com.practise.lbdetector.engine;

import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;
import com.practise.lbdetector.engine.model.ProbeSettings;
import com.practise.lbdetector.engine.model.ScanTarget;
import com.practise.lbdetector.engine.model.TlsSample;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.regex.Pattern;

/**
 * Collects raw observations from the target using only the JDK.
 *
 * <p>Key design choices:
 * <ul>
 *   <li>Every HTTP probe uses a <b>brand-new {@link HttpClient}</b>, so connection reuse can't pin
 *       all probes to one backend (L4 balancers distribute per connection).</li>
 *   <li>No cookie handler, so sticky-session cookies are never sent back.</li>
 *   <li>Every TLS probe uses a <b>fresh {@link SSLContext}</b>, so there is no session resumption.</li>
 *   <li>Probes run on <b>virtual threads</b>, throttled by a semaphore to stay polite.</li>
 * </ul>
 */
public final class Prober {

    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9.]+$|^\\[?[0-9a-fA-F:]+]?$");

    private final ProbeSettings settings;
    private final Clock clock;

    public Prober(ProbeSettings settings, Clock clock) {
        this.settings = settings;
        this.clock = clock;
    }

    public ProbeData probe(ScanTarget target) {
        var errors = Collections.synchronizedList(new ArrayList<String>());
        var gate = new Semaphore(Math.max(1, settings.concurrency()));

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            // DNS first (sequential, cheap) so rotation between lookups is observable.
            List<List<String>> dns = resolveRepeatedly(target.host(), errors);

            List<Future<HttpSample>> httpFutures = new ArrayList<>();
            for (int i = 0; i < target.samples(); i++) {
                final int index = i;
                httpFutures.add(executor.submit(throttled(gate, () -> httpSample(index, target))));
            }
            List<Future<TlsSample>> tlsFutures = new ArrayList<>();
            if (target.isHttps()) {
                for (int i = 0; i < settings.tlsSamples(); i++) {
                    final int index = i;
                    tlsFutures.add(executor.submit(throttled(gate, () -> tlsSample(index, target))));
                }
            }
            var http = collect(httpFutures, "HTTP", errors);
            var tls = collect(tlsFutures, "TLS", errors);
            return new ProbeData(target, http, tls, dns, errors);
        }
    }

    private List<List<String>> resolveRepeatedly(String host, List<String> errors) {
        var stripped = host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
        if (IP_LITERAL.matcher(stripped).matches()) {
            return List.of(List.of(stripped));
        }
        List<List<String>> lookups = new ArrayList<>();
        for (int i = 0; i < settings.dnsLookups(); i++) {
            try {
                lookups.add(Arrays.stream(InetAddress.getAllByName(stripped))
                        .map(InetAddress::getHostAddress).toList());
            } catch (Exception e) {
                errors.add("DNS lookup " + i + " failed: " + e.getMessage());
            }
        }
        return lookups;
    }

    private HttpSample httpSample(int index, ScanTarget target) throws Exception {
        try (var client = HttpClient.newBuilder()
                .connectTimeout(settings.timeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_2)
                .build()) {
            var request = HttpRequest.newBuilder(target.uri())
                    .timeout(settings.timeout())
                    .header("User-Agent", settings.userAgent())
                    .header("Cache-Control", "no-cache") // ask CDNs/caches to go to origin
                    .GET()
                    .build();
            var sentAt = clock.instant();
            long start = System.nanoTime();
            var response = client.send(request, HttpResponse.BodyHandlers.discarding());
            long latencyMs = (System.nanoTime() - start) / 1_000_000;
            return new HttpSample(index, response.statusCode(), response.headers().map(),
                    sentAt, latencyMs, response.version().name());
        }
    }

    private TlsSample tlsSample(int index, ScanTarget target) throws Exception {
        var context = SSLContext.getInstance("TLS");
        context.init(null, null, null); // fresh session cache => full handshake every time
        try (var socket = (SSLSocket) context.getSocketFactory().createSocket()) {
            var params = socket.getSSLParameters();
            params.setServerNames(List.of(new SNIHostName(target.host())));
            params.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(params);
            int timeoutMs = (int) settings.timeout().toMillis();
            socket.connect(new InetSocketAddress(target.host(), target.port()), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            socket.startHandshake();

            var session = socket.getSession();
            var cert = (X509Certificate) session.getPeerCertificates()[0];
            var fingerprint = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            return new TlsSample(index,
                    cert.getSubjectX500Principal().getName(),
                    cert.getIssuerX500Principal().getName(),
                    new BigInteger(1, cert.getSerialNumber().toByteArray()).toString(16),
                    fingerprint, session.getProtocol(), session.getCipherSuite());
        }
    }

    private static <T> Callable<T> throttled(Semaphore gate, Callable<T> task) {
        return () -> {
            gate.acquire();
            try {
                return task.call();
            } finally {
                gate.release();
            }
        };
    }

    private static <T> List<T> collect(List<Future<T>> futures, String kind, List<String> errors) {
        List<T> results = new ArrayList<>();
        for (int i = 0; i < futures.size(); i++) {
            try {
                results.add(futures.get(i).get());
            } catch (ExecutionException e) {
                var cause = e.getCause();
                errors.add(kind + " probe " + i + " failed: " + cause.getClass().getSimpleName()
                        + (cause.getMessage() != null ? " - " + cause.getMessage() : ""));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                errors.add(kind + " probe " + i + " interrupted");
            }
        }
        return results;
    }
}
