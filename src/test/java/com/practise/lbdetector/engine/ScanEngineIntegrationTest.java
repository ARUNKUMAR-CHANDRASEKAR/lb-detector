package com.practise.lbdetector.engine;

import com.practise.lbdetector.engine.detector.ClockSkewDetector;
import com.practise.lbdetector.engine.detector.ContentVarianceDetector;
import com.practise.lbdetector.engine.detector.Detector;
import com.practise.lbdetector.engine.detector.DnsDetector;
import com.practise.lbdetector.engine.detector.HeaderVarianceDetector;
import com.practise.lbdetector.engine.detector.LatencyDetector;
import com.practise.lbdetector.engine.detector.SignatureDetector;
import com.practise.lbdetector.engine.detector.TlsVarianceDetector;
import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.ProbeSettings;
import com.practise.lbdetector.engine.model.ScanTarget;
import com.practise.lbdetector.engine.model.Verdict;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end over real HTTP: a local server pretends to be a load balancer alternating between
 * two backends, and another is a single plain server.
 */
class ScanEngineIntegrationTest {

    private static final List<Detector> DETECTORS = List.of(new SignatureDetector(), new HeaderVarianceDetector(),
            new TlsVarianceDetector(), new ClockSkewDetector(), new ContentVarianceDetector(), new DnsDetector(),
            new LatencyDetector());

    private final ScanEngine engine = new ScanEngine(
            new Prober(ProbeSettings.defaults(), Clock.systemUTC()), DETECTORS, Clock.systemUTC());

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    private URI start(boolean balanced) throws IOException {
        var counter = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/", exchange -> {
            var headers = exchange.getResponseHeaders();
            if (balanced) {
                boolean nodeB = counter.getAndIncrement() % 2 == 1;
                headers.set("X-Backend-Server", nodeB ? "node-b" : "node-a");
                headers.set("ETag", nodeB ? "\"b-123\"" : "\"a-456\"");
                headers.add("Set-Cookie", "AWSALB=opaque; Path=/");
            } else {
                headers.set("ETag", "\"same\"");
            }
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
    }

    @Test
    void detectsSimulatedLoadBalancer() throws IOException {
        var report = engine.scan(new ScanTarget(start(true), 12));

        assertThat(report.verdict()).isEqualTo(Verdict.LOAD_BALANCED);
        assertThat(report.identifiedProducts()).contains("AWS Application Load Balancer");
        assertThat(report.evidence()).extracting(Evidence::detector)
                .contains("signature", "header-variance", "content-variance");
        assertThat(report.stats().httpSucceeded()).isEqualTo(12);
    }

    @Test
    void singleServerShowsNoEvidence() throws IOException {
        var report = engine.scan(new ScanTarget(start(false), 12));

        assertThat(report.verdict()).as(() -> ReportFormatter.toText(report)).isEqualTo(Verdict.NO_EVIDENCE);
        assertThat(report.evidence()).as(() -> ReportFormatter.toText(report)).isEmpty();
    }

    @Test
    void unreachableTargetProducesWarningNotException() {
        var report = engine.scan(new ScanTarget(URI.create("http://127.0.0.1:1/"), 3));

        assertThat(report.stats().httpSucceeded()).isZero();
        assertThat(report.warnings()).anyMatch(w -> w.contains("No probe succeeded"));
    }
}
