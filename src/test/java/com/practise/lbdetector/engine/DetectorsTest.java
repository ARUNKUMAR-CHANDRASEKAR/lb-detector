package com.practise.lbdetector.engine;

import com.practise.lbdetector.engine.detector.ClockSkewDetector;
import com.practise.lbdetector.engine.detector.ContentVarianceDetector;
import com.practise.lbdetector.engine.detector.DnsDetector;
import com.practise.lbdetector.engine.detector.HeaderVarianceDetector;
import com.practise.lbdetector.engine.detector.LatencyDetector;
import com.practise.lbdetector.engine.detector.SignatureDetector;
import com.practise.lbdetector.engine.detector.TlsVarianceDetector;
import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;
import com.practise.lbdetector.engine.model.ScanTarget;
import com.practise.lbdetector.engine.model.TlsSample;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.IntFunction;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Detectors are pure functions over {@link ProbeData}, so they are tested with synthetic samples.
 */
class DetectorsTest {

    private static final Instant T0 = Instant.parse("2026-11-24T04:00:00Z");
    private static final ScanTarget TARGET = new ScanTarget(URI.create("https://shop.example/"), 10);

    private static List<HttpSample> samples(int n, IntFunction<Map<String, List<String>>> headers) {
        var list = new ArrayList<HttpSample>();
        for (int i = 0; i < n; i++) {
            list.add(new HttpSample(i, 200, headers.apply(i), T0.plusSeconds(i), 20, "HTTP_2"));
        }
        return list;
    }

    private static ProbeData http(List<HttpSample> samples) {
        return new ProbeData(TARGET, samples, List.of(), List.of(), List.of());
    }

    @Nested
    class Signature {
        @Test
        void identifiesAwsAlbFromCookie() {
            var data = http(samples(3, i -> Map.of("Set-Cookie", List.of("AWSALB=abc; Path=/"))));
            var evidence = new SignatureDetector().analyze(data);
            assertThat(evidence).extracting(Evidence::product).containsExactly("AWS Application Load Balancer");
            assertThat(evidence.getFirst().weight()).isGreaterThanOrEqualTo(0.9);
        }

        @Test
        void identifiesF5AndCloudflareTogether() {
            var data = http(samples(2, i -> Map.of(
                    "Set-Cookie", List.of("BIGipServerpool_web=1677787402.36895.0000"),
                    "CF-RAY", List.of("8c1d2e3f4a5b6c7d-SIN"))));
            assertThat(new SignatureDetector().analyze(data)).extracting(Evidence::product)
                    .containsExactlyInAnyOrder("F5 BIG-IP", "Cloudflare");
        }

        @Test
        void detectsNetscalerMangledConnectionHeader() {
            var data = http(samples(1, i -> Map.of("Cneonction", List.of("close"))));
            assertThat(new SignatureDetector().analyze(data)).extracting(Evidence::product)
                    .containsExactly("Citrix NetScaler / ADC");
        }

        @Test
        void plainResponseHasNoSignature() {
            var data = http(samples(3, i -> Map.of("Content-Type", List.of("text/html"))));
            assertThat(new SignatureDetector().analyze(data)).isEmpty();
        }
    }

    @Nested
    class HeaderVariance {
        @Test
        void differentBackendHeadersAreEvidence() {
            var data = http(samples(6, i -> Map.of("X-Served-By", List.of("web-0" + (i % 3)))));
            var evidence = new HeaderVarianceDetector().analyze(data);
            assertThat(evidence).hasSize(1);
            assertThat(evidence.getFirst().weight()).isEqualTo(0.8);
            assertThat(evidence.getFirst().details()).hasSize(3);
        }

        @Test
        void requestIdsAreIgnored() {
            var data = http(samples(6, i -> Map.of("X-Request-Id", List.of("req-" + i))));
            assertThat(new HeaderVarianceDetector().analyze(data)).isEmpty();
        }

        @Test
        void identicalServerHeaderIsNotEvidence() {
            var data = http(samples(6, i -> Map.of("Server", List.of("nginx"))));
            assertThat(new HeaderVarianceDetector().analyze(data)).isEmpty();
        }
    }

    @Nested
    class ClockSkew {
        @Test
        void twoClocksSevenSecondsApartAreDetected() {
            var data = http(samples(10, i -> Map.of("Date", List.of(DateTimeFormatter.RFC_1123_DATE_TIME
                    .format(T0.plusSeconds(i).plusSeconds(i % 2 == 0 ? 0 : 7).atZone(ZoneOffset.UTC))))));
            var evidence = new ClockSkewDetector().analyze(data);
            assertThat(evidence).hasSize(1);
            assertThat(evidence.getFirst().details()).hasSize(2);
        }

        @Test
        void singleClockIsNotEvidence() {
            var data = http(samples(10, i -> Map.of("Date", List.of(DateTimeFormatter.RFC_1123_DATE_TIME
                    .format(T0.plusSeconds(i).atZone(ZoneOffset.UTC))))));
            assertThat(new ClockSkewDetector().analyze(data)).isEmpty();
        }
    }

    @Nested
    class ContentVariance {
        @Test
        void repeatingEtagsAreStrongEvidence() {
            var data = http(samples(8, i -> Map.of("ETag", List.of(i % 2 == 0 ? "\"a1\"" : "\"b2\""))));
            var evidence = new ContentVarianceDetector().analyze(data);
            assertThat(evidence).singleElement().satisfies(e -> assertThat(e.weight()).isEqualTo(0.6));
        }

        @Test
        void uniqueEtagPerResponseIsWeak() {
            var data = http(samples(8, i -> Map.of("ETag", List.of("\"v" + i + "\""))));
            var evidence = new ContentVarianceDetector().analyze(data);
            assertThat(evidence).singleElement().satisfies(e -> assertThat(e.weight()).isLessThan(0.2));
        }
    }

    @Test
    void dnsRoundRobinIsDetected() {
        var data = new ProbeData(TARGET, List.of(), List.of(),
                List.of(List.of("203.0.113.1", "203.0.113.2"), List.of("203.0.113.2", "203.0.113.1")), List.of());
        assertThat(new DnsDetector().analyze(data)).hasSize(2);
    }

    @Test
    void differentCertificatesAreDetected() {
        var tls = List.of(
                new TlsSample(0, "CN=shop.example", "CN=CA", "1a", "aa".repeat(32), "TLSv1.3", "TLS_AES_128_GCM_SHA256"),
                new TlsSample(1, "CN=shop.example", "CN=CA", "2b", "bb".repeat(32), "TLSv1.3", "TLS_AES_128_GCM_SHA256"));
        var data = new ProbeData(TARGET, List.of(), tls, List.of(), List.of());
        assertThat(new TlsVarianceDetector().analyze(data)).singleElement()
                .satisfies(e -> assertThat(e.summary()).contains("2 different certificates"));
    }

    @Test
    void bimodalLatencyIsDetected() {
        var list = new ArrayList<HttpSample>();
        for (int i = 0; i < 20; i++) {
            list.add(new HttpSample(i, 200, Map.of(), T0, i % 2 == 0 ? 12 + i % 3 : 95 + i % 5, "HTTP_2"));
        }
        assertThat(new LatencyDetector().analyze(http(list))).hasSize(1);
    }

    @Test
    void coldStartSlowFirstWaveIsNotEvidence() {
        // First probes are slow because the JVM/HTTP client is warming up, not because of a second backend.
        var list = new ArrayList<HttpSample>();
        for (int i = 0; i < 12; i++) {
            list.add(new HttpSample(i, 200, Map.of(), T0, i < 4 ? 70 + i : 6 + i % 3, "HTTP_2"));
        }
        assertThat(new LatencyDetector().analyze(http(list))).isEmpty();
    }

    @Test
    void slowBurstInOneHalfOfTheRunIsNotEvidence() {
        var list = new ArrayList<HttpSample>();
        for (int i = 0; i < 20; i++) {
            list.add(new HttpSample(i, 200, Map.of(), T0, i >= 4 && i < 10 ? 90 : 10, "HTTP_2"));
        }
        assertThat(new LatencyDetector().analyze(http(list))).isEmpty();
    }

    @Test
    void steadyLatencyIsNotEvidence() {
        var list = new ArrayList<HttpSample>();
        for (int i = 0; i < 20; i++) {
            list.add(new HttpSample(i, 200, Map.of(), T0, 40 + i % 4, "HTTP_2"));
        }
        assertThat(new LatencyDetector().analyze(http(list))).isEmpty();
    }
}
