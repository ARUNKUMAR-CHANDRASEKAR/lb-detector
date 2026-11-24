package com.practise.lbdetector.engine.model;

import java.time.Duration;

/**
 * Tuning knobs for the prober.
 *
 * @param timeout      per-request connect/read timeout
 * @param concurrency  maximum probes in flight at once (be polite to the target)
 * @param tlsSamples   number of fresh TLS handshakes to perform for https targets
 * @param dnsLookups   number of DNS resolutions to perform
 * @param userAgent    User-Agent header sent with every request
 */
public record ProbeSettings(Duration timeout, int concurrency, int tlsSamples, int dnsLookups, String userAgent) {

    public static ProbeSettings defaults() {
        return new ProbeSettings(Duration.ofSeconds(10), 4, 6, 5, "lb-detector/1.0");
    }
}
