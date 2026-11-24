package com.practise.lbdetector.engine.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Final result of a scan, returned by the REST API and printed by the CLI.
 */
public record ScanReport(
        String target,
        Instant startedAt,
        long durationMs,
        Verdict verdict,
        int confidencePercent,
        String summary,
        List<String> identifiedProducts,
        List<Evidence> evidence,
        Stats stats,
        List<String> warnings) {

    /**
     * Raw probe statistics, useful for judging how much to trust the verdict.
     */
    public record Stats(int httpRequested, int httpSucceeded, int tlsSucceeded, int dnsLookups,
                        List<String> distinctIps, Map<Integer, Long> statusCodes,
                        long latencyMinMs, long latencyP50Ms, long latencyP95Ms, long latencyMaxMs) {
    }
}
