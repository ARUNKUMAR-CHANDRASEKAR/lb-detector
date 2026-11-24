package com.practise.lbdetector.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * All tunables under the {@code lbdetector.*} prefix (see application.yml).
 *
 * @param defaultSamples      HTTP probes per scan when the request doesn't say
 * @param maxSamples          upper bound a caller may request
 * @param timeout             per-probe connect/read timeout
 * @param concurrency         probes in flight at once per scan
 * @param tlsSamples          fresh TLS handshakes per https scan
 * @param dnsLookups          DNS resolutions per scan
 * @param maxConcurrentScans  scans running at once across the service; extra requests get HTTP 429
 * @param allowPrivateTargets allow loopback/private/link-local targets (SSRF protection off)
 * @param userAgent           User-Agent sent with every probe
 */
@Validated
@ConfigurationProperties(prefix = "lbdetector")
public record LbDetectorProperties(
        @DefaultValue("20") @Min(1) int defaultSamples,
        @DefaultValue("100") @Min(1) @Max(1000) int maxSamples,
        @DefaultValue("10s") @NotNull Duration timeout,
        @DefaultValue("4") @Min(1) @Max(64) int concurrency,
        @DefaultValue("6") @Min(0) int tlsSamples,
        @DefaultValue("5") @Min(1) int dnsLookups,
        @DefaultValue("4") @Min(1) int maxConcurrentScans,
        @DefaultValue("false") boolean allowPrivateTargets,
        @DefaultValue("lb-detector/1.0") @NotBlank String userAgent) {
}
