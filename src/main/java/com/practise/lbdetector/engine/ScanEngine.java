package com.practise.lbdetector.engine;

import com.practise.lbdetector.engine.detector.Detector;
import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;
import com.practise.lbdetector.engine.model.ScanReport;
import com.practise.lbdetector.engine.model.ScanTarget;
import com.practise.lbdetector.engine.model.Verdict;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Orchestrates a scan: probe the target, run every detector, combine the evidence.
 *
 * <p><b>Scoring.</b> Evidence is combined with a noisy-OR: {@code P = 1 - Π(1 - wᵢ)}. Each piece
 * of evidence is treated as an independent chance that the target is load balanced, so several
 * weak signals add up while one strong signal is enough on its own. Evidence is first combined
 * within each detector, and each detector's contribution is capped at its strongest single weight
 * plus a small bonus, so one detector repeating itself can't dominate.
 */
public final class ScanEngine {

    private static final int MAX_WARNINGS = 20;

    private final Prober prober;
    private final List<Detector> detectors;
    private final Clock clock;

    public ScanEngine(Prober prober, List<Detector> detectors, Clock clock) {
        this.prober = Objects.requireNonNull(prober);
        this.detectors = List.copyOf(detectors);
        this.clock = Objects.requireNonNull(clock);
    }

    public List<Detector> detectors() {
        return detectors;
    }

    public ScanReport scan(ScanTarget target) {
        var startedAt = clock.instant();
        var data = prober.probe(target);
        return evaluate(data, startedAt, Duration.between(startedAt, clock.instant()).toMillis());
    }

    /** Runs the detectors over already-collected data. Public so it can be tested without network access. */
    public ScanReport evaluate(ProbeData data, java.time.Instant startedAt, long durationMs) {
        var warnings = new ArrayList<String>();
        var evidence = new ArrayList<Evidence>();
        for (Detector detector : detectors) {
            try {
                evidence.addAll(detector.analyze(data));
            } catch (RuntimeException e) {
                warnings.add("Detector '" + detector.name() + "' failed: " + e.getMessage());
            }
        }
        evidence.sort(Comparator.comparingDouble(Evidence::weight).reversed());

        double confidence = combine(evidence);
        var verdict = Verdict.fromConfidence(confidence);
        if (data.http().isEmpty() && data.tls().isEmpty()) {
            warnings.add("No probe succeeded - the target may be unreachable; the verdict is not meaningful.");
        } else if (data.http().size() < 5) {
            warnings.add("Only " + data.http().size() + " HTTP responses collected - use more samples for a reliable result.");
        }
        data.errors().stream().limit(MAX_WARNINGS).forEach(warnings::add);
        if (data.errors().size() > MAX_WARNINGS) {
            warnings.add("... and " + (data.errors().size() - MAX_WARNINGS) + " more probe errors");
        }

        var products = evidence.stream().map(Evidence::product).filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        return new ScanReport(
                data.target().uri().toString(),
                startedAt,
                durationMs,
                verdict,
                (int) Math.round(confidence * 100),
                summarise(verdict, evidence, products),
                List.copyOf(products),
                List.copyOf(evidence),
                stats(data),
                List.copyOf(warnings));
    }

    static double combine(List<Evidence> evidence) {
        Map<String, List<Evidence>> byDetector = evidence.stream()
                .collect(Collectors.groupingBy(Evidence::detector, LinkedHashMap::new, Collectors.toList()));
        double notBalanced = 1.0;
        for (var group : byDetector.values()) {
            double strongest = group.stream().mapToDouble(Evidence::weight).max().orElse(0);
            double within = 1 - group.stream().mapToDouble(e -> 1 - e.weight()).reduce(1, (a, b) -> a * b);
            double contribution = Math.min(within, Math.min(0.97, strongest + 0.1));
            notBalanced *= (1 - contribution);
        }
        return 1 - notBalanced;
    }

    private static String summarise(Verdict verdict, List<Evidence> evidence, LinkedHashSet<String> products) {
        if (evidence.isEmpty()) {
            return verdict.description() + ".";
        }
        var sb = new StringBuilder(verdict.description()).append(". ");
        if (!products.isEmpty()) {
            sb.append("Identified: ").append(String.join(", ", products)).append(". ");
        }
        sb.append("Strongest signal: ").append(evidence.getFirst().summary()).append('.');
        return sb.toString();
    }

    private static ScanReport.Stats stats(ProbeData data) {
        long[] latencies = data.http().stream().mapToLong(HttpSample::latencyMs).sorted().toArray();
        Map<Integer, Long> statuses = data.http().stream()
                .collect(Collectors.groupingBy(HttpSample::status, TreeMap::new, Collectors.counting()));
        var ips = data.dnsLookups().stream().flatMap(List::stream).distinct().toList();
        return new ScanReport.Stats(
                data.target().samples(),
                data.http().size(),
                data.tls().size(),
                data.dnsLookups().size(),
                ips,
                statuses,
                percentile(latencies, 0),
                percentile(latencies, 50),
                percentile(latencies, 95),
                percentile(latencies, 100));
    }

    private static long percentile(long[] sorted, int p) {
        if (sorted.length == 0) return 0;
        int idx = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.clamp(idx, 0, sorted.length - 1)];
    }
}
