package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;

import java.util.Comparator;
import java.util.List;

/**
 * Looks for two well-separated clusters in response times (e.g. backends in different zones or
 * with different load). Network noise makes this the weakest signal, so its weight is capped low.
 *
 * <p>Uses a one-dimensional Otsu split: try every cut point in the sorted latencies and keep the
 * one that maximises between-group variance.
 *
 * <p><b>Guarding against false positives.</b> The first wave of probes is slow for reasons that
 * have nothing to do with the target (class loading, JIT warm-up, TLS/HTTP client start-up), which
 * looks exactly like "a slow backend". So:
 * <ol>
 *   <li>the first {@link #WARMUP} probes are ignored, and</li>
 *   <li>slow and fast responses must both occur in the first <em>and</em> second half of the run.
 *       A balancer interleaves backends throughout; a one-off slow burst doesn't.</li>
 * </ol>
 */
public final class LatencyDetector implements Detector {

    static final int WARMUP = 4;
    static final int MIN_SAMPLES = 10;

    @Override
    public String name() {
        return "latency";
    }

    @Override
    public String description() {
        return "Bimodal response-time distribution, interleaved across the run, suggesting backends with different performance (weak signal).";
    }

    @Override
    public List<Evidence> analyze(ProbeData data) {
        List<HttpSample> steady = data.http().stream()
                .filter(s -> s.index() >= WARMUP)
                .sorted(Comparator.comparingInt(HttpSample::index))
                .toList();
        int n = steady.size();
        if (n < MIN_SAMPLES) {
            return List.of();
        }
        long[] sorted = steady.stream().mapToLong(HttpSample::latencyMs).sorted().toArray();
        double total = 0;
        for (long v : sorted) total += v;

        double bestVariance = -1;
        int bestCut = -1;
        double prefix = 0;
        for (int cut = 1; cut < n; cut++) {
            prefix += sorted[cut - 1];
            double w0 = (double) cut / n;
            double w1 = 1 - w0;
            double m0 = prefix / cut;
            double m1 = (total - prefix) / (n - cut);
            double between = w0 * w1 * (m0 - m1) * (m0 - m1);
            if (between > bestVariance) {
                bestVariance = between;
                bestCut = cut;
            }
        }
        int lowCount = bestCut;
        int highCount = n - bestCut;
        double lowMean = 0, highMean = 0;
        for (int i = 0; i < n; i++) {
            if (i < bestCut) lowMean += sorted[i]; else highMean += sorted[i];
        }
        lowMean /= lowCount;
        highMean /= highCount;
        long gap = sorted[bestCut] - sorted[bestCut - 1];

        boolean bothSizable = lowCount >= n * 0.2 && highCount >= n * 0.2;
        boolean separated = highMean >= Math.max(lowMean * 1.8, lowMean + 15) && gap >= 10;
        if (!bothSizable || !separated) {
            return List.of();
        }

        // Interleaving: both halves of the run (in send order) must contain fast and slow responses.
        long threshold = sorted[bestCut];
        var firstHalf = steady.subList(0, n / 2);
        var secondHalf = steady.subList(n / 2, n);
        if (!hasBoth(firstHalf, threshold) || !hasBoth(secondHalf, threshold)) {
            return List.of();
        }

        return List.of(Evidence.of(name(), 0.25, Category.BACKEND_POOL,
                String.format("Response times form two interleaved clusters (~%.0f ms and ~%.0f ms)", lowMean, highMean),
                List.of(lowCount + " fast responses, mean " + Math.round(lowMean) + " ms",
                        highCount + " slow responses, mean " + Math.round(highMean) + " ms",
                        "first " + WARMUP + " probes ignored as warm-up")));
    }

    private static boolean hasBoth(List<HttpSample> samples, long threshold) {
        boolean slow = samples.stream().anyMatch(s -> s.latencyMs() >= threshold);
        boolean fast = samples.stream().anyMatch(s -> s.latencyMs() < threshold);
        return slow && fast;
    }
}
