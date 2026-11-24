package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The same static resource served by several nodes often carries a different {@code ETag}
 * (e.g. Apache/nginx include the inode or mtime) or {@code Last-Modified} per node.
 *
 * <p>A small set of values that <em>repeat</em> is a strong signal (a handful of nodes); a value
 * that changes on every response just means the content is dynamic, so it is weighted low.
 */
public final class ContentVarianceDetector implements Detector {

    private static final List<String> HEADERS = List.of("etag", "last-modified");

    @Override
    public String name() {
        return "content-variance";
    }

    @Override
    public String description() {
        return "Same URL returning a small repeating set of ETag / Last-Modified values (one per backend node).";
    }

    @Override
    public List<Evidence> analyze(ProbeData data) {
        var ok = data.http().stream().filter(s -> s.status() >= 200 && s.status() < 300).toList();
        if (ok.size() < 3) {
            return List.of();
        }
        var evidence = new ArrayList<Evidence>();
        for (String header : HEADERS) {
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (HttpSample s : ok) {
                s.header(header).ifPresent(v -> counts.merge(v, 1, Integer::sum));
            }
            int seen = counts.values().stream().mapToInt(Integer::intValue).sum();
            if (counts.size() < 2 || seen < 3) {
                continue;
            }
            boolean repeating = counts.size() <= Math.max(2, seen / 2)
                    && counts.values().stream().filter(c -> c > 1).count() >= 2;
            double weight = repeating ? 0.6 : 0.15;
            evidence.add(Evidence.of(name(), weight, Category.BACKEND_POOL,
                    counts.size() + " distinct " + header + " values for the same URL"
                            + (repeating ? " repeating across responses (one per node)" : " (looks like dynamic content - weak)"),
                    counts.entrySet().stream().limit(10).map(e -> e.getKey() + " x" + e.getValue()).toList()));
        }
        return evidence;
    }
}
