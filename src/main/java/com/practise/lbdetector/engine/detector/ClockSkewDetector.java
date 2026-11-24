package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

/**
 * Each backend stamps the HTTP {@code Date} header from its own clock. Comparing it to our
 * clock gives a per-response offset; one machine gives a tight band (Date has 1 s resolution),
 * several machines with unsynchronised clocks give clusters several seconds apart.
 */
public final class ClockSkewDetector implements Detector {

    /** Offsets further apart than this cannot come from a single clock with 1-second resolution. */
    static final long SPREAD_THRESHOLD_MS = 2_500;

    @Override
    public String name() {
        return "clock-skew";
    }

    @Override
    public String description() {
        return "Inconsistent HTTP Date headers: backends with different clocks produce clustered time offsets.";
    }

    @Override
    public List<Evidence> analyze(ProbeData data) {
        var offsets = new ArrayList<Long>();
        for (HttpSample sample : data.http()) {
            sample.header("date").ifPresent(date -> {
                try {
                    var serverTime = ZonedDateTime.parse(date, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                    offsets.add(serverTime.toEpochMilli() - sample.serverTimeEstimate().toEpochMilli());
                } catch (RuntimeException ignored) {
                    // malformed Date header: skip
                }
            });
        }
        if (offsets.size() < 4) {
            return List.of();
        }
        long min = offsets.stream().mapToLong(Long::longValue).min().orElse(0);
        long max = offsets.stream().mapToLong(Long::longValue).max().orElse(0);
        if (max - min < SPREAD_THRESHOLD_MS) {
            return List.of();
        }
        // Group offsets into whole-second buckets to show the clusters.
        var buckets = new TreeMap<Long, Integer>();
        offsets.forEach(o -> buckets.merge(Math.round(o / 1000.0), 1, Integer::sum));
        var details = buckets.entrySet().stream()
                .map(e -> String.format("offset %+ds: %d responses", e.getKey(), e.getValue()))
                .toList();
        return List.of(Evidence.of(name(), 0.65, Category.BACKEND_POOL,
                "Date headers disagree by up to " + (max - min) / 1000.0 + " s - responses come from machines with different clocks",
                details));
    }
}
