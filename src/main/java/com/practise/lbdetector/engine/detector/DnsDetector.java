package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.ProbeData;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * DNS-level balancing: several addresses for one name, or the answer order rotating
 * between lookups (classic DNS round-robin).
 *
 * <p>Requires the JVM DNS cache to be disabled ({@code networkaddress.cache.ttl=0}),
 * which the application does at start-up; otherwise every lookup returns the cached answer.
 */
public final class DnsDetector implements Detector {

    @Override
    public String name() {
        return "dns";
    }

    @Override
    public String description() {
        return "Multiple A/AAAA records or rotating record order across repeated lookups (DNS round-robin).";
    }

    @Override
    public List<Evidence> analyze(ProbeData data) {
        var lookups = data.dnsLookups();
        if (lookups.isEmpty()) {
            return List.of();
        }
        var evidence = new ArrayList<Evidence>();

        var distinct = new LinkedHashSet<String>();
        lookups.forEach(distinct::addAll);
        if (distinct.size() > 1) {
            evidence.add(Evidence.of(name(), 0.5, Category.DNS,
                    "Host resolves to " + distinct.size() + " different addresses",
                    List.copyOf(distinct)));
        }

        var orderings = new LinkedHashSet<List<String>>(lookups);
        if (orderings.size() > 1) {
            evidence.add(Evidence.of(name(), 0.3, Category.DNS,
                    "DNS answer changed across " + lookups.size() + " lookups (round-robin rotation)",
                    orderings.stream().map(Object::toString).toList()));
        }
        return evidence;
    }
}
