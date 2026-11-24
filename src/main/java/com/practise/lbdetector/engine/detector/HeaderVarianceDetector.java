package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Headers that identify the serving node (Server, X-Served-By, X-Backend-Server, ...) taking
 * different values across requests mean different machines answered.
 *
 * <p>Headers that are unique per request by design (request ids, trace ids, Date, ...) are ignored.
 */
public final class HeaderVarianceDetector implements Detector {

    /** Header names that identify a node or its software build. */
    private static final Pattern NODE_HEADER = Pattern.compile(
            "^(server|via|x-powered-by|x-aspnet-version|x-served-by|x-server|x-host|x-node|x-backend.*"
                    + "|x-upstream.*|x-instance.*|x-pod.*|x-hostname|x-machine.*|x-origin-server|x-cache-node"
                    + "|x-.*-(server|host|node|backend))$");

    /** Per-request values that would cause false positives. */
    private static final Pattern IGNORED = Pattern.compile(
            ".*(request-id|trace|span|correlation|ray|cf-id|-id$|nonce|token).*");

    /** Header values whose differing build numbers suggest a mixed fleet rather than distinct nodes. */
    private static final Set<String> SOFTWARE_HEADERS = Set.of("server", "x-powered-by", "x-aspnet-version");

    @Override
    public String name() {
        return "header-variance";
    }

    @Override
    public String description() {
        return "Node-identifying headers (Server, X-Served-By, X-Backend-Server, Via, ...) that change between requests.";
    }

    @Override
    public List<Evidence> analyze(ProbeData data) {
        if (data.http().size() < 2) {
            return List.of();
        }
        Map<String, Set<String>> valuesByHeader = new LinkedHashMap<>();
        for (HttpSample sample : data.http()) {
            for (var entry : sample.headers().entrySet()) {
                var header = entry.getKey();
                if (NODE_HEADER.matcher(header).matches() && !IGNORED.matcher(header).matches()) {
                    valuesByHeader.computeIfAbsent(header, h -> new LinkedHashSet<>())
                            .add(String.join(", ", entry.getValue()));
                }
            }
        }
        var evidence = new ArrayList<Evidence>();
        int samples = data.http().size();
        valuesByHeader.forEach((header, values) -> {
            if (values.size() < 2) {
                return;
            }
            // Every response different => probably something per-request, not per-node.
            boolean uniquePerRequest = values.size() == samples && samples >= 6;
            double weight = SOFTWARE_HEADERS.contains(header) ? 0.6 : 0.8;
            if (uniquePerRequest) {
                weight = 0.25;
            }
            evidence.add(Evidence.of(name(), weight, Category.BACKEND_POOL,
                    "Header '" + header + "' had " + values.size() + " distinct values across "
                            + samples + " responses" + (uniquePerRequest ? " (unique per request - weak)" : ""),
                    values.stream().limit(10).toList()));
        });
        return evidence;
    }
}
