package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.ProbeData;
import com.practise.lbdetector.engine.model.TlsSample;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Different certificates (or different negotiated parameters) on different fresh TLS connections
 * mean different terminating nodes - typical of DNS/L4 balancing or a mid-rotation fleet.
 */
public final class TlsVarianceDetector implements Detector {

    @Override
    public String name() {
        return "tls-variance";
    }

    @Override
    public String description() {
        return "Different TLS certificates or handshake parameters on separate fresh connections.";
    }

    @Override
    public List<Evidence> analyze(ProbeData data) {
        if (data.tls().size() < 2) {
            return List.of();
        }
        var evidence = new ArrayList<Evidence>();

        Map<String, TlsSample> byFingerprint = new LinkedHashMap<>();
        data.tls().forEach(t -> byFingerprint.putIfAbsent(t.sha256Fingerprint(), t));
        if (byFingerprint.size() > 1) {
            evidence.add(Evidence.of(name(), 0.7, Category.BACKEND_POOL,
                    byFingerprint.size() + " different certificates served across " + data.tls().size() + " TLS connections",
                    byFingerprint.values().stream()
                            .map(t -> "serial " + t.serialNumber() + " / " + t.subject() + " / sha256 "
                                    + t.sha256Fingerprint().substring(0, 16) + "...")
                            .toList()));
        }

        var handshakes = new LinkedHashSet<String>();
        data.tls().forEach(t -> handshakes.add(t.protocol() + " " + t.cipherSuite()));
        if (handshakes.size() > 1) {
            evidence.add(Evidence.of(name(), 0.4, Category.BACKEND_POOL,
                    "Negotiated TLS parameters differ between connections (differently configured terminators)",
                    List.copyOf(handshakes)));
        }
        return evidence;
    }
}
