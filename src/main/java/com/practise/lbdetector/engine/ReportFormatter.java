package com.practise.lbdetector.engine;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.ScanReport;

/**
 * Renders a {@link ScanReport} as human-readable text for the command line.
 */
public final class ReportFormatter {

    private ReportFormatter() {
    }

    public static String toText(ScanReport r) {
        var sb = new StringBuilder();
        sb.append("Target      : ").append(r.target()).append('\n');
        sb.append("Verdict     : ").append(r.verdict()).append(" (").append(r.confidencePercent()).append("% confidence)\n");
        sb.append("Summary     : ").append(r.summary()).append('\n');
        if (!r.identifiedProducts().isEmpty()) {
            sb.append("Identified  : ").append(String.join(", ", r.identifiedProducts())).append('\n');
        }
        var s = r.stats();
        sb.append("Probes      : ").append(s.httpSucceeded()).append('/').append(s.httpRequested()).append(" HTTP ok, ")
                .append(s.tlsSucceeded()).append(" TLS, ").append(s.dnsLookups()).append(" DNS lookups, ")
                .append(r.durationMs()).append(" ms\n");
        sb.append("Statuses    : ").append(s.statusCodes()).append('\n');
        sb.append("Latency ms  : min ").append(s.latencyMinMs()).append(" / p50 ").append(s.latencyP50Ms())
                .append(" / p95 ").append(s.latencyP95Ms()).append(" / max ").append(s.latencyMaxMs()).append('\n');
        if (!s.distinctIps().isEmpty()) {
            sb.append("Addresses   : ").append(String.join(", ", s.distinctIps())).append('\n');
        }
        sb.append('\n');
        if (r.evidence().isEmpty()) {
            sb.append("No evidence found.\n");
        } else {
            sb.append("Evidence (strongest first):\n");
            for (Evidence e : r.evidence()) {
                sb.append(String.format("  [%3d%%] %-16s %s%n", Math.round(e.weight() * 100), e.detector(), e.summary()));
                for (String d : e.details()) {
                    sb.append("                           - ").append(d).append('\n');
                }
            }
        }
        if (!r.warnings().isEmpty()) {
            sb.append("\nWarnings:\n");
            r.warnings().forEach(w -> sb.append("  ! ").append(w).append('\n'));
        }
        return sb.toString();
    }
}
