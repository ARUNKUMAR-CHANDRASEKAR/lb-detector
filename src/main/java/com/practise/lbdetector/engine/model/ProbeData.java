package com.practise.lbdetector.engine.model;

import java.util.List;

/**
 * Everything the prober collected. Detectors only read this, so they are pure functions
 * and trivial to unit-test with synthetic data.
 *
 * @param target      what was scanned
 * @param http        successful HTTP samples, in send order
 * @param tls         successful TLS samples (empty for plain http)
 * @param dnsLookups  each element is the ordered address list from one DNS lookup
 * @param errors      human-readable errors from failed probes
 */
public record ProbeData(ScanTarget target, List<HttpSample> http, List<TlsSample> tls,
                        List<List<String>> dnsLookups, List<String> errors) {

    public ProbeData {
        http = List.copyOf(http);
        tls = List.copyOf(tls);
        dnsLookups = dnsLookups.stream().map(List::copyOf).toList();
        errors = List.copyOf(errors);
    }
}
