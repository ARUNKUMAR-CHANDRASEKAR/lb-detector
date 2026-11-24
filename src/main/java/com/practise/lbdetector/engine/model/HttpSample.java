package com.practise.lbdetector.engine.model;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * One HTTP response collected from the target over a fresh connection.
 *
 * @param index     sequence number of the probe
 * @param status    HTTP status code
 * @param headers   response headers, keys normalised to lower case
 * @param sentAt    wall-clock time the request was sent
 * @param latencyMs round-trip time in milliseconds (time to response headers)
 * @param protocol  negotiated protocol, e.g. HTTP_2
 */
public record HttpSample(int index, int status, Map<String, List<String>> headers,
                         Instant sentAt, long latencyMs, String protocol) {

    public HttpSample {
        var normalised = new TreeMap<String, List<String>>();
        headers.forEach((k, v) -> normalised.merge(k.toLowerCase(Locale.ROOT), List.copyOf(v),
                (a, b) -> java.util.stream.Stream.concat(a.stream(), b.stream()).toList()));
        headers = java.util.Collections.unmodifiableMap(normalised);
    }

    /** First value of a header (case-insensitive). */
    public Optional<String> header(String name) {
        var values = headers.get(name.toLowerCase(Locale.ROOT));
        return values == null || values.isEmpty() ? Optional.empty() : Optional.of(values.getFirst());
    }

    /** All values of a header (case-insensitive). */
    public List<String> headerValues(String name) {
        return headers.getOrDefault(name.toLowerCase(Locale.ROOT), List.of());
    }

    /** Cookie names set by this response (from Set-Cookie headers). */
    public List<String> cookieNames() {
        return headerValues("set-cookie").stream()
                .map(c -> c.split("=", 2)[0].trim())
                .filter(n -> !n.isEmpty())
                .toList();
    }

    /** Midpoint between send and receive: best estimate of when the server stamped its Date header. */
    public Instant serverTimeEstimate() {
        return sentAt.plusMillis(latencyMs / 2);
    }
}
