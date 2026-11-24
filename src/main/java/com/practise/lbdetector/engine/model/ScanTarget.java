package com.practise.lbdetector.engine.model;

import java.net.URI;
import java.util.Objects;

/**
 * What to scan and how hard.
 *
 * @param uri     absolute http(s) URL
 * @param samples number of HTTP probes to send
 */
public record ScanTarget(URI uri, int samples) {

    public ScanTarget {
        Objects.requireNonNull(uri, "uri");
        if (!uri.isAbsolute() || uri.getHost() == null) {
            throw new IllegalArgumentException("Target must be an absolute URL with a host: " + uri);
        }
        var scheme = uri.getScheme().toLowerCase();
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException("Only http and https targets are supported: " + uri);
        }
        if (samples < 1) {
            throw new IllegalArgumentException("samples must be >= 1");
        }
    }

    public String host() {
        return uri.getHost();
    }

    public boolean isHttps() {
        return uri.getScheme().equalsIgnoreCase("https");
    }

    public int port() {
        return uri.getPort() != -1 ? uri.getPort() : (isHttps() ? 443 : 80);
    }
}
