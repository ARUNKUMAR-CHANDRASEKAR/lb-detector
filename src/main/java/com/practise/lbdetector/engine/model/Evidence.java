package com.practise.lbdetector.engine.model;

import java.util.List;

/**
 * One piece of evidence that the target is load balanced.
 *
 * @param detector name of the detector that produced it
 * @param weight   0..1 — how strongly this alone suggests load balancing
 * @param summary  one-line explanation
 * @param product  identified product/vendor, or {@code null} if none
 * @param category what kind of component the evidence points at
 * @param details  supporting observations (e.g. the distinct values seen)
 */
public record Evidence(String detector, double weight, String summary, String product,
                       Category category, List<String> details) {

    public enum Category { LOAD_BALANCER, CDN_EDGE, WAF, REVERSE_PROXY, BACKEND_POOL, DNS }

    public Evidence {
        if (weight < 0 || weight > 1) {
            throw new IllegalArgumentException("weight must be within 0..1");
        }
        details = details == null ? List.of() : List.copyOf(details);
    }

    public static Evidence of(String detector, double weight, Category category, String summary, List<String> details) {
        return new Evidence(detector, weight, summary, null, category, details);
    }
}
