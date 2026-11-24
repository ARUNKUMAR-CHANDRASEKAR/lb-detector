package com.practise.lbdetector.engine.model;

/**
 * Overall conclusion. Note the asymmetry: evidence can show a load balancer is present,
 * but a lack of evidence never proves one is absent (a well-configured L4 balancer with
 * identical backends is invisible from outside).
 */
public enum Verdict {
    LOAD_BALANCED("Load balancing detected with high confidence"),
    LIKELY_LOAD_BALANCED("Load balancing is likely"),
    POSSIBLY_LOAD_BALANCED("Weak signs of load balancing"),
    NO_EVIDENCE("No evidence of load balancing found (this does not prove there is none)");

    private final String description;

    Verdict(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }

    public static Verdict fromConfidence(double confidence) {
        if (confidence >= 0.80) return LOAD_BALANCED;
        if (confidence >= 0.50) return LIKELY_LOAD_BALANCED;
        if (confidence >= 0.20) return POSSIBLY_LOAD_BALANCED;
        return NO_EVIDENCE;
    }
}
