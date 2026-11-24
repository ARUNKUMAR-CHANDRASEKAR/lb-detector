package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.ProbeData;

import java.util.List;

/**
 * A single detection technique. Implementations must be stateless and side-effect free:
 * they only inspect the {@link ProbeData} that was already collected.
 *
 * <p>To add a technique, implement this interface and register it as a Spring bean
 * (see {@code DetectorConfiguration}); the engine picks it up automatically.
 */
public interface Detector {

    /** Short stable identifier, e.g. {@code "dns"}. */
    String name();

    /** One-sentence description shown by {@code GET /api/v1/detectors}. */
    String description();

    /** Return zero or more pieces of evidence. Never return {@code null}. */
    List<Evidence> analyze(ProbeData data);
}
