package com.practise.lbdetector.service;

import com.practise.lbdetector.config.LbDetectorProperties;
import com.practise.lbdetector.engine.ScanEngine;
import com.practise.lbdetector.engine.detector.Detector;
import com.practise.lbdetector.engine.model.ScanReport;
import com.practise.lbdetector.engine.model.ScanTarget;
import com.practise.lbdetector.security.TargetGuard;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.Semaphore;

/**
 * Application service shared by the REST API and the CLI: validates input, limits concurrent
 * scans, runs the engine and records metrics.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanEngine engine;
    private final TargetGuard guard;
    private final LbDetectorProperties props;
    private final MeterRegistry meters;
    private final Semaphore scanSlots;

    public ScanService(ScanEngine engine, TargetGuard guard, LbDetectorProperties props, MeterRegistry meters) {
        this.engine = engine;
        this.guard = guard;
        this.props = props;
        this.meters = meters;
        this.scanSlots = new Semaphore(props.maxConcurrentScans());
    }

    public ScanReport scan(String rawTarget, Integer requestedSamples) {
        var uri = guard.validate(rawTarget);
        int samples = requestedSamples == null ? props.defaultSamples() : requestedSamples;
        if (samples < 1 || samples > props.maxSamples()) {
            throw new IllegalArgumentException("samples must be between 1 and " + props.maxSamples());
        }
        if (!scanSlots.tryAcquire()) {
            throw new TooManyScansException(props.maxConcurrentScans());
        }
        try {
            log.info("Scanning {} with {} samples", uri, samples);
            var sample = Timer.start(meters);
            var report = engine.scan(new ScanTarget(uri, samples));
            sample.stop(Timer.builder("lbdetector.scan")
                    .description("Time taken by a load-balancer detection scan")
                    .tag("verdict", report.verdict().name())
                    .register(meters));
            log.info("Scan of {} finished: {} ({}%)", uri, report.verdict(), report.confidencePercent());
            return report;
        } finally {
            scanSlots.release();
        }
    }

    public List<Detector> detectors() {
        return engine.detectors();
    }
}
