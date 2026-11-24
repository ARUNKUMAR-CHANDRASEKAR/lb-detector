package com.practise.lbdetector.config;

import com.practise.lbdetector.engine.Prober;
import com.practise.lbdetector.engine.ScanEngine;
import com.practise.lbdetector.engine.detector.ClockSkewDetector;
import com.practise.lbdetector.engine.detector.ContentVarianceDetector;
import com.practise.lbdetector.engine.detector.Detector;
import com.practise.lbdetector.engine.detector.DnsDetector;
import com.practise.lbdetector.engine.detector.HeaderVarianceDetector;
import com.practise.lbdetector.engine.detector.LatencyDetector;
import com.practise.lbdetector.engine.detector.SignatureDetector;
import com.practise.lbdetector.engine.detector.TlsVarianceDetector;
import com.practise.lbdetector.engine.model.ProbeSettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import java.time.Clock;
import java.util.List;

/**
 * Wires the framework-free engine into Spring. Each detector is its own bean, so adding a new
 * technique is just another {@code @Bean} (or {@code @Component}) implementing {@link Detector}.
 */
@Configuration(proxyBeanMethods = false)
public class DetectorConfiguration {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean @Order(1) Detector signatureDetector() { return new SignatureDetector(); }
    @Bean @Order(2) Detector headerVarianceDetector() { return new HeaderVarianceDetector(); }
    @Bean @Order(3) Detector tlsVarianceDetector() { return new TlsVarianceDetector(); }
    @Bean @Order(4) Detector clockSkewDetector() { return new ClockSkewDetector(); }
    @Bean @Order(5) Detector contentVarianceDetector() { return new ContentVarianceDetector(); }
    @Bean @Order(6) Detector dnsDetector() { return new DnsDetector(); }
    @Bean @Order(7) Detector latencyDetector() { return new LatencyDetector(); }

    @Bean
    Prober prober(LbDetectorProperties props, Clock clock) {
        return new Prober(new ProbeSettings(props.timeout(), props.concurrency(), props.tlsSamples(),
                props.dnsLookups(), props.userAgent()), clock);
    }

    @Bean
    ScanEngine scanEngine(Prober prober, List<Detector> detectors, Clock clock) {
        return new ScanEngine(prober, detectors, clock);
    }
}
