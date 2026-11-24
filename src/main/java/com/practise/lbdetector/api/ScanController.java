package com.practise.lbdetector.api;

import com.practise.lbdetector.engine.model.ScanReport;
import com.practise.lbdetector.service.ScanService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST API. Requests run on virtual threads ({@code spring.threads.virtual.enabled=true}),
 * so a scan blocking for several seconds doesn't tie up a platform thread.
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Load balancer detection")
public class ScanController {

    private final ScanService service;

    public ScanController(ScanService service) {
        this.service = service;
    }

    @PostMapping("/scans")
    @Operation(summary = "Scan a URL and report whether it is load balanced")
    public ScanReport scan(@Valid @RequestBody ScanRequest request) {
        return service.scan(request.target(), request.samples());
    }

    @GetMapping("/detectors")
    @Operation(summary = "List the detection techniques in use")
    public List<DetectorInfo> detectors() {
        return service.detectors().stream()
                .map(d -> new DetectorInfo(d.name(), d.description()))
                .toList();
    }

    public record DetectorInfo(String name, String description) {
    }
}
