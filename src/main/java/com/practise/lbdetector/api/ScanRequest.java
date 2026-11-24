package com.practise.lbdetector.api;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /api/v1/scans}.
 */
public record ScanRequest(
        @Schema(description = "Absolute http(s) URL to probe", example = "https://example.com/")
        @NotBlank @Size(max = 2048) String target,

        @Schema(description = "Number of HTTP probes (defaults to lbdetector.default-samples)", example = "20")
        @Min(1) @Max(1000) Integer samples) {
}
