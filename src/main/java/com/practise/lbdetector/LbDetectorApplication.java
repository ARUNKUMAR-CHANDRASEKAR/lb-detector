package com.practise.lbdetector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.security.Security;
import java.util.Arrays;

/**
 * Entry point. Runs as a REST service by default, or as a one-shot CLI when started with
 * {@code --target=<url>}.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class LbDetectorApplication {

    static void main(String[] args) {
        // The JVM caches DNS answers (30 s by default). Disable it, otherwise repeated lookups
        // always return the same answer and DNS round-robin can never be observed.
        // Must run before the first name lookup.
        Security.setProperty("networkaddress.cache.ttl", "0");
        Security.setProperty("networkaddress.cache.negative.ttl", "0");

        var app = new SpringApplication(LbDetectorApplication.class);
        if (Arrays.stream(args).anyMatch(a -> a.startsWith("--target="))) {
            app.setWebApplicationType(WebApplicationType.NONE); // CLI mode: no web server
        }
        app.run(args);
    }
}
