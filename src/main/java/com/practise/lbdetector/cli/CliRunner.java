package com.practise.lbdetector.cli;

import com.practise.lbdetector.engine.ReportFormatter;
import com.practise.lbdetector.service.ScanService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Command-line mode:
 * <pre>
 * java -jar lb-detector.jar --target=https://example.com/ [--samples=30]
 * </pre>
 * Prints a text report and exits (the application starts without a web server in this mode).
 */
@Component
public class CliRunner implements ApplicationRunner {

    private final ScanService service;

    public CliRunner(ScanService service) {
        this.service = service;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!args.containsOption("target")) {
            return; // server mode
        }
        var target = args.getOptionValues("target").getFirst();
        Integer samples = args.containsOption("samples")
                ? Integer.valueOf(args.getOptionValues("samples").getFirst())
                : null;
        try {
            var report = service.scan(target, samples);
            System.out.println();
            System.out.print(ReportFormatter.toText(report));
        } catch (RuntimeException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        }
    }
}
