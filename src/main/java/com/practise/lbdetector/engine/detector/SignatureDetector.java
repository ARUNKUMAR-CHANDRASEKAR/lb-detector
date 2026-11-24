package com.practise.lbdetector.engine.detector;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.HttpSample;
import com.practise.lbdetector.engine.model.ProbeData;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Fingerprints known load balancers, CDNs and WAFs from the cookies and headers they add.
 */
public final class SignatureDetector implements Detector {

    /** Where a signature looks. */
    enum Location { COOKIE_NAME, HEADER_PRESENT, HEADER_VALUE, HEADER_NAME }

    /**
     * @param header  header to inspect (for HEADER_PRESENT / HEADER_VALUE), ignored otherwise
     * @param pattern regex matched against the cookie name, header value, or header name
     */
    record Signature(String product, Category category, double weight,
                     Location location, String header, Pattern pattern) {

        static Signature cookie(String product, Category category, double weight, String regex) {
            return new Signature(product, category, weight, Location.COOKIE_NAME, null, Pattern.compile(regex));
        }

        static Signature present(String product, Category category, double weight, String header) {
            return new Signature(product, category, weight, Location.HEADER_PRESENT, header, null);
        }

        static Signature value(String product, Category category, double weight, String header, String regex) {
            return new Signature(product, category, weight, Location.HEADER_VALUE, header,
                    Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
        }

        static Signature headerName(String product, Category category, double weight, String regex) {
            return new Signature(product, category, weight, Location.HEADER_NAME, null,
                    Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
        }
    }

    private static final double LB = 0.9;     // dedicated load-balancer fingerprint
    private static final double EDGE = 0.75;  // CDN / global edge: balancing by definition
    private static final double PROXY = 0.35; // reverse proxy that is often, not always, balancing

    static final List<Signature> SIGNATURES = List.of(
            // AWS
            Signature.cookie("AWS Application Load Balancer", Category.LOAD_BALANCER, LB, "^AWSALB(CORS|TG|TGCORS)?$"),
            Signature.cookie("AWS Classic Elastic Load Balancer", Category.LOAD_BALANCER, LB, "^AWSELB(CORS)?$"),
            Signature.value("AWS Elastic Load Balancer", Category.LOAD_BALANCER, LB, "server", "^awselb/"),
            Signature.present("AWS CloudFront", Category.CDN_EDGE, EDGE, "x-amz-cf-id"),
            // F5
            Signature.cookie("F5 BIG-IP", Category.LOAD_BALANCER, LB, "^BIGipServer"),
            Signature.value("F5 BIG-IP", Category.LOAD_BALANCER, LB, "server", "BigIP|BIG-IP"),
            Signature.cookie("F5 BIG-IP ASM", Category.WAF, LB, "^TS01[0-9a-f]{6}$"),
            // Citrix
            Signature.cookie("Citrix NetScaler / ADC", Category.LOAD_BALANCER, LB, "^NSC_"),
            Signature.value("Citrix NetScaler / ADC", Category.LOAD_BALANCER, LB, "via", "NS-CACHE"),
            Signature.headerName("Citrix NetScaler / ADC", Category.LOAD_BALANCER, LB, "^(cneonction|nncoection)$"),
            // Open source / software balancers
            Signature.cookie("HAProxy", Category.LOAD_BALANCER, 0.6, "^SERVERID$"),
            Signature.value("HAProxy", Category.LOAD_BALANCER, LB, "server", "haproxy"),
            Signature.present("Envoy", Category.LOAD_BALANCER, 0.7, "x-envoy-upstream-service-time"),
            Signature.value("Envoy", Category.LOAD_BALANCER, 0.7, "server", "^envoy"),
            Signature.cookie("Kubernetes ingress-nginx", Category.LOAD_BALANCER, LB, "^INGRESSCOOKIE$"),
            Signature.cookie("Barracuda Load Balancer", Category.LOAD_BALANCER, LB, "^BNI__BARRACUDA_LB_COOKIE"),
            Signature.cookie("Kemp LoadMaster", Category.LOAD_BALANCER, 0.6, "^kt[0-9a-f]{0,8}$"),
            // Microsoft
            Signature.present("Azure Front Door", Category.CDN_EDGE, EDGE, "x-azure-ref"),
            Signature.cookie("Azure Application Gateway", Category.LOAD_BALANCER, LB, "^ApplicationGatewayAffinity(CORS)?$"),
            Signature.cookie("IIS Application Request Routing", Category.LOAD_BALANCER, 0.8, "^ARRAffinity(SameSite)?$"),
            // Google
            Signature.value("Google Cloud Load Balancer", Category.LOAD_BALANCER, LB, "via", "\\b1\\.1 google\\b"),
            Signature.cookie("Google Cloud Load Balancer", Category.LOAD_BALANCER, LB, "^GCLB$"),
            // CDNs / edges
            Signature.present("Cloudflare", Category.CDN_EDGE, EDGE, "cf-ray"),
            Signature.value("Cloudflare", Category.CDN_EDGE, EDGE, "server", "^cloudflare"),
            Signature.value("Akamai", Category.CDN_EDGE, EDGE, "server", "AkamaiGHost|AkamaiNetStorage"),
            Signature.present("Akamai", Category.CDN_EDGE, EDGE, "akamai-grn"),
            Signature.present("Fastly", Category.CDN_EDGE, EDGE, "x-fastly-request-id"),
            Signature.value("Fastly", Category.CDN_EDGE, EDGE, "x-served-by", "^cache-"),
            Signature.cookie("Imperva Incapsula", Category.WAF, EDGE, "^(incap_ses_|visid_incap_)"),
            Signature.present("Imperva Incapsula", Category.WAF, EDGE, "x-iinfo"),
            // Reverse proxies (weak on their own)
            Signature.present("Varnish", Category.REVERSE_PROXY, PROXY, "x-varnish"),
            Signature.value("Nginx", Category.REVERSE_PROXY, 0.1, "server", "^nginx"),
            Signature.value("Apache Traffic Server", Category.REVERSE_PROXY, PROXY, "server", "ATS/")
    );

    @Override
    public String name() {
        return "signature";
    }

    @Override
    public String description() {
        return "Known load balancer, CDN and WAF fingerprints in cookies and headers (AWS, F5, Citrix, HAProxy, Envoy, Azure, GCP, Cloudflare, Akamai, ...).";
    }

    @Override
    public List<Evidence> analyze(ProbeData data) {
        // product -> (signature, first matching observation); keep the strongest per product
        Map<String, Match> matches = new LinkedHashMap<>();
        for (HttpSample sample : data.http()) {
            for (Signature sig : SIGNATURES) {
                var observed = match(sig, sample);
                if (observed != null) {
                    matches.merge(sig.product(), new Match(sig, observed),
                            (a, b) -> a.signature().weight() >= b.signature().weight() ? a : b);
                }
            }
        }
        var evidence = new ArrayList<Evidence>();
        matches.forEach((product, m) -> evidence.add(new Evidence(name(), m.signature().weight(),
                product + " fingerprint found", product, m.signature().category(), List.of(m.observed()))));
        return evidence;
    }

    private record Match(Signature signature, String observed) {
    }

    private static String match(Signature sig, HttpSample sample) {
        return switch (sig.location()) {
            case COOKIE_NAME -> sample.cookieNames().stream()
                    .filter(n -> sig.pattern().matcher(n).find())
                    .findFirst().map(n -> "cookie " + n).orElse(null);
            case HEADER_PRESENT -> sample.header(sig.header())
                    .map(v -> "header " + sig.header() + ": " + v).orElse(null);
            case HEADER_VALUE -> sample.headerValues(sig.header()).stream()
                    .filter(v -> sig.pattern().matcher(v).find())
                    .findFirst().map(v -> "header " + sig.header() + ": " + v).orElse(null);
            case HEADER_NAME -> sample.headers().keySet().stream()
                    .filter(h -> sig.pattern().matcher(h).find())
                    .findFirst().map(h -> "header name " + h).orElse(null);
        };
    }
}
