# lb-detector

Detects whether a web endpoint sits behind a **load balancer** (or CDN edge, WAF, or reverse-proxy pool), and identifies the product when it can. It runs as a REST service or as a one-shot command-line tool.

## Technology stack

| Area | Technology |
|---|---|
| Language | **Java 25 (LTS)**: records, pattern-matching `switch`, **virtual threads** |
| Framework | **Spring Boot 4.1** / Spring Framework 7 (Spring MVC) |
| Probing | JDK only: `java.net.http.HttpClient` (HTTP/2), `SSLSocket`, `InetAddress` |
| API | REST + Jakarta Bean Validation + RFC 9457 Problem Details |
| API docs | springdoc-openapi 3.1 (OpenAPI 3.1 + Swagger UI) |
| Observability | Spring Boot Actuator + Micrometer (`lbdetector.scan` timer, tagged by verdict) |
| Security | SSRF guard that blocks private, loopback, link-local and metadata addresses |
| Tests | JUnit Jupiter, AssertJ, MockMvc; the JDK `HttpServer` simulates load-balanced backends |
| Build / run | Maven, Docker (multi-stage, Temurin 25 JRE, non-root) |

## How detection works

The prober collects raw observations. Each **HTTP probe uses a brand-new connection** with no cookies, so neither connection reuse nor sticky sessions can pin every probe to one backend. Each **TLS probe uses a fresh SSL context**, so sessions are never resumed. Probes run on virtual threads, throttled to `concurrency` requests at a time.

Seven independent detectors then examine the data:

| Detector | Signal | Weight |
|---|---|---|
| `signature` | Known fingerprints such as `AWSALB`/`AWSELB` cookies, `BIGipServer*` (F5), `NSC_*` and the `Cneonction` header (Citrix), `SERVERID` (HAProxy), `x-envoy-*`, `INGRESSCOOKIE`, `ApplicationGatewayAffinity`, `ARRAffinity`, `Via: 1.1 google`, `cf-ray`, `x-amz-cf-id`, `x-azure-ref`, Akamai, Fastly, Imperva and more | 0.1–0.9 |
| `header-variance` | Node-identifying headers (`Server`, `X-Served-By`, `X-Backend-Server`, `Via`, ...) that change between requests | 0.6–0.8 |
| `tls-variance` | Different certificates or handshake parameters on separate fresh connections | 0.4–0.7 |
| `clock-skew` | `Date` headers from machines whose clocks disagree by more than 2.5 s | 0.65 |
| `content-variance` | A small repeating set of `ETag` / `Last-Modified` values for the same URL | 0.15–0.6 |
| `dns` | Several A/AAAA records, or answers that rotate between lookups | 0.3–0.5 |
| `latency` | Two well-separated response-time clusters (Otsu split) | 0.25 |

**Scoring:** the weights are combined with a noisy-OR, `confidence = 1 − Π(1 − wᵢ)`. A single strong fingerprint is enough on its own, and several weak signals add up. Each detector's share is capped, so one detector can't dominate by repeating itself.

| Confidence | Verdict |
|---|---|
| ≥ 80% | `LOAD_BALANCED` |
| ≥ 50% | `LIKELY_LOAD_BALANCED` |
| ≥ 20% | `POSSIBLY_LOAD_BALANCED` |
| < 20% | `NO_EVIDENCE` |

> **Limitation:** "no evidence" does not mean "no load balancer". A layer-4 balancer in front of identical, clock-synchronised backends that strip identifying headers can't be seen from outside. Use more samples (30–50) for borderline results.

## Build and run

Requires JDK 25 and Maven 3.9+.

```bash
mvn verify                       # compile + run all tests
mvn spring-boot:run              # start the REST service on :8080
```

### npm shortcuts

`package.json` wraps the Maven and Docker commands, so the usual npm habits work. Java 25 and Maven are still required, and there are no Node dependencies.

```bash
npm run build                                   # mvn package (skips tests)
npm test                                        # mvn verify
npm start                                       # mvn spring-boot:run
npm run scan -- --target=https://www.example.com/ --samples=30
npm run docker:build && npm run docker:run
```

### REST API

```bash
curl -s -X POST localhost:8080/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://www.example.com/","samples":30}' | jq

curl -s localhost:8080/api/v1/detectors | jq    # list detection techniques
```

- Swagger UI: http://localhost:8080/swagger-ui.html
- Health: `/actuator/health` (plus `/liveness` and `/readiness`)
- Metrics: `/actuator/metrics/lbdetector.scan`

Errors are returned as `application/problem+json`: 400 for an invalid or blocked target, 429 when too many scans are already running.

### Command line

```bash
java -jar target/lb-detector.jar --target=https://www.example.com/ --samples=30
```

Example output:

```
Target      : http://127.0.0.1:33819/
Verdict     : LOAD_BALANCED (99% confidence)
Identified  : AWS Application Load Balancer
Probes      : 20/20 HTTP ok, 0 TLS, 1 DNS lookups, 624 ms

Evidence (strongest first):
  [ 90%] signature        AWS Application Load Balancer fingerprint found
                           - cookie AWSALB
  [ 80%] header-variance  Header 'x-backend-server' had 2 distinct values across 20 responses
                           - node-a
                           - node-b
  [ 60%] content-variance 2 distinct etag values for the same URL repeating across responses (one per node)
  [ 25%] latency          Response times form two clusters (~11 ms and ~98 ms)
```

### Docker

```bash
docker build -t lb-detector .
docker run -p 8080:8080 lb-detector
docker run --rm lb-detector --target=https://www.example.com/   # CLI mode
```

## Configuration (`application.yml`)

| Property | Default | Meaning |
|---|---|---|
| `lbdetector.default-samples` | 20 | HTTP probes per scan |
| `lbdetector.max-samples` | 100 | Upper limit a caller may request |
| `lbdetector.timeout` | 10s | Per-probe timeout |
| `lbdetector.concurrency` | 4 | Probes in flight per scan (keeps load on the target low) |
| `lbdetector.tls-samples` | 6 | Fresh TLS handshakes per https scan |
| `lbdetector.dns-lookups` | 5 | DNS resolutions per scan |
| `lbdetector.max-concurrent-scans` | 4 | Service-wide scan limit (excess requests get 429) |
| `lbdetector.allow-private-targets` | false | Allow internal targets (turns the SSRF guard off) |

Any property can be overridden with an environment variable, for example `LBDETECTOR_ALLOW_PRIVATE_TARGETS=true`.

## Project layout

```
src/main/java/com/example/lbdetector/
├── LbDetectorApplication.java   entry point (disables JVM DNS cache; CLI vs server mode)
├── engine/                      framework-free core
│   ├── Prober.java              collects HTTP / TLS / DNS samples on virtual threads
│   ├── ScanEngine.java          runs detectors, scores, builds the report
│   ├── ReportFormatter.java     text output for the CLI
│   ├── detector/                one class per technique (implements Detector)
│   └── model/                   immutable records
├── service/ScanService.java     validation, concurrency limit, metrics
├── security/TargetGuard.java    SSRF protection
├── api/                         REST controller, DTOs, Problem Details handler
├── cli/CliRunner.java           --target=... mode
└── config/                      typed properties + bean wiring
```

### Adding a detector

Implement `engine.detector.Detector` and register it as a bean in `DetectorConfiguration`. The engine and `/api/v1/detectors` pick it up automatically.

## Responsible use

Only scan systems you own or are authorised to test. The default settings send about 30 polite requests per scan, but repeated scans of third-party sites may break their terms of service.
