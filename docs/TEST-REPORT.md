# lb-detector Test Report

Nov 24, 2026 · Arunkumar Chandrasekar

## Summary

**Result: PASS.** All 43 automated tests passed on 24 Nov 2026, with 0 failures, 0 errors and 0 skipped. The Maven build (`mvn verify`) succeeded.

| Metric | Value |
| --- | --- |
| Test classes | 5 |
| Tests run | 43 |
| Passed | 43 (100%) |
| Failed / errors / skipped | 0 / 0 / 0 |
| Total test time | 1.24 s |
| Defects found during testing | 1 (fixed and retested) |

The one defect was a false positive in latency detection that only showed on a cold JVM. It was fixed, two regression tests were added, and the full suite then passed (see [Defect found and fixed](#defect-found-and-fixed)).

## Test environment

The suite ran on a developer MacBook Pro with `pnpm test`, which calls `mvn -B verify`.

| Item | Version |
| --- | --- |
| Operating system | macOS 26.7 (Apple silicon, aarch64) |
| JDK | Java 25.0.2 (Oracle) |
| Build tool | Apache Maven 3.9.11 |
| Framework | Spring Boot 4.1.1 / Spring Framework 7 |
| Test runner | Maven Surefire 3.5.6, JUnit Platform |
| Test libraries | JUnit Jupiter, AssertJ, Spring MockMvc |
| Test servers | JDK `HttpServer` on 127.0.0.1 (no external network) |

No test calls the internet. API tests stop at the SSRF guard, and engine tests use local servers or synthetic data.

## Results by test class

Every class passed. The integration and API tests take the longest because they start real servers or a Spring context.

| Test class | Area | Type | Tests | Passed | Failed | Time (s) |
| --- | --- | --- | --- | --- | --- | --- |
| `DetectorsTest` | All 7 detectors | Unit | 17 | 17 | 0 | 0.022 |
| `TargetGuardTest` | SSRF protection | Unit (parameterised) | 14 | 14 | 0 | 0.056 |
| `ScanControllerTest` | REST API, Actuator | Spring Boot + MockMvc | 5 | 5 | 0 | 1.060 |
| `ScoringTest` | Confidence scoring, verdicts | Unit | 4 | 4 | 0 | 0.001 |
| `ScanEngineIntegrationTest` | End-to-end scan over HTTP | Integration | 3 | 3 | 0 | 0.103 |
| **Total** | | | **43** | **43** | **0** | **1.242** |

## Test case details

Each row is one test, or a group of parameterised runs. All passed. "Positive" means the detector should find evidence; "Negative" means it must stay silent.

| ID | Test | Area | Kind | What it verifies | Result |
| --- | --- | --- | --- | --- | --- |
| TC-01 | identifiesAwsAlbFromCookie | Signature | Positive | An `AWSALB` cookie identifies an AWS Application Load Balancer at ≥ 90% weight | Pass |
| TC-02 | identifiesF5AndCloudflareTogether | Signature | Positive | `BIGipServer*` cookie and `CF-RAY` header are both identified in one response | Pass |
| TC-03 | detectsNetscalerMangledConnectionHeader | Signature | Positive | The `Cneonction` header identifies Citrix NetScaler | Pass |
| TC-04 | plainResponseHasNoSignature | Signature | Negative | An ordinary response matches no fingerprint | Pass |
| TC-05 | differentBackendHeadersAreEvidence | Header variance | Positive | 3 different `X-Served-By` values give evidence at 80% | Pass |
| TC-06 | requestIdsAreIgnored | Header variance | Negative | Per-request IDs (`X-Request-Id`) are not mistaken for backends | Pass |
| TC-07 | identicalServerHeaderIsNotEvidence | Header variance | Negative | A constant `Server` header gives no evidence | Pass |
| TC-08 | twoClocksSevenSecondsApartAreDetected | Clock skew | Positive | `Date` headers 7 s apart are reported as 2 clock clusters | Pass |
| TC-09 | singleClockIsNotEvidence | Clock skew | Negative | One consistent clock gives no evidence | Pass |
| TC-10 | repeatingEtagsAreStrongEvidence | Content variance | Positive | 2 ETags alternating gives 60% evidence | Pass |
| TC-11 | uniqueEtagPerResponseIsWeak | Content variance | Negative | A new ETag on every response (dynamic page) stays below 20% | Pass |
| TC-12 | dnsRoundRobinIsDetected | DNS | Positive | 2 addresses with rotating order give 2 pieces of evidence | Pass |
| TC-13 | differentCertificatesAreDetected | TLS variance | Positive | 2 different certificates across connections are reported | Pass |
| TC-14 | bimodalLatencyIsDetected | Latency | Positive | Interleaved ~13 ms and ~97 ms responses are detected | Pass |
| TC-15 | steadyLatencyIsNotEvidence | Latency | Negative | Stable response times (40–43 ms) give no evidence | Pass |
| TC-16 | coldStartSlowFirstWaveIsNotEvidence | Latency | Negative (regression) | A slow first batch from JVM warm-up is not reported | Pass |
| TC-17 | slowBurstInOneHalfOfTheRunIsNotEvidence | Latency | Negative (regression) | A one-off slow burst is not reported as a second backend | Pass |
| TC-18 | noEvidenceMeansZero | Scoring | Negative | No evidence gives 0% confidence | Pass |
| TC-19 | independentDetectorsCombineWithNoisyOr | Scoring | Positive | Two 50% signals from different detectors combine to 75% | Pass |
| TC-20 | oneDetectorRepeatingItselfIsCapped | Scoring | Negative | Four 25% signals from one detector are capped at 35% | Pass |
| TC-21 | verdictThresholds | Scoring | Positive | 90/60/30/10% map to the 4 verdicts correctly | Pass |
| TC-22 | detectsSimulatedLoadBalancer | End-to-end | Positive | A local server alternating 2 backends is reported as `LOAD_BALANCED` and identified as AWS ALB | Pass |
| TC-23 | singleServerShowsNoEvidence | End-to-end | Negative | A single plain server gives `NO_EVIDENCE` | Pass |
| TC-24 | unreachableTargetProducesWarningNotException | End-to-end | Error handling | A dead port returns a warning, not a crash | Pass |
| TC-25 | internalAddressesAreBlocked (×10) | SSRF guard | Security | Loopback, private, link-local, CGNAT, metadata (169.254.169.254) and IPv6 local addresses are blocked | Pass |
| TC-26 | publicAddressesAreAllowed (×4) | SSRF guard | Security | Public IPv4 and IPv6 addresses are allowed | Pass |
| TC-27 | listsAllDetectors | REST API | Positive | `GET /api/v1/detectors` returns all 7 detectors | Pass |
| TC-28 | rejectsLoopbackTargetWithProblemDetail | REST API | Security | Scanning 127.0.0.1 returns 400 with an RFC 9457 problem body | Pass |
| TC-29 | rejectsNonHttpScheme | REST API | Validation | An `ftp://` target returns 400 | Pass |
| TC-30 | rejectsMissingTarget | REST API | Validation | A request with no target returns 400 | Pass |
| TC-31 | healthEndpointIsUp | REST API | Operations | `/actuator/health` reports `UP` | Pass |

## Defect found and fixed

The first run on macOS had 1 failure in 41 tests. It was a real false positive in the latency detector, not a broken test. It is now fixed and covered by regression tests.

| Field | Detail |
| --- | --- |
| ID | DEF-01 |
| Severity | Medium: a single server could be reported as possibly load balanced |
| Failing test | `ScanEngineIntegrationTest.singleServerShowsNoEvidence`: expected `NO_EVIDENCE`, got `POSSIBLY_LOAD_BALANCED` |
| Root cause | On a freshly started JVM, the first batch of 4 parallel probes is slow because of class loading, JIT warm-up and HTTP client start-up. The latency detector read those slow responses as a second, slower backend, which scored 25% confidence. |
| Why it was missed | Passed in the Linux build environment; failed only on a cold JVM on the Mac |
| Fix | `LatencyDetector` ignores the first 4 probes as warm-up, and requires fast and slow responses in both halves of the run. A real load balancer mixes backends throughout; warm-up and one-off slowdowns happen in one burst. |
| Regression tests added | TC-16 `coldStartSlowFirstWaveIsNotEvidence`, TC-17 `slowBurstInOneHalfOfTheRunIsNotEvidence` |
| Test improvement | The integration test now prints the full scan report when it fails, showing which signal fired |
| Retest | All 43 tests passed on the same Mac. The positive case still works: a genuine interleaved pattern is still detected. |
| Status | Closed |

## Coverage gaps and recommendations

Each of the 7 detectors, the scoring, the SSRF guard and the API contract has at least one positive and one negative test. The gaps below are areas the suite does not reach yet.

| Gap | Risk | Recommendation |
| --- | --- | --- |
| No test scans a real public load balancer | Fingerprints may drift as vendors change cookies or headers | Run a manual or nightly scan against a few known targets you are authorised to test |
| TLS probing is only tested with synthetic data | Handshake or SNI bugs would go unnoticed | Add a test with a local HTTPS server and two self-signed certificates |
| Clock skew is only tested with synthetic data (the JDK test server overwrites `Date`) | Date parsing on real responses is unproven | Use a test server that lets the test set `Date`, such as WireMock |
| No successful `POST /api/v1/scans` in API tests (all targets are blocked) | JSON shape of a full report is not checked | Add a test profile with `allow-private-targets=true` and scan a local server |
| Command-line mode is untested | Argument handling could break unnoticed | Add a test that runs the CLI against a local server and checks the output |
| HTTP 429 limit (too many scans) is untested | Concurrency limit could regress | Add a test that holds the scan slots and expects 429 |
| No code-coverage measurement | Untested code paths are invisible | Add the JaCoCo Maven plugin and publish its report |
| Not yet run in CI | Results depend on one machine | Add a GitHub Actions workflow running `mvn verify` on Linux and macOS |
