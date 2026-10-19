# ZAP Core Security and Quality Audit

Date: 2026-10-19

## Executive summary

This review covered all 2,267 Git-tracked files in the repository with repository-wide static analysis, dependency scanning, the standard Java test suite, and manual validation of security-sensitive source-to-sink paths.

No confirmed critical or high-severity remotely exploitable vulnerability was found. Three defense-in-depth weaknesses and four reproducible Windows test defects were confirmed. The automated tools also produced several expected findings caused by ZAP's role as an intercepting security proxy; those are documented below so they are not mistaken for vulnerabilities.

| Classification | Count |
| --- | ---: |
| Critical vulnerabilities | 0 |
| High vulnerabilities | 0 |
| Medium hardening findings | 3 |
| Low hardening findings | 1 |
| Confirmed test/portability defects | 4 groups / 6 failing tests |

## Scope and methodology

- Scope: the complete current checkout, including Java, Python, Gradle, Docker, CI, and distribution files.
- Semgrep: 244 rules over 1,357 applicable tracked files; 35 candidates, all manually triaged.
- Bandit: all Python under `python/`; three candidates.
- OSV-Scanner: recursive source scan; no vulnerability was reported from the two Python packages it could identify. The repository has no Gradle lockfile/SBOM that OSV-Scanner could fully resolve, so this is not a complete Java dependency audit.
- Gradle: `:zap:test` compiled the project and executed 2,706 tests; 2,700 passed, 6 failed, and 5 were skipped.
- Manual review: API access controls, API file transfer, XML/XSLT construction, object deserialization, scripting, process invocation, archive extraction, SQL construction, socket listeners, TLS compatibility, cookies, and HTML response generation.

The AXGuard CLI was unavailable and its installed audit service rejected the run because the service-side runtime budget was exhausted. No AXGuard finding is represented as having completed.

## Attack-surface inventory

### Network entry points

- Intercepting HTTP/HTTPS proxy listeners. Anonymous traffic is expected because inspecting arbitrary HTTP traffic is the product's purpose.
- ZAP HTTP API and web UI. Requests are constrained by sender address and Host header; defaults allow loopback/ZAP domains. Unsafe operations require an API key unless explicitly disabled. HTTPS-only mode is optional.
- Extension-provided API views, actions, callbacks, and shortcut handlers.
- Additional proxy listeners configured through the proxies extension.
- Outbound HTTP/TLS/DNS connections to operator-selected scan targets and update/add-on sources.

### Local and operator-controlled entry points

- Command-line arguments and configuration files.
- Session databases and imported/exported session data.
- Add-on archives and their manifests, libraries, classes, and resources.
- Scripts intentionally executed with access to ZAP's model and control objects.
- API file upload/download, disabled by default and restricted to a configured transfer directory.
- Comparison XML/XSL files selected by the operator.
- HAR, certificate, report, configuration, and language-pack imports/exports.

### Trust boundaries and sensitive assets

- Untrusted proxied web traffic -> HTTP parsers, scanners, history/session database, UI renderers.
- API client -> address/Host allowlist -> API key/nonce -> actions and data export.
- Remote target -> outbound network stack -> proxy/scanner engine.
- Add-on archive -> metadata parser/class loader -> full in-process extension privileges.
- Script file -> language engine -> privileged ZAP objects.
- Local filesystem -> session/config/add-on import -> application state.

High-value assets include proxied credentials and cookies, API key, generated root CA private key, client certificates, authentication configuration, session history, and filesystem paths exposed through optional file transfer.

## Confirmed hardening findings

### H-01: Deprecated unrestricted Java deserialization utility remains shipped

- Severity: Medium (latent/unreachable in this repository)
- CWE: CWE-502
- Location: `zap/src/main/java/org/zaproxy/zap/utils/ViewState.java:74`
- Evidence: `decode(String)` Base64-decodes arbitrary bytes and passes them directly to `ObjectInputStream.readObject()` without an allowlist or `ObjectInputFilter`.
- Reachability: no production or test call site exists in this repository. The class has been deprecated since ZAP 2.10.0, so this is not presently a demonstrated remote exploit path.
- Risk: an add-on or future core caller could expose this helper to untrusted input and create an unsafe deserialization path.
- Recommendation: remove the deprecated class in the next compatible API-removal cycle. If compatibility requires retention, reject untrusted input and apply a strict JEP 290 object filter.

### H-02: API transfer-directory containment is lexical and follows links

- Severity: Medium (conditional defense-in-depth)
- CWE: CWE-22 / CWE-59
- Locations: `zap/src/main/java/org/zaproxy/zap/extension/api/CoreAPI.java:994`, `:1620`, and `:1651`
- Evidence: `getChildPath()` uses `normalize()` and `startsWith()` before `Files.readAllBytes()` or `Files.writeString()`. It does not resolve the parent and existing ancestors with `toRealPath()` or reject symbolic links/junctions.
- Preconditions: API file transfer must be explicitly enabled; the caller must pass API authorization; and a link/junction or unsafe transfer-directory configuration must already exist. The upload endpoint itself does not create links.
- Risk: under those preconditions, a path lexically below the transfer directory can resolve outside it, permitting read/write outside the intended boundary.
- Recommendation: resolve the configured root to a real path, reject symbolic links for every existing component, and verify the resolved parent remains under the real root immediately before opening the file. Add symlink/junction tests on supported platforms.

### H-03: XSLT transformer allows external resource access

- Severity: Medium (local/operator-triggered)
- CWE: CWE-611 / CWE-918
- Location: `zap/src/main/java/org/zaproxy/zap/extension/compare/ExtensionCompare.java:387`
- Evidence: `TransformerFactory.newInstance()` is used with an operator-selected stylesheet without setting `XMLConstants.ACCESS_EXTERNAL_DTD` and `XMLConstants.ACCESS_EXTERNAL_STYLESHEET` to empty strings.
- Reachability: the compared XML is parsed with the project's XXE-disabled builder. The remaining exposure is through XSLT imports/includes or document access in a stylesheet selected locally by the user.
- Risk: a malicious stylesheet can attempt local-file or network access in the ZAP process context.
- Recommendation: disable external DTD and stylesheet access by default. If external imports are a required feature, expose a narrowly scoped opt-in resolver.

### H-04: API key comparison is not constant-time

- Severity: Low
- CWE: CWE-208
- Location: `zap/src/main/java/org/zaproxy/zap/extension/api/API.java:1111`
- Evidence: the configured API key is compared with `String.equals()`.
- Counter-evidence: sender/Host restrictions, network jitter, and lack of a high-resolution oracle make practical remote recovery unlikely under default settings.
- Recommendation: compare encoded key bytes using `MessageDigest.isEqual()` after equalizing invalid/missing input handling.

## Confirmed bugs and quality issues

### B-01: Core API path tests hard-code POSIX separators

- Location: `zap/src/test/java/org/zaproxy/zap/extension/api/CoreAPIUnitTest.java:103`
- Impact: two tests fail on Windows because `Path.toString()` returns backslashes while the assertion constructs a slash-separated string.
- Fix: build expected values with `Paths.get(parent, child).normalize()` or compare `Path` objects.

### B-02: Add-on SBOM test creates an invalid Windows JAR URI

- Location: `zap/src/test/java/org/zaproxy/zap/control/AddOnUnitTest.java:1010`
- Impact: one test fails with `URISyntaxException` because `URI.create("jar:file:" + addOnPath)` embeds Windows backslashes.
- Fix: construct the URI as `URI.create("jar:" + addOnPath.toUri())` or use the ZIP filesystem provider's `Path` overload.

### B-03: Home-lock assertions read a file while ZAP intentionally holds its lock

- Location: `zap/src/test/java/org/parosproxy/paros/ConstantUnitTest.java:88` and `:104`
- Impact: two tests fail on Windows with a sharing/locking violation while reading `.homelock`; POSIX permits the read.
- Fix: assert existence/size without reopening the locked file, or release the lock during test teardown before inspecting contents.

### B-04: Add-on loader tests leak ZIP filesystem/file handles

- Location: `zap/src/test/java/org/zaproxy/zap/control/AddOnLoaderUnitTest.java` (temporary add-on archives)
- Impact: JUnit cannot delete the temporary directory on Windows after `executionError`, leaving multiple `.zap` files locked.
- Fix: identify and close all `ZipFile`, ZIP filesystem, and add-on classloader resources in the tested error path; add a Windows cleanup regression test.

## Automated candidates rejected as false positives or intentional behavior

- API XML serialization creates a new empty DOM and never parses external input; the XXE rules at `API.java:836` and `ApiException.java:161` are false positives. Setting external-access restrictions is still harmless hardening.
- Unencrypted proxy sockets are expected: ZAP must accept and inspect HTTP, and separately handles TLS interception.
- DES, RC4, MD5, and ECB findings are in NTLM protocol compatibility code. Substituting AES would break the protocol rather than secure it. Prefer disabling legacy NTLM modes where compatibility permits.
- `SSLContext("TLS")` is used by a scanner that must negotiate operator-selected/legacy protocols. Protocol policy is configurable; generic rules cannot classify this correctly.
- Cookie findings mostly copy or model target-application cookies. Forcing `Secure`/`HttpOnly` would alter the traffic under test.
- Script-engine execution is an explicit privileged feature operating on user-installed scripts, not an injection sink reached from proxied traffic.
- The Bandit shell finding is in a legacy example/test harness. Configuration controls only an appended ZAP home argument, so it is not production exposure; nevertheless `subprocess` with an argument vector is safer.
- Add-on library extraction derives a destination filename from add-on metadata. Add-ons already execute arbitrary in-process Java code, so a malicious add-on is not given a new privilege boundary by this path. Path validation would still prevent accidental escape.

## Dependency and secret review limitations

- Semgrep's secret pack found no committed secret candidate.
- OSV-Scanner reported no known vulnerability, but it resolved only the Python requirements it recognized. It did not produce a complete Gradle dependency inventory.
- A release-quality follow-up should generate a CycloneDX SBOM from the resolved Gradle graph and scan that SBOM with OSV/Dependency-Check, including transitive dependencies and add-ons bundled by distribution tasks.
- Dynamic behavior, add-ons stored in other repositories, and deployed configuration were out of scope for this checkout-only review.

## Recommended contribution order

1. Fix B-01 through B-04 to establish a clean Windows test baseline.
2. Remove or constrain `ViewState.decode()` (H-01).
3. Harden transfer-directory resolution and add link/junction regression tests (H-02).
4. Lock down external XSLT resources (H-03).
5. Generate and scan a resolved Gradle SBOM in CI.
