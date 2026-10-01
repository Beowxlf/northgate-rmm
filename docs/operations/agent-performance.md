# Management worker performance

Worker 1.1.0-lab.6 reduces repeated work without changing the one-second polling
interval, terminal frame limits, job contracts or authorization leases.

The serial poll loop reuses its bounded HTTPS connection pool. It still reads
the protected identity and CA files on every poll and retires the pool if either
changes or becomes unreadable/invalid. Certificate validity boundaries, a
five-minute maximum pool lifetime and network failures also retire it. Normal
TLS 1.3 hostname/chain validation and per-request server enrollment/job checks
remain enabled. There is no TLS session-resumption cache or ambient proxy use.

Installed agent and capture-tool version strings are cached for at most 30
seconds. File replacement, size/mtime changes, removal or a failed probe force
a fresh result. These cached strings are display metadata; signed update
verification does not rely on them. Terminal batches copy only the frames they
send, and acknowledged frame references are cleared to release their strings.

`BenchmarkManagementPollHTTPS` compares the prior fresh-client pattern with
the reusable client using real local TLS requests and client certificates. It
reports time, allocation volume and connection count. A Windows development
machine measured about 4 ms versus 0.5 ms per request and about 216 KB versus
23 KB allocated per request over three 100-request samples. This is a component
benchmark, not a whole-agent or WAN throughput claim. Use matched endpoint CPU
and memory sampling plus operational checks to assess deployment impact.

Regression coverage checks connection reuse, trust rotation, corrupt identity
replacement, expiry-driven refresh, continued application revocation checks,
version invalidation and failure retry. Existing file, signature, lease,
terminal and update tests remain applicable. Release tests that install/remove
dependencies or exercise canary system changes require their separate explicit
qualification environment and are not implicit in an ordinary test run.

Rollback uses the signed updater's retained previous binary and existing release
catalog. The monitoring agent and Wxlfgar binary do not need replacement for this
worker-only optimization.
