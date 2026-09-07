# V1 private lab acceptance progress

This is an implementation and lab qualification candidate, not an accepted 1.0
release. Detailed private evidence remains in the lab asset records. No private
keys, credentials, endpoint identifiers, or network addresses are published here.

## Verified behavior

- A Debian 12 control plane runs the monitoring and supporting services.
- Debian 12 amd64 and Windows 11 amd64 agents enroll, send activation and
  liveness heartbeats, and deliver native inventory under dedicated identities.
- Both platforms preserve their identity across service and normal OS restarts.
- Queued message hashes match accepted server receipts after connection recovery.
- Real elapsed-time tests show online, stale, offline, and restored online
  states on both platforms; the rendered endpoint details match the status.
- Linux live revocation rejects certificate authentication and subsequent
  observations. Removal refuses an installed identity; after verified revocation
  and protected evidence retention, package removal and fresh enrollment pass.
- Server leaf renewal preserves keys and restores verified TLS listeners.
- Audit delivery enforcement rejects stale acknowledgement and excessive
  backlog. Signed checkpoints are independently verified on protected host
  storage; this is not hardware WORM storage or physical-host independence.
- A normal server package contains the UTC database-session correction. It
  avoids ambiguous daylight-saving timestamp comparisons.

## Executed checks

The runtime source at `7ff446a77c22749c90beee4d7754eeda4b5ad3f1` passed
339 non-PostgreSQL tests and 27 PostgreSQL integration tests, with three other
tests skipped. Integration tests used a separate empty database in an isolated
network namespace and verified synthetic backup/restore preserves revocation.
Ruff and Linux-target strict typing passed. The Windows Go suite passed using a
protected temporary directory; the normal workstation temporary directory was
correctly rejected because additional accounts could modify it.

Bandit reported no medium or high findings. These results do not replace the
remaining mandatory scanners or exact-commit CI qualification.

## Outstanding acceptance

Owner interactive password and authenticator enrollment, encrypted identity-
provider restore, Windows removal/re-enrollment, Windows Server 2022 runtime
qualification, remaining containment/recovery and soak requirements, complete
security review, and immutable signed final release remain open.

The independent encrypted identity-provider backup has passed signature and
ciphertext verification; its restore must not be claimed from the synthetic
RMM database restore test. Temporary bootstrap identities still need lifecycle
closeout. Lab artifacts retain development/candidate version metadata.
