# Security model

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not post credentials, device inventories, event logs, private keys, or exploit details in public issues. This is an experimental observe-only preview with no supported production release or security response-time commitment.

## Assets and adversaries

Protect endpoint availability, local policy, device identities, model credentials, observation confidentiality, and integrity of findings/actions. Inputs include malicious advisory documents, compromised model responses, unauthenticated LAN clients, malicious enrolled peers, malformed local state, clock changes, process failure, and network loss. A compromised kernel or local administrator can bypass this application. Same-user malware can access user-owned preview state and Credential Manager; this preview is not a tamper-resistant privileged service.

## Current boundaries

`vasp-core` forbids unsafe Rust and contains bounded parsers, typed protocol objects, deterministic matching, model validation, quota accounting, policy decisions, and update verification. `vasp-platform` confines Windows FFI to inventory, process isolation, credentials/ACLs, and WFP wrappers. The Rust application/UI crates forbid unsafe code through workspace lints. Dependencies still contain native and unsafe code; Rust alone does not establish immunity.

The desktop/coordinator is a normal user process. Collector children use Job Objects with memory/process/time limits, but execute with the user's token. They are **not** security-isolated from that user's files. Feed parsers run in a separate network-denied AppContainer. Fetching and model communication use distinct AppContainer profiles with explicit network capability classes. Workers inherit only pipe handles and a small environment allowlist, not arbitrary credentials or proxy configuration. The parent assigns AppContainer workers to a Job before resuming them. Failure to establish isolation aborts the operation.

The parser conformance probe tests denial of a protected data-file read, a public TCP connection, and a child process. It is a limited integration check, not a proof of all AppContainer guarantees. Internet-capable AppContainers have OS capability-level network permission, not an OS-level per-origin firewall. The application additionally restricts origins, DNS results, redirects, response sizes, and deadlines; native code execution inside an internet-capable worker could defeat those application-level restrictions. A model worker necessarily holds its selected provider credential for the request.

Public fetches use fixed structured sources, HTTPS certificate validation, no redirects/proxies, public-address validation, and connection pinning to validated DNS answers. Parser output never supplies a URL to fetch automatically. LAN model endpoints have a separate private-IP/CA/authentication path. A malicious report cannot nominate a private address or change that configuration.

LAN clients initiate mTLS connections and pin the coordinator certificate. The coordinator requires an explicitly enrolled client certificate, binds the certificate fingerprint to a device UUID, validates frame size/schema/time/device identity, records replay IDs, and limits concurrent connections. It accepts observations only. A compromised enrolled endpoint can lie about itself, not authorize changes on another device. Repeated delivery of an identical previously accepted observation is idempotent; changing its contents or sending older observations is rejected.

SQLite data and identity files inherit ACLs for the current user, SYSTEM, and Administrators. SQLite uses WAL, full synchronization, integrity checks, and a database page limit. Retention removes records older than 30 days while preserving the latest observation per device and a contiguous audit prefix anchor. Audit chaining detects ordinary edits/truncation, not a local administrator rewriting both records and anchors. Reparse-point races, external WAL readers, full-disk behavior, and large-scale database denial of service require further testing. Model quotas use immediate SQLite transactions and conservative reservations. Clock rollback denies additional model/policy authorization; arbitrary clock changes and OS compromise remain outside trustworthy accounting.

## Enforcement boundary

Automatic enforcement is hard-disabled in this preview. A separate broker service and authenticated local pipe are implemented; see [BROKER.md](docs/BROKER.md). Its handler always denies block proposals and never opens a WFP session. The service has not been installed or positively validated under SCM on this development PC. No UI, remote protocol, or model operation calls the WFP block method. There is no generic command, script, registry-write, file-write, patch, or process-termination API.

Future activation requires an administrator-owned endpoint policy and authenticated local-only broker IPC, qualified local evidence validation, transactional action journals, protected management/recovery targets, three-block concurrency and rolling duration limits, and an independently tested watchdog. Dynamic WFP sessions provide cleanup when sessions end; they alone do not address hung processes, sleep/resume, or reconciliation failures. Flipping the release constant is not a supported activation procedure.

## Updates and release keys

The pure verifier checks signed metadata thresholds, sequence rollback, expiry, sizes, and artifact hashes. There is no deployed update installer, production trust root, Authenticode signature, staged rollout, or recovery implementation. Preview checksums are for local artifact identification, not authenticated distribution. Production signing keys must live outside endpoints and outside this repository.

## Required release review

Independent reviewers must assess unsafe Windows wrappers and handle lifetimes, token/ACL/IPC boundaries, parser and TLS fuzzing, source version semantics and withdrawal handling, identity rotation/revocation, resource exhaustion, data retention, update key rotation/recovery, and real WFP fault behavior. Do not describe this preview as attack-proof or deploy it broadly as an autonomous protection product.
