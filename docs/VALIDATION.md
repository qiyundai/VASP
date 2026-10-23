# Validation record

## Public repository and elevated recovery suite

The reviewed source-only initial commit is `015c8d11f6f8beb7a8c0ae01f2e012d961cb529f` on [qiyundai/VASP](https://github.com/qiyundai/VASP). Its live default branch is `trunk`. Gitleaks 8.30.1 found no secrets in the staged publication; runtime data, keys, credentials, binaries, local tools and logs were excluded. Public commits use a GitHub no-reply address. GitHub secret scanning, push protection, private vulnerability reporting and dependency alerts are enabled. This is a publication check, not a security certification.

The [hosted Windows run for ab010c476ad238492139d37a00f18912d05cbbee](https://github.com/qiyundai/VASP/actions/runs/40025585567) passed on 2026-10-23: formatting, Clippy, **43 Rust tests**, optimized workspace build, all three live AppContainer denials, and **13 elevated service scenarios**. The native desktop was not exercised interactively on the hosted runner. The same 43 Rust tests passed locally; no service was installed on the development PC.

The elevated scenarios verify authenticated production-client operations; an enrolled ordinary local account authenticating the SYSTEM broker; cross-device/session/policy/stale-request rejection; fabricated evidence denial; replay across a clean restart; forced process termination with explicit restart and journal replay recovery; bounded stop with a stalled client; malformed input rejection; enabled-policy rejection; loose policy ACL rejection; observer-role limits; corrupt-journal refusal and recovery after restoration; and unavailable-service rejection. Every successful receipt reported blocking disabled and zero active blocks. The suite removes its service registration and temporary user, preserving test files only inside the disposable runner.

Failures during development exposed an administrator-only test assumption and a receipt-delivery race: DisconnectNamedPipe discarded unread output. The corrected transport retains pending connects across idle polls and waits for a bounded receipt acknowledgement before disconnecting. Standard-user verification authenticates pipe ownership, session zero and SCM state without requesting SYSTEM-token access. Tests also exercise actual SQLite SQLITE_FULL via a small temporary page ceiling and verify transaction rollback, journal reopening and retry; they do not fill the host filesystem.

These results do not validate WFP filters, automated crash restart, a hung-broker watchdog, reboot, sleep/resume, remote SMB rejection, physical disk/power loss, or the complete Windows 11 elevated matrix. Automatic blocking remains hard-disabled. The GitHub glib alert (GHSA-wrw7-89jp-8q8g) is left open: Cargo tree confirms it belongs to the unsupported Linux tray stack and is absent from the Windows target. The dependency warnings below remain release-review items.

## Broker and renderer increment

The final broker/IPC workspace suite passes **41 tests with zero failures**. Production crates pass Clippy with no source diagnostics; Rust formatting and PowerShell syntax checks pass. An optimized workspace build produced `vasp-broker.exe`, `vasp.exe`, and the Direct3D 12 desktop. The native screenshot smoke test exited successfully and the user confirmed that the restarted app window now looks stable. The staged CLI's AppContainer smoke check again denied private-file reads, public network connections, and child processes.

The broker tests exercise real Windows named pipes under a normal user token and a durable SQLite journal. They do not claim successful elevated SCM installation or WFP recovery. The session token was checked and was not elevated; no broker service was installed. See [BROKER.md](BROKER.md) for the exact validated boundary and pending elevated tests. The original soak is continuing on its original binary; it is not evidence for the new broker.

The dependency audit was repeated after the renderer change: zero vulnerability-category entries and the same three warnings described below. The current audit is `.tools/audit-broker.json`; this increment's staged artifacts and hashes are in `dist/broker-ipc`. Neither hashes nor passing tests constitute release signing or independent security review.

The following record describes the earlier observe-only preview:

Date: 2026-10-23. Local Windows x64 checkout; Rust 1.99.1. No authoritative Git remote exists. This is evidence for an observe-only preview, not acceptance of the full protection product.

## Completed checks

- `cargo test --workspace --locked --offline`: **33 passed, zero failures** (7 application integration/unit tests, 15 core tests, 11 security regressions).
- `cargo build --workspace --release --locked --offline`: optimized CLI and desktop binaries built successfully.
- `cargo clippy --workspace --lib --bins --locked --offline`: no source diagnostics after fixes. Some sandboxed builds report an incremental-cache hard-link fallback, which does not change the build result.
- `cargo fmt --all -- --check`: passed.
- Real release-binary parser AppContainer check: protected data-file read denied, public TCP connection denied, child process creation denied. The tool uses an actual Windows AppContainer and Job Object, not a mocked policy.
- Native inventory on the development PC: OS build, registry applications, services, TCP listeners, passive neighbors, startup-entry hashes, Defender/firewall state, and available event channels collected. Partial/inaccessible sources reported as coverage gaps. No system protection settings were changed.
- Live CISA KEV, current-month Microsoft CVRF JSON, Chromium RSS, and relevant EPSS retrieval/parsing completed successfully in isolated workers. NVD pagination worked in earlier checks; a later page timed out and retained an incomplete/stale status with backoff. Initial NVD bootstrap remains incomplete.
- Native egui window captured through its own screenshot mechanism and visually inspected. No web UI or listening browser administration service is used.

## Security regression scope

Tests cover supported version boundaries; Windows-advisory/SDK confusion; product/publisher identity; conservative complex-CPE handling; conflicting sources and stale inventory; withdrawn OSV responses and unknown range limits; malformed/oversized data; DTD rejection; explicit pagination rejection; and a deterministic malformed-input corpus through multiple parsers.

Model tests cover strict schema rejection of executable/action fields, fabricated finding references, unauthorized policy output, sensitive-field exclusion, and budget clock rollback. These establish that hostile output cannot acquire execution authority, not that a model can never write a misleading explanation.

Policy tests cover disabled policy, fabricated/stale evidence, cross-device requests, replay, clock rollback, protected IPv4/IPv6 destinations, ten-minute lifetime, three concurrent blocks, and rolling hourly budget. They test authorization logic, **not actual Windows packet filtering**.

Application integration tests exercise a real pinned mutual-TLS observation round trip, idempotent retry, unpaired and cross-device rejection, truncated/oversized frames, database replay/revocation, audit truncation, and retention across backward wall-clock changes.

## Dependency review

Cargo Audit against the locally fetched RustSec database reported zero entries in its vulnerability category after updating `anyhow` to 1.0.104. This is **not an all-clear**: `ttf-parser 0.25.1` has an unmaintained warning (RUSTSEC-2026-0192) and is in the Windows egui font stack. `glib 0.18.5` has an unsoundness warning and `proc-macro-error 1.0.4` has an unmaintained warning in the cross-platform lockfile; target-specific Cargo tree inspection showed no `glib` dependency in the Windows build. Review their other-platform paths before adding platforms. No warning is silently suppressed. The font-stack maintenance issue remains a broad-release gate.

The machine-readable local audit is `.tools/audit-final.json`; preview binary hashes are `dist/preview-checksums.json`. Hashes do not authenticate an unsigned release. Dependency scanning does not substitute for code review, exploitability analysis, or provenance verification.

## Soak and unverified requirements

`scripts/Soak.ps1` is a bounded observer harness, defaulting to 72 hours. It records the main observer's CPU time, working set, private memory, and data-directory growth, then verifies the audit chain. Its measurements exclude completed child-worker CPU and do not establish end-to-end detection latency. A short run is a smoke test only. A 72-hour observe-only run also cannot validate false-positive containment because this build cannot block traffic.

The full acceptance suite remains incomplete: privileged broker/IPC authorization, real WFP IPv4/IPv6 targeting, crash/hang/reboot/sleep/resume/clock recovery, full-disk/corruption fault injection, model-provider live tests, sustained coverage-guided parser/IPC fuzzing, historical feed completeness, Windows supersedence fixtures, authenticated updater installation/recovery, and independent security review. No paid model request, automatic block, patch, process termination, router change, or Windows audit-policy change was made during validation.

### Local soak runs

The short observe-only run completed on 2026-10-23. It requested 0.04 hours and produced 15 samples ten seconds apart (last sample at 140.44 seconds), followed by successful audit verification. Sampled main-observer peak working set was 17,240,064 bytes, cumulative main-observer CPU was 2.34375 seconds, and the final sampled data directory was 3,660,013 bytes. These are small smoke-test measurements, not performance guarantees. Worker costs are excluded. NVD remained explicitly incomplete and the Windows Security event channel remained unavailable under the normal user token.

A separate **72-hour observe-only soak was started at 2026-10-23 18:43:51 UTC** in `data/soak-72`. Its results are pending. `soak-run.json` records the executable hash, observer PID, and supervisor PID. `soak.csv`, `watch.stderr.log`, and `supervisor.stderr.log` hold progress; `soak-result.json` is written only on normal completion or cooperative stop. No completion or pass is claimed here.

To stop this test without terminating unrelated processes, create its stop marker:

```powershell
New-Item -ItemType File -Path .\data\soak-72\stop.request -Force
```

The supervisor checks the marker at the next sample, stops its own observer, and verifies the audit. It labels that result stopped, not completed. The long run does not replace VM recovery testing or the independent security review.
