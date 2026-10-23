# VASP

Local AI-assisted security observation for Windows 11 x64. **This is an unsigned, observe-only developer preview, not the completed protection release.** It never installs patches, terminates processes, changes security settings, or creates firewall blocks. See [delivery status](docs/IMPLEMENTATION.md) before relying on it.

## Run

From PowerShell in this directory:

```powershell
.\scripts\Start-Vasp.ps1
```

The native window closes to the tray. Choose **Quit VASP** in the tray to stop monitoring. Monitoring runs while the application is open; the separate development broker service is optional and is not installed automatically. Default local data is `data/local`.

The desktop performs an initial scan, hourly inventory, 30-second security-event polling, and scheduled advisory updates. It shows incomplete coverage and feed failures. Standard-user access to the Windows Security log may be unavailable. VASP does not change audit policy to obtain access. Missing coverage never proves that a device is healthy.

Command-line examples, using the packaged executable:

```powershell
.\dist\vasp.exe --data data/local init
.\dist\vasp.exe --data data/local scan
.\dist\vasp.exe --data data/local feeds
.\dist\vasp.exe --data data/local status
.\dist\vasp.exe --data data/local verify-audit
.\dist\vasp.exe --data data/local sandbox-check
.\dist\vasp.exe --data data/local watch
```

`init` preserves existing configuration. Run either the desktop observer or `watch` for a given data directory, rather than starting multiple schedulers. `feeds` explicitly refreshes public sources; cloud **model** use remains disabled. For completely offline operation, set `feeds_enabled` to `false` in a copy of `configs/local-only.json` and apply it with `configure <file>`.

## Build

Install Visual Studio C++ build tools and the Windows SDK. Rust is pinned in `rust-toolchain.toml`, direct dependencies are exact versions, and transitive dependencies are locked in `Cargo.lock`.

```powershell
.\scripts\cargo.ps1 build --workspace --locked
.\scripts\cargo.ps1 test --workspace --locked
.\scripts\cargo.ps1 clippy --workspace --lib --bins --locked
.\scripts\Package-Preview.ps1
```

The wrapper uses a project-local Rust installation under `.tools` when present, otherwise an installed Cargo. Use a normal user terminal for integration tests: the tests deliberately tighten temporary-directory ACLs and exercise loopback TLS, which some development sandboxes prohibit. Do not run the desktop elevated merely to hide coverage warnings.

The latest broker/IPC increment is staged in `dist/broker-ipc`; `Start-Vasp.ps1` prefers it when present. That build uses Direct3D 12 and a stable status area to address app-window flicker. [Broker setup and authorization details](docs/BROKER.md) describe the separate service, local command catalog, and tests. It is not installed automatically, and blocking remains disabled.

## Enroll another PC

Each PC owns a separate data directory and device identity. Copy only public `identity.der` certificates. Never copy `identity.key`. Compare SHA-256 fingerprints through a trusted local channel, independently of the file transfer.

1. Run `vasp --data data/local identity` on both devices. Record the device IDs, fingerprints, and public certificate paths.
2. On the coordinator, run `vasp --data data/local enroll --device <agent-uuid> --certificate <agent-public.der> --fingerprint <verified-agent-sha256>`.
3. On the agent, run `vasp --data data/local connect --coordinator <private-coordinator-ip>:7443 --certificate <coordinator-public.der> --fingerprint <verified-coordinator-sha256>`.
4. On the coordinator, run `vasp --data data/local serve --bind <private-coordinator-ip>:7443` in a separate terminal. Start the desktop or `watch` on the agent. New observations report automatically; failed reporting retries with backoff while local collection continues.

The coordinator listener is optional and accepts only enrolled, pinned certificates. This command does not create an inbound Windows firewall exception; authorize a narrowly scoped private-LAN rule yourself if needed. Never forward this port through your router. `revoke <agent-uuid>` rejects subsequent reports. `disconnect` on an agent removes its coordinator configuration. Revocation/expiry requires explicit re-enrollment; automatic certificate rotation is not implemented.

Telemetry includes software, service, listener, startup-entry hashes, and bounded security events. Treat coordinator storage as sensitive. This detailed LAN report is separate from the much smaller model projection.

## Models and privacy

Cloud is off by default. No subscription tokens are reused. Direct OpenAI API and authenticated HTTPS LAN-compatible adapters are implemented; a documented subscription adapter is outside this release. Model identifiers are configuration values, including Astra only where the configured service actually exposes it.

Copy `configs/cloud.example.json` or `configs/lan.example.json`, choose an accessible model, configure quotas, then run `vasp --data data/local configure <file>`. Set the cloud cost ceiling per million tokens to at least the highest applicable input/output rate for the selected model. Pricing is operator-supplied; this preview does not independently verify it against provider billing. Requests reserve a conservative token and cost allowance before starting, including failed requests. API account spending limits remain an additional control.

`vasp credential openai` and `vasp credential lan` read a credential from standard input and store it using Windows Credential Manager. Supply it using a trusted secret manager pipe; avoid command arguments or shell history. Credentials are scoped to the current Windows user and shared across that user's VASP data directories. The model worker receives only its own provider credential.

Models receive finding IDs, validated public advisory IDs, applicability, and priority. They receive no raw observations, personal documents, passwords, machine names, paths, or full event logs. This deliberately limits explanation quality. Returned text is untrusted advisory text. It cannot authorize actions, execute commands, edit policy, or install rules. Suggested investigations are schema-validated and displayed; an autonomous multi-step investigation executor is not implemented. There is no silent cloud fallback.

LAN endpoints must use a literal private address, HTTPS, an explicitly configured CA certificate with a matching IP SAN, and an authentication credential. Loopback addresses are not accepted by the LAN adapter.

## Scope and interpretation

- Registry-installed applications, OS build/hotfixes, services, TCP listeners, selected startup locations, Defender/firewall state, and bounded event logs are observed. Portable applications, other users, scheduled-task persistence, Store packages, and transitive dependencies are incomplete.
- LAN visibility is passive neighbor-table collection. It may include cached or virtual-interface entries; it is not a verified live home-network inventory. There is no active discovery, port scan, or router enforcement.
- Name-only matches are research candidates. Simple, supported NVD application version ranges and supported OSV SemVer ranges can establish applicability. Windows update supersedence and complex CPE conditions remain unconfirmed. Conflicting version evidence never becomes a confirmed finding.
- Initial NVD ingestion covers a seven-day **modified-record** window, not the complete historic vulnerability database. Microsoft ingestion currently covers the current month. OSV and CVE lookups are explicit CLI operations. Coverage is insufficient to conclude that an older installation is unaffected.
- KEV signals known exploitation; EPSS is an estimate. Neither proves that a particular installation is vulnerable. Up to 100 relevant CVE IDs are enriched daily in this preview.

See [threat model](SECURITY.md), [implementation boundaries](docs/IMPLEMENTATION.md), and [validation evidence](docs/VALIDATION.md). No local application can guarantee integrity after its operating system or administrator account is compromised.
