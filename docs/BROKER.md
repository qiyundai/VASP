# Local privileged broker

The broker and authenticated IPC are implemented as a separate `vasp-broker.exe`. **Automatic blocking is still disabled at compile time.** There is no runtime flag, policy edit, CLI command, model instruction, or IPC operation that activates it. This development build is not installed as a service on the development PC.

## Trust and transport

The production process runs through Windows SCM as `VaspBroker`, LocalSystem in session 0. It loads a separate endpoint policy from the Windows ProgramData known folder, `VASP/Broker/policy.json`. It refuses user-owned state, unexpected ACL entries, reparse points, an enabled policy, a wrong endpoint journal, or an invalid audit chain. Configuration changes require an administrator and a service restart. The observer/coordinator database cannot supply broker policy.

The fixed pipe is `\\.\pipe\VASP.Broker.v1`. The server uses `FILE_FLAG_FIRST_PIPE_INSTANCE`, rejects remote clients, applies an explicit DACL, and grants each enrolled user SID only data/read-attribute/synchronize rights. It does not grant user callers `FILE_CREATE_PIPE_INSTANCE`. After reading a fixed preface, it identifies the caller with `ImpersonateNamedPipeClient` and the thread token, then reverts before processing. Failed impersonation denies the connection; failed reversion terminates the broker. AppContainer and low-integrity callers are rejected even if their user SID is enrolled. A normal process running as an enrolled user shares that user's authority; this does not distinguish a compromised UI from another process under the same user account.

The client requests identification-only security QoS. Before sending its preface it verifies the connected pipe's SYSTEM/Administrators owner and server session zero, then requires its server PID to match the running, dedicated LocalSystem SCM service. Enrolled callers receive READ_CONTROL to inspect the pipe owner, but no permission to create another pipe instance or change its security. It never requests debug privileges or reads SYSTEM's process token. Knowing the pipe name is insufficient to impersonate the broker. A local administrator remains outside the protection boundary; service configuration changes by an administrator are trusted.

Microsoft references: [named-pipe access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [client impersonation semantics](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient), [process-token privilege requirements](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken), and [SCM configuration queries](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw).

## Command catalog

| Operation | Minimum role | Behavior in this build |
|---|---|---|
| Status | Observer | Returns endpoint identity, policy version, and disabled enforcement state |
| Inventory | Observer | Reads a fixed Windows build/revision registry location; accepts no path |
| StopAutomaticActions | Operator | Durably records the local disabled state |
| RemoveTemporaryBlocks | Operator | Reports zero owned filters; this executable never opens a WFP session |
| ProposeBlock | Operator | Always denies with a release-gate reason; never evaluates supplied evidence as authority |

No arbitrary command, script, file path, registry path, plugin, policy replacement, or enable operation is accepted. Strict empty-struct command variants reject extra JSON fields, including fields that Serde's internally tagged unit variants can otherwise ignore.

Each connection receives a random session challenge and permits one request. Requests bind the session, endpoint UUID, policy version, unique request ID, and a 30-second freshness window. The 16 KiB frame limit is checked before payload allocation. Overlapped I/O has a five-second session deadline; cancellation completes before buffers/OVERLAPPED storage are freed. An idle connection remains pending across stop polls. After reading and validating a receipt, the client sends a fixed acknowledgement before the server disconnects; this prevents Windows discarding an unread response without an unbounded flush. See [DisconnectNamedPipe semantics](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe). There is one connection at a time; malformed connections incur a short backoff. An enrolled caller can still deny availability by repeatedly occupying the bounded connection slot. This has no containment effect while enforcement is disabled.

Service errors emit only internal operation labels and numeric OS error codes to the Windows Application log, at most once per minute during a running instance. Startup failures also emit a diagnostic. Payloads, credentials, SIDs and paths are not logged. A zero code denotes a validation failure without an underlying Win32 error.

## Durable state and recovery

The administrator/SYSTEM-only SQLite journal commits an accepted request ID, receipt, chain link, and high-water clock value atomically before responding. It limits requests to 60 per enrolled SID per minute, caps the database at 64 MiB, and retains a contiguous 30-day chain with an anchor. Clock rollback denies new requests. Startup verifies the journal, checks its endpoint binding, and records a fresh boot ID with automatic actions disabled. Disk/write failures cannot produce accepted durable receipts. Administrator tampering with both journal and anchors is not prevented.

The broker does not recover or recreate packet filters. Future enforcement must add independently qualified endpoint evidence, transactional lease reservation/application, watchdog supervision, authenticated emergency removal, and tested WFP recovery. The existing policy and WFP primitives are not connected to this command handler.

## Running in a disposable Windows VM

Build/package first. Copy the repository preview and scripts to the VM. Obtain the endpoint UUID from `vasp --data <directory> identity` and the intended ordinary user's SID with `whoami /user` in that user's session. Use an elevated PowerShell terminal:

```powershell
.\scripts\Install-Broker.ps1 -DeviceId <endpoint-uuid> -OperatorSid <user-sid> -AllowUnsignedPreview
```

The script installs the fixed executable in Program Files, creates the state parent and child with SYSTEM/Administrators-only ACLs atomically, gives binaries and policy fresh protected ACLs, registers a manual-start LocalSystem service, and starts it. The broker validates and holds both state directories against replacement while running. The explicit unsigned-preview flag is for development testing; there is no production signature chain yet. Existing installations or state parents are not overwritten. No firewall exception or automatic-block permission is created.

From the enrolled user's session, using the same endpoint data directory:

```powershell
.\dist\broker-recovery\vasp.exe --data data/local broker status
.\dist\broker-recovery\vasp.exe --data data/local broker inventory
.\dist\broker-recovery\vasp.exe --data data/local broker stop
.\dist\broker-recovery\vasp.exe --data data/local broker remove-blocks
```

The desktop's Settings page also has a local broker check and stop/remove controls. An absent or unauthorized broker produces an error; no unprivileged fallback is presented as successful privileged execution.

`scripts/Test-BrokerService.ps1 -DisposableEnvironment` is an elevated disposable-VM integration harness. It tests SCM-authenticated typed operations; device/session/policy/time rejection; fabricated block evidence; replay across clean restart and forced process termination; bounded stop with a stalled client; malformed messages; enabled policy, loose policy ACLs, and corrupt journal rejection; observer-role limits; and unavailable-service handling. It removes its SCM registration on cleanup while preserving protected files for diagnostics. It refuses existing service/state and never creates a packet filter. Results are written to the ignored test data directory. A stalled client is not a hung broker-process test.

The public repository is [qiyundai/VASP](https://github.com/qiyundai/VASP), with live default branch `trunk`. Its hosted Windows CI runs the elevated harness on a disposable runner. Consult [validation evidence](VALIDATION.md) for actual results rather than inferring success from the presence of a test. The development PC still has no installed broker service.

## Validation and open gates

Real local pipe tests passed for token identity, ACL rejection of an unlisted user, rejection of an unprivileged fake server, duplicate server-name ownership, oversized frames, silent-client timeout/cancellation, and refusal of user-owned policy state. Journal/protocol tests passed for roles, strict schemas, session/device/policy/time binding, replay across reopen, corruption, clock rollback, quotas, and storage failure. New block proposals always returned denial.

The 13-case elevated suite passed on a disposable hosted Windows runner at commit `ab010c4`, including standard-user production-client authentication, forced termination and explicit restart, durable replay rejection, stalled-client stop, policy/ACL/role rejection, malformed commands and corrupt journal recovery. [Exact run and validation scope](VALIDATION.md) are recorded separately from the local tests.

Still required: Windows 11 elevated and multi-session coverage, AppContainer token negative tests through the actual broker, remote SMB transport rejection tests in an isolated network, durable filesystem/power-loss fault injection, installer adversarial review, independent Windows FFI review, and the full WFP crash/hang/sleep/reboot/clock matrix. SQLite-full behavior is tested by a bounded page ceiling, not by filling a physical disk. The existing 72-hour observe-only soak exercises an older observer binary and does not validate this broker.
