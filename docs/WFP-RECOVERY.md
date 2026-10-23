# WFP recovery validation

Automatic blocking remains hard-disabled by `vasp_core::broker::ENFORCEMENT_ENABLED = false`. The service still denies every block proposal, opens no WFP session, and exposes no fault-injection commands. Passing this suite does not activate endpoint policy. Evidence qualification, transactional lease accounting, protected worker launch/IPC, Windows 11 power recovery validation, and explicit administrator activation remain release gates.

## Implemented recovery primitives

`RecoveryGuard` uses a boot-relative clock that includes sleep, plus an independently checked wall deadline. It stops on expiry, backward clocks, missed heartbeats, and repeated/skipped heartbeat sequence numbers. Stops are sticky: a queued heartbeat after resume cannot restart a lease. It has no persistence/deserialization path. Restart never restores old filters or permissions.

The Windows wrapper uses [QueryInterruptTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttime); [Windows interrupt time](https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time) includes sleep/hibernation bias. WFP objects belong to a [dynamic session](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0). If individual expiry deletion fails, VASP closes the entire session and permanently invalidates that lease owner. Native leases accept at most three filters and ten-minute deadlines. This is not yet the broker's durable per-target hourly accounting.

The separate fault-test supervisor puts a filter owner in a Windows [kill-on-close Job](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects). The child waits for an inherited-pipe startup byte before opening WFP, so no filter exists before successful job assignment. The supervisor checks its own absolute deadline and a two-second heartbeat deadline before reading queued heartbeats. A hung owner is terminated; a crashed supervisor loses its non-inherited job handle and Windows kills the owner. This is a recovery prototype, **not yet the production broker supervisor**. Resource Jobs alone do not establish a restricted identity or privilege sandbox. Simultaneous suspension of both processes cannot remove a filter until execution resumes; kernel compromise remains outside the threat model.

## Disposable elevated test suite

On a disposable Windows VM, from an elevated PowerShell:

```powershell
./scripts/Test-WfpRecovery.ps1 -DisposableEnvironment
```

This builds the explicitly gated `wfp-recovery` example. Preview packaging never includes it. Fixtures only target the fixture executable on loopback TCP high ports, and never management traffic, the production broker, arbitrary application paths, or persistent firewall rules. The suite checks real connection outcomes and WFP filter absence, rather than treating successful API calls as enforcement proof. Cases cover IPv4/IPv6 inbound/outbound matching, an unaffected second port/application, explicit removal, session closure, lease expiry, owner crash, missed heartbeat, supervisor crash, and closing all filters after a native deletion failure. Tests require successful baseline and recovery connections. Privileged tests do not run in normal `cargo test`.

The workflow runs this suite on a disposable GitHub-hosted Windows runner. Its Windows Server result must not be described as Windows 11 power-state validation. Pure deterministic clock-jump tests cover simulated sleep/boot clock changes; they are explicitly not actual reboot/resume acceptance.

## Actual reboot and sleep/resume gate

These checks require an elevated, disposable Windows 11 VM that supports the selected power state. **They have not yet passed on a real power transition.** The development PC is not rebooted/suspended by these scripts, and hosted CI does not claim that coverage.

Build/run the disposable suite first. Then, on a fresh VM snapshot, arm one transition:

```powershell
./scripts/Test-WfpPowerRecovery.ps1 -Phase Prepare -Transition Sleep -DisposableEnvironment
# Manually sleep the disposable VM within 60 seconds; leave it asleep at least ten seconds.
./scripts/Test-WfpPowerRecovery.ps1 -Phase Verify -Transition Sleep -DisposableEnvironment
```

Repeat from another fresh snapshot with `-Transition Reboot`. Complete the reboot within 90 seconds of arming. The harness never invokes a power transition itself. Keep the repository/fixture path identical. Verification requires the same machine/binary, a changed Windows boot timestamp for reboot or actual Windows sleep/wake events for resume, and absence of the original filter GUID. Sleep also requires a post-wake watchdog receipt. A new native suite then confirms recovery and the disabled production gate. Failed/unsupported/late transitions are failures, never skips reported as passes. Modern Standby systems that do not emit the required events remain unvalidated by this harness.

Checkpoints and logs are under ignored `data/wfp-power-*`; keep them local because they contain machine-specific test metadata. Preserve evidence before reverting a VM. These receipts are test diagnostics, not a signed attestation or an administrator-tamper-proof audit. Do not use them to enable production enforcement automatically.
