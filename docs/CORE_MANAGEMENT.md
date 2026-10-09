# Core packages, adapters and runtime instances

In the standalone console, open **Overview → Core management**. For managed nodes, use **Captain → Nodes → node details → Core management** as a full administrator. Upgrade bosun before using the controls: older nodes do not advertise the new inventory or execute these jobs.

An inbound selects a protocol and an adapter using the existing `core` field. Core management selects the installed release for each adapter. Downloading a package does not start it or alter any inbound. Each distribution has one active version; several distributions can run together. The catalog contains reviewed versions, not arbitrary URLs or executable uploads.

1. Choose a distribution/version and download it.
2. Select **Activate / switch**, review the interruption notice, and confirm.
3. Select that core in an inbound's editor, or retain automatic selection for existing supported protocols.

A switch serializes with configuration application and reporting. It checks the inventory revision and configuration compatibility, validates sing-box/Xray configurations with the candidate binary, delivers outstanding traffic, stops the old instance and waits for the new instance's statistics API. Failed startup or selection persistence restores the old instance and reports the error. Other adapters validate their rendered model and then use startup/readiness checks. Switching interrupts connections served by that distribution. It cannot atomically stop network traffic and persist counters; existing traffic-journal failure boundaries still apply.

Successful selections and preference order persist in `<data_dir>/cores/active.json`; downloaded executables are under `<data_dir>/cores/<distribution>/<version>/`. New UI-enabled distributions are appended to the preference order. A switch that would move existing automatically assigned inbounds to another core is rejected; pin them first. A failed configuration apply must be resolved before switching. These files are installation state, separate from the standalone configuration backup; preserve the data volume or reselect cores when restoring on a new host. An explicit `config.yaml` binary path remains an administrator pin and cannot be replaced through the UI.

The agent's catalog is the source of available packages. Extending it requires reviewing the upstream format, adapter capabilities, platform assets, checksums and runtime tests. Updating the inventory never silently activates a release. Concurrent activation requests, stale revisions and expired tasks are rejected. Successful replayed jobs do not restart the core again.

## sing-box Extended

`singbox-extended` is a separate distribution and adapter instance. The official `singbox` instance remains available, with a separate statistics port (9101 versus 9105). Optional YAML boot configuration:

```yaml
cores:
  singbox: {}
  singbox_extended:
    version: 1.14.1-extended-2.7.2-r2
    stats_listen: 127.0.0.1:9105
```

The build pins [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended) at `v1.14.1-extended-2.7.2`, commit `55faa763f986f4ca8a492d9b2719bc6330d2bef5`, with `with_v2ray_api` and the tags listed in `scripts/build-singbox-extended.sh`. The upstream release binary lacks the statistics API needed for billing. Vetted dependency security updates are applied to go.mod/go.sum; upstream Go implementation files are unchanged. Published packages include corresponding source, the updated module manifests, GPL license, build instructions and checksums. No GPL implementation is copied into bosun's MIT source.

Linux amd64/arm64 packages are produced by the reusable release workflow. Before those assets are published, or on other platforms, the installer can build from the pinned source when Go and git are available. The source build applies the same dependency pins. The release workflow checks the exact source/build tags for reachable vulnerabilities and exercises the real binary; a bare Go module advisory is not evidence that its affected package is compiled into the executable.

The `-r2` package keeps the same upstream commit and uses Go 1.26.9 with reviewed October security dependency updates. The previous `-r1` assets remain immutable; existing explicitly activated installations retain their selection until the administrator switches versions.

### WARP outbound

Both sing-box distributions reuse bosun's registered or manually supplied WARP credentials. Extended's WireGuard endpoint does not accept the official `reserved` option, so bosun omits it only from that instance's generated configuration. The stored account and the official sing-box/Xray configuration keep those bytes. No account re-registration or core-package replacement is needed for this adapter fix.

CI checks default, rule-selected and unused WARP configurations with the real pinned binaries, including Extended SSH and Mieru. A separate live check is available with `BOSUN_EXTENDED_TEST_BINARY=/path/to/sing-box BOSUN_WARP_TEST_ACCOUNT=/private/account.json go test ./internal/core/singbox -run '^TestExtendedLiveWARP$' -v`. It reads a `spec.WARPAccount` JSON file without modifying it, verifies direct/WARP egress using Cloudflare's trace response and checks SSH per-user/per-inbound traffic counters. Keep that account file private and outside the repository; the test never registers an account or changes host routing.

### Mieru

Select `singbox-extended` explicitly; automatic selection continues to use the existing Mieru adapter. TCP, UDP and BOTH are supported. BOTH uses adjacent ports, preserving the existing subscription convention. The embedded upstream implementation cannot bind a specific listener IP: direct binds and NAT/IPLC ingress binds are rejected; use `mita` for those installations.

Extended Mieru accounts use `UUID|inbound-tag` as the wire username to maintain per-inbound accounting. Statistics map back to the unchanged billing identity. Switching from `mita` retains the user's UUID/password and subscription URL, but clients **must refresh their subscription**. Native mita rolling quotas are unsupported and incompatible combinations are rejected; Captain/bosun still enforce their normal allowance rules. Do not enable mita native quotas for an Extended Mieru deployment. Empty-user listeners wait for a grant instead of preventing the rest of the core from starting.

### SSH proxy

The SSH inbound provides password-authenticated TCP `direct-tcpip` forwarding. Its users are panel subscribers, not operating-system accounts. It does not provide a shell, SFTP, root login or native UDP and does not replace the machine's SSH service. Use a separate free port.

Saving creates a persistent Ed25519 host key. Editing the inbound preserves it; reusable presets omit the key. sing-box subscriptions contain the host **public** key and a per-inbound username. The host private key never belongs in a subscription. Formats without supported SSH output omit this entry.

Typed remote SSH outbounds accept a username, password or inline private key, and a required pinned host public key in `remote.ssh.host_key`; private-key file paths and shell commands are not accepted. They are available through sing-box's outbound adapter. This is protocol support, not a claim of validation against a particular commercial SSH provider.
