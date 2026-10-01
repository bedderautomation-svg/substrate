# Native Substrate harness

This private Sprite service supervises a serial queue of bounded, read-only Codex jobs. Its idle health and source checks do not invoke a model. It uses the existing native Codex login and installed profile; it does not copy account credentials, install skills, approve hooks, expose a port, or change profile configuration.

The application source is independently deployed. Queue readiness does not establish that Substrate's cluster or workers run successfully. Substrate integration remains gated until their separate receipts verify success. Hosted ChatGPT sessions and other devices are not migrated by this service.

## Prepare on an existing authenticated client

Use an isolated private directory and an existing checkout at the intended exact commit. `prepare.py` refuses an existing config or manifest; updates require inspecting and preserving the installation. It reads the supplied existing profile and source, and writes only the supplied harness directory. The migration controller must have released both its guard and lock before preparation or any runtime launch.

```sh
python3 -B prepare.py --root /home/sprite/substrate-isolated-20261001/native-harness --source /home/sprite/substrate-isolated-20261001/live-source --source-commit f35db03b09645efe659c4c443373f0b1e1c03214 --profile /home/sprite/.codex --cli /home/sprite/.local/bin/codex --migration-guard /home/sprite/substrate-isolated-20261001/rootless-podman/continuation-20261001/launch-guard.json --migration-lock /home/sprite/substrate-isolated-20261001/rootless-podman/continuation-20261001/launch-guard.lock
```

For the existing Sprite, register the prepared supervisor through the Sprites service-create operation using `service.example.json`. Check that the selected service name is absent before creating it; an existing installation requires an owner-checked update. The example has no HTTP port. For another authenticated client, replace the paths and target with its own existing profile and exact source pin; do not copy credentials or shared skill bundles.

The four runtime scripts are integrity pinned in a task-owned manifest. All queue and result directories are mode 0700; files are mode 0600. `supervise.py --root PATH` is the service entrypoint and restarts only its own queue worker, at most three times in ten minutes. Migration pauses new jobs; each running job holds the controller's shared flock until it finishes. The independent native launcher retains the exact lease descriptor through its owned group cleanup, including if the queue worker dies. Interrupted model jobs are recorded and never automatically retried.

## Attach and read status

From an existing authenticated Sprite terminal, including a terminal opened through Hey Terminal:

```sh
/home/sprite/substrate-isolated-20261001/native-harness/harness.py status --root /home/sprite/substrate-isolated-20261001/native-harness
cat /home/sprite/substrate-isolated-20261001/native-harness/supervisor-health.json
```

This is a user-run terminal handoff; it does not imply that Hey Terminal's iOS app was controlled or executed remotely. The existing Sprite HTTP authentication is preserved. There is no public listener.

The service and queue persist on the Sprite. VM sleep can suspend idle computation; a bounded foreground enqueue-and-wait command wakes the VM and waits for actual progress. A fresh heartbeat and receipt establish observed readiness, not continuous computation while the VM sleeps.

## Queue finite work

The command prints a job ID. A completed queue receipt with an exact sentinel and native completion events establishes actual execution; readiness alone does not. Its private receipt appears at `results/JOB_ID.json`. Use `enqueue-wait --kind status --wait-seconds 180` to keep a bounded foreground request open through completion; audit JSON can be submitted with `enqueue-wait --request-file FILE`. Waiting polls only the private result file and never requests another model turn.

```sh
/home/sprite/substrate-isolated-20261001/native-harness/harness.py enqueue --root /home/sprite/substrate-isolated-20261001/native-harness --kind status
/home/sprite/substrate-isolated-20261001/native-harness/harness.py enqueue --root /home/sprite/substrate-isolated-20261001/native-harness --kind source --file README.md
```

`status` and `source` use fixed local Git commands and never invoke a model. `verify` requests one fixed sentinel response. `audit` performs one read-only model turn using at most eight selected tracked files and 32 KiB total source. A queued `verify` or `audit` uses the existing account and can consume its quota. Jobs default to a 120-second process deadline and a 32,768-token observed budget; JSON requests can reduce those within 30–120 seconds and 8,192–32,768 tokens.

```json
{
  "schema_version": 1,
  "kind": "audit",
  "question": "Inspect the supplied files for material correctness and security issues.",
  "files": ["README.md"],
  "max_runtime_seconds": 120,
  "token_budget": 16384
}
```

Submit a private regular request file with `harness.py enqueue-file --root PATH --request-file FILE`. Requests cannot supply arbitrary commands, absolute paths, path traversal, untracked source, credential filenames, or an unbounded runtime. File reads use a no-follow descriptor and verify single-link regular-file bounds. Source text may still contain sensitive material; regex redaction is best effort, so supply appropriate source files.

Each native call applies invocation-only restrictions for shell, editing, image, sleep, connector, web, and delegation tools, selects the read-only sandbox, refuses unattended permission requests, and starts an ephemeral thread. Any observed execution/tool event ends that model job. An independent process-group watchdog bounds the wall clock even if protocol stdin stalls. Cleanup sweeps the owned group after graceful shutdown. A separate launcher establishes its own deadline before app-server can start and terminates the group if its queue worker dies, closing the spawn-before-receipt race. Native rollout-budget tracking and cancellation occur when usage updates arrive; this does not guarantee exact hidden-token preemption during a response.

## Native hook evidence

`harness.py probe --root PATH` initializes the existing native app-server, enumerates enabled/trusted hooks, and validates one ephemeral thread with configured MCP servers disabled and zero tools, without requesting inference. This native client triggers SessionStart lazily at its first turn. `--include-model` adds one fixed sentinel turn and records actual SessionStart and UserPromptSubmit delivery. `native-probe.json` records native `hook/completed` events, their result status, context hashes, and protected profile integrity. It omits raw hook context, commands, free-form hook diagnostics, and private reasoning. Failed hook receipts retain result, duration, entry kinds, and diagnostic hashes; selected integration failures end the bounded job.

Definition presence, manager verification, native discovery/trust, and actual native delivery are separate observations. Installed skill definitions are checked with `harness.py availability --root PATH`. A discovered trusted hook is not described as delivered unless a successful native completion receipt is present. Profile hook events apply only to clients that support and load that profile. Future devices must use their own supported authenticated client; this harness does not establish account-wide automatic execution.

## Focused verification

`python3 -B -m unittest -v test_harness.py` runs offline transport and boundary regressions with fake local children. It includes a nonreading stdin child, a TERM-resistant descendant after leader exit, observed budget/tool refusal, source bounds, and migration launch prevention. Offline fixtures are not evidence of real native hook delivery. Operational receipts separately record the remote service, native probe, private queue jobs, profile integrity, and exact source pin.

These operational artifacts are copyright 2026 bedderautomation-svg and licensed under Apache-2.0; see the repository LICENSE.
