#!/usr/bin/python3
# Copyright 2026 bedderautomation-svg
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Bounded native Codex app-server client; never edits native profile or trust."""
import hashlib
import fcntl
import json
import os
import pathlib
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
import tomllib


class ClientError(RuntimeError):
    pass


def redact(text):
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(token|api[_-]?key|access[_-]?token|secret|password)([=:]\s*)[^\s&]+", r"\1\2[REDACTED]", text)
    return re.sub(r"(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", text)


def profile_hashes(profile):
    names = ("config.toml", "hooks.json", "AGENTS.md", "axiom-field-voice/manifest.json", "og-runtime-hooks/manifest.json", "blueprint-runtime/manifest.json", "max-mouth/state.json")
    return {name: hashlib.sha256((profile / name).read_bytes()).hexdigest() if (profile / name).is_file() else None for name in names}


def restricted_config(profile, token_budget):
    config = {
        "features.hooks": True,
        "features.shell_tool": False,
        "features.view_image": False,
        "features.sleep_tool": False,
        "features.unified_exec": False,
        "features.multi_agent": False,
        "features.apps": False,
        "features.plugins": False,
        "features.remote_plugin": False,
        "features.skill_mcp_dependency_install": False,
        "features.goals": False,
        "features.code_mode.enabled": False,
        "features.rollout_budget.enabled": True,
        "features.rollout_budget.limit_tokens": token_budget,
        "features.rollout_budget.reminder_at_remaining_tokens": [token_budget // 4],
        "features.rollout_budget.sampling_token_weight": 1.0,
        "features.rollout_budget.prefill_token_weight": 1.0,
        "tools.view_image": False,
        "include_apply_patch_tool": False,
        "web_search": "disabled",
        "hide_agent_reasoning": True,
        "memories.generate_memories": False,
    }
    # An empty table merges with profile entries. Supply a complete, disabled
    # transport per existing name so bootstrap validation accepts the override.
    # Read only transport kind; do not copy URLs, environment, or credentials.
    data = tomllib.loads((profile / "config.toml").read_text())
    servers = {}
    for name, server in data.get("mcp_servers", {}).items():
        if "url" in server:
            servers[name] = {"url": "http://127.0.0.1:9", "enabled": False}
        elif "command" in server:
            servers[name] = {"command": "/usr/bin/false", "enabled": False}
        else:
            raise ClientError("unsupported_mcp_transport_kind")
    config["mcp_servers"] = servers
    return config


def toml_value(value):
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key) + "=" + toml_value(item) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(toml_value(item) for item in value) + "]"
    return json.dumps(value)


class NativeClient:
    def __init__(self, cli, cwd, profile, max_runtime=120, token_budget=32768, guard_fd=None):
        if guard_fd is None:
            raise ClientError("native_launcher_requires_migration_lease")
        os.fstat(guard_fd)
        fcntl.flock(guard_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        self.started = time.monotonic()
        self.deadline = self.started + max_runtime
        self.profile = pathlib.Path(profile)
        self.before = profile_hashes(self.profile)
        self.cwd = str(cwd)
        self.config = restricted_config(self.profile, token_budget)
        self.token_budget = token_budget
        self.token_usage = None
        self.hook_events = []
        self.hook_metadata = {}
        self.mcp_observations = []
        self.stderr = []
        self.event_methods = []
        self.pending = []
        self.answers = []
        self.turn_status = None
        self.tool_events = 0
        self.output_chars = 0
        self.next_id = 1
        self.closed = False
        self.deadline_killed = False
        self.close_lock = threading.RLock()
        args = [cli, "app-server", "--listen", "stdio://"]
        for key, value in self.config.items():
            args.extend(["-c", key + "=" + toml_value(value)])
        launcher = pathlib.Path(__file__).with_name("native_watchdog.py")
        launch_args = [sys.executable, "-B", str(launcher), "--parent-pid", str(os.getpid()), "--max-runtime", str(max_runtime), "--guard-fd", str(guard_fd), "--"] + args
        self.process = subprocess.Popen(launch_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, cwd=self.cwd, bufsize=0, pass_fds=(guard_fd,))
        self.watchdog = threading.Timer(max(0, self.deadline - time.monotonic()), self._deadline_kill)
        self.watchdog.daemon = True
        self.watchdog.start()
        self.selector = selectors.DefaultSelector()
        self.buffers = {}
        for stream, label in ((self.process.stdout, "stdout"), (self.process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, label)
            self.buffers[label] = b""

    def _deadline_kill(self):
        # Independent of protocol reads/writes: even a nonreading child is bounded.
        with self.close_lock:
            if self.closed:
                return
            self.deadline_killed = True
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def send(self, message):
        payload = (json.dumps(message) + "\n").encode()
        offset = 0
        while offset < len(payload):
            if self.deadline_killed or time.monotonic() >= self.deadline:
                raise ClientError("process_deadline_exceeded")
            written = self.process.stdin.write(payload[offset:])
            if not written:
                raise ClientError("native_stdin_closed")
            offset += written
        if self.deadline_killed:
            raise ClientError("process_deadline_exceeded")
        self.process.stdin.flush()

    def _event(self, message):
        method = message.get("method", "")
        self.event_methods.append(method)
        params = message.get("params", {})
        if method == "hook/completed":
            run = params.get("run", {})
            entries = run.get("entries", [])
            self.hook_events.append({
                "event": run.get("eventName"), "status": run.get("status"),
                "display_order": run.get("displayOrder"),
                "integration": self.hook_metadata.get((run.get("eventName"), run.get("sourcePath"), run.get("displayOrder"))),
                "source": run.get("source"),
                "source_path": run.get("sourcePath"), "duration_ms": run.get("durationMs"),
                "entry_kinds": [e.get("kind") for e in entries],
                "entry_characters": sum(len(e.get("text", "")) for e in entries),
                "diagnostic_sha256": [hashlib.sha256(e.get("text", "").encode()).hexdigest() for e in entries if e.get("kind") in ("error", "warning")],
                "diagnostic_code": "native_hook_not_completed" if run.get("status") != "completed" else None,
                "context_sha256": [hashlib.sha256(e.get("text", "").encode()).hexdigest() for e in entries if e.get("kind") == "context"],
            })
            if self.hook_events[-1].get("integration") in ("axiom-field-voice", "og-runtime-hooks", "blueprint-runtime") and run.get("status") != "completed":
                raise ClientError("selected_native_hook_failed: " + self.hook_events[-1]["integration"])
        if method == "thread/tokenUsage/updated":
            self.token_usage = params.get("tokenUsage", {}).get("total")
            if self.token_usage and self.token_usage.get("totalTokens", 0) > self.token_budget:
                raise ClientError("observed_token_budget_exceeded")
        if method == "item/agentMessage/delta":
            self.output_chars += len(params.get("delta", ""))
            if self.output_chars > 16384:
                raise ClientError("visible_output_limit_exceeded")
        if method == "item/completed":
            item = params.get("item", {})
            if item.get("type") == "agentMessage":
                self.answers.append(redact(item.get("text", ""))[:16384])
        if method == "item/started":
            item_type = params.get("item", {}).get("type")
            if item_type in ("commandExecution", "mcpToolCall", "dynamicToolCall", "webSearch", "fileChange"):
                self.tool_events += 1
                raise ClientError("unexpected_model_tool_request")
        if method == "turn/completed":
            self.turn_status = params.get("turn", {}).get("status")
        # No unattended permission, hook trust, elicitation, or dynamic-tool grant.
        if "id" in message and method:
            self.send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32001, "message": "This read-only harness does not grant unattended permissions or credentials."}})

    def pump(self, wait=0.5):
        if time.monotonic() >= self.deadline:
            raise ClientError("process_deadline_exceeded")
        if self.process.poll() is not None and not self.selector.get_map():
            raise ClientError("native_process_ended")
        messages = []
        for key, _ in self.selector.select(min(wait, max(0, self.deadline - time.monotonic()))):
            try:
                chunk = os.read(key.fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            label = key.data
            self.buffers[label] += chunk
            if len(self.buffers[label]) > 2 * 1024 * 1024:
                raise ClientError("native_output_bound_exceeded")
            while b"\n" in self.buffers[label]:
                raw, self.buffers[label] = self.buffers[label].split(b"\n", 1)
                line = raw.decode("utf-8", "replace")
                if label == "stderr":
                    self.stderr = (self.stderr + [redact(line)[:2048]])[-8:]
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                if message.get("method"):
                    self._event(message)
                else:
                    messages.append(message)
        self.pending.extend(messages)

    def request(self, method, params, timeout=90):
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        request_deadline = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < request_deadline:
            for index, message in enumerate(self.pending):
                if message.get("id") == request_id:
                    self.pending.pop(index)
                    if "error" in message:
                        error = message["error"]
                        raise ClientError(method + ": " + redact(str(error.get("message", "native error")))[:512])
                    return message.get("result", {})
            self.pump()
        raise ClientError(method + "_deadline_exceeded")

    def initialize(self):
        result = self.request("initialize", {"clientInfo": {"name": "axiom_substrate_native_harness", "title": "AXIOM Substrate Native Harness", "version": "1.0.0"}, "capabilities": {"experimentalApi": True}}, timeout=90)
        self.send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        return {key: result[key] for key in ("userAgent", "platformFamily", "platformOs") if key in result}

    def hooks_list(self):
        result = self.request("hooks/list", {"cwds": [self.cwd]}, timeout=20)
        projected = []
        for entry in result.get("data", []):
            hooks = []
            for hook in entry.get("hooks", []):
                command = hook.get("command", "")
                integration = next((name for name in ("axiom-field-voice", "og-runtime-hooks", "blueprint-runtime", "max-mouth") if "/" + name + "/" in command), None)
                self.hook_metadata[(hook.get("eventName"), hook.get("sourcePath"), hook.get("displayOrder"))] = integration
                hooks.append({"event": hook.get("eventName"), "enabled": hook.get("enabled"), "trust": hook.get("trustStatus"), "source_path": hook.get("sourcePath"), "display_order": hook.get("displayOrder"), "integration": integration, "handler_type": hook.get("handlerType"), "timeout_seconds": hook.get("timeoutSec")})
            projected.append({"cwd": entry.get("cwd"), "errors_count": len(entry.get("errors", [])), "warnings_count": len(entry.get("warnings", [])), "hooks": hooks})
        return projected

    def requested_skills(self):
        selected = {"axiom-field-voice", "og-runtime-hooks", "blueprint-runtime", "blueprint-alchemist", "breakthrough-lab", "og-compute", "uncommon-og"}
        result = self.request("skills/list", {"cwds": [self.cwd], "forceReload": False}, timeout=20)
        return [{"cwd": entry.get("cwd"), "errors_count": len(entry.get("errors", [])), "skills": [{key: item.get(key) for key in ("name", "enabled", "path", "scope")} for item in entry.get("skills", []) if item.get("name") in selected]} for entry in result.get("data", [])]

    def mcp_status(self, thread_id=None):
        params = {"limit": 100, "detail": "toolsAndAuthOnly"}
        if thread_id:
            params["threadId"] = thread_id
        result = self.request("mcpServerStatus/list", params, timeout=20)
        servers = [{"name": item.get("name"), "auth_status": item.get("authStatus"), "runtime_status": item.get("runtimeStatus"), "tool_count": len(item.get("tools", {}))} for item in result.get("data", [])]
        receipt = {"servers": servers, "configured_table_empty": not servers and not result.get("nextCursor"), "all_servers_disabled_without_tools": all(item.get("runtime_status") == "disabled" and item.get("tool_count") == 0 for item in servers) and not result.get("nextCursor")}
        self.mcp_observations.append(receipt)
        if thread_id and not (receipt["configured_table_empty"] or receipt["all_servers_disabled_without_tools"]):
            raise ClientError("native_mcp_restriction_not_disabled")
        return receipt

    def start_thread(self):
        result = self.request("thread/start", {"cwd": self.cwd, "sandbox": "read-only", "ephemeral": True, "environments": [], "approvalPolicy": {"granular": {"sandbox_approval": False, "rules": False, "skill_approval": False, "request_permissions": False, "mcp_elicitations": False}}}, timeout=30)
        return result["thread"]["id"]

    def turn(self, thread_id, prompt):
        self.request("turn/start", {"threadId": thread_id, "input": [{"type": "text", "text": prompt}], "environments": []}, timeout=20)
        while self.turn_status is None:
            self.pump()
        return {"status": self.turn_status, "answers": self.answers, "token_usage": self.token_usage, "tool_events": self.tool_events}

    def receipt(self):
        return {"duration_seconds": round(time.monotonic() - self.started, 3), "mcp_observations": self.mcp_observations, "native_hook_completions": self.hook_events, "stderr_tail": self.stderr, "token_usage": self.token_usage, "token_budget": self.token_budget, "model_tool_events": self.tool_events, "protected_profile_bytes_unchanged": profile_hashes(self.profile) == self.before, "process_exit_code": self.process.poll(), "deadline_watchdog_fired": self.deadline_killed, "independent_launcher_deadline": True, "native_trust_edits": False, "account_wide_activation": False, "token_enforcement_limit": "Native rollout-budget tracking and cancellation at received usage updates; no claim of exact hidden-token preemption during one response. Independent launcher establishes a process-group wall deadline before native spawn and also terminates its group when the queue worker dies."}

    def close(self):
        with self.close_lock:
            if self.closed:
                return
            self.closed = True
            self.watchdog.cancel()
        # Signal the owned group even if its leader has exited; owned children
        # must not survive an otherwise successful protocol invocation.
        try:
            deadline_reached = time.monotonic() >= self.deadline
            os.killpg(self.process.pid, signal.SIGKILL if deadline_reached else signal.SIGTERM)
        except ProcessLookupError:
            pass
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=3)
        # A successful wait for the leader says nothing about TERM-resistant
        # hook descendants. Sweep the owned process group unconditionally.
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.selector.close()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


def verify_native(cli, root, profile, include_model=False, guard_fd=None):
    client = NativeClient(cli, root, profile, guard_fd=guard_fd)
    receipt = {}
    try:
        receipt["initialize"] = client.initialize()
        receipt["hooks"] = client.hooks_list()
        receipt["requested_skills"] = client.requested_skills()
        receipt["mcp_status"] = client.mcp_status()
        thread = client.start_thread()
        receipt["thread_mcp_status"] = client.mcp_status(thread)
        receipt["hook_trigger_scope"] = "This native client lazily triggers SessionStart at the first turn; thread creation alone does not establish delivery."
        if include_model:
            receipt["turn"] = client.turn(thread, "Reply exactly SUBSTRATE_NATIVE_HOOK_VERIFICATION; do not call tools or modify files.")
    except (ClientError, OSError, KeyError) as error:
        receipt["error"] = redact(str(error))[:1024]
    finally:
        client.close()
        receipt.update(client.receipt())
    return receipt
