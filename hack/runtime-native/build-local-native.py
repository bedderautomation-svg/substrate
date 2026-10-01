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

"""Build every root-module main at a verified clean source pin, offline."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import time


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--go", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--cache", type=pathlib.Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()
    if not all(re.fullmatch("[0-9a-f]{40}", x) for x in (args.commit, args.tree)):
        raise ValueError("commit and tree must be exact Git object IDs")
    source = args.source.resolve(strict=True)
    go = args.go.resolve(strict=True)
    output = args.output.resolve()
    if git(source, "rev-parse", "HEAD") != args.commit or git(source, "rev-parse", "HEAD^{tree}") != args.tree:
        raise RuntimeError("source pin mismatch")
    if git(source, "status", "--porcelain"):
        raise RuntimeError("source checkout is dirty")
    for name in ("bin", "logs"):
        (output / name).mkdir(parents=True, exist_ok=True)
    if any((output / "bin").iterdir()):
        raise RuntimeError("output contains pre-existing binaries")
    args.cache.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({"PATH": str(go.parent) + ":/usr/bin:/bin", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0", "GOCACHE": str(args.cache.resolve()), "GOMAXPROCS": "4", "GOMEMLIMIT": "1GiB", "GOENV": "off", "GOWORK": "off", "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOFLAGS": "", "GOEXPERIMENT": ""})
    started = time.monotonic()
    listed = subprocess.check_output([str(go), "list", "-mod=vendor", "-f", '{{if eq .Name "main"}}{{.ImportPath}}{{end}}', "./..."], cwd=source, env=env, text=True)
    packages = [x for x in listed.splitlines() if x]
    names = [x.rsplit("/", 1)[-1] for x in packages]
    if not packages or len(set(names)) != len(names):
        raise RuntimeError("main list empty or executable names collide")
    tag = "axiom-" + args.commit[:12]
    command = [str(go), "build", "-mod=vendor", "-p", "4", "-trimpath", "-buildvcs=true", "-ldflags=-X=github.com/agent-substrate/substrate/internal/version.Version=" + tag, "-o", str(output / "bin") + "/", *packages]
    receipt = {"schema_version": 1, "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_commit": args.commit, "source_tree": args.tree, "source_clean": True, "toolchain": subprocess.check_output([str(go), "version"], env=env, text=True).strip(), "go_binary_sha256": hashlib.sha256(go.read_bytes()).hexdigest(), "packages": packages, "command": command, "environment": {k: env[k] for k in ("GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "CGO_ENABLED", "GOMAXPROCS", "GOMEMLIMIT", "GOENV", "GOWORK", "GOOS", "GOARCH", "GOAMD64", "GOFLAGS", "GOEXPERIMENT")}, "state": "building"}
    receipt_path = output / "build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    with (output / "logs" / "build.log").open("w") as log:
        process = subprocess.Popen(command, cwd=source, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            code = "timeout"
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            time.sleep(0.1)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    receipt.update({"exit_code": code, "duration_seconds": round(time.monotonic() - started, 3), "state": "built" if code == 0 else "failed", "artifacts": []})
    if code == 0:
        if git(source, "rev-parse", "HEAD") != args.commit or git(source, "status", "--porcelain"):
            raise RuntimeError("source changed during build")
        for package, name in zip(packages, names):
            path = output / "bin" / name
            version_info = subprocess.check_output([str(go), "version", "-m", str(path)], env=env, text=True)
            (output / "logs" / (name + ".build-info.txt")).write_text(version_info)
            receipt["artifacts"].append({"package": package, "file": "bin/" + name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "build_info_sha256": hashlib.sha256(version_info.encode()).hexdigest()})
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"state": receipt["state"], "exit_code": code, "duration_seconds": receipt["duration_seconds"], "artifact_count": len(receipt["artifacts"])}), flush=True)
    return 0 if code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
