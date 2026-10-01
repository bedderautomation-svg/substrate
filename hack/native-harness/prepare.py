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


"""Create an owned private harness config without changing any native profile."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess

OWNER = "axiom-substrate-native-harness"
CODE = ("harness.py", "native_client.py", "supervise.py", "native_watchdog.py")


def write_exclusive(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser()
    for name in ("root", "source", "source-commit", "profile", "cli", "migration-guard", "migration-lock"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    root = pathlib.Path(args.root).absolute()
    origin = pathlib.Path(__file__).resolve().parent
    source = pathlib.Path(args.source).absolute()
    profile = pathlib.Path(args.profile).absolute()
    if root.is_symlink() or any((root / name).exists() for name in ("config.json", "manifest.json")):
        raise ValueError("existing_config_refused; inspect ownership and preserve existing installation")
    if not (profile / "config.toml").is_file() or not os.access(args.cli, os.X_OK):
        raise ValueError("existing_native_profile_or_executable_missing")
    commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    if commit != args.source_commit:
        raise ValueError("source_pin_mismatch")
    guard = pathlib.Path(args.migration_guard)
    lock = pathlib.Path(args.migration_lock)
    if not guard.is_file() or not lock.is_file() or json.loads(guard.read_text()).get("active", True):
        raise ValueError("migration_guard_not_released")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    for name in CODE:
        target = root / name
        if target.exists() and target.resolve() != (origin / name).resolve():
            raise ValueError("existing_code_refused")
        if not target.exists():
            shutil.copyfile(origin / name, target)
        os.chmod(target, 0o700)
    config = {"owner": OWNER, "schema_version": 1, "source": str(source), "source_commit": commit, "profile": str(profile), "cli": args.cli, "migration_guard": str(guard), "migration_lock": str(lock), "max_concurrency": 1, "default_max_runtime_seconds": 120, "default_token_budget": 32768, "public_listener": False, "idle_model_calls": 0}
    manifest = {"owner": OWNER, "schema_version": 1, "code_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in CODE}}
    write_exclusive(root / "manifest.json", manifest)
    write_exclusive(root / "config.json", config)
    print(json.dumps({"state": "prepared", "root": str(root), "source_commit": commit, "native_profile_modified": False, "model_called": False}))


if __name__ == "__main__":
    main()
