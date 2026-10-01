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


"""Supervise only this task's queue worker. No idle model requests."""
import argparse
import os
import pathlib
import signal
import subprocess
import time

from harness import GuardLease, atomic, now, read_config, guard_active

STOP = False
CHILD = None


def halt(*_):
    global STOP
    STOP = True
    if CHILD is not None and CHILD.poll() is None:
        try:
            os.killpg(CHILD.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def supervise(root):
    global CHILD
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, halt)
    restarts = []
    while not STOP:
        config = read_config(root)
        if guard_active(config):
            atomic(root / "supervisor-health.json", {"state": "migration_paused", "heartbeat": now(), "idle_model_calls": 0})
            time.sleep(2)
            continue
        restarts = [stamp for stamp in restarts if time.monotonic() - stamp < 600]
        if len(restarts) >= 3:
            atomic(root / "supervisor-health.json", {"state": "restart_budget_exhausted", "heartbeat": now(), "idle_model_calls": 0})
            time.sleep(5)
            continue
        try:
            # Hold the controller's shared lease through process creation only.
            # Each worker job separately holds it throughout all child activity.
            with GuardLease(config):
                CHILD = subprocess.Popen(["/usr/bin/python3", "-B", str(root / "harness.py"), "serve", "--root", str(root)], stdin=subprocess.DEVNULL, start_new_session=True, cwd=str(root))
        except (ValueError, OSError):
            time.sleep(2)
            continue
        atomic(root / "supervisor-health.json", {"state": "running", "worker_pid": CHILD.pid, "heartbeat": now(), "restarts_in_window": len(restarts), "idle_model_calls": 0, "owned_component": "native queue worker only"})
        while CHILD.poll() is None and not STOP:
            time.sleep(1)
            atomic(root / "supervisor-health.json", {"state": "running", "worker_pid": CHILD.pid, "heartbeat": now(), "restarts_in_window": len(restarts), "idle_model_calls": 0, "owned_component": "native queue worker only"})
        if STOP:
            halt()
            try:
                CHILD.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(CHILD.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                CHILD.wait(timeout=3)
            break
        restarts.append(time.monotonic())
        atomic(root / "supervisor-health.json", {"state": "restarting_owned_worker", "previous_exit_code": CHILD.returncode, "heartbeat": now(), "idle_model_calls": 0})
        time.sleep(3)
    atomic(root / "supervisor-health.json", {"state": "stopped", "heartbeat": now(), "idle_model_calls": 0})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    supervise(pathlib.Path(parser.parse_args().root).absolute())
