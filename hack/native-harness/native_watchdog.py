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


"""Independent native process-group deadline and worker-death boundary."""
import argparse
import fcntl
import os
import signal
import subprocess
import sys
import time


def kill_owned_group(*_):
    # This launcher was created with start_new_session=True. Every native
    # descendant inherits its group; no caller-supplied PID is ever signalled.
    os.killpg(os.getpgrp(), signal.SIGKILL)


def run(parent_pid, max_runtime, guard_fd, argv):
    if os.getpid() != os.getpgrp() or os.getpid() != os.getsid(0):
        raise RuntimeError("launcher_requires_own_session")
    if not 0 < max_runtime <= 120 or not argv or parent_pid <= 1:
        raise ValueError("invalid_launcher_bounds")
    # Retain the worker's exact shared lease through this group's cleanup, so
    # a worker crash cannot release exclusive migration while native is alive.
    os.fstat(guard_fd)
    fcntl.flock(guard_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    for event in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM):
        signal.signal(event, kill_owned_group)
    # Established before app-server can spawn or initialize; this process and
    # timer survive a queue-worker crash/SIGKILL. A dead parent prevents spawn.
    signal.setitimer(signal.ITIMER_REAL, max_runtime)
    if os.getppid() != parent_pid:
        return
    try:
        child = subprocess.Popen(argv, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, close_fds=True)
        while child.poll() is None:
            if os.getppid() != parent_pid:
                kill_owned_group()
            time.sleep(0.05)
    finally:
        # Leader completion does not imply that its hook descendants are gone.
        kill_owned_group()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--max-runtime", type=float, required=True)
    parser.add_argument("--guard-fd", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    command = options.command[1:] if options.command[:1] == ["--"] else options.command
    run(options.parent_pid, options.max_runtime, options.guard_fd, command)
