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


import hashlib
import fcntl
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import time
import tomllib
import unittest
from unittest.mock import patch

import harness
from native_client import NativeClient, ClientError, restricted_config, toml_value


def held_guard(root):
    fd=os.open(root/'fixture-guard.lock',os.O_RDWR|os.O_CREAT,0o600)
    fcntl.flock(fd,fcntl.LOCK_SH)
    return fd


def guarded_client(cli,root,**kwargs):
    fd=held_guard(root)
    try:return NativeClient(str(cli),str(root),str(root),guard_fd=fd,**kwargs)
    finally:os.close(fd)


def process_state(pid):
    namespace=os.stat('/proc/self/ns/pid').st_ino
    for path in pathlib.Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            if os.stat(path/'ns/pid').st_ino!=namespace:continue
            line=next(line for line in (path/'status').read_text().splitlines() if line.startswith('NSpid:'))
            if int(line.split()[-1])!=pid:continue
            return (path/'stat').read_text().rsplit(')',1)[1].split()[0]
        except (FileNotFoundError,PermissionError,StopIteration):pass
    raise FileNotFoundError


FAKE_CLI = '''#!/usr/bin/python3
import json,sys
def emit(obj):
 print(json.dumps(obj),flush=True)
for line in sys.stdin:
 message=json.loads(line);method=message.get('method');rid=message.get('id')
 if method=='initialize':emit({'id':rid,'result':{'userAgent':'fake-native-test'}})
 if method=='hooks/list':emit({'id':rid,'result':{'data':[{'cwd':'test','errors':[],'warnings':[],'hooks':[{'eventName':'sessionStart','enabled':True,'trustStatus':'trusted','sourcePath':'test-hooks','statusMessage':'test'}]}]}})
 if method=='mcpServerStatus/list':emit({'id':rid,'result':{'data':[],'nextCursor':None}})
 if method=='thread/start':
  emit({'method':'hook/completed','params':{'run':{'eventName':'sessionStart','status':'completed','source':'user','sourcePath':'test-hooks','entries':[{'kind':'context','text':'verified fixed test context'}]}}})
  emit({'id':rid,'result':{'thread':{'id':'fixture-thread'}}})
 if method=='turn/start':
  emit({'id':rid,'result':{'turn':{'id':'fixture-turn'}}})
  emit({'method':'hook/completed','params':{'run':{'eventName':'userPromptSubmit','status':'completed','source':'user','sourcePath':'test-hooks','entries':[]}}})
  emit({'method':'thread/tokenUsage/updated','params':{'tokenUsage':{'total':{'totalTokens':128,'inputTokens':100,'outputTokens':28}}}})
  emit({'method':'item/completed','params':{'item':{'type':'agentMessage','text':'TEST_SENTINEL'}}})
  emit({'method':'turn/completed','params':{'turn':{'status':'completed'}}})
'''


class NativeTransportTests(unittest.TestCase):
    def test_close_kills_term_resistant_child_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'config.toml').write_text('')
            pidfile=root/'child.pid'
            cli=root/'forking-child'
            cli.write_text('#!/usr/bin/python3\nimport os,signal,time,pathlib\npid=os.fork()\nif pid:\n pathlib.Path('+repr(str(pidfile))+').write_text(str(pid))\n os._exit(0)\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\ntime.sleep(30)\n')
            cli.chmod(0o700)
            client=guarded_client(cli,root,max_runtime=5)
            deadline=time.monotonic()+2
            while not pidfile.exists() and time.monotonic()<deadline:time.sleep(0.01)
            self.assertTrue(pidfile.exists())
            pid=int(pidfile.read_text());time.sleep(0.03)
            client.close()
            deadline=time.monotonic()+1
            live=True
            while time.monotonic()<deadline:
                try:
                    state=process_state(pid)
                    if state=='Z':live=False;break
                except FileNotFoundError:
                    live=False;break
                time.sleep(0.01)
            self.assertFalse(live)

    def test_watchdog_kills_child_that_never_reads_large_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'config.toml').write_text('')
            cli=root/'nonreading-child';cli.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(30)\n');cli.chmod(0o700)
            client=guarded_client(cli,root,max_runtime=0.2)
            started=time.monotonic()
            try:
                with self.assertRaises((BrokenPipeError, OSError, ClientError)):
                    client.send({'payload':'x'*1048576})
                self.assertLess(time.monotonic()-started,2)
                self.assertTrue(client.receipt()['independent_launcher_deadline'])
            finally:
                client.close()

    def test_nonblocking_rpc_proves_completion_without_persisting_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'config.toml').write_text('')
            cli = root / 'fake-codex'
            cli.write_text(FAKE_CLI)
            cli.chmod(0o700)
            client = guarded_client(cli,root,max_runtime=5)
            try:
                self.assertEqual(client.initialize()['userAgent'], 'fake-native-test')
                self.assertEqual(client.hooks_list()[0]['hooks'][0]['trust'], 'trusted')
                self.assertTrue(client.mcp_status()['configured_table_empty'])
                thread = client.start_thread()
                self.assertTrue(client.mcp_status(thread)['configured_table_empty'])
                result = client.turn(thread, 'fixed test')
                self.assertEqual(result['status'], 'completed')
                self.assertEqual(result['answers'], ['TEST_SENTINEL'])
                self.assertEqual([e['event'] for e in client.hook_events], ['sessionStart','userPromptSubmit'])
                serialized = json.dumps(client.receipt())
                self.assertNotIn('verified fixed test context', serialized)
                self.assertTrue(client.receipt()['protected_profile_bytes_unchanged'])
            finally:
                client.close()

    def test_usage_and_tool_events_fail_closed(self):
        client = object.__new__(NativeClient)
        client.token_budget = 100
        client.event_methods = []
        client.tool_events = 0
        with self.assertRaisesRegex(ClientError, 'token_budget'):
            client._event({'method':'thread/tokenUsage/updated','params':{'tokenUsage':{'total':{'totalTokens':101}}}})
        with self.assertRaisesRegex(ClientError, 'tool_request'):
            client._event({'method':'item/started','params':{'item':{'type':'mcpToolCall'}}})


class QueueBoundaryTests(unittest.TestCase):
    def test_mcp_override_is_valid_complete_disabled_transport_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            (root/'config.toml').write_text('[mcp_servers.example-http]\nurl="https://example.test/private"\nbearer_token_env_var="SECRET_ENV"\n[mcp_servers.example-stdio]\ncommand="/private/program"\nenv={TOKEN="secret-test-value"}\n')
            value=restricted_config(root,32768)['mcp_servers']
            parsed=tomllib.loads('mcp_servers='+toml_value(value))['mcp_servers']
            self.assertEqual(parsed['example-http'],{'url':'http://127.0.0.1:9','enabled':False})
            self.assertEqual(parsed['example-stdio'],{'command':'/usr/bin/false','enabled':False})
            self.assertNotIn('secret-test-value',toml_value(value))
            self.assertNotIn('SECRET_ENV',toml_value(value))

    def test_foreground_wait_reads_receipt_without_model_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'results').mkdir()
            job_id='a'*32;(root/'results'/(job_id+'.json')).write_text('{"state":"completed","model_called":false}')
            with patch.object(harness,'NativeClient') as native:
                receipt=harness.await_job(root,job_id,1)
                self.assertEqual(receipt['receipt']['state'],'completed')
                native.assert_not_called()
            with self.assertRaises(ValueError):harness.await_job(root,job_id,301)

    def test_independent_launcher_enforces_deadline_without_client_watchdog(self):
        launcher=pathlib.Path(__file__).with_name('native_watchdog.py')
        started=time.monotonic()
        with tempfile.TemporaryDirectory() as directory:
            fd=held_guard(pathlib.Path(directory))
            try:
                process=subprocess.Popen(['/usr/bin/python3','-B',str(launcher),'--parent-pid',str(os.getpid()),'--max-runtime','0.2','--guard-fd',str(fd),'--','/usr/bin/python3','-c','import time; time.sleep(30)'],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,pass_fds=(fd,))
            finally:os.close(fd)
            self.assertEqual(process.wait(timeout=2),-9)
        self.assertLess(time.monotonic()-started,2)

    def test_launcher_retains_exact_guard_lease_after_caller_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            fd=held_guard(root)
            launcher=pathlib.Path(__file__).with_name('native_watchdog.py')
            process=subprocess.Popen(['/usr/bin/python3','-B',str(launcher),'--parent-pid',str(os.getpid()),'--max-runtime','0.4','--guard-fd',str(fd),'--','/usr/bin/python3','-c','import time; time.sleep(30)'],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,pass_fds=(fd,))
            os.close(fd)
            controller=os.open(root/'fixture-guard.lock',os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(controller,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual(process.wait(timeout=2),-9)
                fcntl.flock(controller,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:
                os.close(controller)

    def test_launcher_does_not_spawn_for_dead_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            marker=root/'unexpected-spawn'
            launcher=pathlib.Path(__file__).with_name('native_watchdog.py')
            fd=held_guard(root)
            try:
                result=subprocess.run(['/usr/bin/python3','-B',str(launcher),'--parent-pid',str(os.getpid()+100000),'--max-runtime','0.2','--guard-fd',str(fd),'--','/usr/bin/python3','-c','import pathlib; pathlib.Path('+repr(str(marker))+').write_text("spawned")'],start_new_session=True,stdin=subprocess.DEVNULL,timeout=2,pass_fds=(fd,))
            finally:os.close(fd)
            self.assertEqual(result.returncode,0)
            self.assertFalse(marker.exists())

    def test_independent_launcher_cleans_native_after_worker_sigkill(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'config.toml').write_text('')
            marker=root/'native.pid'
            cli=root/'fake-native';cli.write_text('#!/usr/bin/python3\nimport os,pathlib,time\npathlib.Path('+repr(str(marker))+').write_text(str(os.getpid()))\ntime.sleep(30)\n');cli.chmod(0o700)
            worker=root/'crashing-worker.py'
            worker.write_text(
                "import os,sys,time,pathlib,signal,fcntl\n"
                f"sys.path.insert(0,{str(pathlib.Path(__file__).resolve().parent)!r})\n"
                "from native_client import NativeClient\n"
                f"fd=os.open({str(root/'worker-guard.lock')!r},os.O_RDWR|os.O_CREAT,0o600)\n"
                "fcntl.flock(fd,fcntl.LOCK_SH)\n"
                f"client=NativeClient({str(cli)!r},{str(root)!r},{str(root)!r},max_runtime=120,guard_fd=fd)\n"
                "deadline=time.monotonic()+2\n"
                f"while not pathlib.Path({str(marker)!r}).exists() and time.monotonic()<deadline:time.sleep(0.01)\n"
                "os.kill(os.getpid(),signal.SIGKILL)\n"
            )
            process=subprocess.Popen(['/usr/bin/python3','-B',str(worker)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.assertEqual(process.wait(timeout=4),-9)
            self.assertTrue(marker.exists())
            native_pid=int(marker.read_text());deadline=time.monotonic()+2;live=True
            while time.monotonic()<deadline:
                try:
                    if process_state(native_pid)=='Z':live=False;break
                except FileNotFoundError:live=False;break
                time.sleep(0.01)
            self.assertFalse(live)

    def test_regular_file_reader_rejects_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);target=root/'target';target.write_text('private')
            link=root/'link';link.symlink_to(target)
            with self.assertRaises(OSError):harness.regular(link)
            link.unlink();os.link(target,link)
            with self.assertRaisesRegex(ValueError,'unsafe'):harness.regular(link)

    def test_rejects_path_escape_credentials_and_unbounded_requests(self):
        for name in ('../auth.json','/etc/passwd','.git/config','auth.json','secrets.pem','a/../README.md'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                harness.validate_job({'schema_version':1,'kind':'audit','files':[name]})
        for patch_data in ({'max_runtime_seconds':121},{'token_budget':32769},{'command':'arbitrary'},{'question':'x'*4097}):
            with self.assertRaises(ValueError):
                harness.validate_job({'schema_version':1,'kind':'audit',**patch_data})

    def test_active_guard_prevents_every_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            guard=root/'guard.json';guard.write_text('{"active":true}')
            config={'migration_guard':str(guard),'source':'unused'}
            with patch.object(harness,'fixed_command') as command:
                with self.assertRaisesRegex(ValueError,'guard_active'):
                    harness.process_job(root,config,{'schema_version':1,'kind':'status'})
                command.assert_not_called()

    def test_status_and_source_jobs_never_construct_model_client(self):
        config={'source':'fixture','source_commit':'fixture-pin','migration_guard':'/nonexistent-fixture-guard'}
        with patch.object(harness,'source_status',return_value={'source_pin_matches':True}), patch.object(harness,'source_context',return_value=[{'path':'README.md','sha256':'fixture','text':'source'}]), patch.object(harness,'NativeClient') as native:
            for kind in ('status','source'):
                result=harness.process_job(pathlib.Path('/tmp'),config,{'schema_version':1,'kind':kind})
                self.assertEqual(result['state'],'completed')
                self.assertFalse(result['model_called'])
            native.assert_not_called()

    def test_source_context_refuses_untracked_or_oversized_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'README.md').write_text('x'*32769)
            config={'source':str(root)}
            with patch.object(harness,'fixed_command',return_value='README.md\0'):
                with self.assertRaisesRegex(ValueError,'not_tracked'):
                    harness.source_context(config,{'files':['other.md']})
                with self.assertRaisesRegex(ValueError,'oversized'):
                    harness.source_context(config,{'files':['README.md']})


if __name__ == '__main__':
    unittest.main()
