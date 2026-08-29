#!/usr/bin/env python3
"""Regression tests for protected CI, dispatch templates, and suite isolation."""

from pathlib import Path
from unittest import mock
import datetime as dt
import hashlib
import importlib.util
import inspect
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".agent/scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import adaptive_common as ADAPTIVE
import deliveryctl as DELIVERYCTL
import providerctl as PROVIDERCTL
import templatectl as TEMPLATECTL
from workflowlib import boundedio as BOUNDEDIO
from workflowlib import boundedprocess as BOUNDEDPROCESS

RUNNER_PATH = ROOT / "tests/run_all.py"
SPEC = importlib.util.spec_from_file_location("self_suite_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def trusted_fixture_parent() -> Path:
    return Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)


class RunnerHardeningTests(unittest.TestCase):
    def test_bounded_process_timeout_includes_blocked_stdin(self):
        started=time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            BOUNDEDPROCESS.run([sys.executable,"-c","import time;time.sleep(60)"],input=b"x"*(1024*1024),timeout=0.2)
        self.assertLess(time.monotonic()-started,5)

    def test_control_plane_file_reads_are_bounded_before_materialization(self):
        with tempfile.TemporaryDirectory() as raw:
            raw_root=Path(raw); root=raw_root.resolve(); safe=root/"safe"; safe.write_bytes(b"ok")
            self.assertEqual(BOUNDEDIO.read_bytes(safe,maximum=2),b"ok")
            self.assertEqual(BOUNDEDIO.read_bytes(raw_root/"safe",maximum=2),b"ok")
            oversized=root/"oversized"; oversized.write_bytes(b"abc")
            with self.assertRaisesRegex(RuntimeError,"bounded regular file"):
                BOUNDEDIO.read_bytes(oversized,maximum=2)
            link=root/"link"; link.symlink_to(safe)
            with self.assertRaisesRegex(RuntimeError,"bounded regular file"):
                BOUNDEDIO.read_bytes(link,maximum=2)
            real_parent=root/"real-parent"; real_parent.mkdir(); (real_parent/"child").write_bytes(b"ok")
            linked_parent=root/"linked-parent"; linked_parent.symlink_to(real_parent,target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,"opened safely"):
                BOUNDEDIO.read_bytes(linked_parent/"child",maximum=2)
        production=[
            SCRIPT_DIR/name for name in ("agentctl.py","artifactctl.py","contextctl.py","contexttx.py","deliveryctl.py","humandecision.py","templatectl.py","testrun.py")
        ]+[ROOT/"install.py",ROOT/".agent/skills/manage-agent-team/scripts/agentledger.py",ROOT/".agent/assets/templates/ci-cd/github-ci.yml.tmpl"]
        for path in production:
            source=path.read_text(encoding="utf-8")
            normalized=source.replace("boundedio.read_bytes(","bounded_read(").replace("boundedio.read_text(","bounded_read(")
            self.assertNotRegex(normalized,r"[.]read_(?:bytes|text)[(]",str(path))

    def test_staged_workspace_cleanup_requires_exact_private_owned_directory(self):
        workspace=Path(tempfile.mkdtemp(prefix="agent-workflow-self-suite-"))
        workspace.chmod(0o700); (workspace/"sentinel").write_text("owned",encoding="utf-8")
        with RUNNER.owned_staged_workspace(workspace) as captured:
            self.assertEqual(Path(captured),workspace.resolve())
        self.assertFalse(workspace.exists())

        unsafe=Path(tempfile.mkdtemp(prefix="agent-workflow-self-suite-")); unsafe.chmod(0o755)
        try:
            with self.assertRaisesRegex(RuntimeError,"ownership is invalid"):
                with RUNNER.owned_staged_workspace(unsafe): pass
        finally:
            unsafe.chmod(0o700); shutil.rmtree(unsafe)

        with tempfile.TemporaryDirectory(prefix="runner-external-sentinel-") as raw:
            external=Path(raw); sentinel=external/"sentinel"; sentinel.write_text("preserve",encoding="utf-8")
            link=Path(tempfile.gettempdir())/f"agent-workflow-self-suite-link-{os.getpid()}-{time.time_ns()}"
            link.symlink_to(external,target_is_directory=True)
            try:
                with self.assertRaisesRegex(RuntimeError,"ownership is invalid"):
                    with RUNNER.owned_staged_workspace(link): pass
                self.assertEqual(sentinel.read_text(encoding="utf-8"),"preserve")
            finally: link.unlink(missing_ok=True)

    def test_child_environment_drops_credentials_and_isolates_state(self):
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.dict(os.environ, {
                "GITHUB_TOKEN": "secret",
                "AGENT_MCP_ALLOWED_ROOTS": "/unsafe",
                "AGENT_INSTALL_TEST_CRASH_AFTER": "1",
                "HOME":"/host-home","PATH":"/poison","PYTHONPATH":"/poison","NODE_OPTIONS":"--require=/poison","LD_PRELOAD":"/poison",
            },clear=False):
                env = RUNNER.child_environment(Path(raw))
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("AGENT_MCP_ALLOWED_ROOTS", env)
        self.assertNotIn("AGENT_INSTALL_TEST_CRASH_AFTER",env)
        for name in ("PYTHONPATH","NODE_OPTIONS","LD_PRELOAD"):
            self.assertNotIn(name,env)
        self.assertNotIn("/poison",env["PATH"])
        self.assertNotEqual(env["HOME"], "/host-home")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")

    def test_staged_launcher_environment_ignores_python_and_loader_injection(self):
        poisoned={
            "PYTHONPATH":"/poison","PYTHONHOME":"/poison","PYTHONSTARTUP":"/poison/start.py",
            "LD_PRELOAD":"/poison.so","LD_LIBRARY_PATH":"/poison","DYLD_INSERT_LIBRARIES":"/poison.dylib",
            "NODE_OPTIONS":"--require=/poison","AWS_SECRET_ACCESS_KEY":"secret","PATH":"/poison",
        }
        with tempfile.TemporaryDirectory() as raw, mock.patch.dict(os.environ,poisoned,clear=False):
            workspace=Path(raw)/"workspace"; staged=workspace/"staged"; source=Path(raw)/"source"
            sealed_path="/trusted/tools"+os.pathsep+os.defpath
            env=RUNNER.staged_child_environment(workspace,staged,source,"a"*64,"b"*64,"c"*64,7,sealed_path)
        for name in poisoned:
            if name!="PATH": self.assertNotIn(name,env)
        self.assertEqual(env["PATH"],sealed_path)
        self.assertNotIn("/poison",env["PATH"])
        self.assertEqual((env["LANG"],env["LC_ALL"],env["TZ"]),("C","C","UTC"))
        self.assertEqual(env["TMPDIR"],str(workspace.parent))
        self.assertEqual(env["AGENT_RUN_ALL_INDEX_COUNT"],"7")

    def test_darwin_process_observers_use_exclusive_matrix_lane(self):
        expected={
            ".agent/scripts/self_test_adaptive_workflow.py",
            ".agent/scripts/self_test_security_control_plane.py",
            ".agent/scripts/self_test_runner_trust.py",
            ".agent/skills/manage-local-runtime/scripts/self_test_managed_run.py",
            "ci-hardening",
        }
        self.assertTrue(expected<=RUNNER.DARWIN_PROCESS_OBSERVER_TESTS)
        source=inspect.getsource(RUNNER.run_batch)
        self.assertIn('sys.platform.startswith("darwin")',source)
        self.assertIn('{name for name,_command,_root in executions}',source)
        self.assertIn('for index,(name,command,execution_root) in serial',source)

    def test_lifecycle_cleanup_never_signals_numeric_process_groups_or_reaps_early(self):
        sources={
            "installer":(ROOT/"install.py").read_text(encoding="utf-8"),
            "runner":RUNNER_PATH.read_text(encoding="utf-8"),
            "human-adapter":(ROOT/".agent/scripts/humandecision.py").read_text(encoding="utf-8"),
            "test-supervisor":(ROOT/".agent/scripts/testrun.py").read_text(encoding="utf-8"),
            "blueprint-supervisor":(ROOT/".agent/scripts/blueprintacceptance.py").read_text(encoding="utf-8"),
            "acceptance-runtime":(ROOT/".agent/skills/run-full-chain-acceptance/scripts/run_acceptance_runtime.py").read_text(encoding="utf-8"),
            "workflow-release":(ROOT/".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py").read_text(encoding="utf-8"),
            "agentctl":(ROOT/".agent/scripts/agentctl.py").read_text(encoding="utf-8"),
            "skillctl":(ROOT/".agent/scripts/skillctl.py").read_text(encoding="utf-8"),
        }
        for label,source in sources.items():
            self.assertNotIn("killpg(",source,label)
        self.assertNotIn("process.poll(",sources["runner"])
        for label in ("acceptance-runtime","workflow-release"):
            self.assertNotIn("communicate(",sources[label],label)
            self.assertNotIn("subprocess.run(",sources[label],label)
            self.assertIn("supervise_bounded_process",sources[label],label)
        self.assertIn("HTTP_BODY_LIMIT_BYTES+1",sources["acceptance-runtime"])
        self.assertNotIn("response.read()",sources["acceptance-runtime"])
        self.assertNotIn("subprocess.run(",sources["agentctl"])
        self.assertIn("run_bounded_command",sources["agentctl"])
        self.assertNotIn("urllib.request.urlopen",sources["agentctl"])
        self.assertIn("RejectManagedHealthRedirect",sources["agentctl"])
        self.assertNotIn("rglob(",sources["test-supervisor"])
        self.assertIn("MAX_CANDIDATE_ENTRIES",sources["test-supervisor"])
        self.assertIn("GITHUB_TOTAL_DEADLINE_SECONDS",sources["skillctl"])
        self.assertIn("github_io_deadline",sources["skillctl"])
        self.assertIn("unreaped PID binding",sources["installer"])
        self.assertIn("unreaped PID binding",sources["runner"])
        self.assertIn("unreaped PID binding",sources["human-adapter"])
        self.assertIn("reaped numeric PID",sources["test-supervisor"])
        self.assertIn("unreaped launch session",sources["test-supervisor"])

    def test_empty_selection_is_never_green_evidence(self):
        with self.assertRaises(SystemExit):
            RUNNER.select_tests(None,("no-such-protected-test",))
        self.assertIn("self-test selection is empty; refusing green zero-test evidence",inspect.getsource(RUNNER.main))

    def test_skip_is_distinct_and_can_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            script = Path(raw) / "skip.py"
            script.write_text("raise SystemExit(77)\n", encoding="utf-8")
            record = RUNNER.execute("explicit-skip", [sys.executable, str(script)], Path(raw), 10)
        self.assertEqual(record["status"], "skip")
        self.assertEqual(RUNNER.result_counts([record], fail_on_skip=False)[1], 0)
        self.assertEqual(RUNNER.result_counts([record], fail_on_skip=True)[1], 1)
        RUNNER.classify_skips([record], ["explicit-skip"])
        counts, failures = RUNNER.result_counts([record], fail_on_skip=True)
        self.assertEqual((counts["allowed_skip"], counts["unapproved_skip"], failures), (1, 0, 0))

    def test_required_command_fails_when_missing(self):
        with mock.patch.object(RUNNER.shutil, "which", return_value=None):
            with self.assertRaises(SystemExit):
                RUNNER.validate_required_commands(["required-tool"])

    def test_fixture_copies_only_tracked_regular_files(self):
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "source"
            target = Path(raw) / "target"
            source.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=source, check=True)
            (source / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            (source / ".gitignore").write_text("*.env\n", encoding="utf-8")
            (source / "untracked-secret.env").write_text("SECRET=value\n", encoding="utf-8")
            (source / ".agent").mkdir()
            (source / ".agent/managed.txt").write_text("managed elsewhere\n", encoding="utf-8")
            (source / "plugins/pxpipe-context").mkdir(parents=True)
            (source / "plugins/pxpipe-context/quarantine.txt").write_text("source only\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt", ".gitignore", ".agent/managed.txt", "plugins/pxpipe-context/quarantine.txt"], cwd=source, check=True)
            (source / "tracked.txt").write_text("unstaged worktree bytes\n", encoding="utf-8")
            RUNNER.copy_project_without_agent(source, target)
            self.assertEqual((target / "tracked.txt").read_text(encoding="utf-8"), "tracked\n")
            self.assertFalse((target / "untracked-secret.env").exists())
            self.assertFalse((target / ".agent").exists())
            self.assertFalse((target / "plugins/pxpipe-context").exists())


    def test_fixture_rejects_unsupported_and_unmerged_index_entries(self):
        with tempfile.TemporaryDirectory() as raw:
            source=Path(raw)/"source"; source.mkdir(); subprocess.run(["git","init","-q"],cwd=source,check=True)
            (source/"target.txt").write_text("target\n",encoding="utf-8")
            (source/"link").symlink_to("target.txt")
            subprocess.run(["git","add","link"],cwd=source,check=True)
            with self.assertRaisesRegex(RuntimeError,"unsupported staged Git mode"):
                list(RUNNER.staged_entries(source))
        with tempfile.TemporaryDirectory() as raw:
            source=Path(raw)/"source"; source.mkdir(); subprocess.run(["git","init","-q"],cwd=source,check=True)
            first=subprocess.run(["git","hash-object","-w","--stdin"],cwd=source,input=b"first\n",stdout=subprocess.PIPE,check=True).stdout.strip().decode()
            second=subprocess.run(["git","hash-object","-w","--stdin"],cwd=source,input=b"second\n",stdout=subprocess.PIPE,check=True).stdout.strip().decode()
            index=f"100644 {first} 1\tconflict.txt\n100644 {second} 2\tconflict.txt\n"
            subprocess.run(["git","update-index","--index-info"],cwd=source,input=index.encode(),check=True)
            with self.assertRaisesRegex(RuntimeError,"unmerged staged Git entry"):
                list(RUNNER.staged_entries(source))

    def test_staged_reexec_rejects_caller_supplied_nonindex_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw); source=base/"source"; source.mkdir(); (source/"tests").mkdir()
            subprocess.run(["git","init","-q"],cwd=source,check=True)
            (source/"tests/run_all.py").write_text("# staged launcher\n",encoding="utf-8")
            (source/"payload.txt").write_text("index bytes\n",encoding="utf-8")
            subprocess.run(["git","add","tests/run_all.py","payload.txt"],cwd=source,check=True)
            entries=RUNNER.staged_entries(source); index_sha=RUNNER.staged_index_digest(entries)
            staged=base/"staged"; RUNNER.materialize_staged_tree(source,staged,entries)
            tree_sha=RUNNER.staged_tree_digest(staged,entries); (staged/"payload.txt").write_text("attacker bytes\n",encoding="utf-8")
            launcher=staged/"tests/run_all.py"; original_file=RUNNER.__file__
            environment={
                "AGENT_RUN_ALL_STAGED_ROOT":str(staged),"AGENT_RUN_ALL_ORIGINAL_ROOT":str(source),
                "AGENT_RUN_ALL_INDEX_SHA256":index_sha,"AGENT_RUN_ALL_INDEX_COUNT":str(len(entries)),
                "AGENT_RUN_ALL_LAUNCHER_SHA256":RUNNER.bounded_file_sha256(launcher),"AGENT_RUN_ALL_TREE_SHA256":tree_sha,
            }
            try:
                RUNNER.__file__=str(launcher)
                with mock.patch.dict(os.environ,environment,clear=False), self.assertRaisesRegex(RuntimeError,"exact Git index objects"):
                    RUNNER.staged_reexec(source)
            finally:
                RUNNER.__file__=original_file

    def test_ci_selected_path_precedes_system_default_tool(self):
        original_path=RUNNER.ORIGINAL_TOOL_PATH
        try:
            with tempfile.TemporaryDirectory(prefix="ci-tool-selection-",dir=trusted_fixture_parent()) as raw:
                root=Path(raw); selected=root/"selected"; fallback=root/"fallback"; selected.mkdir(); fallback.mkdir()
                for directory,body in ((selected,"selected"),(fallback,"fallback")):
                    tool=directory/"node"; tool.write_text(f"#!/bin/sh\nprintf '{body}\n'\n",encoding="utf-8"); tool.chmod(0o700)
                RUNNER.ORIGINAL_TOOL_PATH=str(selected)
                with mock.patch.object(RUNNER.os,"defpath",str(fallback)):
                    self.assertEqual(RUNNER.trusted_tool_path("node"),(selected/"node").resolve())
        finally:
            RUNNER.ORIGINAL_TOOL_PATH=original_path

    def test_source_checks_and_controls_are_isolated(self):
        source=RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIsNotNone(re.search(r"SOURCE_CHECKS\],\s*source,timeout=args\.test_timeout,jobs=1,isolate=True",source))
        self.assertIn('("source-runtime-control", source_runtime_control_command())',source)
        control=RUNNER.source_runtime_control_command()
        self.assertEqual(control[:2],[sys.executable,"-c"])
        self.assertIn('capture-runtime-baseline',control[2])
        self.assertIn('assert-clean',control[2])
        compile(control[2],"<source-runtime-control>","exec")

    def test_mutable_tool_replacement_after_preflight_is_rejected(self):
        original=(RUNNER.TOOL_SEALS,RUNNER.TRUSTED_TOOL_NAMES,RUNNER.ORIGINAL_TOOL_PATH)
        try:
            with tempfile.TemporaryDirectory(prefix="ci-tool-mutation-",dir=trusted_fixture_parent()) as raw:
                root=Path(raw); tools_dir=root/"bin"; tools_dir.mkdir(); tool=tools_dir/"mutable-tool"
                tool.write_text("#!/bin/sh\nprintf 'sealed-tool\n'\n",encoding="utf-8"); tool.chmod(0o700)
                RUNNER.TOOL_SEALS=None; RUNNER.TRUSTED_TOOL_NAMES=("mutable-tool",); RUNNER.ORIGINAL_TOOL_PATH=str(tools_dir)
                RUNNER.initialize_tool_seals()
                record=RUNNER.run(["mutable-tool"],root,timeout=10,label="sealed-mutable-tool")
                self.assertEqual(record["output"],"sealed-tool\n")
                tool.write_text("#!/bin/sh\nprintf 'replaced-tool\n'\n",encoding="utf-8"); tool.chmod(0o700)
                with self.assertRaisesRegex(RuntimeError,"trusted tool identity changed"):
                    RUNNER.run(["mutable-tool"],root,timeout=10,label="replaced-mutable-tool")
        finally:
            RUNNER.TOOL_SEALS,RUNNER.TRUSTED_TOOL_NAMES,RUNNER.ORIGINAL_TOOL_PATH=original

    def test_fixture_rejects_nonignored_untracked_source(self):
        for relative, content in (("install.py", "print('new')\n"), ("compose.yaml", "services: {}\n")):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                source = Path(raw) / "source"
                source.mkdir()
                subprocess.run(["git", "init", "-q"], cwd=source, check=True)
                (source / relative).write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "stage or remove"):
                    RUNNER.copy_project_without_agent(source, Path(raw) / "target")

    def test_captured_output_is_byte_bounded(self):
        scripts = (
            "print('x' * 100000)\n",
            "import sys; sys.stdout.buffer.write(b'\\xff' * 100000)\n",
        )
        for source in scripts:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as raw:
                script = Path(raw) / "flood.py"
                script.write_text(source, encoding="utf-8")
                record = RUNNER.run([sys.executable, str(script)], Path(raw), timeout=10, label="flood")
                self.assertLessEqual(
                    len(record["output"].encode("utf-8")), RUNNER.MAX_CAPTURE_BYTES,
                )
                self.assertTrue(record["output_truncated"])

    def test_observer_exception_still_reaps_owned_leader(self):
        captured=[]; real_popen=RUNNER.subprocess.Popen
        def capture(*args,**kwargs):
            process=real_popen(*args,**kwargs)
            command=list(args[0])
            if kwargs.get("start_new_session") and "-c" in command and "import time;time.sleep(60)" in command: captured.append(process)
            return process
        with tempfile.TemporaryDirectory() as raw,                 mock.patch.object(RUNNER.subprocess,"Popen",side_effect=capture),                 mock.patch.object(RUNNER,"discover_descendants",side_effect=RuntimeError("observer failed")):
            with self.assertRaisesRegex(RuntimeError,"observer failed"):
                RUNNER.run([sys.executable,"-c","import time;time.sleep(60)"],Path(raw),timeout=5,label="observer-failure")
        self.assertEqual(len(captured),1)
        self.assertIsNotNone(captured[0].returncode)

    def test_success_with_detached_descendant_fails_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); pid_file=root/"child.pid"; script=root/"detach.py"
            script.write_text("import os,signal,time\npid=os.fork()\nif pid==0:\n os.setsid();signal.signal(signal.SIGTERM,signal.SIG_IGN);open('child.pid','w').write(str(os.getpid()));time.sleep(30);os._exit(0)\ntime.sleep(.3)\n",encoding="utf-8")
            with self.assertRaises(RUNNER.RunFailure) as caught:
                RUNNER.run([sys.executable,str(script)],root,timeout=10,label="detached-success")
            self.assertEqual(caught.exception.record["exit_code"],125)
            child_pid=int(pid_file.read_text(encoding="utf-8"))
            for _ in range(40):
                try: os.kill(child_pid,0)
                except ProcessLookupError: break
                time.sleep(.05)
            else: self.fail("successful detached descendant survived runner cleanup")

    def test_timeout_kills_term_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            pid_file = root / "child.pid"
            script = root / "spawn.py"
            script.write_text(
                "import pathlib, signal, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])\n"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            with self.assertRaises(RUNNER.RunFailure) as captured:
                RUNNER.run([sys.executable, str(script)], root, timeout=0.5, label="descendant-timeout")
            self.assertEqual(captured.exception.record["exit_code"], 124)
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            alive = True
            while alive and time.monotonic() < deadline:
                observed = RUNNER.process_snapshot().get(child_pid)
                alive = observed is not None and not observed[3].startswith("Z")
                if alive:
                    time.sleep(0.05)
            self.assertFalse(alive, f"timed-out descendant {child_pid} survived cleanup")

    def test_timeout_kills_direct_setsid_descendant(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            pid_file = root / "detached.pid"
            script = root / "spawn-detached.py"
            script.write_text(
                "import pathlib, signal, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'], "
                "start_new_session=True)\n"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            with self.assertRaises(RUNNER.RunFailure):
                RUNNER.run([sys.executable, str(script)], root, timeout=0.5, label="setsid-timeout")
            detached_pid = int(pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                snapshot = RUNNER.process_snapshot()
                if detached_pid not in snapshot:
                    break
                time.sleep(0.05)
            self.assertNotIn(detached_pid, RUNNER.process_snapshot(), "setsid descendant survived cleanup")

    def test_context_specific_report_names_do_not_collide(self):
        first = RUNNER.default_report_path(("idle-source",), (1, 2))
        second = RUNNER.default_report_path(("polluted-source",), (1, 2))
        self.assertNotEqual(first, second)


class SourceCheckRegistryTests(unittest.TestCase):
    def test_dashboard_auth_self_test_is_registered(self):
        checks = dict(RUNNER.SOURCE_CHECKS)
        self.assertEqual(
            checks.get("pxpipe-dashboard-auth"),
            ("plugins/pxpipe-context/scripts/dashboard-auth-self-test.mjs",),
        )
        self.assertEqual(
            checks.get("pxpipe-integrity"),
            ("plugins/pxpipe-context/scripts/verify-integrity.mjs", "--allow-quarantined"),
        )


class WorkflowHardeningTests(unittest.TestCase):
    @staticmethod
    def provider_authority_environment(provider):
        github = provider == "github"
        receipt = {
            "schema": "agent-provider-authority-proof/v3",
            "receipt_id": "authority-proof-123",
            "authority": "provider-authenticated-protected-adapter",
            "provider": provider,
            "project_id": "71",
            "repository_host": "example.com",
            "repository": "example/repository",
            "authority_kind": "github-external-workflow" if github else "gitlab-pipeline-execution-policy",
            "immutable_authority_ref": (
                "security/authority/.github/workflows/verify.yml@" + "a" * 40
                if github else "policy/security-release@" + "a" * 40
            ),
            "effective_config_sha256": "b" * 64,
            "effective_config_bytes": 4096,
            "collision_result": {"status": "clear", "evidence_sha256": "c" * 64},
            "producer_identity": {
                "subject": "provider/security-authority", "issuer": "https://provider.example",
                "provider_actor_id": "88",
            },
            "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "candidate_revision":"a"*40,"candidate_tree":"b"*40,
        }
        return {
            "AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON": json.dumps(receipt, sort_keys=True, separators=(",", ":")),
            "AGENT_PROVIDER_PROJECT_ID": "71",
            "AGENT_PROVIDER_REPOSITORY_HOST": "example.com",
            "AGENT_PROVIDER_REPOSITORY": "example/repository",
        }

    @staticmethod
    def accept_provider_receipt(*_args, receipt_raw=None, **_kwargs):
        return mock.Mock(
            returncode=0,
            stdout="VERIFIED PROVIDER PREFLIGHT sha256=" + hashlib.sha256(receipt_raw).hexdigest() + "\n",
        )

    def test_protected_workflow_pins_actions_and_covers_all_contexts(self):
        text = (ROOT / ".github/workflows/selftest.yml").read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
        expected_actions = {
            "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
            "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
            "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
            "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
        }
        self.assertEqual(
            {value.split("@", 1)[0]: value.split("@", 1)[1] for value in uses},
            expected_actions,
        )
        for value in uses:
            self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$")
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("name: candidate-selftest-evidence",text)
        self.assertNotIn("Validate external required-verifier configuration",text)
        self.assertNotIn("vars.AGENT_GITHUB_AUTHORITY_",text)
        self.assertIn("branches: [main]",text)
        self.assertIn("max-parallel: 4",text)
        self.assertIn("for context in idle-source polluted-source installed-project",text)
        self.assertIn('python-version: "3.9.21"',text)
        self.assertIn('python-version: "3.9.13"',text)
        self.assertIn('python-version: "3.14.0"',text)
        self.assertIn('node-version: "20.19.4"',text)
        self.assertIn('node-version: "22.18.0"',text)
        self.assertIn("/usr/bin/sudo -n /usr/bin/env",text)
        self.assertEqual(text.count("python -I -B"), 3)
        self.assertIn('"$SELECTED_PYTHON" -I -B -', text)
        self.assertNotIn("python -c '", text)
        self.assertNotIn("          python - <<'PY'", text)
        self.assertIn("selected Python path exceeds its bound",text)
        self.assertIn("selected Python owner chain exceeds its depth bound",text)
        self.assertIn("selected Python owner chain has an unsafe identity",text)
        self.assertIn("selected Python runtime exceeds its entry bound",text)
        self.assertIn("selected Python runtime exceeds its byte bound",text)
        self.assertIn("selected Python runtime contains an external symlink",text)
        self.assertIn('path.resolve(strict=False).relative_to(runtime_root)',text)
        self.assertEqual(text.count("--jobs 1"),1)
        self.assertIn("AGENT_CI_PYTHON",text)
        self.assertIn("trusted Node copy digest mismatch",text)
        for context in RUNNER.ALL_CONTEXTS:
            self.assertIn(context, text)
        self.assertIn("--context", text)
        self.assertIn("--require-command node",text)
        self.assertIn("--require-command lsof",text)
        self.assertIn("--require-command git",text)
        self.assertNotIn("--require-command python",text)
        self.assertIn("os: [ubuntu-24.04, macos-14]",text)
        self.assertIn("runs-on: ${{ matrix.os }}",text)
        self.assertIn("toolchain: [minimum, modern-pinned]",text)
        self.assertNotIn("context: [idle-source, polluted-source, installed-project]",text)
        self.assertEqual(text.count('"$AGENT_CI_PYTHON" tests/run_all.py'),1)
        self.assertIn("--fail-on-skip", text)
        self.assertIn("--allow-skip .agent/skills/manage-local-runtime/scripts/self_test_docker_http.py", text)
        self.assertNotIn("toolchain: [minimum, current]", text)
        self.assertIn("actions/upload-artifact@", text)
        self.assertIn("if: always()", text)

    def test_canonical_gitlab_pipeline_is_pinned_bounded_and_runnable(self):
        text=(ROOT/".gitlab-ci.yml").read_text(encoding="utf-8")
        self.assertRegex(text,r"image: python:3\.9\.21-bookworm@sha256:[0-9a-f]{64}")
        self.assertRegex(text,r'NODE_LINUX_X64_SHA256: "[0-9a-f]{64}"')
        self.assertIn('LSOF_DEB_VERSION: "4.95.0-1"',text)
        self.assertIn('LSOF_DEB_AMD64_SHA256: "e4b15cf8d0b9051cf7957e7ab29a67ca7d21f42ea1b2b7dad1b52e65d02d1408"',text)
        self.assertIn("tags: [hk-cluster-devops-cicd]",text)
        self.assertIn("maximum_archive_bytes = 128 * 1024 * 1024",text)
        self.assertIn("downloaded > maximum_archive_bytes",text)
        self.assertIn("archive = bytearray()", text)
        self.assertIn("tarfile.open(fileobj=io.BytesIO(bytes(archive))", text)
        self.assertNotIn(".ci-node.tar.xz", text)
        self.assertNotIn('archive.open("wb")', text)
        self.assertIn("maximum_lsof_package_bytes = 2 * 1024 * 1024",text)
        self.assertIn('bundle.getmember("./usr/bin/lsof")',text)
        self.assertNotIn("source.read()",text)
        self.assertIn('SHARD: ["1/2", "2/2"]',text)
        self.assertIn("for context in idle-source polluted-source installed-project",text)
        self.assertNotIn(".gitlab-host-toolchain-matrix",text)
        self.assertNotIn("candidate-selftest-modern-linux-evidence",text)
        self.assertNotIn("candidate-selftest-minimum-macos-evidence",text)
        self.assertNotIn("candidate-selftest-modern-macos-evidence",text)
        self.assertNotIn("CI_COMMIT_TAG",text)
        self.assertNotIn("AGENT_GITLAB_AUTHORITY_MODE",text)
        for command in ("python", "node", "lsof", "git"):
            self.assertIn(f'"--require-command", "{command}"',text)
        self.assertIn("git --version",text)
        self.assertIn('trusted_root = Path("/opt/agent-ci-tools")',text)
        self.assertIn('"PATH": "/opt/agent-ci-tools:/usr/local/bin:/usr/bin:/bin"',text)
        self.assertIn("ci_uid = 10001",text)
        self.assertEqual(text.count("/usr/local/bin/python3 -I -B"), 3)
        self.assertNotIn("      python3 - <<'PY'", text)
        self.assertNotIn('      python3 - "$context"', text)
        self.assertIn("os.setuid(10001)",text)
        self.assertIn("CI checkout exceeds its ownership entry bound",text)
        self.assertIn("CI checkout exceeds its ownership byte bound",text)
        self.assertEqual(text.count('"--jobs", "1"'),1)
        self.assertNotIn("$CI_PROJECT_DIR/.ci-bin",text)
        suite_line = next(line for line in text.splitlines() if 'interpreter, "tests/run_all.py"' in line)
        self.assertIn("tests/run_all.py", suite_line)
        self.assertIn('"--fail-on-skip"', text)
        self.assertIn('"--allow-skip"', text)
        self.assertNotIn("GITLAB_TOKEN", text)
        self.assertIn("parallel:\n    matrix:", text)
        self.assertIn("when: always", text)
        self.assertNotIn(":latest", text)

    def test_quarantined_pxpipe_stat_metadata_is_bsd_and_gnu_portable(self):
        scripts=[ROOT/"plugins/pxpipe-context/scripts"/name for name in (
            "install-codex-default.sh","uninstall-codex-default.sh","status-codex-default.sh")]
        for script in scripts:
            text=script.read_text(encoding="utf-8")
            self.assertIn("stat_owner_mode()",text,script.name)
            self.assertIn("/usr/bin/stat -f '%u %Lp'",text,script.name)
            self.assertIn("/usr/bin/stat -c '%u %a'",text,script.name)
        for script in scripts[:2]:
            text=script.read_text(encoding="utf-8")
            self.assertIn("stat_links_owner_mode()",text,script.name)
            self.assertIn("/usr/bin/stat -f '%l %u %Lp'",text,script.name)
            self.assertIn("/usr/bin/stat -c '%h %u %a'",text,script.name)

    def test_github_workflows_use_confirmed_authority_and_pinned_actions(self):
        template_dir=ROOT/".agent/assets/templates/ci-cd"
        texts={path.name:path.read_text(encoding="utf-8") for path in template_dir.glob("github-*.yml.tmpl")}
        for name,text in texts.items():
            self.assertIn("runs-on: {{github_protected_runner}}",text,name)
            if name=="github-ci.yml.tmpl": self.assertIn("runs-on: {{github_candidate_runner}}",text,name)
            else: self.assertNotIn("github_candidate_runner",text,name)
            self.assertNotIn("github_runner",text,name)
            self.assertIn("{{github_container}}",text,name)
            self.assertIn("{{github_default_branch}}",text,name)
            self.assertNotIn("ubuntu-latest",text,name)
            self.assertNotIn("refs/heads/main",text,name)
            for uses in re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)",text,re.MULTILINE):
                self.assertRegex(uses,r"^[^@]+@[0-9a-f]{40}$",f"mutable action ref in {name}: {uses}")
        ci=texts["github-ci.yml.tmpl"]
        self.assertEqual(ci.count("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"),1)
        self.assertIn("verify-build-once:",ci)
        self.assertIn("publish-protected-artifact:",ci)
        self.assertIn("github.event_name == 'push'",ci)
        self.assertIn("github.sha == github.event.after",ci)
        self.assertIn("environment: artifact-publication",ci)
        for name in ("github-test-cd.yml.tmpl","github-production-cd.yml.tmpl"):
            deployment=texts[name]
            self.assertIn("  dispatch-guard:",deployment)
            self.assertIn("  terminal:",deployment)
            self.assertIn("if: always()",deployment)
            self.assertNotIn("if: github.event_name == 'workflow_dispatch'",deployment)
        verify=ci.split("  verify-build-once:",1)[1].split("  publish-protected-artifact:",1)[0]
        publisher=ci.split("  publish-protected-artifact:",1)[1]
        self.assertIn("agent-artifact-inventory/v1",verify)
        self.assertIn("agent-artifact-authenticity-receipt/v1",verify)
        self.assertIn("actions/upload-artifact@",verify)
        self.assertNotIn("id-token: write",verify)
        self.assertIn("id-token: write",publisher)
        self.assertIn("attestations: write",publisher)
        self.assertIn("actions/download-artifact@",publisher)
        self.assertIn("actions/attest-build-provenance@",publisher)
        self.assertNotIn("actions/checkout@",publisher)
        self.assertNotRegex(publisher,r"(?m)^\s+(?:run|shell):")
        self.assertIn("artifact-ids: ${{ needs.verify-publication-payload.outputs.publication_artifact_id }}",publisher)
        for command in ("{{install_command}}", "{{static_security_command}}", "{{test_command}}",
                        "{{integration_command}}", "{{migration_dry_run_command}}", "{{build_command}}"):
            self.assertNotIn(command,publisher)
        for name in ("github-test-cd.yml.tmpl","github-production-cd.yml.tmpl"):
            deployment=texts[name]
            self.assertEqual(deployment.count("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"),1,name)
            self.assertIn("ref: ${{ env.CI_HEAD_SHA }}",deployment,name)
            self.assertIn("persist-credentials: false",deployment,name)
            self.assertLess(deployment.index("Checkout exact dispatched revision"),deployment.index("blueprintctl.py run-command"),name)

    def test_gitlab_shadowing_and_authenticated_external_authority_fail_closed(self):
        clean='include:\n  - local: "/.gitlab/agent-workflow.yml"\nother-job:\n  script: exit 0\n'
        PROVIDERCTL.strict_gitlab_root_include(clean)
        for shadowed in (
            clean+'agent-workflow-candidate-evidence:\n  script: exit 0\n',
            clean+'"agent-workflow-candidate-evidence": {script: "exit 0"}\n',
            clean+'# agent-workflow-candidate-evidence must never be candidate-owned\n',
        ):
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"mention or shadow included candidate evidence"):
                PROVIDERCTL.strict_gitlab_root_include(shadowed)
        for self_asserted in (
            clean+'variables:\n  AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON: "forged"\n',
            clean+'variables: {"AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON": "forged"}\n',
            clean+'notes: |\n  AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON: forged\n',
        ):
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"mention or self-assert protected provider evidence"):
                PROVIDERCTL.strict_gitlab_root_include(self_asserted)
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"authenticated provider authority receipt"):
            PROVIDERCTL.validate_gitlab_external_authority_environment({})
        valid=self.provider_authority_environment("gitlab")
        identity={"candidate_revision":"a"*40,"candidate_tree":"b"*40}
        with mock.patch.object(PROVIDERCTL,"_current_candidate_git_identity",return_value=identity), \
             mock.patch.object(PROVIDERCTL,"trusted_git_repository",return_value={"host":"example.com","repository":"example/repository"}), \
             mock.patch.object(PROVIDERCTL,"_provider_authority_adapter",return_value=Path("/protected/adapter")), \
             mock.patch.object(PROVIDERCTL.humandecision,"run_adapter",side_effect=self.accept_provider_receipt):
            PROVIDERCTL.validate_gitlab_external_authority_environment(valid,root=ROOT)
            mutable=json.loads(valid["AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON"])
            mutable["immutable_authority_ref"]="policy/security-release@main"
            forged=dict(valid); forged["AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON"]=json.dumps(mutable)
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"immutable authority"):
                PROVIDERCTL.validate_gitlab_external_authority_environment(forged,root=ROOT)
            wrong_host=dict(valid); wrong_host["AGENT_PROVIDER_REPOSITORY_HOST"]="attacker.example"
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"bind project"):
                PROVIDERCTL.validate_gitlab_external_authority_environment(wrong_host,root=ROOT)
            wrong_receipt=json.loads(valid["AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON"]); wrong_receipt["repository_host"]="attacker.example"
            forged_host=dict(valid); forged_host["AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON"]=json.dumps(wrong_receipt)
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"bind project"):
                PROVIDERCTL.validate_gitlab_external_authority_environment(forged_host,root=ROOT)
        legacy={"AGENT_GITLAB_AUTHORITY_MODE":"pipeline-execution-policy","AGENT_GITLAB_AUTHORITY_PROJECT_ID":"71",
                "AGENT_GITLAB_AUTHORITY_REF_SHA":"a"*40,"AGENT_GITLAB_EFFECTIVE_CONFIG_SHA256":"b"*64,
                "AGENT_GITLAB_COLLISION_EVIDENCE_SHA256":"c"*64}
        with self.assertRaises(ADAPTIVE.AdaptiveError):
            PROVIDERCTL.validate_gitlab_external_authority_environment(legacy,root=ROOT)

    def test_github_external_verifier_requires_protected_adapter_proof(self):
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"authenticated provider authority receipt"):
            PROVIDERCTL.validate_github_external_authority_environment({})
        valid=self.provider_authority_environment("github")
        identity={"candidate_revision":"a"*40,"candidate_tree":"b"*40}
        with mock.patch.object(PROVIDERCTL,"_current_candidate_git_identity",return_value=identity), \
             mock.patch.object(PROVIDERCTL,"trusted_git_repository",return_value={"host":"example.com","repository":"example/repository"}), \
             mock.patch.object(PROVIDERCTL,"_provider_authority_adapter",return_value=Path("/protected/adapter")), \
             mock.patch.object(PROVIDERCTL.humandecision,"run_adapter",side_effect=self.accept_provider_receipt):
            PROVIDERCTL.validate_github_external_authority_environment(valid,root=ROOT)
        rejected=mock.Mock(returncode=1,stdout="REJECTED\n")
        with mock.patch.object(PROVIDERCTL,"_current_candidate_git_identity",return_value=identity), \
             mock.patch.object(PROVIDERCTL,"trusted_git_repository",return_value={"host":"example.com","repository":"example/repository"}), \
             mock.patch.object(PROVIDERCTL,"_provider_authority_adapter",return_value=Path("/protected/adapter")), \
             mock.patch.object(PROVIDERCTL.humandecision,"run_adapter",return_value=rejected):
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"adapter rejected"):
                PROVIDERCTL.validate_github_external_authority_environment(valid,root=ROOT)
        stale=json.loads(valid["AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON"])
        stale["observed_at"]="2000-01-01T00:00:00+00:00"
        invalid=dict(valid); invalid["AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON"]=json.dumps(stale)
        with mock.patch.object(PROVIDERCTL,"_current_candidate_git_identity",return_value=identity), \
             mock.patch.object(PROVIDERCTL,"trusted_git_repository",return_value={"host":"example.com","repository":"example/repository"}), \
             self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"stale"):
            PROVIDERCTL.validate_github_external_authority_environment(invalid,root=ROOT)
        generated_source=inspect.getsource(PROVIDERCTL.github_files)
        verification_source=inspect.getsource(PROVIDERCTL._command_verify_locked)
        self.assertIn("validate_github_external_authority_environment(os.environ,root=root,required_paths=tuple(expected)+(trace_relative,))",verification_source)
        self.assertIn("vars.AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON",generated_source)
        blueprint={"design":{"goals":[],"architecture":[],"technology_choices":[],"capabilities":[],
                    "acceptance":[],"constraints":[],"commands":[],"providers":[{
                        "id":"github","host":"github.enterprise.example:8443","runner":"ubuntu-24.04","protected_runner":"ubuntu-24.04","candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":None,"default_branch":"trunk"}]},
                   "confirmation":{"design_sha256":"a"*64}}
        workflow=PROVIDERCTL.github_files(blueprint)[".github/workflows/agent-verify.yml"]
        self.assertIn("python3 .agent/scripts/providerctl.py verify --provider github",workflow)
        self.assertIn("AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON: ${{ vars.AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON }}",workflow)
        self.assertIn('AGENT_PROVIDER_REPOSITORY_HOST: "github.enterprise.example:8443"',workflow)
        self.assertIn('branches:\n      - "trunk"',workflow)
        self.assertIn("sys.platform",workflow)
        self.assertIn("Candidate-owned evidence only",workflow)
        self.assertNotIn("name: agent-workflow-verify",workflow)

    def test_gitlab_release_chain_is_typed_and_renderable(self):
        template_dir=ROOT/".agent/assets/templates/ci-cd"
        provider={"id":"gitlab","platform":"linux","image":"python@sha256:"+"a"*64,"tags":["linux","candidate"],"protected_tags":["linux","protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True}
        authority=TEMPLATECTL.gitlab_workflow_authority(provider,"b"*64)
        rendered={}
        for name in ("gitlab-ci.yml.tmpl","gitlab-test-cd.yml.tmpl","gitlab-production-cd.yml.tmpl"):
            source=(template_dir/name).read_text(encoding="utf-8")
            tag_key="gitlab_candidate_tags" if name=="gitlab-ci.yml.tmpl" else "gitlab_protected_tags"
            scoped_authority={key:value for key,value in authority.items() if key not in {"gitlab_candidate_tags","gitlab_protected_tags"} or key==tag_key}
            placeholders=set(TEMPLATECTL.PLACEHOLDER.findall(source))-set(scoped_authority)
            variables={key:("dist" if key=="artifact_path" else "confirmed-command") for key in placeholders}
            text=TEMPLATECTL.render_gitlab_workflow_yaml(source,variables,scoped_authority).decode()
            self.assertNotIn("{{",text); self.assertIn("blueprintctl.py run-command --id confirmed-command",text)
            self.assertIn("sys.platform",text); self.assertIn("$CI_DEFAULT_BRANCH",text)
            rendered[name]=text
        self.assertIn("stage: build",rendered["gitlab-ci.yml.tmpl"])
        self.assertIn("stage: test-receipt",rendered["gitlab-test-cd.yml.tmpl"])
        self.assertIn("stage: test-promotion",rendered["gitlab-test-cd.yml.tmpl"])
        production=rendered["gitlab-production-cd.yml.tmpl"]; test_cd=rendered["gitlab-test-cd.yml.tmpl"]
        self.assertIn("stage: production-promotion",production)
        self.assertIn("artifacts:\n    when: always",production)
        self.assertNotIn("artifacts:\n    when: on_success",production)
        self.assertNotIn("agent-production-rollback:",production)
        production_source=(template_dir/"gitlab-production-cd.yml.tmpl").read_text(encoding="utf-8")
        self.assertEqual(production_source.count("{{rollback_production_command_id}}"),1)
        self.assertEqual(production_source.count("{{publish_promotion_receipt_command_id}}"),1)
        self.assertEqual(production_source.count("{{verify_promotion_receipt_authenticity_command_id}}"),1)
        self.assertLess(production_source.index("{{deploy_production_command_id}}"),production_source.index("{{rollback_production_command_id}}"))
        self.assertLess(production_source.index("{{rollback_production_command_id}}"),production_source.index("{{publish_promotion_receipt_command_id}}"))
        self.assertIn("receipt_disposition=rolled-back",production)
        self.assertIn('if [ "$receipt_disposition" = promoted ]',production)
        cleanup_raw=production_source.split("    - |\n",1)[1].split("  environment:",1)[0]
        cleanup_command="\n".join(line[6:] if line.startswith("      ") else line for line in cleanup_raw.splitlines())
        with tempfile.TemporaryDirectory(prefix="gitlab-receipt-cleanup-") as raw:
            cleanup_root=Path(raw); receipt=cleanup_root/"agent-production-deployment-receipt.json"
            self.assertEqual(subprocess.run(["/bin/sh","-c",cleanup_command],cwd=raw).returncode,0)
            receipt.write_text("stale",encoding="utf-8")
            self.assertEqual(subprocess.run(["/bin/sh","-c",cleanup_command],cwd=raw).returncode,0); self.assertFalse(receipt.exists())
            target=cleanup_root/"target"; target.write_text("keep",encoding="utf-8"); receipt.symlink_to(target)
            self.assertEqual(subprocess.run(["/bin/sh","-c",cleanup_command],cwd=raw).returncode,0); self.assertFalse(receipt.exists()); self.assertEqual(target.read_text(),"keep")
            receipt.mkdir()
            self.assertNotEqual(subprocess.run(["/bin/sh","-c",cleanup_command],cwd=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE).returncode,0)
        test_source=(template_dir/"gitlab-test-cd.yml.tmpl").read_text(encoding="utf-8")
        self.assertLess(test_source.index("{{test_acceptance_command_id}}"),test_source.index("{{cleanup_test_command_id}}"))
        self.assertIn('if [ "$deploy_status" -eq 0 ] && [ "$acceptance_status" -eq 0 ] && [ "$cleanup_status" -eq 0 ]',test_cd)
        with self.assertRaisesRegex(SystemExit,"macOS runner cannot use"):
            TEMPLATECTL.gitlab_workflow_authority({**provider,"platform":"macos"},"b"*64)

    def test_provider_presence_without_capability_is_generic_only(self):
        blueprint={"design":{"goals":[],"architecture":[],"technology_choices":[],"capabilities":[],
                   "acceptance":[],"constraints":[],"commands":[],"providers":[{
                       "id":"github","runner":"ubuntu-24.04","protected_runner":"ubuntu-24.04","candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":None,"default_branch":"trunk"}]},
                   "confirmation":{"design_sha256":"a"*64}}
        self.assertFalse(PROVIDERCTL.provider_specific_authorized(blueprint,"github"))
        files=PROVIDERCTL.generic_files(blueprint,"github")
        self.assertNotIn(".github/workflows/agent-verify.yml",files)
        contract=json.loads(files[".agent/provider-design/github/integration.json"])
        self.assertEqual(contract["configuration_keys"],[])
        authorized=json.loads(json.dumps(blueprint)); authorized["design"]["capabilities"]=[{
            "id":"ci-provider-github","description":"explicit built-in provider authorization"}]
        self.assertTrue(PROVIDERCTL.provider_specific_authorized(authorized,"github"))

    def test_provider_git_output_is_bounded_while_streaming(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); flood=root/"git-flood"
            flood.write_text("#!/bin/sh\npython3 -c 'import sys; sys.stdout.buffer.write(bytes([120])*1048576)'\n",encoding="utf-8")
            flood.chmod(0o755); metadata=os.stat(flood,follow_symlinks=False)
            identity=(metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_uid,metadata.st_ctime_ns)
            trusted=PROVIDERCTL._trusted_git_executable; PROVIDERCTL._trusted_git_executable=lambda:(str(flood),identity)
            try:
                with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"output is unbounded"):
                    PROVIDERCTL._git_candidate_command(root,["status"],max_output=4096)
            finally: PROVIDERCTL._trusted_git_executable=trusted

    def test_provider_git_lookup_ignores_inherited_path(self):
        with tempfile.TemporaryDirectory(prefix="poisoned-git-") as raw:
            fake=Path(raw)/"git"; fake.write_text("#!/bin/sh\nexit 99\n",encoding="utf-8"); fake.chmod(0o755)
            with mock.patch.dict(os.environ,{"PATH":raw}):
                trusted_raw,identity=PROVIDERCTL._trusted_git_executable(); trusted=Path(trusted_raw)
            self.assertNotEqual(trusted,fake); self.assertTrue(trusted.is_absolute())
            self.assertEqual(len(identity),5)

    def test_provider_repository_identity_binds_self_hosted_origin_and_namespace(self):
        deep="/".join(["namespace"]*12+["repository.git"])
        fixtures=(
            ("https://git.internal.example:8443/group/subgroup/repository.git",{"host":"git.internal.example:8443","repository":"group/subgroup/repository"}),
            ("git@git.internal.example:group/subgroup/repository.git",{"host":"git.internal.example","repository":"group/subgroup/repository"}),
            ("ssh://git@git.internal.example:2222/group/repository.git",{"host":"git.internal.example:2222","repository":"group/repository"}),
            ("ssh://git@[2001:db8::1]:2222/group/repository.git",{"host":"[2001:db8::1]:2222","repository":"group/repository"}),
            ("https://192.0.2.4/"+deep,{"host":"192.0.2.4","repository":deep[:-4]}),
        )
        for remote,expected in fixtures:
            with self.subTest(remote=remote), mock.patch.object(PROVIDERCTL,"_git_candidate_command",return_value=remote):
                self.assertEqual(PROVIDERCTL.trusted_git_repository(ROOT),expected)
        for remote in ("https://user@git.internal.example/group/repository.git","https://git.internal.example/group/repository.git/","git@bad_host!:group/repository.git","https://git..example/group/repository.git","https://git.example/group/../repository.git","ssh://root@git.example/group/repository.git","https://010.0.0.1/group/repository.git"):
            with self.subTest(remote=remote), mock.patch.object(PROVIDERCTL,"_git_candidate_command",return_value=remote), self.assertRaises(ADAPTIVE.AdaptiveError):
                PROVIDERCTL.trusted_git_repository(ROOT)

    def test_provider_authority_candidate_identity_requires_one_clean_committed_tree(self):
        with tempfile.TemporaryDirectory(prefix="provider-candidate-") as raw:
            root=Path(raw); subprocess.run(["git","init","-q"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Fixture"],cwd=root,check=True)
            subprocess.run(["git","config","user.email","fixture@example.invalid"],cwd=root,check=True)
            required=root/"authority.yml"; required.write_text("trusted\n",encoding="utf-8")
            subprocess.run(["git","add","authority.yml"],cwd=root,check=True)
            subprocess.run(["git","commit","-qm","candidate"],cwd=root,check=True)
            identity=PROVIDERCTL._current_candidate_git_identity(root,("authority.yml",))
            self.assertRegex(identity["candidate_revision"],r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
            self.assertRegex(identity["candidate_tree"],r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
            monitor=root/".git/fsmonitor.sh"; invoked=root/".git/fsmonitor-invoked"
            monitor.write_text(f"#!/bin/sh\nprintf invoked > {invoked}\nexit 0\n",encoding="utf-8"); monitor.chmod(0o755)
            subprocess.run(["git","config","core.fsmonitor",str(monitor)],cwd=root,check=True)
            PROVIDERCTL._current_candidate_git_identity(root,("authority.yml",))
            self.assertFalse(invoked.exists(),"provider candidate status executed repository core.fsmonitor")
            subprocess.run(["git","config","--unset","core.fsmonitor"],cwd=root,check=True)
            required.write_text("unstaged\n",encoding="utf-8")
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"uncommitted candidate drift"):
                PROVIDERCTL._current_candidate_git_identity(root,("authority.yml",))
            subprocess.run(["git","add","authority.yml"],cwd=root,check=True)
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"uncommitted candidate drift"):
                PROVIDERCTL._current_candidate_git_identity(root,("authority.yml",))
            subprocess.run(["git","checkout","-q","HEAD","--","authority.yml"],cwd=root,check=True)
            (root/"generated-uncommitted.yml").write_text("untracked\n",encoding="utf-8")
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"uncommitted candidate drift"):
                PROVIDERCTL._current_candidate_git_identity(root,("authority.yml",))
            (root/"generated-uncommitted.yml").unlink()
            subprocess.run(["git","update-index","--assume-unchanged","authority.yml"],cwd=root,check=True)
            required.write_text("hidden assume-unchanged\n",encoding="utf-8")
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"assume-unchanged or skip-worktree"):
                PROVIDERCTL._current_candidate_git_identity(root,("authority.yml",))
            subprocess.run(["git","update-index","--no-assume-unchanged","authority.yml"],cwd=root,check=True)
            subprocess.run(["git","checkout","-q","HEAD","--","authority.yml"],cwd=root,check=True)
            subprocess.run(["git","update-index","--skip-worktree","authority.yml"],cwd=root,check=True)
            required.write_text("hidden skip-worktree\n",encoding="utf-8")
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"assume-unchanged or skip-worktree"):
                PROVIDERCTL._current_candidate_git_identity(root,("authority.yml",))
            subprocess.run(["git","update-index","--no-skip-worktree","authority.yml"],cwd=root,check=True)

    def test_candidate_verifier_tamper_never_becomes_required_authority(self):
        source=inspect.getsource(PROVIDERCTL.github_files)
        self.assertIn("Candidate-owned evidence only",source)
        self.assertIn("immutable external/default-branch verifier",source)
        blueprint={"design":{"goals":[],"architecture":[],"technology_choices":[],"capabilities":[
                    {"id":"ci-provider-github","description":"explicit"},{"id":"ci-provider-gitlab","description":"explicit"}],
                    "acceptance":[],"constraints":[],"commands":[],"providers":[
                        {"id":"github","runner":"ubuntu-24.04","protected_runner":"ubuntu-24.04","candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":None,"default_branch":"main"},
                        {"id":"gitlab","platform":"linux","image":None,"tags":["candidate"],"protected_tags":["protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"default_branch":"main"}]},
                   "confirmation":{"design_sha256":"a"*64}}
        github=json.loads(PROVIDERCTL.design_artifact(blueprint,"github"))
        gitlab=json.loads(PROVIDERCTL.design_artifact(blueprint,"gitlab"))
        self.assertFalse(github["integration"]["candidate_workflow_is_authority"])
        self.assertTrue(github["integration"]["candidate_bytes_are_data_only"])
        self.assertTrue(github["integration"]["configuration_required"])
        self.assertFalse(gitlab["integration"]["included_job_names_are_authority"])
        tampered=dict(github); tampered["integration"]=dict(github["integration"])
        tampered["integration"]["candidate_workflow_is_authority"]=True
        self.assertNotEqual(tampered,github)

    def test_oidc_publisher_cannot_checkout_or_execute_project_code(self):
        text=(ROOT/".agent/assets/templates/ci-cd/github-ci.yml.tmpl").read_text(encoding="utf-8")
        lines=text.splitlines(); jobs={}
        starts=[(index,line[2:-1]) for index,line in enumerate(lines) if re.fullmatch(r"  [A-Za-z0-9_.-]+:",line)]
        for position,(start,name) in enumerate(starts):
            end=starts[position+1][0] if position+1<len(starts) else len(lines)
            jobs[name]="\n".join(lines[start:end])+"\n"
        privileged={name:body for name,body in jobs.items() if re.search(r"(?m)^\s+id-token:\s*write\s*$",body)}
        self.assertEqual(set(privileged),{"publish-protected-artifact"})
        publisher=privileged["publish-protected-artifact"]
        self.assertNotRegex(publisher,r"(?m)^\s+(?:run|shell):")
        self.assertNotIn("actions/checkout@",publisher)
        uses=re.findall(r"(?m)^\s+uses:\s*([^\s#]+)",publisher)
        self.assertEqual(uses,[
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
        ])
        self.assertIn("artifact-ids: ${{ needs.verify-publication-payload.outputs.publication_artifact_id }}",publisher)
        self.assertEqual(text.count("{{build_command_id}}"),1)
        self.assertNotRegex(text,r"\{\{[a-z_]+_command\}\}")
        self.assertIn("blueprintctl.py run-command --id {{build_command_id}}",text)
        self.assertEqual(text.count("id-token: write"),1)

    def test_cd_oidc_jobs_are_minimal_and_project_commands_are_unprivileged(self):
        template_dir=ROOT/".agent/assets/templates/ci-cd"
        expected={"github-test-cd.yml.tmpl":"publish-test-provenance",
                  "github-production-cd.yml.tmpl":"publish-production-provenance"}
        for name,privileged_name in expected.items():
            text=(template_dir/name).read_text(encoding="utf-8")
            lines=text.splitlines(); starts=[(i,line[2:-1]) for i,line in enumerate(lines) if re.fullmatch(r"  [A-Za-z0-9_.-]+:",line)]
            jobs={job:"\n".join(lines[start:(starts[pos+1][0] if pos+1<len(starts) else len(lines))])+"\n"
                  for pos,(start,job) in enumerate(starts)}
            privileged={job:body for job,body in jobs.items() if re.search(r"(?m)^\s+id-token:\s*write\s*$",body)}
            self.assertEqual(set(privileged),{privileged_name},name)
            publisher=privileged[privileged_name]
            self.assertNotRegex(publisher,r"(?m)^\s+(?:run|shell|container):")
            self.assertNotIn("actions/checkout@",publisher)
            self.assertNotIn("_command_id}}",publisher)
            self.assertEqual(re.findall(r"(?m)^\s+uses:\s*([^\s#]+)",publisher),[
                "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
                "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be"])
            self.assertIn("artifact-ids: ${{ needs.",publisher)
            unprivileged="".join(body for job,body in jobs.items() if job!=privileged_name)
            self.assertIn("_command_id}}",unprivileged)
            self.assertNotIn("id-token: write",unprivileged)

    def test_required_check_receipt_binds_authenticated_external_authority(self):
        github={
            "producer_identity":{"identity_type":"github-app","subject":"app/security-checks",
                                 "issuer":"https://token.actions.githubusercontent.com","provider_actor_id":"71"},
            "external_authority":{"kind":"github-external-workflow","authority_id":"workflow-verify",
                                  "immutable_ref":"security/authority/.github/workflows/verify.yml@"+"a"*40,
                                  "evidence_sha256":"b"*64}}
        self.assertTrue(DELIVERYCTL.valid_required_check_authority(github,"github"))
        for mutation in (
            {"producer_identity":dict(github["producer_identity"],provider_actor_id="caller")},
            {"external_authority":dict(github["external_authority"],immutable_ref="security/authority/.github/workflows/verify.yml@main")},
            {"external_authority":dict(github["external_authority"],kind="candidate-workflow")},
        ):
            forged=dict(github); forged.update(mutation)
            self.assertFalse(DELIVERYCTL.valid_required_check_authority(forged,"github"))
        gitlab={
            "producer_identity":{"identity_type":"gitlab-service-account","subject":"service/security-policy",
                                 "issuer":"https://gitlab.example","provider_actor_id":"88"},
            "external_authority":{"kind":"gitlab-compliance-pipeline","authority_id":"compliance-release",
                                  "immutable_ref":"compliance/release@"+"c"*40,"evidence_sha256":"d"*64}}
        self.assertTrue(DELIVERYCTL.valid_required_check_authority(gitlab,"gitlab"))
        self.assertFalse(DELIVERYCTL.valid_required_check_authority(gitlab,"github"))

    def test_artifact_substitution_is_bound_by_inventory_and_receipt(self):
        text=(ROOT/".agent/assets/templates/ci-cd/github-ci.yml.tmpl").read_text(encoding="utf-8")
        lines=text.splitlines(); step=lines.index("      - name: Verify exact inventory, bytes, and authenticity receipt")
        start=lines.index("        run: |",step)+1; body=[]
        for line in lines[start:]:
            if line.startswith("      - name:"): break
            if line.strip():
                self.assertTrue(line.startswith("          "),line); body.append(line[10:])
        script="\n".join(body)+"\n"
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); payload=b"trusted bytes\n"
            import hashlib, tarfile
            member=root/"payload.bin"; member.write_bytes(payload)
            with tarfile.open(root/"artifact.tar","w") as bundle: bundle.add(member,arcname="payload.bin")
            member.unlink()
            archive=(root/"artifact.tar").read_bytes()
            inventory={"schema":"agent-artifact-inventory/v1","files":[{"path":"payload.bin","bytes":len(payload),
                       "sha256":hashlib.sha256(payload).hexdigest(),"mode":0o644}],"total_bytes":len(payload)}
            inventory_raw=(json.dumps(inventory,sort_keys=True,separators=(",",":"))+"\n").encode()
            (root/"inventory.json").write_bytes(inventory_raw)
            ready=root/"ready"
            env=dict(os.environ); env.update({"PUBLISH_ROOT":str(root),"READY_ROOT":str(ready),"WORKFLOW_SHA":"a"*40,"BUILD_RUN_ID":"71",
                "BUILD_RUN_ATTEMPT":"2","EXPECTED_ARTIFACT_SHA256":hashlib.sha256(archive).hexdigest(),
                "EXPECTED_INVENTORY_SHA256":hashlib.sha256(inventory_raw).hexdigest()})
            receipt={"schema":"agent-artifact-authenticity-receipt/v1","source_sha":"a"*40,"build_run_id":"71",
                     "build_run_attempt":"2","artifact_sha256":env["EXPECTED_ARTIFACT_SHA256"],"artifact_bytes":len(archive),
                     "inventory_sha256":env["EXPECTED_INVENTORY_SHA256"],"inventory_bytes":len(inventory_raw)}
            receipt_raw=(json.dumps(receipt,sort_keys=True,separators=(",",":"))+"\n").encode()
            (root/"authenticity-receipt.json").write_bytes(receipt_raw)
            env["EXPECTED_RECEIPT_SHA256"]=hashlib.sha256(receipt_raw).hexdigest()
            accepted=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertEqual(accepted.returncode,0,accepted.stdout+accepted.stderr)
            self.assertEqual((ready/"artifact.tar").read_bytes(),archive)
            with (root/"artifact.tar").open("ab") as target: target.write(b"substitution")
            rejected=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertNotEqual(rejected.returncode,0)

    def test_mutable_action_reference_is_rejected_by_pin_policy(self):
        def validate(text):
            uses=re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)",text,re.MULTILINE)
            if any(re.fullmatch(r"[^@]+@[0-9a-f]{40}",value) is None for value in uses):
                raise ValueError("mutable action reference")
        source=(ROOT/".agent/assets/templates/ci-cd/github-ci.yml.tmpl").read_text(encoding="utf-8")
        validate(source)
        mutable=source.replace("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683","actions/checkout@v4",1)
        with self.assertRaisesRegex(ValueError,"mutable action reference"):
            validate(mutable)

    def test_confirmed_container_is_rendered_and_impossible_combinations_rejected(self):
        image="registry.example/runtime@sha256:"+"a"*64
        github=ADAPTIVE.validate_providers([{
            "id":"github","runner":["self-hosted","linux","candidate"],"protected_runner":["self-hosted","linux","protected"],
            "candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,
            "container_image":image,"default_branch":"trunk",
        }])[0]
        authority=TEMPLATECTL.github_workflow_authority(github,"a"*64)
        self.assertEqual(authority["github_candidate_runner"],["self-hosted","linux","candidate"])
        self.assertEqual(authority["github_protected_runner"],["self-hosted","linux","protected"])
        self.assertEqual(authority["github_default_branch"],"trunk")
        self.assertEqual(authority["github_container"],image)
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"distinct authority labels"):
            ADAPTIVE.validate_providers([{**github,"protected_runner":github["runner"]}])
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"ephemeral isolation authority"):
            ADAPTIVE.validate_providers([{**github,"protected_ephemeral":False}])
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"distinct authority tags"):
            ADAPTIVE.validate_providers([{"id":"gitlab","platform":"linux","image":None,"tags":["linux","candidate"],"protected_tags":["linux","candidate"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True}])
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"macOS runner with a container"):
            ADAPTIVE.validate_providers([{
                "id":"github","runner":"macos-14","protected_runner":"macos-14","candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":image,"default_branch":"trunk",
            }])
        for invalid_image in (
            "registry.example/runtime:latest", "Registry.example/runtime@sha256:"+"a"*64,
            "registry.example/runtime@sha256:"+"A"*64, "runtime:latest@sha256:"+"a"*64,
        ):
            invalid=dict(github); invalid["container_image"]=invalid_image
            with self.assertRaisesRegex(SystemExit,"container authority is invalid"):
                TEMPLATECTL.github_workflow_authority(invalid,"a"*64)
        shorthand="node@sha256:"+"b"*64
        self.assertEqual(ADAPTIVE.validate_providers([{
            "id":"gitlab","platform":"linux","image":shorthand,"tags":["candidate"],"protected_tags":["protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,
        }])[0]["image"],shorthand)
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"cannot combine a GitLab macOS runner with a container"):
            ADAPTIVE.validate_providers([{
                "id":"gitlab","platform":"macos","image":shorthand,"tags":["candidate"],"protected_tags":["protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,
            }])
        with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"GitLab fields"):
            ADAPTIVE.validate_providers([{"id":"gitlab","image":None,"tags":[]}])
        for selected_image in (image,None):
            with self.assertRaisesRegex(ADAPTIVE.AdaptiveError,"native Windows runner tags"):
                ADAPTIVE.validate_providers([{
                    "id":"gitlab","platform":"linux","image":selected_image,"tags":["docker","windows-2022","candidate"],"protected_tags":["docker","protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,
                }])

    @staticmethod
    def validation_script(text):
        lines = text.splitlines()
        start = lines.index("        run: |", lines.index("      - name: Validate dispatch inputs")) + 1
        body = []
        for line in lines[start:]:
            if line.startswith("      - name:"):
                break
            if line.strip():
                if not line.startswith("          "):
                    raise AssertionError(f"unexpected validator indentation: {line!r}")
                body.append(line[10:])
        return "\n".join(body) + "\n"

    def test_dispatch_inputs_are_env_bound_validated_and_quoted(self):
        template_dir = ROOT / ".agent/assets/templates/ci-cd"
        for name in ("github-test-cd.yml.tmpl", "github-production-cd.yml.tmpl"):
            text = (template_dir / name).read_text(encoding="utf-8")
            self.assertIn("Validate dispatch inputs", text)
            self.assertIn("[0-9a-f]{64}", text)
            self.assertNotRegex(text, r"run:\s*[^\n]*\$\{\{\s*inputs\.")
            for line in text.splitlines():
                if "{{" in line and "_command_id}}" in line:
                    self.assertNotIn("${{ inputs.", line)
            self.assertIn('"$ARTIFACT_DIGEST"', text)
            self.assertIn("verify_ci_artifact_provenance_command",text)
            self.assertIn("ARTIFACT_PROVENANCE_RECEIPT: ${{ inputs.artifact_provenance_receipt }}",text)
            self.assertIn("$CI_RUN_ID",text); self.assertIn("$CI_HEAD_SHA",text)
        test_text=(template_dir/"github-test-cd.yml.tmpl").read_text(encoding="utf-8")
        production_text=(template_dir/"github-production-cd.yml.tmpl").read_text(encoding="utf-8")
        self.assertIn("agent-test-deployment-receipt/v2",test_text)
        self.assertIn("blueprintctl.py run-command --id {{verify_artifact_and_receipt_command_id}}",production_text)
        self.assertNotRegex(production_text,r"\{\{[a-z_]+_command\}\}")

    def test_dispatch_validator_rejects_shell_payloads_without_execution(self):
        template_dir = ROOT / ".agent/assets/templates/ci-cd"
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "injected"
            payload = f"sha256:{'a' * 64};touch {marker}"
            for name in ("github-test-cd.yml.tmpl", "github-production-cd.yml.tmpl"):
                text = (template_dir / name).read_text(encoding="utf-8")
                script = self.validation_script(text)
                env = dict(os.environ)
                env.update({
                    "ARTIFACT_DIGEST": payload,
                    "ARTIFACT_PROVENANCE_RECEIPT": "provenance:ci-1", "CI_RUN_ID": "71",
                    "CI_HEAD_SHA": "b" * 40, "WORKFLOW_HEAD_SHA": "b" * 40,
                    "WORKFLOW_EVENT_NAME": "workflow_dispatch", "WORKFLOW_REF": "refs/heads/trunk",
                    "EXPECTED_DEFAULT_REF": "refs/heads/trunk", "TEST_RECEIPT": "receipt:test-1", "TEST_RECEIPT_SHA256": "c" * 64,
                    "PROVIDER_PREFLIGHT_RECEIPT": "receipt:preflight-1",
                    "PRODUCTION_DECISION_PACKET": "decision:production-1",
                })
                result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(marker.exists())

            production = (template_dir / "github-production-cd.yml.tmpl").read_text(encoding="utf-8")
            env = dict(os.environ)
            env.update({
                "ARTIFACT_DIGEST": "sha256:" + "a" * 64,
                "ARTIFACT_PROVENANCE_RECEIPT": "provenance:ci-1", "CI_RUN_ID": "71",
                "CI_HEAD_SHA": "b" * 40, "WORKFLOW_HEAD_SHA": "b" * 40,
                "WORKFLOW_EVENT_NAME": "workflow_dispatch", "WORKFLOW_REF": "refs/heads/trunk",
                "EXPECTED_DEFAULT_REF": "refs/heads/trunk", "TEST_RECEIPT": f"receipt;touch {marker}", "TEST_RECEIPT_SHA256": "c" * 64,
                "PROVIDER_PREFLIGHT_RECEIPT": "receipt:preflight-1",
                "PRODUCTION_DECISION_PACKET": "decision:production-1",
            })
            result = subprocess.run(
                ["bash", "-c", self.validation_script(production)],
                env=env, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertFalse(marker.exists())

    def test_dispatch_validator_accepts_bounded_values(self):
        template_dir = ROOT / ".agent/assets/templates/ci-cd"
        env = dict(os.environ)
        env.update({
            "ARTIFACT_DIGEST": "sha256:" + "a" * 64,
            "ARTIFACT_PROVENANCE_RECEIPT": "provenance:ci-1", "CI_RUN_ID": "71",
            "CI_HEAD_SHA": "b" * 40, "WORKFLOW_HEAD_SHA": "b" * 40,
            "WORKFLOW_EVENT_NAME": "workflow_dispatch", "WORKFLOW_REF": "refs/heads/trunk",
            "EXPECTED_DEFAULT_REF": "refs/heads/trunk", "TEST_RECEIPT": "receipt:test-1", "TEST_RECEIPT_SHA256": "c" * 64,
            "PROVIDER_PREFLIGHT_RECEIPT": "receipt:preflight-1",
            "PRODUCTION_DECISION_PACKET": "decision:production-1",
        })
        for name in ("github-test-cd.yml.tmpl", "github-production-cd.yml.tmpl"):
            text = (template_dir / name).read_text(encoding="utf-8")
            result = subprocess.run(
                ["bash", "-c", self.validation_script(text)], env=env,
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_test_publisher_receipt_binds_cleanup_before_success(self):
        text=(ROOT/".agent/assets/templates/ci-cd/github-test-cd.yml.tmpl").read_text(encoding="utf-8")
        self.assertIn("if: always() && steps.deploy_test.outcome == 'success' && steps.accept_test.outcome == 'success' && steps.cleanup_test.outcome == 'success'",text)
        self.assertLess(text.index("      - name: Clean test runtime"),text.index("      - name: Publish digest-bound test receipt"))
        self.assertIn("steps.cleanup_test.outcome != 'success'",text)
        self.assertIn("steps.verify_test_receipt.outcome != 'success'",text)
        lines=text.splitlines(); start=lines.index("        run: |",lines.index("      - name: Verify published receipt binds cleanup and this successful run"))+1
        body=[]
        for line in lines[start:]:
            if line.startswith("      - name:"): break
            if line.strip():
                self.assertTrue(line.startswith("          "),line); body.append(line[10:])
        script="\n".join(body)+"\n"
        with tempfile.TemporaryDirectory() as raw:
            receipt=Path(raw)/"receipt.json"; env=dict(os.environ)
            env.update({"ARTIFACT_DIGEST":"sha256:"+"a"*64,"ARTIFACT_PROVENANCE_RECEIPT":"provenance:ci-1",
                        "CI_RUN_ID":"71","CI_HEAD_SHA":"b"*40,"RECEIPT_RUN_ID":"71","RECEIPT_RUN_ATTEMPT":"2",
                        "RECEIPT_HEAD_SHA":"b"*40,"RECEIPT_REF":"refs/heads/trunk","RECEIPT_PATH":str(receipt),
                        "RECEIPT_CLEANUP_OUTCOME":"success"})
            value={"schema":"agent-test-deployment-receipt/v2","artifact_digest":env["ARTIFACT_DIGEST"],
                   "artifact_provenance_receipt":"provenance:ci-1","ci_run_id":"71","ci_head_sha":"b"*40,"run_id":"71",
                   "run_attempt":"2","head_sha":"b"*40,"ref":"refs/heads/trunk","deploy_outcome":"success",
                   "acceptance_outcome":"success","cleanup_outcome":"success","conclusion":"success"}
            receipt.write_text(json.dumps(value)+"\n",encoding="utf-8")
            accepted=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertEqual(accepted.returncode,0,accepted.stdout+accepted.stderr)
            value["unexpected"]="forged"; receipt.write_text(json.dumps(value)+"\n",encoding="utf-8")
            rejected=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertNotEqual(rejected.returncode,0)
            receipt.unlink(); target=Path(raw)/"target.json"; target.write_text("{}\n",encoding="utf-8"); receipt.symlink_to(target)
            symlinked=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertNotEqual(symlinked.returncode,0)

    def test_production_receipt_separates_verify_and_rollback_outcomes(self):
        text=(ROOT/".agent/assets/templates/ci-cd/github-production-cd.yml.tmpl").read_text(encoding="utf-8")
        self.assertIn("agent-production-deployment-receipt/v3",text)
        self.assertIn("verify_promotion_receipt_authenticity_command",text)
        self.assertIn("steps.verify_promotion_authenticity.outcome != 'success'",text)
        self.assertIn("steps.rollback_production.outcome != 'skipped'",text)
        self.assertLess(text.index("      - name: Verify deployed production artifact"),text.index("      - name: Roll back failed or unverified deployment"))
        lines=text.splitlines()
        start=lines.index("        run: |",lines.index("      - name: Verify exact structured deployment receipt bindings"))+1
        body=[]
        for line in lines[start:]:
            if line.startswith("      - name:"): break
            if line.strip():
                self.assertTrue(line.startswith("          "),line); body.append(line[10:])
        script="\n".join(body)+"\n"
        with tempfile.TemporaryDirectory() as raw:
            receipt=Path(raw)/"deployment.json"
            env=dict(os.environ)
            env.update({
                "ARTIFACT_DIGEST":"sha256:"+"a"*64,"ARTIFACT_PROVENANCE_RECEIPT":"provenance:ci-1",
                "CI_RUN_ID":"71","CI_HEAD_SHA":"b"*40,"TEST_RECEIPT":"receipt:test-1","TEST_RECEIPT_SHA256":"c"*64,
                "PROVIDER_PREFLIGHT_RECEIPT":"receipt:provider-1","PRODUCTION_DECISION_PACKET":"decision:prod-1",
                "PRODUCTION_RUN_ID":"82","PRODUCTION_RUN_ATTEMPT":"3","PRODUCTION_HEAD_SHA":"b"*40,
                "PRODUCTION_REF":"refs/heads/trunk","DEPLOY_OUTCOME":"success","VERIFY_OUTCOME":"success",
                "ROLLBACK_OUTCOME":"skipped","RECEIPT_DISPOSITION":"promoted","RECEIPT_CONCLUSION":"success",
                "RECEIPT_PATH":str(receipt),
            })
            value={"schema":"agent-production-deployment-receipt/v3","artifact_digest":env["ARTIFACT_DIGEST"],
                   "artifact_provenance_receipt":env["ARTIFACT_PROVENANCE_RECEIPT"],"ci_run_id":"71",
                   "ci_head_sha":"b"*40,"test_receipt":env["TEST_RECEIPT"],"test_receipt_sha256":env["TEST_RECEIPT_SHA256"],
                   "provider_preflight_receipt":env["PROVIDER_PREFLIGHT_RECEIPT"],
                   "production_decision_packet":env["PRODUCTION_DECISION_PACKET"],"production_run_id":"82",
                   "production_run_attempt":"3","production_head_sha":"b"*40,"production_ref":"refs/heads/trunk",
                   "deploy_outcome":"success","verify_outcome":"success","rollback_outcome":"skipped",
                   "disposition":"promoted","conclusion":"success"}
            receipt.write_text(json.dumps(value)+"\n",encoding="utf-8")
            accepted=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertEqual(accepted.returncode,0,accepted.stdout+accepted.stderr)
            value.update({"verify_outcome":"failure","rollback_outcome":"success","disposition":"rolled-back"})
            receipt.write_text(json.dumps(value)+"\n",encoding="utf-8")
            rolled_back_env=dict(env); rolled_back_env.update({"VERIFY_OUTCOME":"failure","ROLLBACK_OUTCOME":"success","RECEIPT_DISPOSITION":"rolled-back"})
            forged_success=subprocess.run(["bash","-c",script],env=rolled_back_env,text=True,capture_output=True)
            self.assertNotEqual(forged_success.returncode,0,"rollback must never validate as successful promotion")
            value["conclusion"]="failure"; receipt.write_text(json.dumps(value)+"\n",encoding="utf-8")
            rolled_back_env["RECEIPT_CONCLUSION"]="failure"
            rollback_record=subprocess.run(["bash","-c",script],env=rolled_back_env,text=True,capture_output=True)
            self.assertEqual(rollback_record.returncode,0,rollback_record.stdout+rollback_record.stderr)
            value["test_receipt"]="receipt:unrelated"; receipt.write_text(json.dumps(value)+"\n",encoding="utf-8")
            unrelated=subprocess.run(["bash","-c",script],env=rolled_back_env,text=True,capture_output=True)
            self.assertNotEqual(unrelated.returncode,0)
            receipt.unlink(); absent=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertNotEqual(absent.returncode,0)
            target=Path(raw)/"target.json"; target.write_text(json.dumps(value),encoding="utf-8"); receipt.symlink_to(target)
            symlinked=subprocess.run(["bash","-c",script],env=env,text=True,capture_output=True)
            self.assertNotEqual(symlinked.returncode,0)

    def test_installed_template_carries_exact_mit_terms(self):
        self.assertEqual((ROOT / "LICENSE").read_bytes(), (ROOT / ".agent/LICENSE").read_bytes())

    def test_quarantined_pxpipe_redistributes_no_opaque_bundles(self):
        plugin = ROOT / "plugins/pxpipe-context"
        integrity = json.loads((plugin / "integrity.json").read_text(encoding="utf-8"))
        self.assertEqual(integrity["provenance_status"], "quarantined")
        for field in (
            "source_package_sha256", "runtime_bundle", "runtime_bundle_sha256",
            "proxy_bundle", "proxy_bundle_sha256",
        ):
            self.assertIsNone(integrity[field])
        self.assertFalse((plugin / "mcp/vendor/pxpipe-runtime.mjs").exists())
        self.assertFalse((plugin / "proxy/vendor/pxpipe-node.mjs").exists())


    def test_all_production_command_and_inventory_paths_are_prebounded(self):
        production = [
            ROOT/"install.py", ROOT/".agent/scripts/agentctl.py", ROOT/".agent/scripts/workflowctl.py",
            ROOT/".agent/scripts/deliveryctl.py", ROOT/".agent/scripts/knowledgectl.py", ROOT/".agent/scripts/templatectl.py",
            ROOT/".agent/scripts/humandecision.py", ROOT/".agent/scripts/artifactctl.py", ROOT/".agent/scripts/providerctl.py",
            ROOT/".agent/scripts/contexttx.py", ROOT/".agent/skills/manage-agent-team/scripts/agentledger.py",
        ]
        for path in production:
            with self.subTest(path=path):
                source=path.read_text(encoding="utf-8")
                self.assertNotIn("subprocess.run(",source)
                self.assertNotIn(".communicate(",source)
        installer=(ROOT/"install.py").read_text(encoding="utf-8")
        self.assertNotIn("rglob(",installer)
        self.assertIn("bounded_tree_entries",installer)
        self.assertIn("run_installer_command",installer)
        workflow=(ROOT/".agent/scripts/workflowctl.py").read_text(encoding="utf-8")
        self.assertIn("run_bounded_command",workflow)
        observer=(ROOT/".agent/scripts/process_observation.py").read_text(encoding="utf-8")
        self.assertIn("bounded_trusted_command_output",observer)
        github=(ROOT/".agent/assets/templates/ci-cd/github-ci.yml.tmpl").read_text(encoding="utf-8")
        self.assertNotIn("rglob(",github)
        self.assertNotIn("archive.read_bytes()",github)
        self.assertIn("os.scandir",github)
        validator=(ROOT/".agent/skills/run-full-chain-acceptance/scripts/validate_acceptance_report.py").read_text(encoding="utf-8")
        self.assertNotIn("rglob(",validator)
        self.assertIn("MAX_SCOPE_ENTRIES",validator)
        runtime=(ROOT/".agent/skills/run-full-chain-acceptance/scripts/run_acceptance_runtime.py").read_text(encoding="utf-8")
        self.assertIn('"--volumes"',runtime)
        self.assertIn('"volume","ls"',runtime)
        self.assertIn('"image","rm"',runtime)


if __name__ == "__main__":
    unittest.main(verbosity=2, failfast=True)
