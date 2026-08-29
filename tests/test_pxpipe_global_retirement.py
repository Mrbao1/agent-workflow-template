#!/usr/bin/env python3
"""Focused isolated-home regressions for global pxpipe retirement."""

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workflow_installer", ROOT / "install.py")
INSTALLER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(INSTALLER)


class GlobalPxpipeRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pxpipe-retirement-focused-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"; self.home.mkdir(mode=0o700)
        self.old_home = os.environ.get("HOME"); os.environ["HOME"] = str(self.home)
        self.old_observer = INSTALLER._observe_pxpipe_service_absence
        INSTALLER._observe_pxpipe_service_absence = lambda _port: True

    def tearDown(self):
        INSTALLER._observe_pxpipe_service_absence = self.old_observer
        if self.old_home is None: os.environ.pop("HOME", None)
        else: os.environ["HOME"] = self.old_home
        self.temporary.cleanup()

    def project(self, name="project"):
        target = self.root / name
        plugin = target / "plugins/pxpipe-context/scripts"
        evidence = target / ".agent/state/evidence"
        plugin.mkdir(parents=True); evidence.mkdir(parents=True)
        files = {}
        for helper in INSTALLER.GLOBAL_PXPIPE_HELPERS:
            source = ROOT / "plugins/pxpipe-context" / helper
            destination = target / "plugins/pxpipe-context" / helper
            shutil.copy2(source, destination)
            files[helper] = hashlib.sha256(destination.read_bytes()).hexdigest()
        extra = target / "plugins/pxpipe-context/legacy.js"
        extra.write_bytes(b"legacy\n"); files["legacy.js"] = hashlib.sha256(extra.read_bytes()).hexdigest()
        manifest = target / ".agent/.workflow-manifest.json"
        installed=INSTALLER.install_manifest({}, {}, files, "3"*64, "verified", "4"*64, "5"*64)
        manifest.write_text(json.dumps(installed,sort_keys=True,separators=(",",":")) + "\n", encoding="utf-8")
        return target, manifest, files, installed

    def test_prepared_intent_survives_crash_then_converges_before_plugin_deletion(self):
        target, manifest, files, installed = self.project()
        original = INSTALLER._private_json
        def crash_after_prepared(path, value, create=False):
            original(path, value, create=create)
            if value.get("schema") == "agent-global-pxpipe-retirement-intent/v1":
                raise RuntimeError("injected crash after durable prepare")
        INSTALLER._private_json = crash_after_prepared
        try:
            with self.assertRaisesRegex(RuntimeError, "injected crash"):
                INSTALLER.ensure_global_pxpipe_retired(target, manifest, installed, files)
        finally:
            INSTALLER._private_json = original
        self.assertTrue((target / INSTALLER.GLOBAL_PXPIPE_INTENT_RELATIVE).is_file())
        self.assertTrue((target / "plugins/pxpipe-context").is_dir())
        receipt = INSTALLER.ensure_global_pxpipe_retired(target, manifest, installed, files)
        self.assertEqual(receipt["schema"], "agent-global-pxpipe-retirement-receipt/v1")
        self.assertTrue(receipt["terminal"])
        self.assertFalse((target / INSTALLER.GLOBAL_PXPIPE_INTENT_RELATIVE).exists())
        self.assertTrue(all(value == {"kind": "absent"} for value in receipt["post_state"].values()))

    def test_incomplete_global_artifact_set_fails_closed(self):
        target, manifest, files, installed = self.project("incomplete")
        state = self.home / ".pxpipe"; state.mkdir(mode=0o700)
        (state / "codex-default.json").write_text("{}\n", encoding="utf-8")
        os.chmod(state / "codex-default.json", 0o600)
        with self.assertRaisesRegex(RuntimeError, "missing a required authenticated artifact"):
            INSTALLER.ensure_global_pxpipe_retired(target, manifest, installed, files)
        self.assertFalse((target / INSTALLER.GLOBAL_PXPIPE_INTENT_RELATIVE).exists())
        self.assertFalse((target / INSTALLER.GLOBAL_PXPIPE_RECEIPT_RELATIVE).exists())
        self.assertTrue((target / "plugins/pxpipe-context").is_dir())


    def test_missing_v5_installation_anchor_fails_before_global_or_project_mutation(self):
        target, manifest, files, _installed = self.project("missing-v5-anchor")
        legacy={"schema":"agent-workflow-install/v4","migration_version":41,"repo_plugin_files":files}
        manifest.write_text(json.dumps(legacy,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError,"exact released v3/v4/v5 ownership anchor"):
            INSTALLER.ensure_global_pxpipe_retired(target,manifest,legacy,files)
        self.assertFalse((target/INSTALLER.GLOBAL_PXPIPE_INTENT_RELATIVE).exists())
        self.assertTrue((target/"plugins/pxpipe-context").is_dir())


    def test_malformed_prepared_intent_and_missing_helper_fail_closed(self):
        target, manifest, files, installed = self.project("malformed")
        intent = target / INSTALLER.GLOBAL_PXPIPE_INTENT_RELATIVE
        intent.write_text("{}\n", encoding="utf-8"); os.chmod(intent, 0o600)
        with self.assertRaisesRegex(RuntimeError, "invalid agent-global-pxpipe-retirement-intent/v1"):
            INSTALLER.ensure_global_pxpipe_retired(target, manifest, installed, files)
        self.assertTrue((target / "plugins/pxpipe-context").is_dir())

        other, other_manifest, other_files, other_installed = self.project("missing-helper")
        (other / "plugins/pxpipe-context/scripts/uninstall-codex-default.sh").unlink()
        with self.assertRaisesRegex(RuntimeError, "helper drift"):
            INSTALLER.ensure_global_pxpipe_retired(other, other_manifest, other_installed, other_files)
        self.assertFalse((other / INSTALLER.GLOBAL_PXPIPE_INTENT_RELATIVE).exists())
        self.assertTrue((other / "plugins/pxpipe-context").is_dir())

    def test_terminal_receipt_fails_if_listener_absence_no_longer_observed(self):
        target, manifest, files, installed = self.project("listener")
        INSTALLER.ensure_global_pxpipe_retired(target, manifest, installed, files)
        INSTALLER._observe_pxpipe_service_absence = lambda _port: False
        with self.assertRaisesRegex(RuntimeError, "no longer verifies terminal state"):
            INSTALLER.ensure_global_pxpipe_retired(target, manifest, installed, files)
        self.assertTrue((target / "plugins/pxpipe-context").is_dir())


    def test_complete_live_set_invokes_only_manifest_pinned_uninstaller(self):
        target, manifest, files, installed = self.project("live")
        paths = INSTALLER._global_pxpipe_paths(); original=b"# original Codex config\r\nmodel = \"careful\"\r\n"; managed=b"# pxpipe managed config\n"
        paths["ownership"].parent.mkdir(mode=0o700,parents=True,exist_ok=True); paths["ownership"].parent.chmod(0o700)
        for name in ("codex_config","config_backup","dashboard_token","ownership","plist","prior_absent"):
            paths[name].parent.mkdir(parents=True,exist_ok=True)
            paths[name].write_bytes(managed if name=="codex_config" else original if name=="config_backup" else (name+"\n").encode()); os.chmod(paths[name],0o600)
        state={"schema":"pxpipe-codex-default/v2","config":str(paths["codex_config"].resolve()),
               "backup":str(paths["config_backup"].resolve()),"configExisted":True,
               "beforeSha256":hashlib.sha256(original).hexdigest(),"managedSha256":hashlib.sha256(managed).hexdigest(),
               "providerName":"pxpipe","baseUrl":"http://127.0.0.1:47821/v1"}
        paths["config_state"].write_text(json.dumps(state,sort_keys=True)+"\n",encoding="utf-8"); os.chmod(paths["config_state"],0o600)
        calls = []
        original_run = INSTALLER.run_installer_command
        def pinned_run(command, **kwargs):
            helper=Path(command[0]); calls.append({
                "name":helper.name,"sha256":hashlib.sha256(helper.read_bytes()).hexdigest(),
                "mode":os.stat(helper).st_mode & 0o777,"inside_project":target.resolve() in helper.resolve().parents,
            })
            for name,artifact in paths.items():
                if name!="codex_config" and artifact.exists(): artifact.unlink()
            paths["codex_config"].write_bytes(original); os.chmod(paths["codex_config"],0o600)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        INSTALLER.run_installer_command = pinned_run
        try:
            receipt = INSTALLER.ensure_global_pxpipe_retired(target, manifest, installed, files)
        finally:
            INSTALLER.run_installer_command = original_run
        self.assertEqual(calls, [{
            "name":"uninstall-codex-default.sh",
            "sha256":files["scripts/uninstall-codex-default.sh"],
            "mode":0o500,"inside_project":False,
        }])
        self.assertTrue(receipt["terminal"])
        self.assertEqual(paths["codex_config"].read_bytes(),original)
        self.assertEqual(receipt["expected_codex_config"],{"kind":"present","bytes":len(original),"mode":0o600,"sha256":hashlib.sha256(original).hexdigest()})
        self.assertEqual(receipt["post_state"]["codex_config"]["sha256"],hashlib.sha256(original).hexdigest())

    def test_unrelated_codex_config_is_preserved_without_invoking_pxpipe_helper(self):
        target,manifest,files,installed=self.project("unrelated-config")
        config=INSTALLER._global_pxpipe_paths()["codex_config"]; config.parent.mkdir(parents=True); original=b"# unrelated user config\r\n"
        config.write_bytes(original); config.chmod(0o600)
        original_run=INSTALLER.run_installer_command
        INSTALLER.run_installer_command=lambda *_args,**_kwargs: (_ for _ in ()).throw(AssertionError("uninstaller invoked"))
        try: receipt=INSTALLER.ensure_global_pxpipe_retired(target,manifest,installed,files)
        finally: INSTALLER.run_installer_command=original_run
        self.assertEqual(config.read_bytes(),original)
        self.assertEqual(receipt["expected_codex_config"]["sha256"],hashlib.sha256(original).hexdigest())
        self.assertEqual(receipt["post_state"]["codex_config"]["sha256"],hashlib.sha256(original).hexdigest())
        self.assertEqual(receipt["listener_port"],47821)

    def test_markerless_pxpipe_config_is_unknown_not_terminal(self):
        target,manifest,files,installed=self.project("markerless-stale-config")
        config=INSTALLER._global_pxpipe_paths()["codex_config"]; config.parent.mkdir(parents=True)
        original=b'[model_providers.pxpipe]\nbase_url = "http://127.0.0.1:47821/v1"\n'
        config.write_bytes(original); config.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError,"still references pxpipe"):
            INSTALLER.ensure_global_pxpipe_retired(target,manifest,installed,files)
        self.assertEqual(config.read_bytes(),original)


    def test_symlinked_global_state_root_is_rejected_without_escape(self):
        outside=self.root/"outside"; outside.mkdir(mode=0o700)
        (self.home/".pxpipe").symlink_to(outside,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,"lock root is unsafe"):
            with INSTALLER.global_pxpipe_retirement_lock(): pass
        self.assertFalse((outside/".agent-workflow-retirement.lock").exists())

    def test_global_artifact_leaf_swap_is_detected(self):
        state=self.home/".pxpipe"; state.mkdir(mode=0o700)
        artifact=state/"dashboard-token"; artifact.write_bytes(b"original"); artifact.chmod(0o600)
        replacement=state/"replacement"; replacement.write_bytes(b"replacement"); replacement.chmod(0o600)
        real_stat=INSTALLER.os.stat; calls=0
        def swap_on_rebind(name,*args,**kwargs):
            nonlocal calls
            if name==artifact.name and kwargs.get("dir_fd") is not None:
                calls+=1
                if calls==2:
                    artifact.rename(state/"moved-original"); replacement.rename(artifact)
            return real_stat(name,*args,**kwargs)
        INSTALLER.os.stat=swap_on_rebind
        try:
            with self.assertRaisesRegex(RuntimeError,"pathname changed"):
                INSTALLER._secure_global_file(artifact)
        finally: INSTALLER.os.stat=real_stat
        self.assertEqual((state/"moved-original").read_bytes(),b"original")
        self.assertEqual(artifact.read_bytes(),b"replacement")


if __name__ == "__main__":
    unittest.main()
