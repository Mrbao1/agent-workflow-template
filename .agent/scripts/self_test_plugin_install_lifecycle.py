#!/usr/bin/env python3
"""Targeted repo-plugin install/update/adopt transaction tests."""

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile


PLUGIN=Path("plugins/pxpipe-context")
MARKET=Path(".agents/plugins/marketplace.json")


def run(installer,target,*args,expected=0,env=None):
    arguments=list(args)
    result=subprocess.run(
        [sys.executable,str(installer),str(target),*arguments],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
    )
    if result.returncode!=expected:
        raise SystemExit(f"unexpected exit {result.returncode}, expected {expected}:\n{result.stdout}")
    return result.stdout


def copy_source(source,destination):
    destination.mkdir(parents=True)
    shutil.copy2(source/"install.py",destination/"install.py")
    shutil.copy2(source/"AGENTS.md",destination/"AGENTS.md")
    shutil.copy2(source/"CLAUDE.md",destination/"CLAUDE.md")
    shutil.copytree(source/".agent",destination/".agent")
    shutil.copytree(source/"plugins",destination/"plugins")
    shutil.copytree(source/".agents",destination/".agents")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(path):
    if not path.exists(): return None
    if path.is_file(): return digest(path)
    return {str(item.relative_to(path)):digest(item) for item in sorted(path.rglob("*")) if item.is_file()}


def add_other_marketplace_entry(path):
    value=json.loads(path.read_text(encoding="utf-8"))
    value["plugins"].append({
        "name":"project-owned-plugin",
        "source":{"source":"local","path":"./plugins/project-owned-plugin"},
        "policy":{"installation":"AVAILABLE","authentication":"ON_INSTALL"},
        "category":"Developer Tools",
    })
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")


def mutate_source(source,suffix):
    # Change a managed Agent file that is outside the fresh idle policy bundle;
    # quarantined pxpipe bytes are deliberately not an install/update surface.
    document=source/".agent/workflows/METHODOLOGY.md"
    document.write_text(document.read_text(encoding="utf-8")+f"\n<!-- lifecycle-{suffix} -->\n",encoding="utf-8")


def main():
    source=Path(__file__).resolve().parents[2]
    populated_quarantined_source=(source/PLUGIN/"integrity.json").is_file()
    with tempfile.TemporaryDirectory(prefix="plugin-install-lifecycle-") as raw:
        root=Path(raw); template=root/"template"; copy_source(source,template)
        fake_bin=root/"fake-bin"; fake_bin.mkdir()
        for name in ("codex","node"):
            executable=fake_bin/name
            executable.write_text("#!/bin/sh\nexit 99\n",encoding="utf-8"); executable.chmod(0o755)
        env=dict(os.environ); env["PATH"]=str(fake_bin)+os.pathsep+env.get("PATH","")
        installer=template/"install.py"
        spec=importlib.util.spec_from_file_location("transactional_installer",installer)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

        # Installation is allowed before host integration. Bootstrap and start
        # must remain idle until project initialization and explicit model selection;
        # provider authority and runtime baseline gates also fail closed.
        unconfigured=root/"unconfigured"
        installed=subprocess.run(
            [sys.executable,str(installer),str(unconfigured),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        if installed.returncode:
            raise AssertionError(f"unconfigured install failed: {installed.stdout}")
        bootstrap=subprocess.run(
            [sys.executable,".agent/scripts/agentctl.py","bootstrap-check"],cwd=unconfigured,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        blocked_start=subprocess.run(
            [sys.executable,".agent/scripts/agentctl.py","start","--model","provider-neutral/model.fixture","--title","clarification-only"],cwd=unconfigured,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        execution_sentinel=unconfigured/"execution-must-not-run"
        blocked_execution=subprocess.run(
            [
                sys.executable,".agent/scripts/agentctl.py","managed-run","--name","blocked",
                "--timeout","2","--",sys.executable,"-c",
                f"from pathlib import Path; Path({str(execution_sentinel)!r}).write_text('ran')",
            ],cwd=unconfigured,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        blocked_approval=subprocess.run(
            [sys.executable,".agent/scripts/agentctl.py","approve-requirements","--source","user:test"],
            cwd=unconfigured,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        blocked_route=subprocess.run(
            [sys.executable,".agent/scripts/templatectl.py","route"],cwd=unconfigured,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        blocked_advance=subprocess.run(
            [sys.executable,".agent/scripts/workflowctl.py","advance","--node","2","--artifact","missing"],
            cwd=unconfigured,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        blocked_delivery=subprocess.run(
            [
                sys.executable,".agent/scripts/deliveryctl.py","record-artifact",
                "--path","missing","--digest","sha256:"+("0"*64),"--built-by","blocked",
                "--source-branch","test/blocked","--source-revision","0"*40,"--build-run-id","blocked-run",
            ],cwd=unconfigured,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        clean=subprocess.run(
            [sys.executable,".agent/scripts/agentctl.py","assert-clean"],cwd=unconfigured,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        clarification=json.loads((unconfigured/".agent/state/TASK.json").read_text(encoding="utf-8"))
        if (
            installed.returncode!=0 or "PROJECT INIT REQUIRED" not in installed.stdout
            or "BOOTSTRAP NOT READY" not in installed.stdout
            or bootstrap.returncode==0 or blocked_start.returncode==0
            or "project guardrails are incomplete" not in blocked_start.stdout
            or blocked_execution.returncode==0 or execution_sentinel.exists()
            or "local execution is blocked" not in blocked_execution.stdout
            or blocked_approval.returncode==0
            or blocked_route.returncode==0 or "requirements must be clarified and human-approved" not in blocked_route.stdout
            or blocked_advance.returncode==0 or "blocked until requirements are clarified" not in blocked_advance.stdout
            or blocked_delivery.returncode==0 or "delivery is blocked until requirements are clarified" not in blocked_delivery.stdout
            or clean.returncode==0 or "runtime lacks a v2 project-process baseline" not in clean.stdout
            or "BOOTSTRAP NOT READY" not in bootstrap.stdout
            or clarification.get("status")!="idle"
            or clarification.get("phase")!="idle"
            or clarification.get("current_node")!="idle"
            or clarification.get("requirements_clarified") is not False
        ):
            diagnostic = {
                "installed": [installed.returncode, installed.stdout],
                "bootstrap": [bootstrap.returncode, bootstrap.stdout],
                "blocked_start": [blocked_start.returncode, blocked_start.stdout],
                "blocked_execution": [blocked_execution.returncode, blocked_execution.stdout],
                "blocked_approval": [blocked_approval.returncode, blocked_approval.stdout],
                "blocked_route": [blocked_route.returncode, blocked_route.stdout],
                "blocked_advance": [blocked_advance.returncode, blocked_advance.stdout],
                "blocked_delivery": [blocked_delivery.returncode, blocked_delivery.stdout],
                "clean": [clean.returncode, clean.stdout],
                "task": clarification,
            }
            raise SystemExit("unconfigured fresh install did not remain safely idle:" + chr(10) + json.dumps(diagnostic, ensure_ascii=False, indent=2))

        # Fresh install binds Agent state plus canonical plugin expectations
        # without invoking Codex/Node or copying the global plugin into a project.
        target=root/"fresh"
        target.mkdir(); (target/"AGENTS.md").write_text("# Project-owned instructions\n\nKeep this block.\n",encoding="utf-8")
        run(installer,target,"--project-name","fixture",env=env)
        manifest=json.loads((target/".agent/.workflow-manifest.json").read_text(encoding="utf-8"))
        if (
            manifest.get("schema")!="agent-workflow-install/v5"
            or manifest.get("version")!="4.0.0"
            or manifest.get("migration_version")!=42
            or not isinstance(manifest.get("agent_files"),dict)
            or manifest.get("pxpipe")!={
                "name":"pxpipe-context", "provenance_status":"disabled",
                "files":{}, "marketplace_entry_sha256":None,
            }
            or manifest.get("agents_bootstrap",{}).get("path")!="AGENTS.md"
            or manifest.get("claude_bootstrap",{}).get("path")!="CLAUDE.md"
            or (target/PLUGIN).exists()
            or (target/MARKET).exists()
            or "Keep this block." not in (target/"AGENTS.md").read_text(encoding="utf-8")
            or (target/"AGENTS.md").read_text(encoding="utf-8").count("<!-- agent-workflow-bootstrap:start -->")!=1
            or (target/"CLAUDE.md").read_text(encoding="utf-8").count("<!-- agent-workflow-bootstrap:start -->")!=1
        ): raise SystemExit("fresh install did not bind Agent state and canonical plugin expectations")
        run(installer,target,"--check",env=env)

        # A hard death while the staging marker is still a private temporary
        # must not strand the installer or touch any managed project surface.
        marker_crash=root/"marker-crash"
        marker_env=dict(env); marker_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_DURING_MARKER"]="1"
        killed_marker=subprocess.run(
            [sys.executable,str(installer),str(marker_crash),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=marker_env,
        )
        marker_journal=marker_crash.parent/f".{marker_crash.name}.agent-workflow-transaction.json"
        if killed_marker.returncode!=96 or not marker_journal.is_file() or (marker_crash/".agent").exists():
            raise SystemExit("pre-marker crash fixture did not leave only a recoverable initialization journal")
        run(installer,marker_crash,"--check",expected=2,env=env)
        if not marker_journal.is_file() or (marker_crash/".agent").exists():
            raise SystemExit("read-only check mutated a pre-marker recovery journal")
        run(installer,marker_crash,"--project-name","fixture",env=env)
        if marker_journal.exists() or any(
            item.name.startswith(f".{marker_crash.name}.agent-workflow-txn-") for item in marker_crash.parent.iterdir()
        ):
            raise SystemExit("pre-marker mutator recovery left a journal or staging tree")

        # The committing journal is durable before its declared managed parent
        # directories are created.  One representative partial-directory
        # death must restore exact target absence, not strand recovery.
        directory_crash=root/"directory-crash"
        directory_env=dict(env); directory_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_DIRECTORY"]="1"
        killed_directory=subprocess.run(
            [sys.executable,str(installer),str(directory_crash),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=directory_env,
        )
        directory_journal=directory_crash.parent/f".{directory_crash.name}.agent-workflow-transaction.json"
        if killed_directory.returncode!=95 or not directory_journal.is_file():
            raise SystemExit("partial-directory crash fixture did not leave a recoverable commit journal")
        directory_crashed_tree=tree(directory_crash)
        run(installer,directory_crash,"--check",expected=2,env=env)
        if tree(directory_crash)!=directory_crashed_tree or not directory_journal.is_file():
            raise SystemExit("read-only check mutated a partial-directory recovery journal")
        run(installer,directory_crash,"--project-name","fixture",env=env)
        if directory_journal.exists() or not (directory_crash/".agent").is_dir() or any(
            item.name.startswith(f".{directory_crash.name}.agent-workflow-txn-") for item in directory_crash.parent.iterdir()
        ):
            raise SystemExit("partial-directory mutator recovery did not finish cleanly")

        # A same-name replacement of a v4-created directory is never removed
        # using a stale pathname during recovery.
        replaced=root/"directory-replaced"; replaced_env=dict(env)
        replaced_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_DIRECTORY"]="1"
        killed_replaced=subprocess.run([sys.executable,str(installer),str(replaced),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=replaced_env)
        replaced_journal=replaced.parent/f".{replaced.name}.agent-workflow-transaction.json"
        original_created=root/"directory-replaced-original"; replaced.rename(original_created); replaced.mkdir()
        (replaced/"attacker-sentinel").write_text("preserve\n",encoding="utf-8")
        replaced_before=tree(replaced)
        replaced_result=subprocess.run([sys.executable,str(installer),str(replaced),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env)
        if (killed_replaced.returncode!=95 or replaced_result.returncode==0
                or "created transaction directory was replaced" not in replaced_result.stdout
                or tree(replaced)!=replaced_before or not replaced_journal.is_file()):
            raise SystemExit("v4 created-directory replacement was mutated or accepted during rollback")

        # Legacy committing journals cannot identify created directory inodes;
        # they fail before rollback mutation instead of trusting pathnames.
        legacy_created=root/"legacy-created-directory"; legacy_env=dict(env)
        legacy_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_DIRECTORY"]="1"
        killed_legacy=subprocess.run([sys.executable,str(installer),str(legacy_created),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=legacy_env)
        legacy_journal=legacy_created.parent/f".{legacy_created.name}.agent-workflow-transaction.json"
        legacy_value=json.loads(legacy_journal.read_text(encoding="utf-8")); legacy_value["schema"]="agent-workflow-install-transaction/v2"
        legacy_value["created_directories"]=[item["path"] for item in legacy_value["created_directories"]]
        for operation in legacy_value["replacements"]:
            operation.pop("original_content_sha256",None); operation.pop("candidate_content_sha256",None)
            operation.pop("candidate_committed_sha256",None)
        legacy_value.pop("journal_sha256",None)
        legacy_value["journal_sha256"]=hashlib.sha256(json.dumps(legacy_value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        legacy_journal.write_text(json.dumps(legacy_value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        legacy_before=tree(legacy_created)
        legacy_result=subprocess.run([sys.executable,str(installer),str(legacy_created),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env)
        if (killed_legacy.returncode!=95 or legacy_result.returncode==0
                or "cannot safely roll back without full-tree content identities" not in legacy_result.stdout
                or tree(legacy_created)!=legacy_before or not legacy_journal.is_file()):
            raise SystemExit(f"legacy committing journal mutated unidentified created directories: killed={killed_legacy.returncode} result={legacy_result.returncode} output={legacy_result.stdout!r} before={legacy_before!r} after={tree(legacy_created)!r} journal={legacy_journal.is_file()}")

        # Unrelated project plugin/marketplace paths are outside workflow
        # ownership. The retired pxpipe-context namespace is reserved so an
        # unowned collision fails closed instead of being silently preserved.
        project_plugin=target/"plugins/project-owned-plugin"; project_plugin.mkdir(parents=True)
        (project_plugin/"project-owned.txt").write_text("preserve plugin path\n",encoding="utf-8")
        target_market={"name":"project-marketplace","plugins":[]}
        (target/MARKET).parent.mkdir(parents=True)
        (target/MARKET).write_text(json.dumps(target_market,indent=2)+"\n",encoding="utf-8")
        project_surfaces=(tree(project_plugin),tree(target/MARKET))
        mutate_source(template,"update")
        run(installer,target,"--update",env=env)
        if project_surfaces!=(tree(project_plugin),tree(target/MARKET)):
            raise SystemExit("workflow update changed project-owned plugin or marketplace paths")
        run(installer,target,"--check",env=env)

        # An old v1 manifest remains readable and migrates without project plugin surfaces.
        legacy=root/"legacy"
        run(installer,legacy,"--project-name","fixture",env=env)
        current=json.loads((legacy/".agent/.workflow-manifest.json").read_text(encoding="utf-8"))
        agent_files=current["agent_files"]
        legacy_manifest={
            "schema":"agent-workflow-install/v1","version":"3.1.40","migration_version":32,
            "source_tree_sha256":hashlib.sha256(json.dumps(agent_files,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            "files":agent_files,
        }
        (legacy/".agent/.workflow-manifest.json").write_text(json.dumps(legacy_manifest,indent=2)+"\n",encoding="utf-8")
        run(installer,legacy,"--update",env=env)
        if json.loads((legacy/".agent/.workflow-manifest.json").read_text())["schema"]!="agent-workflow-install/v5":
            raise SystemExit("v1 manifest was not migrated to provenance-aware v5")

        # Adopt records canonical plugin expectations but leaves a project
        # marketplace byte-for-byte untouched.  The repository's own live
        # state is intentionally stale between re-seals, so the adopted tree
        # seeds its private state from the canonical fresh-state seed instead
        # of copying that drift (adopt matches only the managed tree anyway).
        adopted=root/"adopted"; adopted.mkdir(); shutil.copytree(template/".agent",adopted/".agent")
        seed=template/".agent/assets/fresh-state/v1"
        shutil.rmtree(adopted/".agent/state"); shutil.rmtree(adopted/".agent/policies")
        shutil.copytree(seed/"state",adopted/".agent/state")
        shutil.copytree(seed/"policies",adopted/".agent/policies")
        shutil.copy2(seed/"config.json",adopted/".agent/config.json")
        (adopted/".agent/.workflow-manifest.json").unlink(missing_ok=True)
        adopted_market=json.loads((template/MARKET).read_text(encoding="utf-8")); adopted_market["plugins"]=[]
        (adopted/MARKET).parent.mkdir(parents=True); (adopted/MARKET).write_text(json.dumps(adopted_market,indent=2)+"\n",encoding="utf-8")
        add_other_marketplace_entry(adopted/MARKET)
        adopted_market_before=tree(adopted/MARKET)
        adopted_entries=module.files(template/".agent")
        module.apply_file_modes(adopted/".agent",module.portable_file_modes(template/".agent",adopted_entries))
        module.apply_managed_directory_modes(adopted/".agent")
        run(installer,adopted,"--adopt",env=env)
        if tree(adopted/MARKET)!=adopted_market_before or (adopted/PLUGIN).exists():
            raise SystemExit("adopt changed project plugin or marketplace surfaces")

        # A commit failure after the Agent swap restores Agent and AGENTS byte-for-byte.
        rollback=root/"rollback"
        run(installer,rollback,"--project-name","fixture",env=env)
        (rollback/"AGENTS.md").unlink()
        mutate_source(template,"rollback")
        template_market=json.loads((template/MARKET).read_text(encoding="utf-8"))
        if template_market.get("plugins") != []:
            raise SystemExit("quarantined template marketplace unexpectedly advertises pxpipe")
        before=(tree(rollback/".agent"),tree(rollback/PLUGIN),tree(rollback/MARKET),tree(rollback/"AGENTS.md"),tree(rollback/"CLAUDE.md"))
        real_replace=module.os.replace
        failed=[False]
        def failing_replace(source_path,target_path,**kwargs):
            if str(target_path)=="AGENTS.md" and kwargs.get("dst_dir_fd") is not None and not failed[0]:
                failed[0]=True; raise OSError("injected AGENTS bootstrap commit failure")
            return real_replace(source_path,target_path,**kwargs)
        module.os.replace=failing_replace; saved_argv=sys.argv
        try:
            sys.argv=[str(installer),str(rollback),"--update"]
            try: module.main()
            except OSError: pass
            else: raise SystemExit("transaction fault injection did not fail")
        finally:
            module.os.replace=real_replace; sys.argv=saved_argv
        after=(tree(rollback/".agent"),tree(rollback/PLUGIN),tree(rollback/MARKET),tree(rollback/"AGENTS.md"),tree(rollback/"CLAUDE.md"))
        if after!=before: raise SystemExit("failed update did not roll back Agent and AGENTS bootstrap")

        # Recovery preflights every operation before restoring any predecessor.
        rollback_tamper=root/"rollback-preflight-tamper"; run(installer,rollback_tamper,"--project-name","fixture",env=env)
        (rollback_tamper/"AGENTS.md").unlink()
        mutate_source(template,"rollback-preflight")
        tamper_env=dict(env); tamper_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET"]="2"
        tamper_crash=subprocess.run([sys.executable,str(installer),str(rollback_tamper),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=tamper_env)
        tamper_journal=rollback_tamper.parent/f".{rollback_tamper.name}.agent-workflow-transaction.json"
        tamper_value=json.loads(tamper_journal.read_text(encoding="utf-8")); installed_ops=[item for item in tamper_value["replacements"] if item["phase"]=="installed"]
        if tamper_crash.returncode!=97 or len(installed_ops)<2: raise SystemExit("rollback preflight fixture did not install two operations")
        labels={".agent":rollback_tamper/".agent","AGENTS.md":rollback_tamper/"AGENTS.md","CLAUDE.md":rollback_tamper/"CLAUDE.md",
                str(PLUGIN):rollback_tamper/PLUGIN,str(MARKET):rollback_tamper/MARKET}
        victim=labels[installed_ops[0]["label"]]; held=victim.with_name(victim.name+"-held"); victim.rename(held)
        if held.is_dir(): shutil.copytree(held,victim)
        else: shutil.copy2(held,victim)
        managed_paths=[path for path in labels.values() if path.exists()]
        preflight_before=(tuple((str(path.relative_to(rollback_tamper)),os.lstat(path).st_dev,os.lstat(path).st_ino) for path in managed_paths),tree(rollback_tamper))
        preflight_result=subprocess.run([sys.executable,str(installer),str(rollback_tamper),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env)
        preflight_after=(tuple((str(path.relative_to(rollback_tamper)),os.lstat(path).st_dev,os.lstat(path).st_ino) for path in managed_paths),tree(rollback_tamper))
        if preflight_result.returncode==0 or "transaction target" not in preflight_result.stdout or preflight_after!=preflight_before or not tamper_journal.is_file():
            raise SystemExit("rollback mutated an earlier operation before detecting a later identity mismatch")

        # A backup directory's unchanged root inode cannot hide modified descendants.
        backup_tamper=root/"backup-descendant-tamper"; run(installer,backup_tamper,"--project-name","fixture",env=env)
        mutate_source(template,"backup-descendant")
        backup_env=dict(env); backup_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET"]="1"
        backup_crash=subprocess.run([sys.executable,str(installer),str(backup_tamper),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=backup_env)
        backup_journal=backup_tamper.parent/f".{backup_tamper.name}.agent-workflow-transaction.json"
        backup_value=json.loads(backup_journal.read_text(encoding="utf-8")); backup_stage=backup_tamper.parent/f".{backup_tamper.name}.agent-workflow-txn-{backup_value['transaction_id']}"
        backup_file=backup_stage/"backups/0/scripts/agentctl.py"; backup_file.write_bytes(backup_file.read_bytes()+b"\n# tampered backup descendant\n")
        backup_before=(tree(backup_tamper),tree(backup_stage))
        backup_recovery=subprocess.run([sys.executable,str(installer),str(backup_tamper),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env)
        if (backup_crash.returncode!=97 or backup_recovery.returncode==0 or "predecessor content" not in backup_recovery.stdout
                or backup_before!=(tree(backup_tamper),tree(backup_stage)) or not backup_journal.is_file()):
            raise SystemExit("tampered backup descendants were restored or partially mutated")

        # A hard process death between target swaps leaves a durable journal.
        # The next installer invocation must recover the exact predecessor
        # before planning and then complete the update without losing project files.
        crash=root/"crash-recovery"
        run(installer,crash,"--project-name","fixture",env=env)
        project_note=crash/"project-owned.txt"; project_note.write_text("preserve me\n",encoding="utf-8")
        (crash/"AGENTS.md").unlink()
        predecessor=(tree(crash/".agent"),tree(crash/PLUGIN),tree(crash/MARKET),tree(crash/"AGENTS.md"),tree(crash/"CLAUDE.md"))
        mutate_source(template,"hard-crash")
        crash_env=dict(env); crash_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET"]="2"
        killed=subprocess.run(
            [sys.executable,str(installer),str(crash),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=crash_env,
        )
        journal=crash.parent/f".{crash.name}.agent-workflow-transaction.json"
        if killed.returncode!=97 or not journal.is_file():
            raise SystemExit(f"hard-crash fixture did not leave a recoverable journal: {killed.returncode}\n{killed.stdout}")
        crashed_tree=(tree(crash/".agent"),tree(crash/PLUGIN),tree(crash/MARKET),tree(crash/"AGENTS.md"),tree(crash/"CLAUDE.md"))
        run(installer,crash,"--check",expected=2,env=env)
        if crashed_tree!=(tree(crash/".agent"),tree(crash/PLUGIN),tree(crash/MARKET),tree(crash/"AGENTS.md"),tree(crash/"CLAUDE.md")) or not journal.is_file():
            raise SystemExit("read-only check mutated a hard-crash transaction")
        run(installer,crash,"--update",env=env)
        run(installer,crash,"--check",env=env)
        if (
            journal.exists()
            or project_note.read_text(encoding="utf-8")!="preserve me\n"
            or any(item.name.startswith(f".{crash.name}.agent-workflow-txn-") for item in crash.parent.iterdir())
        ):
            raise SystemExit("hard-crash recovery left a journal/staging tree or changed project-owned data")

        # A durable committed journal is authoritative: recovery only removes
        # its backups/staging and must retain the newly installed candidate.
        mutate_source(template,"committed-cleanup")
        committed_env=dict(env); committed_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_COMMIT"]="1"
        committed=subprocess.run(
            [sys.executable,str(installer),str(crash),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=committed_env,
        )
        if committed.returncode!=98 or not journal.is_file():
            raise SystemExit("committed-crash fixture did not preserve its cleanup journal")
        committed_tree=(tree(crash/".agent"),tree(crash/PLUGIN),tree(crash/MARKET),tree(crash/"AGENTS.md"),tree(crash/"CLAUDE.md"))
        run(installer,crash,"--check",expected=2,env=env)
        if committed_tree!=(tree(crash/".agent"),tree(crash/PLUGIN),tree(crash/MARKET),tree(crash/"AGENTS.md"),tree(crash/"CLAUDE.md")) or not journal.is_file():
            raise SystemExit("read-only check mutated a committed cleanup journal")
        run(installer,crash,"--update",env=env)
        run(installer,crash,"--check",env=env)
        if journal.exists() or any(item.name.startswith(f".{crash.name}.agent-workflow-txn-") for item in crash.parent.iterdir()):
            raise SystemExit("committed mutator recovery did not roll forward cleanup safely")

        # A quarantined source may not silently restore either opaque vendor
        # bundle, even though quarantined plugin files are never installed.
        corrupt=root/"corrupt"; copy_source(source,corrupt)
        runtime=corrupt/PLUGIN/"mcp/vendor/pxpipe-runtime.mjs"
        runtime.parent.mkdir(parents=True,exist_ok=True)
        runtime.write_text("// forbidden opaque runtime\n",encoding="utf-8")
        rejected=root/"rejected"
        output=run(corrupt/"install.py",rejected,"--project-name","fixture",expected=1,env=env)
        accepted_rejections=(("forbidden opaque vendor bundle",) if populated_quarantined_source else (
            "forbidden opaque vendor bundle",
            "candidate plugin metadata is missing or unsafe",
        ))
        if (not any(marker in output for marker in accepted_rejections)
                or (rejected/".agent").exists() or (rejected/PLUGIN).exists() or (rejected/MARKET).exists()):
            raise SystemExit(f"opaque runtime was not rejected transactionally: {output!r}")

    print("PLUGIN INSTALL LIFECYCLE OK")
    return 0


if __name__=="__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
