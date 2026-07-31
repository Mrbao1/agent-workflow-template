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
    if not any(item in {"--check","--update","--adopt"} for item in arguments) and "--human-decision-adapter" not in arguments:
        arguments.extend(["--human-decision-adapter","/usr/bin/true"])
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
    skill=source/PLUGIN/"skills/use-pxpipe-context/SKILL.md"
    skill.write_text(skill.read_text(encoding="utf-8")+f"\n<!-- lifecycle-{suffix} -->\n",encoding="utf-8")


def main():
    source=Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="plugin-install-lifecycle-") as raw:
        root=Path(raw); template=root/"template"; copy_source(source,template)
        fake_bin=root/"fake-bin"; fake_bin.mkdir()
        for name in ("codex","node"):
            executable=fake_bin/name
            executable.write_text("#!/bin/sh\nexit 99\n",encoding="utf-8"); executable.chmod(0o755)
        env=dict(os.environ); env["PATH"]=str(fake_bin)+os.pathsep+env.get("PATH","")
        installer=template/"install.py"

        # Installation is allowed before host integration. Bootstrap and start
        # may enter a bounded, unapproved clarification draft, but the missing
        # provider adapter must remain an explicit execution/approval block.
        unconfigured=root/"unconfigured"
        installed=subprocess.run(
            [sys.executable,str(installer),str(unconfigured),"--project-name","fixture"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        bootstrap=subprocess.run(
            [sys.executable,".agent/scripts/agentctl.py","bootstrap-check"],cwd=unconfigured,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,env=env,
        )
        blocked_start=subprocess.run(
            [sys.executable,".agent/scripts/agentctl.py","start","--title","clarification-only"],cwd=unconfigured,
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
            or bootstrap.returncode==0 or blocked_start.returncode!=0
            or blocked_execution.returncode==0 or execution_sentinel.exists()
            or "local execution is blocked" not in blocked_execution.stdout
            or blocked_approval.returncode==0
            or blocked_route.returncode==0 or "requirements must be clarified and human-approved" not in blocked_route.stdout
            or blocked_advance.returncode==0 or "blocked until requirements are clarified" not in blocked_advance.stdout
            or blocked_delivery.returncode==0 or "delivery is blocked until requirements are clarified" not in blocked_delivery.stdout
            or clean.returncode!=0
            or "BOOTSTRAP NOT READY" not in bootstrap.stdout
            or clarification.get("status")!="waiting_human"
            or clarification.get("phase")!="clarification"
            or clarification.get("current_node")!=1
            or clarification.get("requirements_clarified") is not False
        ):
            raise SystemExit("unconfigured fresh install did not remain bounded inside clarification")

        # Fresh install binds Agent state plus canonical plugin expectations
        # without invoking Codex/Node or copying the global plugin into a project.
        target=root/"fresh"
        target.mkdir(); (target/"AGENTS.md").write_text("# Project-owned instructions\n\nKeep this block.\n",encoding="utf-8")
        run(installer,target,"--project-name","fixture",env=env)
        manifest=json.loads((target/".agent/.workflow-manifest.json").read_text(encoding="utf-8"))
        if (
            manifest.get("schema")!="agent-workflow-install/v4"
            or manifest.get("version")!="3.1.46"
            or manifest.get("migration_version")!=38
            or not isinstance(manifest.get("agent_files"),dict)
            or not isinstance(manifest.get("repo_plugin_files"),dict)
            or manifest.get("marketplace_entry",{}).get("name")!="pxpipe-context"
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
        run(installer,marker_crash,"--check",expected=1,env=env)
        if marker_journal.exists() or any(
            item.name.startswith(f".{marker_crash.name}.agent-workflow-txn-") for item in marker_crash.parent.iterdir()
        ):
            raise SystemExit("pre-marker crash recovery left a journal or staging tree")
        run(installer,marker_crash,"--project-name","fixture",env=env)

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
        run(installer,directory_crash,"--check",expected=1,env=env)
        if directory_crash.exists() or directory_journal.exists() or any(
            item.name.startswith(f".{directory_crash.name}.agent-workflow-txn-") for item in directory_crash.parent.iterdir()
        ):
            raise SystemExit("partial-directory recovery did not restore exact target absence")
        run(installer,directory_crash,"--project-name","fixture",env=env)

        # Project plugin/marketplace paths are outside workflow ownership. A
        # canonical plugin update changes only the expected hashes in .agent.
        project_plugin=target/PLUGIN; project_plugin.mkdir(parents=True)
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
            "schema":"agent-workflow-install/v1","version":"3.1.26","migration_version":23,
            "source_tree_sha256":hashlib.sha256(json.dumps(agent_files,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            "files":agent_files,
        }
        (legacy/".agent/.workflow-manifest.json").write_text(json.dumps(legacy_manifest,indent=2)+"\n",encoding="utf-8")
        run(installer,legacy,"--update",env=env)
        if json.loads((legacy/".agent/.workflow-manifest.json").read_text())["schema"]!="agent-workflow-install/v4":
            raise SystemExit("v1 manifest was not migrated to v4")

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
        run(installer,adopted,"--adopt",env=env)
        if tree(adopted/MARKET)!=adopted_market_before or (adopted/PLUGIN).exists():
            raise SystemExit("adopt changed project plugin or marketplace surfaces")

        # A commit failure after the Agent swap restores Agent and AGENTS byte-for-byte.
        rollback=root/"rollback"
        run(installer,rollback,"--project-name","fixture",env=env)
        (rollback/"AGENTS.md").unlink()
        mutate_source(template,"rollback")
        template_market=json.loads((template/MARKET).read_text(encoding="utf-8"))
        next(item for item in template_market["plugins"] if item["name"]=="pxpipe-context")["category"]="Context"
        (template/MARKET).write_text(json.dumps(template_market,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        before=(tree(rollback/".agent"),tree(rollback/PLUGIN),tree(rollback/MARKET),tree(rollback/"AGENTS.md"),tree(rollback/"CLAUDE.md"))
        spec=importlib.util.spec_from_file_location("transactional_installer",installer)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        real_replace=module.os.replace; fail_target=(rollback/"AGENTS.md").resolve()
        failed=[False]
        def failing_replace(source_path,target_path):
            if Path(target_path).resolve()==fail_target and not failed[0]:
                failed[0]=True; raise OSError("injected AGENTS bootstrap commit failure")
            return real_replace(source_path,target_path)
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
        run(installer,crash,"--check",expected=1,env=env)
        recovered=(tree(crash/".agent"),tree(crash/PLUGIN),tree(crash/MARKET),tree(crash/"AGENTS.md"),tree(crash/"CLAUDE.md"))
        if recovered!=predecessor:
            raise SystemExit("hard-crash recovery did not restore the exact predecessor before planning")
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
        run(installer,crash,"--check",env=env)
        if (
            committed_tree!=(tree(crash/".agent"),tree(crash/PLUGIN),tree(crash/MARKET),tree(crash/"AGENTS.md"),tree(crash/"CLAUDE.md"))
            or journal.exists()
            or any(item.name.startswith(f".{crash.name}.agent-workflow-txn-") for item in crash.parent.iterdir())
        ):
            raise SystemExit("committed transaction recovery did not roll forward cleanup safely")

        # Runtime-integrity failure is rejected before a fresh target is modified.
        corrupt=root/"corrupt"; copy_source(source,corrupt)
        runtime=corrupt/PLUGIN/"mcp/vendor/pxpipe-runtime.mjs"
        runtime.write_bytes(runtime.read_bytes()+b"\n// corrupt\n")
        rejected=root/"rejected"
        output=run(corrupt/"install.py",rejected,"--project-name","fixture",expected=1,env=env)
        if "runtime SHA-256" not in output or (rejected/".agent").exists() or (rejected/PLUGIN).exists() or (rejected/MARKET).exists():
            raise SystemExit("invalid runtime was not rejected transactionally")

    print("PLUGIN INSTALL LIFECYCLE OK")
    return 0


if __name__=="__main__": raise SystemExit(main())
