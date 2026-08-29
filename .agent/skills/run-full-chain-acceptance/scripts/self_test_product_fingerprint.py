#!/usr/bin/env python3
"""Disposable positive/adversarial fixtures for fail-closed product discovery."""

from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile


TESTRUN = Path(__file__).resolve().parents[3] / "scripts" / "testrun.py"


def write(path: Path, text: str = "fixture\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fixture(root: Path, configured=None, product_roots=None) -> None:
    write(root / ".agent/state/TASK.json", "{}\n")
    value = {
        "scope": {
            "fingerprint_paths": configured or ["governed.txt"],
            "product_roots": product_roots or ["product"],
        }
    }
    write(root / ".agent/config.json", json.dumps(value) + "\n")
    write(root / "governed.txt")


def probe(root: Path):
    return subprocess.run(
        [sys.executable, str(TESTRUN)], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )


def require_discovered(root: Path, label: str) -> None:
    result = probe(root)
    if result.returncode == 0 or "test --receipt and command are required" not in result.stdout:
        raise AssertionError(f"{label} was not discovered successfully: {result.stdout}")


def require_failed(root: Path, needle: str, label: str) -> None:
    result = probe(root)
    if result.returncode == 0 or needle not in result.stdout:
        raise AssertionError(f"{label} did not fail closed with {needle!r}: {result.stdout}")


def require_stale_receipt_rejected(root: Path) -> None:
    config = {
        "scope": {"fingerprint_paths": ["governed.txt"], "product_roots": ["product"]},
        "routing": {"modes": {"release": {"wall_time_minutes": 45, "max_automatic_test_attempts": 1}}},
        "testing": {
            "max_automatic_full_chain_attempts": 1,
            "infrastructure_failure_consumes_code_retry": False,
            "attempt_classes": ["candidate", "test", "infrastructure"],
            "budget_registry": ".agent/state/test-budget.json",
            "budget_receipt_dir": ".agent/state/test-budget-receipts",
        },
    }
    write(root / ".agent/config.json", json.dumps(config) + "\n")
    write(root / ".agent/state/TASK.json", '{"mode":"release"}\n')
    write(root / "governed.txt", "candidate-a\n")
    write(root / "product/bin/tool.py", "print('ok')\n")
    local_runner = root / ".agent/scripts/testrun.py"
    local_runner.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(TESTRUN, local_runner)
    shutil.copy2(TESTRUN.with_name("humandecision.py"), local_runner.with_name("humandecision.py"))
    shutil.copy2(TESTRUN.with_name("process_observation.py"),local_runner.with_name("process_observation.py"))
    shutil.copytree(TESTRUN.parent/"workflowlib",local_runner.parent/"workflowlib")
    command = [
        sys.executable, str(local_runner), "--receipt", "receipt.json", "--run-id", "1" * 32,
        "--case", "case-a", "--timeout", "2", "--", "/usr/bin/true",
    ]
    first = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=20)
    if first.returncode:
        raise AssertionError(f"initial candidate receipt failed: {first.stdout}")
    write(root / "governed.txt", "candidate-b\n")
    second = subprocess.run(
        [*command[:7], "case-b", *command[8:]], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    if second.returncode == 0 or "stale candidate" not in second.stdout:
        raise AssertionError(f"candidate-A receipt accepted a candidate-B case: {second.stdout}")


def main() -> int:
    layouts = {
        "swift-package": {
            "Package.swift": "// swift-tools-version: 5.9\n",
            "Sources/App/main.swift": "print(\"ok\")\n",
        },
        "ios-xcode": {
            "Wish.xcodeproj/project.pbxproj": "// fixture\n",
            "Wish/AppDelegate.swift": "final class AppDelegate {}\n",
        },
        "android": {
            "settings.gradle.kts": 'rootProject.name = "Fixture"\n',
            "app/src/main/java/example/MainActivity.kt": "class MainActivity\n",
        },
        "web": {
            "package.json": '{"scripts":{"test":"node tests/test.mjs"}}\n',
            "src/index.ts": "export const ok = true\n",
        },
        "api": {
            "pyproject.toml": "[project]\nname='fixture'\nversion='0'\n",
            "api/main.py": "def health(): return 'ok'\n",
        },
        "cli-common": {
            "bin/tool.py": "print('ok')\n",
        },
    }
    with tempfile.TemporaryDirectory(prefix="product-fingerprint-") as raw:
        base = Path(raw)
        for label, files in layouts.items():
            root = base / label
            fixture(root)
            for relative, content in files.items():
                write(root / "product" / relative, content)
            require_discovered(root, label)

        custom = base / "custom-layout"
        fixture(custom, configured=["governed.txt", "custom/product.odd"])
        write(custom / "custom/product.odd")
        (custom / "product").mkdir(parents=True)
        require_discovered(custom, "explicit custom source")
        (custom / "custom/product.odd").unlink()
        require_failed(custom, "configured fingerprint path is missing", "disappeared custom source")

        empty_manifest = base / "manifest-without-source"
        fixture(empty_manifest)
        write(empty_manifest / "product/Package.swift", "// swift-tools-version: 5.9\n")
        require_failed(empty_manifest, "product manifest has no discoverable product-owned source", "manifest source loss")

        missing = base / "missing-configured"
        fixture(missing, configured=["missing.txt"])
        (missing / "product").mkdir(parents=True)
        require_failed(missing, "configured fingerprint path is missing", "missing configured path")

        unsafe_source = base / "unsafe-source-root"
        fixture(unsafe_source)
        write(unsafe_source / "outside.py")
        (unsafe_source / "product/src").mkdir(parents=True)
        (unsafe_source / "product/src/linked.py").symlink_to(unsafe_source / "outside.py")
        require_failed(unsafe_source, "product discovery contains a symlink", "symlink product source root")

        configured_ancestor = base / "configured-symlink-ancestor"
        fixture(configured_ancestor, configured=["alias/governed.txt"])
        write(configured_ancestor / "real/governed.txt")
        (configured_ancestor / "alias").symlink_to(configured_ancestor / "real", target_is_directory=True)
        (configured_ancestor / "product").mkdir(parents=True)
        require_failed(configured_ancestor, "configured fingerprint path has a symlink component", "configured symlink ancestor")

        product_ancestor = base / "product-symlink-ancestor"
        fixture(product_ancestor, product_roots=["alias/product"])
        write(product_ancestor / "real/product/bin/tool.py", "print('ok')\n")
        (product_ancestor / "alias").symlink_to(product_ancestor / "real", target_is_directory=True)
        require_failed(product_ancestor, "configured product root has a symlink component", "product-root symlink ancestor")

        discovered_alias = base / "discovered-symlink"
        fixture(discovered_alias)
        write(discovered_alias / "outside.py")
        (discovered_alias / "product").mkdir(parents=True)
        (discovered_alias / "product/alias.py").symlink_to(discovered_alias / "outside.py")
        require_failed(discovered_alias, "product discovery contains a symlink", "discovered symlink")

        stale_receipt = base / "stale-integrator-receipt"
        fixture(stale_receipt)
        require_stale_receipt_rejected(stale_receipt)

    print(f"PASS: {len(layouts)} product layouts, 7 scope attacks, and stale receipt replay")
    return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
