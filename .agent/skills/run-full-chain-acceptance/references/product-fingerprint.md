# Product Fingerprint Discovery

`testrun.py` is the canonical candidate-fingerprint implementation. Acceptance adapters import it, so preflight, integrator execution and read-only verification cannot disagree about candidate bytes.

`scope.fingerprint_paths` is a non-empty list of explicit governed paths. Every listed file or directory must exist, remain inside the project, contain a real file when it is a directory, and contain no symlink. These entries are promises, not optional layout guesses; a missing configured path fails before a test launches.

`scope.product_roots` optionally lists explicit product roots and defaults to `["."]`. Every root must be an existing in-project directory. Discovery includes:

- iOS/Xcode (`*.xcodeproj/project.pbxproj` and Objective-C/Swift/C-family source);
- Swift Package (`Package.swift`, `Sources`, `Tests`);
- Android/Gradle (`settings.gradle[.kts]`, `build.gradle[.kts]`, `app/src` and nested source sets);
- Web/Node (`package.json`, `src`, `app`, `pages`, `public`, frontend/server/test layouts and JS/TS/UI source);
- API projects (`pyproject.toml`, `setup.py`, `requirements.txt`, `go.mod`, `Cargo.toml`, Maven/Ant manifests, and common api/backend/server/src layouts);
- CLI/common projects (`bin`, `cli`, `cmd`, `lib`, `src`, tests and root-level source files).

Generated/dependency roots such as `.git`, `.agent`, `node_modules`, `vendor`, `Pods`, `.gradle`, `DerivedData`, `build`, `dist` and language caches are not automatic product source. Explicitly configured control paths remain governed.

A discovered manifest must own at least one matching source file. Files under a populated common source root, including product assets, are governed; an unsafe symlink fails instead of being skipped. Custom layouts must be listed explicitly in `scope.fingerprint_paths`; deleting or moving that path then fails closed. A candidate declaration is accepted only when it equals the digest recomputed from all configured and automatically discovered files.
