# pxpipe Context Selection Policy

Use image transport only for closed, cold material whose semantic meaning is useful and whose original file remains available for native rereading.

Eligible examples:

- long background documentation;
- historical, already-closed logs where exact lines are not evidence;
- generated reference catalogs or large prose inputs;
- source files used only to understand broad structure, after exact patches and diagnostics are excluded.

Never image:

- system, developer or user instructions;
- requirements, acceptance criteria, decisions or task state;
- patches, diffs, test assertions, failures or active tool-call state;
- security, permission, compliance, financial, migration, deployment, rollback or audit material;
- secrets, credentials, private keys or environment files;
- paths, IDs, hashes, versions, dates or amounts that will be trusted without native rereading;
- `.agent`, `.agents`, `.codex`, `.git` or equivalent workflow, plugin, credential and VCS control state.

Hard limits are mechanical: exact `gpt-5.6-sol`, at most 24 explicit text files, at most 1 MiB per file, at most 512 KiB combined, at most eight PNG pages, no binary input, no path escape, no sensitive filename or obvious credential pattern, no dropped factsheet entries and at least 10% estimated savings. Estimates are local estimates, not provider-measured savings.

User approval is semantic, not inferred from plugin installation. Installation makes the tool available; it does not authorize lossy rendering for every task.
