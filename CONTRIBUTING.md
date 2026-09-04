# Contributing

Contributions should preserve the project's core safety boundary: it collects only authorized, accessible files and does not bypass device security or access protected data.

Before proposing a change:

1. Use only harmless synthetic test data.
2. Do not commit evidence, personal exports, disk images, case folders, credentials, or source-device identifiers.
3. Run `python3 -m unittest -v test_mac_to_autopsy_triage.py`.
4. Document user-facing behavior and safety implications in the README when they change.

Good contribution areas include clearer documentation, accessibility, error messages, test coverage, and compatibility fixes. Features that unlock devices, bypass encryption, access cloud accounts, create device backups, or access app-private phone data are intentionally out of scope.
