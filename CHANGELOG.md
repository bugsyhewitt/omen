# Changelog

All notable changes to omen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

### Added

- **Detection classes (10 total, MAIAN + modern EVM coverage):**
  - `prodigal`, `suicidal`, `greedy` (MAIAN class — trace vulnerabilities, Nikolic et al. USENIX 2018).
  - `reentrancy` (SWC-107 cross-function + cross-contract via Slither reentrancy-eth/reentrancy-balance detectors).
  - `access-control` (Slither protected-vars + events-access; #1 loss category by volume per OWASP Smart Contract Top 10 2025/2026).
  - `tx-origin` (Slither tx-origin detector).
  - `delegatecall` (controlled-delegatecall + delegatecall-loop via Slither).
  - `upgrade` (unprotected-upgrade via Slither).
  - `overflow` (integer-overflow via Slither 0.11+).
  - `weak-randomness` (block-timestamp / oracle-pattern via Slither).
- **Input types:** `sol` (Slither), `vyper` (Slither), `bytecode` (custom EVM opcode heuristics), `address` (live RPC read-only bytecode fetch via evm-toolkit stdlib-only RPC client — no web3 dep).
- **Output formats (12 total):** `text` (compact terminal), `json`, `sarif` (SARIF 2.1.0), `junit` (JUnit XML), `gha` (GitHub Actions workflow-commands), `checkstyle` (Checkstyle XML), `sonarqube` (SonarQube Generic Issue Import JSON), `gitlab-sast` (GitLab SAST Report v15), `bitbucket-code-insights` (Bitbucket Cloud Code Insights), `azure-devops` (Azure DevOps Pipelines logging), `teams-webhook` (Microsoft Teams Incoming Webhook MessageCard), `opsgenie` (Opsgenie Create Alert API JSON), `victorops` (VictorOps / Splunk On-Call REST endpoint).
- **CLI flags (22+ total):**
  - Triage: `--min-severity`, `--min-confidence`, `--severity-override`, `--limit`, `--sort`.
  - Selection: `--check`, `--exclude-check`, `--list-checks`.
  - Output: `--format`, `-o/--output-file`, `--batch`, `--parallel`, `--timeout`, `--batch-summary`.
  - CI gates: `--fail-on {none,low,medium,high}`.
  - Diff/baseline: `--diff`, `--baseline`, `--ignore`, `--sarif-baseline`, `--sarif-merge`.
  - Config: `--config` (TOML config-file defaults).
  - Meta: `--version` (prints `omen 1.0.0`), `--help`.

### Changed

- **Refactor:** Migrated from `web3`-based RPC client to `evm-toolkit`'s stdlib-only RPC client (drops direct `web3` dependency — bytecode fetch in address-mode now uses evm-toolkit).

### Fixed

- **Editable install resolves to repo src/:** added `tests/test_install_sanity.py` regression test pinning `pip install -e .[dev]` resolves `import omen` to a file under `~/dev/necromancer/projects/omen/src/omen/` (regression for `.pth` rot). PR #38.
- **Wheel builds and installs in fresh venv:** added `tests/test_wheel_ship_gate.py` with 7 `@pytest.mark.ship_gate` tests covering wheel build, fresh-venv install, `--version` and `__version__` parity, public API smoke, `--list-checks` smoke, `--help` exits zero, `--check` category validation. PR #39.

### Security

- No security-relevant changes in this v1.0 cut. omen is read-only (analyzer that scans contracts and reports findings; no on-chain writes, no key custody, no remote code execution).

[1.0.0]: https://github.com/bugsyhewitt/omen/releases/tag/v1.0.0
