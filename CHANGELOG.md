# Changelog

## 0.1.1 — 2026-11-09
Code-quality & consistency pass (no architecture changes, no working feature removed).

### Fixed
- **time-based DBMS label**: the reported engine now comes from the vector that
  actually caused the delay. SQLite's heavy-compute payload is labeled SQLite,
  so a delay is never mislabeled as MySQL.
- **`--risk` was defined but unused**: it now changes behaviour — risk 1 is
  AND-based only, risk 2 adds OR-based boolean conditions, risk 3 scales the
  time-based heavy payloads. (Lab-oriented; no change to scope.)
- **`--level` now feeds every technique**: error, boolean, UNION and time draw
  extra boundaries from the on-disk payload library, deduped against each
  technique's own proven list so nothing working is dropped.
- **Robustness**: a target that can't be reached now ends cleanly with a clear
  message instead of sweeping a dead baseline; a corrupt session file loads as
  absent instead of raising.

### Added
- Project website: https://sdark.gt.tc (also shown in the CLI banner).
- `tests/test_audit.py`: every technique at max level/risk, `--risk` effect,
  bad-target handling, corrupt-session handling, CLI list/version commands.
- `requirements.txt`, `CHANGELOG.md`.

### Still TODO (honest)
- The JSON payload library drives the boundary matrix the engine sweeps; the
  per-DBMS *vector* corpus is a reference set, not yet fired one-by-one by the
  detection loop.
- Stacked-query and OOB/DNS paths are implemented but only smoke-tested, not
  validated against a live backend that executes them.
- InfinityFree site content deploy pending (account live; upload in progress).

## 0.1.0 — 2026-11-09
Initial release: techniques E/B/U/T/S, three dump oracles, 16 DBMS, 100+ WAF
signatures + auto-tamper, 41 tampers, sessions, dump/dump-all, zip export.
