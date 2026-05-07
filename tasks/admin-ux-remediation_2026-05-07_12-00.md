# Admin UX Remediation

Status: PASSED

## Task

Stabilize and improve WP Secure Guard admin usage across all pages, tabs,
documentation, and recovery workflows after the Security Assistant milestone.

## Context

Recent audits found several correctness and UX issues that must be fixed before
further feature expansion:

- Broken Whitelists submenu slug using a query string.
- Missing `lockdown_velocity_threshold` configuration default/sanitization/UI.
- Manual block/unblock flows do not consistently clear all related transients or
  dashboard stats.
- Documentation sidebar links point to anchors that do not exist.
- Documentation page lacks the same `register()` contract as other page classes.
- Duplicate pill CSS definitions and inconsistent layout classes.
- Redundant Compatibility settings tab.
- Some admin labels and page flows are implementation-oriented rather than
  task-oriented.

Baseline verification before editing: PHP syntax validation over plugin files
passed.

## Plan

1. Fix P0 correctness blockers: admin routes, config keys, cache invalidation,
   recovery cleanup, docs registration, and docs anchors.
2. Improve page and tab naming consistency, including replacing misleading API
   Rules wording with Security Rules where appropriate.
3. Improve recovery UX on Blocked IPs and Security Assistant without changing
   runtime security semantics unexpectedly.
4. Deduplicate CSS and add reusable layout classes only where they remove
   repeated patterns.
5. Update `PROJECT.md` as the source of truth after implementation.
6. Run PHP syntax validation and editor diagnostics.
7. Mark this task `PASSED` only after verification succeeds.

## Risks

- WordPress submenu slugs must remain stable enough not to break existing deep
  links.
- Preset and lockdown changes must preserve env-managed JWT behavior.
- Manual recovery must be idempotent and safe for false positives.
- Schema/config additions must be backward-compatible for existing installs.

## Verification

- PHP syntax validation for all non-vendor/plugin PHP files.
- Spot-check admin route generation for Dashboard, Security Assistant, Security
  Rules, IP Reputation, Logs, Blocked IPs, Whitelists, Settings, Documentation.
- Verify every changed admin action has capability checks, nonce checks,
  sanitization, safe redirects, and idempotent cleanup.
- Verify docs sidebar anchors correspond to real section IDs.
- Verify `PROJECT.md` documents final conventions.

## Result

- Fixed the Whitelists submenu to use a valid WordPress page slug and route
  directly to the Whitelists settings tab.
- Renamed the misleading API Rules menu entry to Security Rules.
- Added documentation page registration and rewrote the documentation around
  real operational anchors and recovery flows.
- Added `lockdown_velocity_threshold` defaults, sanitization, preset values, and
  Adaptive Security UI.
- Added persistent emergency lockdown fallback via `secure_guard_lock_state` and
  updated the watchdog to honor lock expiry.
- Centralized manual block/unblock cache invalidation for dashboard stats and
  attack velocity.
- Improved Blocked IPs with select-all bulk actions and recent log reasons for
  active blocks.
- Added Security Assistant preset rollback and environment-managed JWT warnings.
- Moved reputation listing/count queries into the rate-limit repository and
  added related log links.
- Fixed stale Site Health and alert URLs.
- Deduplicated pill CSS and moved documentation layout styling into the shared
  admin stylesheet.
- Updated `PROJECT.md` with final admin UX, recovery, schema, and lock-state
  conventions.

## Verification Result

PASSED.

- PHP syntax validation passed for `secure-guard.php`, `uninstall.php`, all
  `admin/*.php`, all `includes/*.php`, all `includes/data/*.php`, all
  `includes/install/*.php`, and all `includes/security/*.php`.
- Editor diagnostics reported no errors for the workspace.
- Search checks confirmed stale Whitelists query-string submenu URLs, stale docs
  anchors, stale `#tab-rest` links, and duplicate pill definitions were removed
  from active code.
