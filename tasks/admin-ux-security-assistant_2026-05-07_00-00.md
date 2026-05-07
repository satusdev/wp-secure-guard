# Admin UX Security Assistant

Status: PASSED

## Task

Start implementation of the high-ROI usability layer for WP Secure Guard:
security presets, easier unban workflows, emergency lockdown controls, and
clearer dashboard/assistant guidance.

## Context

The plugin already has granular security controls, active block management,
reputation scoring, logs, and lock-state infrastructure. Usage is still too
technical because admins must understand individual toggles, manually unblock
IPs one at a time, and cannot activate/release lockdown from the admin UI.

## Plan

1. Add a preset registry for Beginner, Balanced, and Maximum Security presets,
   with Custom as the inferred mode when live settings diverge.
2. Add a Security Assistant admin page that shows current preset, key protection
   state, recommendations, and emergency lockdown controls.
3. Add safe admin actions to apply presets and engage/release lockdown using
   existing nonce/capability patterns.
4. Improve Blocked IPs with bulk selected unblock, login-only unblock,
   unblock-all-login-blocks, and consistent transient cleanup.
5. Fix existing dashboard navigation to the registered Blocked IPs page slug.
6. Update PROJECT.md to document the new UX layer and conventions.
7. Run PHP syntax validation over plugin PHP files.

## Risks

- Presets must not overwrite environment-managed JWT values.
- Lockdown controls must not create a persistent lockout state without a release
  path.
- Bulk unblock must not clear unrelated reputation/firewall state unless
  explicitly requested.
- Existing settings tabs must keep current values when preset actions are
  applied.

## Verification

- PHP syntax validation passes for all plugin PHP files.
- Admin actions require `manage_options`, nonce verification, sanitized inputs,
  and safe redirects.
- Preset application saves through `Secure_Guard_Config::save_settings()` and
  preserves env-overridden JWT fields.
- Lockdown engage/release writes and clears the lock transient consistently.
- Unblock flows remove the expected subjects and transients.
- PROJECT.md documents the new admin UX architecture.

## Result

- Added Security Assistant admin page with preset cards, current mode detection,
  recommendation cards, and emergency lockdown controls.
- Added Beginner, Balanced, and Maximum Security preset registry with Custom
  mode detection.
- Added preset application handler with settings snapshot, sanitizer-backed
  save, env-managed JWT preservation, audit logging, and dashboard cache
  invalidation.
- Added bulk/universal/login-only false-positive recovery workflows on Blocked
  IPs and audit logging for manual block/unblock actions.
- Fixed Dashboard Blocked IPs navigation slug and added a Security Assistant
  quick link.
- Aligned the watchdog lockdown transient with the runtime lock-state key while
  preserving backward compatibility with the old transient key.
- Updated PROJECT.md with the new admin UX layer and conventions.

## Verification Result

PASSED. Ran PHP syntax validation over all non-vendor plugin PHP files:

`for file in admin/*.php includes/*.php includes/*/*.php secure-guard.php uninstall.php; do php -l "$file" || exit 1; done`
