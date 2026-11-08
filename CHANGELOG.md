# Changelog

## 0.1.1

Security

- npm overrides pin `glob` 14.0.4 and `minimatch` 11.0.5 under `@electron/asar`, replacing versions with 3 moderate advisories. `npm audit` now reports none.
- Checked with `npm run build`, `npm test` (5 passing), `ceasefire visualize`, and an `@electron/asar` pack, list and extract round trip.

All packages (`@ceasefire/cli`, `core`, `defender`, `waf`) move to 0.1.1 together.

## 0.1.0

- First release.
