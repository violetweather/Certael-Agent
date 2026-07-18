# Launch splash technical audit

Audit target: `crates/certael-agent/src/ui.rs`, signed branding transport, and the real debug render path.

## Audit health score

| Dimension | Score | Key finding |
| --- | ---: | --- |
| Accessibility | 4/4 | AccessKit is enabled; controls are native widgets; all text tokens pass AA contrast; the layout reflows at 200% scale. |
| Performance | 3/4 | Assets load once from bounded local PNGs, but a maximum-size signed hero is decoded before the first interactive frame. |
| Appearance and theming | 4/4 | Dark-only semantic tokens are centralized and consistently applied. |
| Platform conformance | 4/4 | Native window, native buttons, standard keyboard actions, and OS-level window controls. |
| Adaptivity | 4/4 | Default, minimum-window, 150%, 200%, success-path, and failure-path layouts were rendered and inspected. |
| **Total** | **19/20** | **Excellent** |

## Platform-conformance verdict

Pass. The splash reads as a focused native game-launch checkpoint, not a website port. It uses one window, a single task, ordinary platform controls, no embedded navigation, no card grid, and no decorative security animation.

## Findings

### Resolved P1 — 200% text scaling clipped the active explanation

- **Category:** Accessibility / Adaptivity
- **Impact:** Players using large OS text could not read the authoritative-admission explanation.
- **Resolution:** The signed hero is treated as decorative and is omitted when fewer than 420 logical vertical pixels remain. A 200% render confirms that identity, progress, explanation, and footer remain visible.

### P2 — Maximum-size hero decode occurs before the first frame

- **Category:** Performance
- **Impact:** A publisher-supplied 3840×2160 PNG at the allowed bound may add a short startup delay on low-end hardware.
- **Recommendation:** In a later optimization pass, build and cache a verified display-sized derivative at registration time while retaining the signed source digest as authority.
- **Suggested command:** `$impeccable optimize launch splash`

## Positive findings

- Runtime milestones drive the rail; no fake percentages or timers claim progress.
- The success label is reachable only after authoritative server admission, signed launch-bundle verification, matching build verification, and ready health.
- Failure state identifies its failed phase with an exclamation mark and plain-language recovery copy, not color alone.
- Repair and offline actions appear only when the signed registration permits them.
- Publisher art is local, signed, hash-bound, non-animated PNG content with decoded-size and dimension limits.
- Minimum-window, default, 150%, and 200% renders show no horizontal overflow or clipped player-facing copy.

There are no unresolved P0 or P1 findings.
