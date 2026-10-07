# Host contract: the packages the extensions import

The two extensions import the host's own packages by their upstream specifiers. This file
records every bare host import, where it is declared, and how each host resolves it, so the
next reader does not have to reverse-engineer the plugin-compatibility path.

## Imports

| Specifier | Kind | Used in | Declaration |
|---|---|---|---|
| `@earendil-works/pi-ai` | value (`createAssistantMessageEventStream`, types) | `extensions/jev-adapter.ts` | peer (optional) + dev |
| `@earendil-works/pi-ai/compat` | dynamic import (default `complete` loader) | `extensions/pi-verdict.ts` (`bindCompletion`) | covered by the `pi-ai` peer (subpath remapped on omp) |
| `@earendil-works/pi-coding-agent` | type + dynamic import (`ui.custom` dialog modules) | both extensions | peer (optional) + dev |
| `@earendil-works/pi-tui` | type + dynamic import (`loadDialogModules`) | `extensions/pi-verdict.ts` | peer (optional) + dev |

All three packages are declared in `peerDependencies` with
`peerDependenciesMeta.<pkg>.optional = true`, and again in `devDependencies` (pinned to
`0.84.3`) so the typecheck graph is intentional rather than relying on transitive hoisting.
They are **never** real dependencies: the host provides them, and installing a copy would
create the mixed-runtime hazard the omp compat shims warn about. The peer range `>=0.84.0`
expresses the API line the code targets and is satisfied numerically by omp 18.5.1 as well.

## Resolution per host

On **pi**, the specifiers are the host's own packages.

On **omp**, `src/extensibility/plugins/legacy-pi-compat.ts` resolves them:

- `PI_SCOPE_ALIASES = [oh-my-pi, mariozechner, earendil-works]` aliases the scopes;
- root shims map `pi-ai`, `pi-coding-agent` and `pi-tui` to `@oh-my-pi/<name>`;
- `PI_SUBPATH_REMAPS` maps `pi-ai/compat` to the canonical `@oh-my-pi/pi-ai` root.

`@oh-my-pi/pi-ai@18.5.1` exports both `complete` and
`createAssistantMessageEventStream`, so the imports resolve to working values.

## Verified against

omp 18.5.1 (`@oh-my-pi/pi-ai@18.5.1`, `@oh-my-pi/pi-coding-agent@18.5.1`,
`@oh-my-pi/pi-tui@18.5.1`) on Linux/WSL2; devDependency line pi 0.84.3
(`@earendil-works/*@0.84.3`).

## Note on the dialog helpers

omp 18.5 does not re-export `DynamicBorder`, `keyHint` or `rawKeyHint` from
`@earendil-works/pi-coding-agent` (they live under `@oh-my-pi/pi-tui/chrome`, not re-exported
by its index), so the rich approve dialog uses local, theme-aware substitutes
(`extensions/pi-verdict.ts`, `DialogBorder`/`dialogKeyHint`/`dialogRawKeyHint`) rather than
depend on a host export that may not exist.

## Mouse clicks and the status widget

`buildApproveDialog` parses SGR left-clicks: `dialogLineAtRow` maps the click row through the host's
`children`, `terminal.rows` and `viewportTop`. A click highlights an option, and a second click on the same
mouse-highlighted row confirms it; any keyboard input disarms the highlight. The dialog never writes
mouse-mode sequences itself, so it is inert on a host that does not forward mouse input; pi 0.84.3's
`TuiAltScreen` consumes mouse input before the dialog sees it.

During a gray-zone model call the `tool_call` handler shows a one-row status widget
(`ui.setWidget("verdict", …)`), fed by the UI-free `AdjudicateEnv.onPhase` hook, and clears it before
presenting the verdict. The row carries the phase, the tool name and the model id only, never command or
path text (ADR-0002).
