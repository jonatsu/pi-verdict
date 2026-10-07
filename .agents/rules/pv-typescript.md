---
description: "Before writing or reviewing pi-verdict TypeScript: modules, types, errors, and the gate's architecture limits."
globs: ["**/*.ts"]
paths:
  - "**/*.ts"
---

# TypeScript in pi-verdict

pi-verdict is a permission gate: every tool call an agent makes passes through it. Code here is security code, so
a choice that keeps the gate predictable wins over one that is shorter. Comments follow `pv-comments`; tests follow
`pv-tests`.

## Modules

- Write ESM with `node:`-prefixed built-ins and `.ts` extensions on relative imports.
- Import types with `import type` (or an inline `type` specifier) in new code.
- Keep each module to one concern and roughly 800 lines. Put new code in the module that owns its concern; a new
  shipped file under `extensions/` also joins `package.json` `files`.

## Types

- Type boundaries as `unknown` and narrow them: a tool call's input is `Record<string, unknown>`, and every field
  is checked with `typeof` before use. `extensions/`, `probe/` and `tools/` hold no `any`; biome enforces it.
- Give each `as` cast a comment saying why it is safe at runtime, `as unknown as` included.
- Model a value that takes one of several shapes as a discriminated union (`Verdict`, `RuleResult`, the
  `toolAccess` result), and handle it with a `switch` that ends in a `never` check, so a new variant fails the
  typecheck instead of falling through.
- Model a closed set of strings as a string-literal union or an `as const` object.
- Mark inputs, config and shared data `readonly`, and return new values instead of mutating arguments.
- Declare the return type of every exported function.

## Errors and fail direction

- Resolve every error on a decision path to deny or ask, never to allow. A classifier timeout, a malformed
  response, an unreadable config or an unknown payload shape is a fail-closed verdict.
- Narrow a caught value with `err instanceof Error` before reading `.message`.
- Audit writes are the one fail-soft path: a failed append is reported and the verdict stands.

## Architecture limits

- Ship zero runtime dependencies; the pi package is an optional peer dependency.
- Keep the adjudication core UI-free, and pass host capabilities in through `AdjudicateEnv` (`getModel`,
  `complete`, `host`, `signal`) so tests inject them.
- Register every per-session field in `SessionState.reset()`, the single reset list.
- Report to the user through `ctx.ui.notify`, prefixed `🛡️`; `extensions/` holds no `console.*`.
- Build dangerous literals by concatenation (`"rm " + "-rf /tmp/x"`), so the source never trips its own floor.
- Keep protected-path plaintext out of everything the agent, a notification or a model receives (ADR-0002).

## Done

A change is done when `bun run typecheck`, `mise exec -- biome ci .`, `bun test`, `bun run probe`, and
`bun run coverage && git diff --exit-code docs/coverage.md` all pass.
