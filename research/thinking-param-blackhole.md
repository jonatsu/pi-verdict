# Classifier thinking parameter black hole: root cause of systematic fail-closed in the gray area for GLM-family thinking models (empirical evidence for optional fix item #7)

**Conclusion: the `reasoning: "minimal"` passed by the extension is collapsed on the gateway stack of an internal provider plugin into “send no thinking parameters”; the GLM-family thinking model turns on thinking at its own default level, burns through 512 maxTokens → empty/truncated output → fail-closed; heavy thinking lengthens latency → 15s timeout aborted.**

## Symptoms (5 live samples in this session)

| Time (local) | stopReason | Raw output | Corresponding Langfuse observation |
|---|---|---|---|
| 12:53:32 | length | `""` | (id omitted) |
| 12:53:53 | length | `""` | (id omitted) |
| 12:54:16 | length | `""` | (id omitted) |
| ~14:4x | length | `"<verdict>allow"`(truncated) | (another session sample) |
| ~14:4x | aborted | `""` | (15s timeout) |

## Source layer (internal provider plugin@0.9.0, name undisclosed)

The plugin **does not touch the request body** (only does OAuth/header injection/cost tracking/model list), but uniformly attaches model metadata to all reasoning models (regex matching `glm-`, etc.):

```js
A = { thinkingLevelMap: { max: "max" }, compat: { forceAdaptiveThinking: true } }
```

- `forceAdaptiveThinking` → pi core changes anthropic-messages to send adaptive thinking (budget-based thinking field is abandoned)
- `thinkingLevelMap` has only one key, `max`: according to pi docs, **omitted keys use the default mapping**; `minimal` has no valid mapping on the adaptive stack → **the entire thinking field is omitted**

## Data layer (Langfuse empirical evidence, 2026-08-26)

Comparison of `modelParameters` for three call types on the same instance and same model (GLM-family thinking model):

| Call type | max_tokens | thinking field |
|---|---|---|
| **auto-mode classifier** (3 entries, times match fail-closed to the second, input contains the `<transcript>…<verdict>` contract, output is an empty string) | 512 | **missing (not sent)** |
| Session-level dialogue (outside the extension) | 64000/131072 | `{"type":"adaptive"}` |
| Call with thinking explicitly disabled | 64/8192 | `{"type":"disabled"}` |

→ pi **is capable** of sending `thinking: disabled`, but needs the correct level; on this stack, `minimal` maps neither to disabled nor to effort, and simply evaporates.

Note: LiteLLM reporting drops the system parameter (the classifier system prompt is not in the Langfuse input, consistent with the #4 investigation); identifying calls must rely on user message characteristics (`<transcript>` + `<verdict>` contract + max_tokens 512 + temperature 0).

## Causal chain

```
Extension reasoning:"minimal"
  → pi core: adaptive stack + map{max} has no minimal mapping → thinking field omitted
  → LiteLLM gateway forwards as-is (GLM-family thinking model has thinking on by default)
  → reasons at the default high level → all 512 maxTokens burned (empty output/truncation) or exceeds 15s (timeout)
  → fail-closed deny → systematic interception of the gray area
```

The assumption that “the plugin overrides the thinking level”: **holds in effect, but not in mechanism**—it is not a runtime override; rather, the plugin's model metadata collapses minimal into an omitted parameter, colluding with GLM's thinking-on-by-default on both ends.

## Compatibility: is `reasoning: "off"` universal? (BigModel official mapping table + empirical evidence)

BigModel official documentation (GLM Coding Plan model switching guide)'s effort handling table:

| Value passed by tool | Actual GLM level | Handling |
|---|---|---|
| thinking.type not passed/true/enabled/adaptive | **max** | Uses default level (root cause of this incident: omitted parameter = max) |
| thinking.type is false/disabled/none/off | **low** | Continue request; still does light thinking |
| reasoning_effort is minimal/light/low | low | Automatically converted |
| reasoning_effort is medium/high | high | Automatically converted |
| reasoning_effort is xhigh/max/ultra | max | Automatically converted |
| Priority | Explicit Effort > thinking switch > default max | |

Conclusion: `off` is a **universal request**, not a **universal guarantee**:

| Model/stack | Actual effect of `off` | Evidence |
|---|---|---|
| Real Anthropic | Completely disables thinking | pi standard anthropic behavior |
| GLM/BigModel (empirically verified via internal gateway) | Drops to effort low, cannot go to zero | Official table + actual testing |
| Model without thinking capability (reasoning:false) | No parameter to send, no-op | pi model metadata |
| Model that cannot disable thinking and rejects disabled | May error → fail-closed | Theoretical risk, needs fallback |

Key empirical evidence: on the same gateway, on a GLM-family thinking model, the CC classifier runs with `thinking:{disabled}` + **max_tokens 64**, and successfully outputs `<block>no` (dozens of entries that day, occasional empty output ~3.5%)—“effort low light thinking + small budget” holds in real traffic, and a 512 margin is even more ample.

Another key inference: low levels other than `off` (`minimal`/`low`) also face the “map has no key → omitted parameter → GLM max” black hole on this provider stack; `off` is the only level that has a dedicated wire form (`thinking:{type:disabled}`) and has been verified as delivered on this gateway.

## Fix recommendations (compatibility-corrected version)

1. **Primary fix on the extension side**: use `reasoning: "off"` instead of `"minimal"`—the only level with a dedicated wire form; on GLM it drops to effort low light thinking (64 tokens empirically suffices, 512 margin is ample).
2. **Defensive fallback (must keep, not optional)**: on contract failure/empty output, retry once and raise maxTokens (e.g., 1024)—covering the two long-tail cases of “models that ignore disabled” and “models that cannot disable thinking and reject parameters”; this is the truly model-agnostic compatibility layer.
3. **Keep maxTokens at 512**: CC has already verified low level works at 64; 512 leaves margin for light thinking in other models; raise to 1024 on retry.
4. **Upstream (internal provider plugin)**: `thinkingLevelMap` should complete the low-level mappings (minimal/low → low level or disabled), eliminating the “omitted parameter = GLM max” trap; at minimum document it in the README.
5. **Upstream pi core**: per-call reasoning collapsing to an omitted parameter on the adaptive stack is unsafe for models whose “default level = max”, and is worth reporting for discussion.

## Final root cause correction (third layer, decisive): `reasoning` never left the extension

The previous two rounds of analysis (thinkingLevelMap collapse, off mapping) were reasoning at the **wrong level**—they correctly characterized the behavior of the simple layer (`streamSimple`), but the extension's call never reaches there:

1. The extension calls `ctx.modelRegistry.complete()` — an **API-layer** method, with option type `ModelsApiStreamOptions<TApi> = AnthropicOptions & ...`;
2. The thinking fields of `AnthropicOptions` are `thinkingEnabled/thinkingBudgetTokens/effort/thinkingDisplay`, **there is no `reasoning`** (the latter belongs to `SimpleStreamOptions`, mapped by `streamSimple`; on the extension side `ModelRegistry` does not expose `completeSimple`);
3. Why TS allows it: the extension holds the broad type `Model<Api>`, and the conditional type `ApiStreamOptions<Api>` falls into the fallback branch `StreamOptions & Record<string, unknown>`, **the index signature swallows unknown-property checks**;
4. Runtime sequencing: `if (options?.reasoning)` is always false, and `thinkingEnabled === false` is also not set → **no thinking parameters are sent** → GLM default max level (consistent with the first row of the BigModel table).

**Lesson from the mid-course experiment**: after deploying the `reasoning: "off"` fix, Langfuse still measured no thinking field—precisely this experiment exposed the true root cause. (Also note: if the simple layer actually receives the string "off", `!options?.reasoning` is false → forceAdaptive branch → `mapThinkingLevelToEffort` switch default → **effort "high"**; the string "off" at that layer also does not equal disabling thinking; what equivalently disables thinking is omitting reasoning.)

**Final fix**: `thinkingEnabled: false` (native field for anthropic-messages; the serialization condition `thinkingLevelMap?.off !== null` holds for the internal plugin's `{max:"max"}` map) → empirically delivered `thinking:{"type":"disabled"}`; for other APIs it is a harmless extra property, with defensive retry (512→1024) as fallback.

## Reproduction/verification method

- Query: `GET /api/public/v2/observations?type=GENERATION&fromStartTime=…&fields=core,model,io`, identify classifier calls by `modelParameters.max_tokens==512 && temperature==0` + input containing the `<verdict>` contract
- Criteria: the classifier call's modelParameters lacks the thinking field; output content is an empty string; compare against 64000/131072 (adaptive) and 64/8192 (disabled)
