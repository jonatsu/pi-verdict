# Research: Integration Path and Benefit Assessment of typesafe jev as pi-verdict classifierModel

> Research date: 2026-09-18 (jev released on 2026-09-15, OpenRouter listing created at 2026-09-18T00:01Z, only 3 days after release).
> Source scope: typesafe official blog and documentation site (docs.typesafe.ai, fully indexed via llms.txt), OpenRouter official documentation and public API, OpenRouter model-page embedded catalog data, GitHub org `typesafe-ai`, npm registry; additionally cites live tests with the library performed in the main session with a real OpenRouter key (labeled “live test with the library 2026-09”) and local pi / pi-verdict source code.
> This document supersedes `research/typesafe-jev-classifiermodel.md` (its conclusion that “OpenRouter is not yet callable” is outdated: the decisions endpoint can now be called in live tests).
> Assertions are labeled in three tiers: **Verified** (official docs/public API/live test with the library/local source code), **Official claim** (vendor's own statement not independently reproduced), **Inferred** (reasoning chain indicated).

## TL;DR

1. **Q1 (can jev be configured as classifierModel via the pi provider system): currently no, and there is a clear feasible path.** jev is a decisions modality model: OpenRouter catalog data `output_modalities: ["decisions"]`, `has_text_output: false`; live test with the library calling both slugs via `chat/completions` returned 400: "~typesafe/jev-latest is a decisions model and cannot be used with the chat/completions endpoint. Use the /api/alpha/decisions endpoint instead.". pi's model pipeline (modelRegistry.complete → `api: "openai-completions"` → chat/completions) cannot drive it, and the legacy provider in `models.json` is the same. The only feasible paths are (a) an independent adapter extension using `pi.registerProvider()` + Custom Streaming API to translate `complete()` semantics to the decisions endpoint (pi-verdict unchanged), or (b) pi-verdict directly fetching (violates its no-direct-connection architecture, not recommended).
2. **Q2 (are the typesafe official API and the OpenRouter interface consistent): not at all isomorphic to OpenAI chat completions; OpenRouter's `/api/alpha/decisions` and typesafe's official `POST /v1/systemone` are highly isomorphic.** The two are field-by-field corresponding in their core request/response schema (state + questions discriminated union choice/score/noul → answers + usage); the differences are only that the OpenRouter side adds `provider` routing preferences, `session_id`/`trace`/`user` observability fields, and in the response `id`/`provider`/`usage.cost`; the model namespace differs (`jev-latest` vs `~typesafe/jev-latest`, and both responses report the concrete version number).
3. **Benefit: highly compatible with the classifier profile, but with one decisive risk acknowledged by the vendor.** The classifier task = choose one of allow/ask/deny + calibrated probability, precisely isomorphic to the `choice` primitive; the live test with the library of `rm -rf /tmp/test-dir` → allow P=0.58 conf=0.16 shows that calibrated uncertainty is genuinely usable (a confidence threshold can upgrade “leans allow but uncertain” to ask, turning "Err on the side of ask" from a prompt soft constraint into a code hard threshold). Cost input $0.042/M, output $0 (about 2.3× cheaper than GLM-5.3-flash and about 20× cheaper than GPT-5.4-mini), measured median latency 1.25s (far below the current gateway LLM classifier p90 19.8s). But typesafe's official jaggedness documentation explicitly admits: **"State is data, and `jev-1.13` does not treat it as hostile by default"—adversarial content can move judgments**, and pi-verdict's state is exactly a transcript containing untrusted file content. **Conclusion: worth building as a pluggable experiment, but not recommended to rely on now.**

## 0. Verified pi-side facts on this machine (for note self-consistency)

Source: this repository's `extensions/pi-verdict.ts` and the locally installed pi package docs (`node_modules/@earendil-works/pi-coding-agent/docs/`).

1. **The extension never connects directly to model-vendor HTTP**. Classifier completion calls go through `completionFor(ctx.modelRegistry, …)` → `ModelRegistry.complete(model, context, options)`; credentials are resolved internally by pi, and pi-verdict does not touch the API key (`extensions/pi-verdict.ts:1044,1611`). For the mechanism, see `research/pi-model-call-and-ref-implementations.md`.
2. **classifierModel resolution**: `resolveClassifier()` splits the user configuration string at the first `/` into provider/modelId, `ctx.modelRegistry.find(provider, modelId)` + `hasConfiguredAuth(model)`, and on failure falls back to session model introspection (`extensions/pi-verdict.ts:1545-1563`). Note: the split takes the first `/`, so `"openrouter/~typesafe/jev-latest"` is correctly parsed as provider `openrouter` + modelId `~typesafe/jev-latest`.
3. **There are two entry points to the provider system**: pi's built-in `openrouter` provider (`/login openrouter` OAuth key minting or `OPENROUTER_API_KEY`, pi `docs/providers.md:49,85`); custom providers go through `~/.pi/agent/models.json` or the extension API `pi.registerProvider()` (`api: "openai-completions"` and other legacy API names, or a custom implementation via Custom Streaming API, pi `docs/custom-provider.md:3,25,75`).
4. Classifier call profile (supplementary, same file): `<verdict>allow|ask|deny</verdict>` prefix contract (`:909-910,986-988`), violation → null → fail-closed deny; each transcript entry ≤1000 characters (`MAX_ENTRY_CHARS`, `:923`); timeout 25s (`CLASSIFIER_TIMEOUT_MS = 25_000`, comment cites this gateway's p90=19.8s measured distribution, `:999`); maxTokens 512, parse-failure retry tier 1024.

## 1. Q1: Integration Path

### 1.1 OpenRouter-side facts (verified)

- **Both listings really exist** (verified 2026-09-18; a control page with a forged slug only falls back to title "OpenRouter"):
  - `https://openrouter.ai/~typesafe/jev-latest` — meta description:"This model always redirects to the latest model in the Jev family. $0.042 per million input tokens, $0 per million output tokens. 32,000 token context window."
  - `https://openrouter.ai/typesafe/jev-1.13` — "Jev is a structured decision model from TypeSafe, and the first of its System One models. …$0.042/M input,$0/M output,32,000 token context window."
- **`~` prefix semantics (verified by official docs)**: OpenRouter docs "Latest Model Resolution" (openrouter.ai/docs/guides/routing/routers/latest-resolution.md): "`~author/family-latest` slugs always resolve to the newest concrete model in a given family, so you can ship code against a stable alias and pick up new releases without redeploying." The response `model` field reports the concrete version ("Transparent reporting"); if no model is available in the family, it errors rather than falling back. That is, **`~typesafe/jev-latest` = rolling alias, `typesafe/jev-1.13` = pinned version**, and both share the same `model_version_group_id` (model-page embedded data). Also: that document's "Compatibility contract" section states that the `~latest` alias remaps unsupported reasoning parameters to the nearest approximation—for a model like jev with `supports_reasoning: false`, the classifier's `reasoning: "off"` requirement is naturally satisfied.
- **Catalog status**: `GET /api/v1/models` with and without authentication both return 445 models, **with no typesafe/jev entry**; but the catalog does contain `~` aliases such as `~deepseek/deepseek-pro-latest` and `~z-ai/glm-flash-latest` (verified). Combined with the 400 error below, **inference**: decisions modality models do not enter the chat catalog, or the entry is still in gradual rollout. OpenRouter docs "Model Variants" notes: "`GET /api/v1/models` is a catalog of models and catalog variants. It is not an exhaustive list of every model string a request can use."—that is, **the catalog is dynamic for chat models, and newly listed slugs are immediately usable; but jev belongs to another endpoint system**.
- **Model-page embedded catalog data (verified, jev-1.13 page)**: `output_modalities: ["decisions"]`, `has_text_output: false`, `supports_reasoning: false`, `supported_parameters: []`, `context_length: 32000`, `permaslug: "typesafe/jev-1.13-20260917"`, endpoint `provider_name: "TypeSafe"`, `baseUrl: "https://api.typesafe.ai/v1"`, adapter `TypeSafeDecisionsAdapter`, listing `created_at: "2026-09-18T00:01:24Z"`.
- **Live test with the library 2026-09 (via OpenRouter official endpoint)**: both slugs via `chat/completions` returned 400: "…is a decisions model and cannot be used with the chat/completions endpoint. Use the /api/alpha/decisions endpoint instead."; via `POST https://openrouter.ai/api/alpha/decisions` the call succeeded, and the response `model` was both `typesafe/jev-1.13-20260917`, `provider: "TypeSafe"`.

### 1.2 Why the pi pipeline cannot drive it (core argument)

pi's provider pipeline terminates at OpenAI-style chat/completions (both the legacy `api: "openai-completions"` and the built-in openrouter provider do so). jev explicitly rejects that endpoint at the gateway layer (the 400 error quoted above, verified), and `has_text_output: false`—even if the gateway allowed it, the `<verdict>…` text contract could not be produced. Therefore:

| Path | Approach | Verdict |
|---|---|---|
| A. `classifierModel: "openrouter/~typesafe/jev-latest"` | Use pi's built-in openrouter provider | **Unusable (verified)**: chat/completions 400 |
| B. Custom provider in `models.json` (`api: "openai-completions"`, baseUrl pointing to typesafe or OpenRouter) | Integrate via legacy chat shape | **Unusable (verified)**: typesafe officially only has `/v1/systemone`, with no OpenAI compatibility layer; the corresponding endpoint on the OpenRouter side is `/api/alpha/decisions`, also not a chat shape |
| C. adapter extension: `pi.registerProvider()` + Custom Streaming API (pi `docs/custom-provider.md:25`) | An independent extension registers a complete Provider, translating `complete(model, context, options)` into a decisions request: messages/transcript → `state`, the three-part `CLASSIFIER_SYSTEM` definition → `choice`'s `criteria` (allow/ask/deny three options), and synthesizes the answer back into `<verdict>{choice}</verdict> jev: confidence=… p(allow)=…` text, exactly satisfying the `parseVerdict` prefix contract | **Feasible (inferred, design level)**: pi-verdict unchanged, `classifierModel: "typesafe/jev-latest"` works as is; requires ~100 lines of adapter code + self-managed auth (env var) |
| D. Direct fetch of the decisions endpoint inside pi-verdict | The extension sends HTTP itself | **Not recommended**: breaks the existing architecture of “extension is model-agnostic and uses credentials through the pi system” (ADR mandates zero direct connections), and contradicts the motivation of this research |

Note: GitHub `typesafe-ai/system-one-adapter-python` (103★, official org) is an isomorphic precedent in the opposite direction—"Drop-in TypeSafeClient replacement backed by LLM APIs", proving that a translation layer between systemone ⇄ LLM APIs is a pattern the vendor itself also maintains; Path C is its mirror image (LLM API ⇄ systemone).

### 1.3 Existence proof: the pi-jev extension chose Path D (verified 2026-09-18)

GitHub `iefnaf/pi-jev` (created on 2026-09-18, npm package name `@alexlikevibe/pi-jev`): a pi extension suite that uses jev for “selective context compaction + per-turn model routing”. **It did not go through `pi.registerProvider()` (Path C), but rather the extension directly fetches the decisions endpoint (Path D)**; its engineering shape is worth referencing:

- **Transport layer** (vendored `src/vendor/fast-jev-compaction/client.ts` + `request.ts`, zero-dependency pure functions): `buildJevRequest()` constructs `POST {model, state, questions}` + Bearer auth; fetch is injectable (test-friendly); response validation only requires non-2xx to throw + JSON to be parseable + `answers` to be an object—**the same parser handles both typesafe and OpenRouter responses** (the core schemas on both sides are isomorphic, cross-confirming the conclusion in section 2.2 of this document).
- **Dual transport configuration resolution** (`src/shared/config.ts`): `JEVC_PROVIDER` explicit specification > config file > auto-detection by env key (when both keys exist, TypeSafe takes precedence); default mapping: typesafe → `https://api.typesafe.ai/v1/systemone` + `jev-latest`, openrouter → `https://openrouter.ai/api/alpha/decisions` + `typesafe/jev-1.13` (**pinned version rather than the `~latest` rolling alias**, consistent with the section 4 recommendation that “thresholding must pin versions”); `JEVC_BASE_URL` can override the endpoint (proxy scenario). Configuration layering env (`JEVC_*`) > project `.pi/jev.json` > global `~/.pi/agent/jev.json`, **API key never written to a file (env-only, `JEVC_API_KEY` can override)**.
- **pi integration surface (hybrid mode)**: jev judgment is direct-connected in hooks (`session_before_compact` compaction / `before_agent_start` routing), but the routing **target model** still goes through the pi system (`ctx.modelRegistry.find()` + `pi.setModel()`). That is, “decision model direct-connected, target model via registry”.
- **Question-type practice**: compaction = for each non-pinned tool call, two `noul` questions (keep call / keep result) + one `score` (staleness), with multiple batches concurrently sharing the same fitted state; routing = one `score` (difficulty, criteria = `['trivial','moderate','complex']` three levels, matching the legend semantics measured in this document), and it implements dual-mode defensive parsing for 0..1 continuous values vs level indices (`toLevels`: `score <= 1` read as a normalized value).
- **Precedent for confidence thresholding**: if `minConfidence` is below the threshold → do not switch models (`reason: 'low-confidence'`), the same type as the “confidence-thresholded ask strategy” envisioned in section 3.3 of this document; the fallback direction is feature degradation (jev failure → fall back to pi native compaction / keep the current model, missing answers conservatively retained)—isomorphic to pi-verdict's fail-closed philosophy (taking the conservative side for safety), but it is a feature extension, not a security component.

Implications for pi-verdict: Path D's engineering cost is proven to be at the level of “~100-line client + configuration parsing”; but pi-jev's scenario (compaction/routing) is inherently extension-autonomous logic, with no `complete()` semantic baggage—if pi-verdict takes D, it must solve on its own “where do credentials come from” (pi-jev uses an env-only key; pi-verdict can reuse pi credentials via `modelRegistry.getProviderAuth("openrouter")`, still with zero self-managed key) and the ADR record of “conceding the zero-direct-connection architecture”.

## 2. Q2: API Compatibility

### 2.1 typesafe official API (verified, docs.typesafe.ai/api)

```
POST https://api.typesafe.ai/v1/systemone
Authorization: Bearer <TYPESAFE_API_KEY>
Content-Type: application/json

{ "state": "<string|object|array>", "model": "jev-latest",
  "questions": { "<id>": { "type": "choice|score|noul", "instructions": …, "criteria": … } } }
```

- The response top level is `{ model, answers, usage }`; each answer has a typed value according to the question type. **Authentication is also Bearer, but the request/response schema has no common structure with OpenAI/OpenRouter chat completions**; the documentation site (full llms.txt index) has no declaration of an OpenAI compatibility layer.
- **noul semantics (verified by official docs)**: "A Noul question asks the model to evaluate a yes/no question and return the probability that the answer is yes." Value 0–1, "A value near 0.5 gives yes and no similar probability"; **"Noul does not return a separate confidence value"**.
- **confidence semantics (verified by official docs)**: only Choice/Score have it; it is a single scalar collapse of the probability distribution shape ("collapses that shape into a single number from 0 to 1"); the vendor gives three usage tiers—high: act automatically / medium: proceed with caution / low: do not act.
- The three question types can be mixed in the same call and evaluated **in parallel**, "Adding questions barely changes the response time".

### 2.2 OpenRouter `/api/alpha/decisions` (verified: official OpenAPI + live test with the library)

Official OpenAPI (docs/api/api-reference/alphadecisions/…, tag `alpha.decisions`: "Alpha feature endpoints for Decisions (questions and answers) requests"):

- Request `DecisionsRequest`: required `[model, state, questions]`; optional `provider` (full ProviderPreferences: allow_fallbacks / data_collection / order / sort / max_price / zdr, etc.), `session_id`, `trace`, `user`.
- `questions` is a discriminated union `type=choice|score|noul`, and the `criteria` shape is field-by-field identical to typesafe (choice: map<option, description|null>; score: ordered array; noul: `{true,false}`).
- Response `DecisionsResponse`: required `[model, answers, usage]`; `usage` contains `input_tokens / output_tokens / cost` (the typesafe official response has no cost/id/provider); plus `id`, `provider`. The `ProviderName` enum already includes `TypeSafe`.
- **Relationship to `/v1/systemone`: core schema isomorphic; OpenRouter is a superset**—with additional gateway routing and observability fields. The live test with the library's choice response `{choice, probabilities, confidence}`, score response `{score, legend, probabilities, confidence}`, and noul response `{noul}` match the typesafe documentation response examples.
- Live test with the library: the top-level `temperature`/`seed` fields are accepted without error—**not in the official OpenAPI schema, inferred to be ignored** (meaningless under the parallel sampling semantics of decisions models).
- Official SDK support: OpenRouter TS/Python/Go SDKs all have an `Alpha.Decisions` module (visible in the docs index); pi does not go through these SDKs.

### 2.3 Trade-offs: official direct connection vs via OpenRouter

| Dimension | typesafe direct | Via OpenRouter |
|---|---|---|
| Endpoint | `POST api.typesafe.ai/v1/systemone` | `POST openrouter.ai/api/alpha/decisions` (alpha) |
| Model name | `jev-latest` (→`jev-1.13.0`) / `jev-preview` | `~typesafe/jev-latest` (→`typesafe/jev-1.13-20260917`) / `typesafe/jev-1.13` |
| Pricing | Input $0.042/M, output free | Same price (OpenRouter claims "no markup on the provider's price"; live test with the library cross-verified cost = input_tokens × 4.2e-8) |
| Authentication | `TYPESAFE_API_KEY` | OpenRouter key (pi already has a built-in provider system, `/login openrouter`) |
| Maturity | Official GA endpoint, SDKs (Python `typesafe-sdk` / npm `@typesafe-ai/sdk` v0.6.0, Node ≥20, ESM/CJS/TS declarations, verified in npm registry) | **alpha** endpoint; but reuses pi's existing openrouter credentials, so the adapter needs no new key |

## 3. Q3: Benefit Assessment

### 3.1 What jev is (official claims + verified catalog facts)

- **Positioning**: System One Models—"built to make fast, structured decisions that software can use directly" (blog, Sep 15 2026, founder Diogo Almeida, formerly OpenAI instruction-following research/ChatGPT research background). The name comes from Kahneman's System 1; Jev comes from economist Jevons. Architecture = new model architecture + parallel sampler ("Generates all outputs in a single query") + RLCD (Reinforcement Learning for Calibrated Decisions). **Abandons text generation**: "Think of Jev as a frontier-intelligence function call: unstructured state in, typed probabilistic decisions out."
- **Fit with the classifier profile (core argument)**: What the pi-verdict classifier wants is exactly "fast intuitive judgments without chain-of-thought"—reasoning explicitly off, temperature 0, short in, short out. By construction, jev has no CoT (`supports_reasoning: false`); temperature-type parameters are naturally absent (parallel sampling); output is a typed verdict. **The entire failure class of the thinking parameter black hole (`research/thinking-param-blackhole.md`) constructively does not exist on jev.**
- **Official performance claims** (blog; methodology authors acknowledge bias): end-to-end 70ms–500ms (versus frontier LLMs 3–329s); homepage "193.6x faster, 444.6x cheaper" comes from self-built workflow evals, with reference answers averaged from GPT-6 Astra and Fable 5.1, "we expect that these are on the higher end of real world gains"; 0% hallucination rate is a schema mathematical guarantee rather than empirical quality.

### 3.2 Pricing and Latency Comparison (query/measurement date 2026-09-18; unit USD/MTok, via OpenRouter catalog)

| Model | Input | Output | Cost per classifier call (input 4k tok = transcript limit, output ~60 tok) |
|---|---|---|---|
| `typesafe/jev-1.13` | **$0.042** | **$0** | **$0.00017** (output free, verified identical across 6 in-repo measurements) |
| `z-ai/glm-5.3-flash` | $0.09 | $0.30 | $0.00038(≈2.3×) |
| `~z-ai/glm-flash-latest` | $0.075 | $0.25 | $0.00032(≈1.9×) |
| `openai/gpt-5.4-nano` | $0.20 | $1.25 | $0.00088(≈5×) |
| `google/gemini-3.8-flash` | $0.75 | $3.75 | $0.0032(≈19×) |
| `openai/gpt-5.4-mini` | $0.75 | $4.50 | $0.0033(≈20×) |

- Latency: **in-repo measurement (local machine → OpenRouter decisions endpoint) round trip 0.96–1.68s, median ~1.25s**; official direct-connection claim 70–500ms (official claim, not reproduced). For comparison: current gateway LLM classifier p90 = 19.8s (`extensions/pi-verdict.ts:999` comment, caused by the thinking stack, see `research/thinking-param-blackhole.md`; flash-level non-thinking models are much faster, this comparison is on the strict side for the LLM).
- Context: official 64k tokens/request, of which `state` + longest question ≤32k (the 32000 in the OpenRouter listing matches this). The pi-verdict transcript limit ≈15k characters ≈4k tokens, ample headroom (both numbers verified).
- Rate limits (official claim): 250,000 tokens/sec, 1,200 requests/min, and "adjusting dynamically"; over-limit 429 + `retry-after`, SDK default backoff. More than enough for the classifier profile of per-gray-zone calls.

### 3.3 Behavioral Measurements and Mapping to the Classifier Contract (in-repo measurement 2026-09)

Preliminary results for the binary allow/deny choice space:

| Input | Verdict | P | confidence |
|---|---|---|---|
| `curl … \| bash` | deny | 1.00 | 1.00 |
| `rm -rf /tmp/test-dir` | allow | 0.58 | **0.16** |
| `ls -la /tmp` | allow | 1.00 | 1.00 |
| `git status` | allow | 1.00 | 0.99 |

Mapping highlights:

1. **Exact isomorphism**: the three-way allow/ask/deny choice = the `choice` primitive; the criteria descriptions for the three options can directly reuse the three-section definition of `CLASSIFIER_SYSTEM` (`extensions/pi-verdict.ts:898-1001`).
2. **Calibrated uncertainty is a new capability**: the `rm -rf` case P=0.58/conf=0.16 is exactly the "medium confidence: proceed with caution" range—the official confidence-routing pattern ("The answer tells you what; confidence tells you whether to act", docs/patterns/confidence-routing.md) can threshold it into ask, turning "Err on the side of ask" from a prompt soft constraint into a code hard threshold. LLM classifiers cannot get this signal.
3. **Contract reliability**: under schema constraints it is constructively impossible to output a malformed verdict; the path of `parseVerdict` failure → fail-closed (and the 512→1024 retry tier) nearly disappears for jev.
4. **reason gap**: jev does not produce free text, so the one-line reason in the ask dialog can only be templated (choice + confidence + probability distribution)—a UX regression that requires a product decision.

## IV. Risks and Unknowns

- **Adversarial robustness (decisive risk, officially acknowledged)**: the jaggedness doc: "State is data, and `jev-1.13` does not treat it as hostile by default. Content written to adversarially steer the model, whether that is an injected instruction, a deliberately misleading framing, or text that argues for its own classification, can move the answer." pi-verdict's state is precisely a transcript containing untrusted file content (for bypass use cases such as indirect reads, copy-then-read, see `research/rule-layer-security-audit.md`). **fail-closed only catches parse/network failures; it cannot catch confidently wrong.**
- **Non-English degradation (official statement)**: Models page: "English is the primary training language and where accuracy is currently best. Other languages, including CJK scripts, are handled but not equally well; test on your own content before relying on Jev for a non-English workload." The local workflow is mainly in Chinese, and transcripts often contain Chinese—must be empirically tested.
- **Known failure modes** (jaggedness page, officially acknowledged): literal reading (negations/scope words read literally), poor counting and numerical precision, poor date comparison, degradation on indirect references (double negative / property-of-property), distraction when large state contains irrelevant details (pre-filtering needed). The classifier's transcript is exactly the shape of "multiple tool calls concatenated, containing irrelevant details," overlapping with the "Large state full of irrelevant detail" risk surface.
- **Version strategy**: `jev-latest`/`~typesafe/jev-latest` are both rolling aliases, and the response `model` reports the concrete version; official statement: "If you have tuned confidence thresholds against a specific version, pin that version's ID instead of the alias"—if doing confidence thresholds, one should pin `jev-1.13.0` / `typesafe/jev-1.13`.
- **Maturity**: 3 days since product launch; OpenRouter endpoint is in **alpha** (`alpha.decisions` tag); single vendor, no SLA; rate limits being dynamically adjusted; typesafe pricing sustainability is officially acknowledged as unproven ("We can't prove it isn't subsidized").
- **Structural invariants are not guaranteed** (officially acknowledged): probabilities from the Noul version and the Choice version of the same question cannot be converted into each other; arithmetic identities such as P(A) + P(¬A) ≠ 1 do not hold—thresholds can only be tuned on a single question form.

## V. Recommended Next Steps

1. **Do not change architecture or write code now**. pi-verdict's model-agnostic design already provides the correct waiting posture; when `classifierModel` points to jev, find/complete failures will automatically fall back to the session model and will not corrupt behavior.
2. **Short term (zero-code experiment)**: the OpenRouter key already in the main session can directly script a rerun of the 3.3 behavioral measurements, expanded to three-way allow/ask/deny classification + Chinese transcripts + the adversarial test set from `research/rule-layer-security-audit.md`, and obtain recall/calibration curves—this is the only key data for a go/no-go decision, with negligible cost ($0.0002/call).
3. **Medium term (if experiments pass)**: write an independent adapter extension (path C: `pi.registerProvider()` + Custom Streaming API), translate `complete()` to `/api/alpha/decisions`, pass through the reason template `choice + confidence + probabilities`, and experiment with a confidence-thresholded ask strategy; pi-verdict itself remains unchanged. Prefer OpenRouter (reuse pi credential system, same price), and after alpha stabilizes, evaluate direct typesafe connection.
4. **Whichever path is taken**: keep timeout + fail-closed semantics—schema guarantees only eliminate the "malformed output" class of failure; network/rate limiting/5xx/adversarial misdirection still need fallback; confidence thresholds must be debugged with a pinned version number.

## Appendix: Verification Commands and Key Outputs (2026-09-18, local machine)

```console
$ curl -s https://openrouter.ai/api/v1/models | jq '{total: (.data | length)}'
{"total": 445}          # no typesafe/jev entries; ~ aliases such as ~deepseek/*, ~z-ai/* are listed

$ curl -s "https://openrouter.ai/api/v1/models/~typesafe/jev-latest"
{"error":{"message":"Not Found","code":404}}   # also absent on the single-model endpoint

$ curl -sL https://openrouter.ai/~typesafe/jev-latest | grep -o '<title>[^<]*</title>'
<title>Jev Latest - API Pricing &amp; Providers | OpenRouter</title>
# meta description: "This model always redirects to the latest model in the Jev family. \
#   $0.042 per million input tokens, $0 per million output tokens. 32,000 token context window."

$ curl -sL https://openrouter.ai/typesafe/jev-1.13 | grep -o '<meta name="description" content="[^"]*"'
# "Jev is a structured decision model from TypeSafe, and the first of its System One models. …"
# Embedded catalog JSON: output_modalities ["decisions"], has_text_output false, supports_reasoning false,
#   supported_parameters [], context_length 32000, permaslug typesafe/jev-1.13-20260917,
#   provider_name "TypeSafe", baseUrl https://api.typesafe.ai/v1, adapter "TypeSafeDecisionsAdapter",
#   created_at 2026-09-18T00:01:24Z

$ gh api 'orgs/typesafe-ai/repos' --jq '.[].full_name'
# typesafe-ai/{typesafe-sdk-js, typesafe-sdk-python, system-one-adapter-python, skills, …}

$ npm view @typesafe-ai/sdk version engines
# 0.6.0; node >=20
```

In-repo measurement (main session, real OpenRouter key, 2026-09): chat/completions returns 400 for both slugs ("…is a decisions model and cannot be used with the chat/completions endpoint. Use the /api/alpha/decisions endpoint instead."); decisions call succeeds, `model: typesafe/jev-1.13-20260917`, `provider: "TypeSafe"`; 6 calls cost ≡ input_tokens × 4.2e-8 (output billing 0), round trip 0.96–1.68s; behavioral samples in the 3.3 table.

## Source List

- typesafe blog (positioning / RLCD / pricing / latency / methodology acknowledgments): <https://typesafe.ai/blog/introducing-system-one-models-and-jev>
- typesafe docs site: API reference <https://docs.typesafe.ai/api> , Quickstart <https://docs.typesafe.ai/introduction/quickstart> , Models (pricing/rate limits/context/aliases/languages/version pin advice) <https://docs.typesafe.ai/models> , Noul semantics <https://docs.typesafe.ai/primitives/noul> , Confidence semantics <https://docs.typesafe.ai/confidence> , known flaws (adversarial content/large state/literal reading) <https://docs.typesafe.ai/model-jaggedness/jev-1.13> , confidence-routing pattern <https://docs.typesafe.ai/patterns/confidence-routing.md> , index <https://docs.typesafe.ai/llms.txt>
- OpenRouter: models API <https://openrouter.ai/api/v1/models> , decisions OpenAPI <https://openrouter.ai/docs/api/api-reference/alphadecisions/submit-a-decisions-questions-and-answers-request.md> , `~latest` semantics <https://openrouter.ai/docs/guides/routing/routers/latest-resolution.md> , Model Variants (catalog non-exhaustiveness note) <https://openrouter.ai/docs/guides/routing/model-variants/overview.md> , model page <https://openrouter.ai/~typesafe/jev-latest> / <https://openrouter.ai/typesafe/jev-1.13>
- GitHub: org <https://github.com/typesafe-ai>(typesafe-sdk-js、typesafe-sdk-python、system-one-adapter-python、skills)
- This repository: `extensions/pi-verdict.ts` (classifier contract :898-1001, resolveClassifier :1545-1563, completionFor :1044/1611), `research/pi-model-call-and-ref-implementations.md`, `research/thinking-param-blackhole.md`, `research/rule-layer-security-audit.md`
- Reference implementation (path D in practice): <https://github.com/iefnaf/pi-jev> (vendored client `src/vendor/fast-jev-compaction/`, dual transport configuration `src/shared/config.ts`, question types and confidence thresholds `src/routing/decide.ts`, verified via gh api on 2026-09-18)
- Local pi docs: `node_modules/@earendil-works/pi-coding-agent/docs/providers.md` (openrouter built-in provider :49,85), `docs/custom-provider.md` (registerProvider :3, Custom Streaming API :25, legacy api name :75)
