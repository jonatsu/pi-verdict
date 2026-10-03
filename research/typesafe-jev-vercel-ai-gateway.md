# Research: Feasibility of Vercel AI Gateway as a Second jev Backend Transport

> Research date: 2026-09-19
> Background: pi-verdict's jev classifier backend currently uses only OpenRouter (`extensions/jev-adapter.ts` → `POST https://openrouter.ai/api/alpha/decisions`, reusing pi's OpenRouter login state). The user asked whether Vercel AI Gateway could be supported **at low cost** in addition to OpenRouter, on the basis that "pi-ai has built-in support for Vercel AI Gateway."
> Sources: All conclusions were verified against primary sources—the locally installed pi-ai source (0.84.3 and the latest npm 0.85.1 tarball), Vercel official docs and changelog, `@ai-sdk/gateway@4.0.87` SDK source, the live AI Gateway `/v1/models` directory and unauthenticated endpoint probes, the typesafe official documentation quickstart, and this repository's source. No relevant API keys (`AI_GATEWAY_API_KEY`/`TYPESAFE_API_KEY`) were set locally, so no authenticated calls were made; verification commands and output excerpts are in the appendix.

## Key Conclusions

1. **The user's premise is true, but its utility is limited**: pi-ai does include the `vercel-ai-gateway` provider (0.84.3 and the latest 0.85.1 are identical), but it is just another **chat-class provider**—the API is fixed to `anthropicMessagesApi()`, its model directory has 237 entries, and it has **no jev/evaluation entries**. Its only direct value for the jev backend is the **credential pipeline** (`/login vercel-ai-gateway` or `AI_GATEWAY_API_KEY`, fully analogous to the existing OpenRouter reuse pattern); the adapter itself must still supply the custom transport API. `pi-ai built-in support` does not provide decisions/evaluation call capability (upstream grep found no evaluation/decisions API implementation).
2. **The decisive fact is the opposite**: Vercel AI Gateway **listed jev on 2026-09-16**—the live directory (available without authentication) contains `typesafe-ai/jev`, type `evaluation`, input **$0.042/MTok** (the same price measured on OpenRouter; the gateway states that it adds no markup to provider prices), output $0, and `zdr: "all"` / `no_training: "all"`. The model is not yet in the pi-ai 0.85.1 directory snapshot (the snapshot is stale; the gateway has listed it).
3. **But the gateway does not expose it through OpenAI/Anthropic-compatible endpoints**: the official docs state, "Evaluation is available through the **AI SDK only**. It is not supported through the OpenAI-compatible, Anthropic-compatible, or Cohere-compatible endpoints." The wire contract was extracted from the open-source `@ai-sdk/gateway` source and verified with live unauthenticated probes: `POST https://ai-gateway.vercel.sh/v4/ai/evaluation-model`, the model goes in the **`ai-model-id` request header** (not the body), the body is `{state, questions}`, and the response is `{answers, usage{inputTokens,outputTokens}, warnings, providerMetadata}` (confidence is at `providerMetadata.typesafe.confidence`).
4. **Conclusion: feasible at low cost within a single file**—add a transport branch to `extensions/jev-adapter.ts`, estimated at **40–60 lines**, plus four documentation updates (README.md / README.zh-CN.md / docs/configuration.md / ADR-0003). No changes to pi-verdict itself (gate/classifier/contract). The key mapping is nearly ready: `verdictText()` already parses `{answers.verdict:{choice, probabilities, confidence}}`, which matches the gateway response, so **no change**; add a camelCase branch to `mapUsage()`; remove the `model` field from the request body and add three gateway headers.
5. **Risks and public commitments are at least on par with OpenRouter alpha**: the gateway wire endpoint is not a documented public REST API (AI SDK only), the current protocol version header is `0.0.1`, the spec is `v4`, and the AI SDK labels it experimental; the directory entry's `context_window`/`max_tokens` values are 0 (usage is not checked against the model window, but there is also no upstream window contract to rely on). During implementation, centralize the endpoint/headers as constants and preserve the `PI_VERDICT_JEV_URL` escape-hatch semantics (select the default by transport).
6. **If the goal is only to "get off OpenRouter,"** a third option is direct typesafe connection (`POST api.typesafe.ai/v1/systemone`, `TYPESAFE_API_KEY`, self-service key issuance at console.typesafe.ai), which has the smallest schema difference and the strongest official stability commitment—the request body is identical to OpenRouter decisions except that the `model` value changes from `~typesafe/jev-latest` to `jev-latest`. The gateway path adds value through the Vercel ecosystem (credits/budgets/request logs/team management and ZDR/No-Training declarations).

---

## I. Verify the Premise: What Is pi-ai's Built-In vercel-ai-gateway Provider?

The local repository's devDeps include `@earendil-works/pi-coding-agent@0.84.3` (`package.json:59`), which depends on `@earendil-works/pi-ai`. The provider definition in full (byte-for-byte identical in 0.84.3 and the 0.85.1 tarball):

```js
// node_modules/@earendil-works/pi-ai/dist/providers/vercel-ai-gateway.js
export function vercelAIGatewayProvider() {
    return createProvider({
        id: "vercel-ai-gateway",
        name: "Vercel AI Gateway",
        baseUrl: "https://ai-gateway.vercel.sh",
        auth: { apiKey: envApiKeyAuth("Vercel AI Gateway API key", ["AI_GATEWAY_API_KEY"]) },
        models: Object.values(VERCEL_AI_GATEWAY_MODELS),
        api: anthropicMessagesApi(),
    });
}
```

- Provider ID `vercel-ai-gateway`, baseURL `https://ai-gateway.vercel.sh`, authentication environment variable **`AI_GATEWAY_API_KEY`** (`dist/env-api-keys.js:88`).
- **API type is fixed to `anthropicMessagesApi()`** (the Anthropic Messages chat protocol; see the pi-ai KnownProvider list at `dist/types.d.ts:19`). pi-ai has no second gateway API; it has no implementation for modalities outside chat completions/messages/embeddings (such as evaluation) (the full 0.85.1 tarball grep for `evaluate|evaluation` returned no relevant matches).
- The model directory comes from `dist/providers/data/vercel-ai-gateway.json` (generated by script, mounted at `models.generated.js:34,74`): the only top-level group key is **`anthropic-messages`**, with **237 models**; grep for `jev|typesafe|decision` returns **0 matches**. The same is true of the snapshot in the latest release, `@earendil-works/pi-ai@0.85.1` (npm view, 2026-09-19)—even after upgrading pi, the built-in provider **does not show jev**.
- Credentials/login: the pi official docs list this provider at `docs/providers.md:86`—use `/login` (stored in auth.json under key `vercel-ai-gateway`) or the `AI_GATEWAY_API_KEY` environment variable. Thus, if the jev adapter uses the gateway, it can **copy the existing OpenRouter credential-reuse pattern**: `ctx.modelRegistry.getProviderAuth("vercel-ai-gateway")` + environment-variable fallback.
- The upstream repository is now **earendil-works/pi** (confirmed with `gh api repos/earendil-works/pi`; the old `badlogic/pi-mono` link in the repository now redirects). The only recent gateway-related commit is "fix(ai): preserve Vercel AI Gateway unsigned thinking"; there is no trace of an evaluation/decisions plan.

**Assessment**: "pi-ai has built-in Vercel AI Gateway support" is true and usable today for an **ordinary LLM classifier**—point `classifierModel` to any gateway chat model in the registry (through `modelRegistry`; no pi-verdict changes, not tested). But for the **jev backend**, the built-in provider does not supply the transport—decisions/evaluation calls must be implemented by the adapter's custom API; only the credential-resolution pipeline can be reused.

## II. Decisive Question: Does Vercel AI Gateway Host jev? Yes, as a First-Class Modality

- **Confirmed by the live directory** (`GET https://ai-gateway.vercel.sh/v1/models`, an endpoint the official docs say requires no authentication): 372 models total, including:

## II. The Decisive Question: Does Vercel AI Gateway Host jev—Yes, and It Is a first-class modality

- **Hard evidence from live catalog** (`GET https://ai-gateway.vercel.sh/v1/models`, official docs note this endpoint requires no authentication): 372 models total, including:

```json
{
  "id": "typesafe-ai/jev",
  "owned_by": "typesafe-ai",
  "name": "Jev",
  "type": "evaluation",
  "supported_specifications": ["v4"],
  "context_window": 0,
  "max_tokens": 0,
  "zdr": "all",
  "no_training": "all",
  "pricing": { "input": "0.000000042", "output": "0" }
}
```

  - `0.000000042 $/token × 1e6 = **$0.042/MTok**`, matching the OpenRouter measurement (`research/typesafe-jev-classifiermodel.md` §5, `extensions/jev-adapter.ts:184-185`); the gateway states that it "adds zero markup to provider token prices" (docs/ai-gateway). Output is billed at $0.
- **Official changelog**: "TypeSafe AI's Jev now available on AI Gateway" (2026-09-16)—model ID `typesafe-ai/jev`, called through AI SDK 7's experimental `evaluate` API (supported since `ai@7.0.105`); confidence is at `result.providerMetadata.typesafe.confidence`; requests appear in gateway logs/reporting/budgets. The only stated caveat is that the API is experimental.
- **Documentation**: the gateway groups this under the new **Evaluation modality** (docs/ai-gateway/modalities → evaluation page): "Evaluate shared state against typed questions and get structured answers back"—question types are `choice` (criteria are a record of option-to-description pairs; answers include `choice` + each option's `probabilities`), `score`, and `boolean` (returns a 0–1 `probability`); one request can include multiple questions in parallel; `state` accepts a string/object/array. This is semantically consistent with the `choice` question structure jev-adapter currently sends to OpenRouter (`VERDICT_QUESTIONS`, `extensions/jev-adapter.ts:51-63`).
- **Key limitation** (exact wording from the evaluation documentation page): "Evaluation is available through the AI SDK only. It is not supported through the OpenAI-compatible, Anthropic-compatible, or Cohere-compatible endpoints." That means `/v1/chat/completions` and `/v1/messages` do not host jev (live probes show both routes exist but return 400 for an empty body; `/api/alpha/decisions` and `/v1/decisions` return 404 under the gateway domain; the OpenRouter-specific path does not exist there).

## III. Wire Contract: Extracted from @ai-sdk/gateway Source + Verified Live Without Authentication

The official docs do not document evaluation as a public REST API, but `@ai-sdk/gateway@4.0.87` (MIT-licensed open source) provides the full contract. `GatewayEvaluationModel` (`dist/index.js`):

- **URL**: `${baseURL}/evaluation-model`, where `baseURL` defaults to `https://ai-gateway.vercel.sh/v4/ai` ⇒ **`POST https://ai-gateway.vercel.sh/v4/ai/evaluation-model`** (`/v4` corresponds to the directory field `supported_specifications: ["v4"]`).
- **Request headers**: `Authorization: Bearer <key>`; global `ai-gateway-protocol-version: 0.0.1` (constant `AI_GATEWAY_PROTOCOL_VERSION`); model-specific `ai-evaluation-model-specification-version: 4` and **`ai-model-id: typesafe-ai/jev`** (the model is in the headers, not the body).
- **Request body**: `{ state, questions, providerOptions? }`.
- **Response schema** (zod): `{ answers: Record<string, {type:'choice', choice, probabilities?} | {type:'score', score, probabilities?} | {type:'boolean', probability}>, rounding?, usage?: {inputTokens?, outputTokens?}, warnings?, providerMetadata? }`—note that usage uses camelCase and has **no cost field** (billing uses Vercel credits; per-call cost is not returned in the response); the changelog says confidence is at `providerMetadata.typesafe.confidence`.

**Live verification** (no key locally; contract checked against error responses, 2026-09-19):

| Probe | Result |
|---|---|
| `POST /v4/ai/evaluation-model`, no protocol header | `400 {"error":{"message":"Unsupported gateway protocol version"}}` |
| Same, with `ai-gateway-protocol-version: 0.0.1` + spec header + `ai-model-id`, empty body | `400`; zod errors require `state: string` and `questions: record` field by field—**an exact match for the SDK source schema** |
| `GET /v4/ai/evaluation-model` | `405` (route exists) |
| Unauthenticated `GET /v1/models` | `200`, 372 models including typesafe-ai/jev |

No authenticated 200 response was tested (no credentials); the probes above confirmed the route, protocol headers, and body schema. The only remaining unknown is whether a successful response includes fields beyond the SDK schema.

## IV. Low-Cost Support Path: Change List

All changes are concentrated in the single file `extensions/jev-adapter.ts` (currently 255 lines); no changes to the main package:

1. **Transport selection**: add an environment variable (for example, `PI_VERDICT_JEV_TRANSPORT=openrouter|vercel|typesafe`, default `openrouter` to preserve current behavior). The `JEVC_PROVIDER` selector in iefnaf/pi-jev is a community precedent (README: "auto-detected; when both keys are present, TypeSafe takes priority").
2. **Endpoint and request headers**: gateway branch default URL `https://ai-gateway.vercel.sh/v4/ai/evaluation-model` (preserve the `PI_VERDICT_JEV_URL` escape-hatch semantics, selecting a different default by transport; current `DECISIONS_URL` logic is at `extensions/jev-adapter.ts:43`). Add the gateway headers `ai-gateway-protocol-version` / `ai-evaluation-model-specification-version` / `ai-model-id` (model ID `typesafe-ai/jev`). In the gateway branch, `buildDecisionsBody()` (`:87-89`) **removes the `model` field**.
3. **Credential resolution**: copy the OpenRouter pattern (`:210-222`)—`getProviderAuth("vercel-ai-gateway")` + `AI_GATEWAY_API_KEY` fallback; the availability-check logic re-registered on `session_start` (`:239-245`) remains unchanged. pi already supports `/login vercel-ai-gateway` (`docs/providers.md:86`), so users do not need to manage the key outside pi.
4. **Response mapping**:
   - **No change** to `verdictText()` (`:102-116`)—the gateway `{answers:{verdict:{type:'choice',choice,probabilities}}}` has the same shape as the existing parser; `confidence` is not in the gateway answer itself, so read it from `providerMetadata?.typesafe?.confidence` (about 3 lines; current logic gracefully omits `confText` when it is missing).
   - Add a camelCase branch to `mapUsage()` (`:118-131`) (`inputTokens`/`outputTokens` → existing snake_case fields; `cost` is always 0 because the gateway does not return per-call cost—`notifyAllows`/audit cost displays must accept this difference or document it).
5. **Documentation**: the "Provider: OpenRouter only, for now" sections in README.md and README.zh-CN.md (README.md:129), host/provider notes in docs/configuration.md, and a gateway transport appendix in ADR-0003. No new npm package files (`package.json:8-14` files list remains unchanged).

Estimated code size: **40–60 lines** (including types and error messages); one PR can complete it. Reuse existing `bun test` pure-function tests for `buildDecisionsBody`/`verdictText`, adding 2–3 gateway response samples.

## V. Comparison of the Three Transports

| Dimension | OpenRouter (current) | Vercel AI Gateway | Direct typesafe |
|---|---|---|---|
| Endpoint | `POST openrouter.ai/api/alpha/decisions` | `POST ai-gateway.vercel.sh/v4/ai/evaluation-model` | `POST api.typesafe.ai/v1/systemone` |
| Stability commitment | Alpha endpoint; schema may change at any time (stated in changelog/measurements) | **AI SDK only** (no public REST commitment); protocol `0.0.1` / spec `v4` / experimental | Official stable v1 API |
| Request body | `{model: "~typesafe/jev-latest", state, questions}` | `{state, questions}` + `ai-model-id` header | `{model: "jev-latest", state, questions}` (same shape as OpenRouter) |
| Response differences | `answers.verdict` + `usage{input_tokens, output_tokens, cost}` | `answers.verdict` (no confidence in answer itself) + `usage{inputTokens, outputTokens}` (no cost) + `providerMetadata.typesafe.confidence` | `answers` (includes confidence) + `usage` |
| Account/credentials | Reuses pi's OpenRouter login state; no additional setup | Vercel account + credits (or team BYOK); pi `/login vercel-ai-gateway` already supported | typesafe account + self-service key at `console.typesafe.ai/keys` |
| Pricing | $0.042/MTok input, $0 output (settlement measured through `usage.cost`) | Same price; no gateway markup; no per-call cost returned, uses credits/budget | Same pricing basis (blog/previous research) |
| Data governance | OpenRouter-side policies | Directory declares `zdr: "all"`, `no_training: "all"` | Official ZDR policy (docs) |
| Additional value | — | Vercel ecosystem budgets/logs/team management/failover | Shortest dependency chain, official support channel |

## VI. Risks and Recommendations

1. **Wire stability**: public commitment for the gateway evaluation contract is weaker than for OpenRouter alpha (the latter at least has API docs and a directory page). During implementation, (a) centralize the endpoint, protocol headers, and spec version as constants at the top of the adapter, with comments pointing to the source (`@ai-sdk/gateway` version); and (b) retain fail-closed behavior (already guaranteed—`streamDecisions` emits an error event on exceptions, and the classifier falls back). 2. **Directory lagging the live catalog**: pi-ai's generated directory lacks jev, which could cause friction if pi later validates model existence; the adapter's self-registered model does not use directory validation (currently `hasConfiguredAuth` checks credentials only), so there is no obstacle. 3. **Suggested sequence**: if the adapter is being changed soon, the typesafe direct-connection branch (official v1, same-shape body, smaller change) and gateway branch can be implemented in the same PR with one transport selector; if choosing just one, the gateway rationale is reuse of pi login without a new account + Vercel budget management, while the typesafe rationale is stability. This is a product tradeoff, not a technical constraint. 4. **Upstream contribution (optional)**: open an issue with earendil-works/pi asking pi-ai to add an evaluation API type (aligned with AI SDK v4 spec), enabling the adapter's custom API to be retired once it is supported (combine with the decisions-related issue recommended in the previous research).


## Appendix: Verification Commands and Output Excerpts

```bash
# 1. live Catalog (No Authentication, Officially Declared Auth-Free Endpoint)
$ curl -sS https://ai-gateway.vercel.sh/v1/models | python3 -c "…"
total models: 372
jev/typesafe/systemone: ['typesafe-ai/jev']   decision*: []
# providers: ['alibaba', …, 'typesafe-ai', …]

# 2. Endpoint Route Probing (2026-09-19, No Authentication)
$ POST https://ai-gateway.vercel.sh/v4/ai/evaluation-model   # no protocol header
-> 400 {"error":{"message":"Unsupported gateway protocol version"}}
$ POST same as above + 'ai-gateway-protocol-version: 0.0.1' + spec/model header + '{}'
-> 400 zod: state expected string / questions expected record
$ GET  /v4/ai/evaluation-model -> 405
$ POST /api/alpha/decisions, /v1/decisions (gateway domain) -> 404
$ POST /v1/chat/completions, /v1/messages -> 400 (route exists)

# 3. pi-ai Version and Snapshot
$ npm view @earendil-works/pi-ai version -> 0.85.1
$ python3 … /pi-ai-0.85.1/.../data/vercel-ai-gateway.json
top keys: ['anthropic-messages']  -> 237 models
jev hits: 0  typesafe hits: 0  decision hits: 0

# 4. @ai-sdk/gateway@4.0.87 Key Source Code (dist/index.js after npm pack)
getUrl() { return `${this.config.baseURL}/evaluation-model`; }
baseURL ?? "https://ai-gateway.vercel.sh/v4/ai"
AI_GATEWAY_PROTOCOL_VERSION = "0.0.1"
getModelConfigHeaders() { return { "ai-evaluation-model-specification-version": "4", "ai-model-id": this.modelId }; }
body: { state, questions, ...providerOptions ? { providerOptions } : {} }
gatewayEvaluationAnswerSchema = z.discriminatedUnion("type", [ choice{choice, probabilities?}, score{score, probabilities?}, boolean{probability} ])
usage: z.object({ inputTokens: optional, outputTokens: optional }).optional()

# 5. Credential Environment Variable Check (Names Only)
AI_GATEWAY_API_KEY: unset  VERCEL_AI_GATEWAY_API_KEY: unset  TYPESAFE_API_KEY: unset
```

Local source references:
- `node_modules/@earendil-works/pi-ai/dist/providers/vercel-ai-gateway.js` (full provider definition, 0.84.3; same in 0.85.1 tarball)
- `node_modules/@earendil-works/pi-ai/dist/env-api-keys.js:88`, `dist/models.generated.js:34,74`, `dist/types.d.ts:19`, `dist/providers/data/vercel-ai-gateway.json`
- `node_modules/@earendil-works/pi-coding-agent/docs/providers.md:86` (gateway login/env/auth.json line)
- `extensions/jev-adapter.ts:37-43, 51-63, 87-89, 102-116, 118-131, 148-157, 200-230, 239-245`
- Previous research: `research/typesafe-jev-classifiermodel.md` (OpenRouter alpha measurements, pricing, ADR basis)

External primary sources:
- <https://vercel.com/docs/ai-gateway> (endpoints/zero markup/BYOK/budgets)
- <https://vercel.com/docs/ai-gateway/modalities> and <https://vercel.com/docs/ai-gateway/modalities/evaluation> ("AI SDK only" statement, question types, usage)
- <https://vercel.com/docs/ai-gateway/models-and-providers> (unauthenticated `/v1/models`, model ID format)
- <https://vercel.com/changelog/typesafe-ai-jev-now-available-on-ai-gateway> (2026-09-16, `ai@7.0.105+`, providerMetadata.typesafe.confidence, experimental)
- `@ai-sdk/gateway@4.0.87` (npm, dist/index.js—wire contract)
- <https://docs.typesafe.ai/introduction/quickstart> (`POST api.typesafe.ai/v1/systemone`, Bearer, console.typesafe.ai/keys, `jev-latest`, `{state, model, questions}`)
- <https://github.com/iefnaf/pi-jev> (dual-transport precedent, `TYPESAFE_API_KEY`/`JEVC_PROVIDER`)
- `gh api repos/earendil-works/pi` (upstream repository's current name; related commit "fix(ai): preserve Vercel AI Gateway unsigned thinking")
