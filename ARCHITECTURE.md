# Hermes Room Architecture

## Data flow

```text
tool call → tool result
  → transform_tool_result hook
  → sanitize_text() [Layer 1]
  → should_review()? → reviewer.review_with_model(ctx.llm) [Layer 2, Mode 1]
  → deterministic re-wash of model output
  → save receipt with reviewer verdict
  → return cleaned text to Hermes context
```

## Modules

- `__init__.py` — `register(ctx)` captures `ctx`, hooks `transform_tool_result`, registers tools.
- `sanitizer.py` — deterministic pipeline (stdlib only).
- `reviewer.py` — `ctx.llm.complete_structured` with `REVIEW_SCHEMA`, `purpose=hermes-room.sanitize`, no provider/model override.
- `receipts.py` — JSONL under `HERMES_HOME/hermes-room/` (hashes + rule IDs + reviewer, never raw by default).
- `schemas.py` — `trust_receipt`, `trust_report` tool schemas.
- `fixtures/` — demo corpus.
- `tests/` — stdlib unittest.

## Mode 1 contract

- `ctx.llm.complete_structured()` with **no** `provider=`/`model=`/`task=` → uses active Hermes Desktop/CLI model.
- Trust gate default: allowed, zero-config, audited as `purpose=hermes-room.sanitize`.
- Only called when `should_review()` is true (deterministic risk medium/high, rules hit, or long imperative content).
- Timeout 20s, max 800 tokens, 8k chars. All failures fail open to Layer 1.

## Failure policy

- Sanitizer error → return original, log warning.
- Reviewer error / non-JSON → keep Layer 1 result, log at debug.
- Receipt DB error → return cleaned, log warning.
- Never throws into Hermes tool loop.

## Privacy

- No network besides the user’s own provider call via `ctx.llm`.
- Receipts are local. No raw content stored by default.
