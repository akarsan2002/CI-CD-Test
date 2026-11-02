# mini-aibom

A small AI Bill of Materials scanner, built to **learn how scanners work**.
Pure Python 3.11+, zero dependencies. Every file has `LESSON n` comments.

## Run it

(On Windows use `python`. On macOS/Linux you may need `python3`.)

```bash
python -m mini_aibom scan demo_project                 # table
python -m mini_aibom scan demo_project -f cyclonedx    # standard BOM format
python -m mini_aibom scan demo_project --fail-on high  # exit code 1 (CI)
python -m unittest discover -s tests -v                # run tests
```

All keys and secrets in `demo_project/` are fake.

## The whole idea in one picture

```
files --> [ scanners ] --> AIComponent --> [ risk score ] --> [ reporter ] --> output
          (many, each        (one common      (stateless        (table/json/
           reads one          shape)           function)         cyclonedx)
           kind of file)
```

## Reading order (about 45 minutes)

1. `models.py` the one shape every finding takes
2. `base.py` auto-registration, `supports()` vs `scan()`
3. `scanners/dependency_scanner.py` parsing structured files (the easy, reliable case)
4. `signatures.py` the detection DATA (the long-term maintenance burden)
5. `scanners/code_scanner.py` regex on free text, confidence, false positives, masking secrets
6. `scanners/model_file_scanner.py` evidence without reading content
7. `scanners/mcp_config_scanner.py` where inventory turns into security judgment
7b. `scanners/n8n_scanner.py` built against a REAL n8n export (read its docstring: it lists what the real file taught us)
7c. `detect.py` shared helpers, and why lookalike domains need care
7d. `scanners/log_scanner.py` behavior (network logs) vs intent (config/code), streaming, aggregation
8. `risk.py`, `engine.py`, `reporters.py`
9. `tests/test_scanners.py` each test documents a behavior we care about

## Then compare with Trusera

Open their repo next to this one and read, in this order: `models.py`,
`scanners/base.py`, `scanners/code_scanner.py`, `detectors/` (their signatures),
`utils/risk_scorer.py`, `reporters/cyclonedx.py`. For each, ask:
what do they do that we don't, and is it worth it?
(Their ARCHITECTURE.md says detection is regex by default with an optional
AST mode. Check the code to confirm how it really works.)

## Added in this version: n8n scanner + shared detectors

- `scanners/n8n_scanner.py` reads n8n workflow exports (found by structure, not filename).
- `detect.py` holds key/endpoint/model detection shared by scanners.
  Endpoint matching now rejects lookalike domains (`api.openai.com.evil.example`).
- `fixtures/n8n/` holds one REAL export plus hand-written fixtures. Files named
  `*_HANDWRITTEN` use formats from memory and must be replaced with real exports.
- When two scanners could report the same file, the generic one steps aside (LESSON 16).

- `scanners/log_scanner.py` reads `.log` files (DNS/proxy style), matches hostnames
  exactly (never substrings), and reports one finding per source+service with a count.
  Fixtures are `*_HANDWRITTEN.log` (formats from memory, not real captures).
  It finds AI *activity*, not "shadow" AI: that needs an approved list to compare against
  (exercise: add an `approved.toml` and flag anything seen but not approved).

- `collectors/syslog_udp.py` + `python -m mini_aibom listen` is a tiny live syslog receiver
  (UDP, localhost only by default) that reuses the log scanner's matching. Test it with
  `python tools/send_test_syslog.py`. It is a TESTING tool: UDP syslog has no authentication.
  Collectors GET data, scanners ANALYZE it (LESSON 20).

- **CI/CD:** `-f sarif -o results.sarif` writes SARIF 2.1.0 (validated against the official
  schema), `--fail-on <severity>` sets the exit code (0 ok, 1 findings at/above threshold,
  2 tool error), and `.github/workflows/ai-bom.yml` is a ready GitHub Actions workflow.
  Test the gate locally in PowerShell: `python -m mini_aibom scan demo_project --fail-on high; $LASTEXITCODE`
  NOT yet built: fail only on NEW findings (needs a baseline/diff), scan only changed files,
  PR comments.

**Still unconfirmed:** how n8n stores `credentials` references (the real export had none),
most AI node type names (only `openAi` is confirmed), and what `settings.availableInMCP`
means exactly. Re-export a workflow with a credential attached to settle the first one.

## Known limitations (deliberate, so you can fix them)

Look at the demo output: **LangChain appears 4 times** and Anthropic appears
several times. There is no aggregation. Also `confidence` is recorded but the
risk score ignores it. Also only Python and JS/TS imports are parsed.

## Exercises, easiest first

1. **Add a Dockerfile scanner.** Detect `FROM ollama/ollama`, `vllm/vllm-openai`,
   `huggingface/text-generation-inference`. New file + one import line in
   `scanners/__init__.py`. Nothing else changes. That is the registry paying off.
2. **Add a GitHub Actions scanner.** Parse `.github/workflows/*.yml` for AI actions
   or steps that call model APIs. (No YAML library installed, so start with
   line matching, then decide if a dependency is worth it.)
3. **Aggregate findings.** Group by (name, category) and show "LangChain: 4 locations".
   Where should this live: engine, reporter, or a new step? Argue for your choice.
4. **Use confidence in scoring.** Should a 0.6-confidence model-name string score
   the same as a 1.0 import? Try weighting and see how the output changes.
5. **Reduce false positives.** Put `"model": "gpt-4"` inside a test file or a
   docs string. Does it get reported? Add test-file detection and decide whether
   to skip or just lower confidence.
6. **Add Go and Java import parsing.** Notice how each language needs its own pattern.
   This is the cross-language cost of regex scanning.
7. **Write a ground-truth test.** Hand-label a small real repo (what AI usage
   truly exists), run the scanner, and compute precision and recall. This
   habit matters more than any single scanner.
8. **Taint-lite (hard, this is where our product can differ).** For Python,
   use the `ast` module to find calls like `client.chat.completions.create(...)`
   and check whether the `messages` argument contains a variable that came from
   `request.args` / `input()`. That is a first step toward "untrusted input reaches
   a model", which is reachability, not just inventory.

## What this does NOT do

No live cloud scanning, no Docker or network scanning, no AST analysis,
no reachability, no compliance mapping. Signatures are a small starter set and will
miss many SDKs. It is a learning tool, not a production scanner.
