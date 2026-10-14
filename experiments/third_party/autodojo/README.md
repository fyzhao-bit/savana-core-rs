# AutoDojo optimized injections (third party)

These files are copied verbatim from AutoDojo (Ma et al., arXiv:2606.15057),
https://github.com/xhOwenMa/AutoDojo, commit `aa45879`, under its MIT license
(`LICENSE` in this directory).

| File | Upstream path |
| --- | --- |
| `banking-deepseek-v4-flash-no_defense.json` | `agentdojo/variant_generation/variants/banking/deepseek/deepseek-v4-flash/no_defense/injections.json` |
| `slack-deepseek-v4-flash-no_defense.json` | `agentdojo/variant_generation/variants/slack/deepseek/deepseek-v4-flash/no_defense/injections.json` |
| `travel-deepseek-v4-flash-no_defense.json` | `agentdojo/variant_generation/variants/travel/deepseek/deepseek-v4-flash/no_defense/injections.json` |

Each cache holds, for every (injection task, injection vector) pair, up to five
injection texts that AutoDojo's black-box optimizer found against the
undefended DeepSeek V4 Flash agent (optimizer LLM `google/gemini-3.1-pro-preview`,
6 iterations). AutoDojo covers banking, slack and travel only.

`savana_bench/autodojo_cache.py` replays them exactly as AutoDojo's
`AutoDojoAttack` does (variant selection, fallback to the important-instructions
wrapper when a variant equals the unoptimized goal, YAML escaping). We do not
run AutoDojo's code; the runner and the verifier pin these files by SHA-256.
