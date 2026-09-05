# Savana: Binding Agent Actions to Authorized Task Traces

Implementation-grounded working draft, revised 2026-09-05 against code snapshot
**73e0684** on codex/intent-bound-execution. This replaces the older
information-flow-only paper skeleton. The user's original LaTeX attachment is
preserved unchanged; revisions live here.

This is **not a submission-ready paper** and does not assert a reviewer score.
The implementation increment and engineering checks are complete within the
documented boundary. Empirical security, utility, approval-burden and performance
experiments remain unrun. The PDF is a readable working draft, not a certified
USENIX-formatted submission.

## What changed

- Separately authenticated task authority precedes planning; action approval
  cannot enlarge it.
- Complete resource/destination/action alternatives replace independent field
  reasoning. Seven control selections and their endorsements remain separate
  from ordinary data provenance and the existing G1–G7 gates.
- Atomic task accounting survives replanning, fresh identifiers and authority
  recovery. Executor checks constrain the actual request and retained response.
- Native multi-step, malicious-worker, ACK-loss and executor-reopen witnesses
  are distinguished from end-to-end product and empirical claims.
- Prior work includes CaMeL, Fides, Progent, PCAS/FORGE, IGAC and CapAgent.
  The paper does not claim to invent IFC, endorsement or intent capabilities.
- Evaluation is an explicitly unrun design, without invented result tables.
  Limitations include contract fidelity, closed codecs, missing full kernel
  session reconstruction, pending ACK cleanup and unverified live deployment.

## Files and evidence

| File | Purpose |
| --- | --- |
| main.tex | Anonymous working paper; pdfLaTeX and BibTeX. |
| references.bib | Cited primary sources with version-specific metadata. |
| usenix-fallback.sty | Local layout approximation, not for actual submission. |
| [Claim map](../../docs/verification/intent-bound-claims.md) | Mechanism → production code → test → limit. |
| [Verification record](../../docs/verification/intent-bound-execution.md) | Exact commands, outcomes, failed attempts and exclusions. |
| [Chinese summary](../../docs/academic-summary.zh-CN.md) | Current implementation and research boundary in Chinese. |

The paper reports engineering evidence, including nine native tool cases, seven
native release cases and 1,440 bounded accounting traces. Those are not attack
success rates, an exhaustive distributed proof or independent user tasks.
Default-workspace checks passed. Feature coverage combines a passed long replay
case with a clean sequential rerun filtering only that already-tested case;
the record does not mislabel this as one clean unfiltered invocation.

## Build locally

Run from this directory with a TeX distribution containing latexmk, pdfLaTeX,
BibTeX, Times fonts and microtype:

~~~sh
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=../../tmp/pdfs/usenix -jobname=savana-intent-bound main.tex
mkdir -p ../../output/pdf
cp ../../tmp/pdfs/usenix/savana-intent-bound.pdf \
  ../../output/pdf/savana-intent-bound.pdf
~~~

The build directory and generated PDF are ignored by Git. Source files remain
the reproducible deliverable. Use Poppler to render every page before delivery.
Do not run differing Cargo feature builds concurrently against the same target
directory when reproducing the native integration fixtures.

## Official template and submission preparation

Obtain the official style from the
[USENIX template page](https://www.usenix.org/conferences/author-resources/paper-templates)
and place usenix-2020-09.sty alongside main.tex. It will automatically replace
the fallback. The official download returned HTTP 403 in this environment;
we did not substitute a third-party file and call it official. Overleaf users
can start from the official USENIX template and copy the paper and bibliography.

The [Security '27 CFP](https://www.usenix.org/conference/usenixsecurity27/call-for-papers)
checked on 2026-09-05 permits 13 main-body pages, excluding references and
appendices, in its prescribed format. An Open Science appendix is mandatory;
an Ethical Considerations appendix is strongly recommended. Both are included
as honest working-draft statements, not as claims that an anonymous artifact
or participant study already exists.

Before submission:

- Run and report the declared experiments, with reproducible inputs, budgets,
  denominators and uncertainty. Establish contract fidelity and utility costs.
- Check all cited revisions and the latest CFP; use the official style, without
  font, margin or spacing changes to evade limits.
- Review anonymity in text, metadata and the frozen artifact. This repository
  itself is not the anonymous artifact.
- Verify the target platform's isolation, identity, complete mediation and
  recovery assumptions independently of debug fixture keys.
- Have the human authors verify every factual and scholarly claim.
