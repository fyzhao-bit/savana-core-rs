# Savana — USENIX Security '27 paper skeleton

LaTeX sources for the paper draft that describes the kernel at commit
`bee2ed3` (2026-09-02). Sections 1–8 and 10–12 are drafted from the code;
Section 9 (Evaluation) is a skeleton with research questions, setup notes
and table shells whose numbers are marked `TBD`. Search for `TODO` before
submission.

## Files

| File | Purpose |
| --- | --- |
| `main.tex` | The paper. Compiler: pdfLaTeX. Bibliography: BibTeX. |
| `references.bib` | Bibliography. Entries flagged `verify` need a metadata check. |
| `usenix-fallback.sty` | Approximation of the USENIX layout so the project compiles before the official style file is present. **Not for submission.** |

## Open in Overleaf

1. Zip this directory (or upload the three files) into a new Overleaf
   project, or start from Overleaf's "USENIX Security" gallery template
   and copy `main.tex` and `references.bib` into it.
2. Download the official template from the USENIX author-resources page
   (<https://www.usenix.org/conferences/author-resources/paper-templates>)
   and copy `usenix-2020-09.sty` next to `main.tex`. `main.tex` picks it
   up automatically via `\IfFileExists` and stops using the fallback.
3. Set the main document to `main.tex`, compiler to pdfLaTeX, and compile
   (Overleaf runs BibTeX automatically).

## Local build

```sh
latexmk -pdf -interaction=nonstopmode main.tex
```

## Submission checklist (USENIX Security)

- Double-blind: keep `\anonymoustrue` in `main.tex`; remove identifying
  repository URLs from the Open Science section until camera-ready.
- Check the current CFP for the page limit (13 pages excluding
  references and appendices in recent cycles) and for the mandatory
  Ethics Considerations and Open Science sections, both already present.
- Fill Section 9 and replace every `TODO`/`TBD`; the abstract,
  introduction and conclusion each carry one `TODO` for the headline
  result.
