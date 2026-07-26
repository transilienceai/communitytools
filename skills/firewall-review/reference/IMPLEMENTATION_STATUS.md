# Implementation Status and Capability Boundary

This `communitytools` package is a transferable skill/reference layer. It contains Markdown operating guidance; it does **not** contain the `fwrr` Python package, detector implementations, semantic catalogue YAML, CIS inspector engine, CLI scripts, or Excel/PDF renderers cited by some reference pages.

The existing skill pages point to `https://github.com/ipunithgowda/firewall-review` as their reference implementation. During validation on 2026-07-26, both Git clone and GitHub API access returned repository-not-found/404. The implementation may be private, moved, or removed; its current contents and behavior could not be independently verified.

## What this contribution proves

- The skill instructions are present, internally linked, and structurally valid.
- PR #32’s five FortiGate detector references, semantic catalogue reference, and CIS benchmark reference have been preserved on a clean branch.
- The evidence-state, custom-policy-benchmark, and consolidated-workbook profiles define claim-safe behavior for future implementations or engagement-specific workflows.

## What this contribution does not prove

- That the named `fwrr.*` modules or CLI commands currently execute.
- That 22 executable detectors, 15 executable semantic checks, or 64 executable CIS checks are shipped in this repository.
- That the current runtime produces the six-sheet base workbook or the network-team collaboration profile.
- That version pins, function names, line numbers, and behavior described in inherited runtime-reference pages still match an accessible implementation.

## Capability acceptance gate

Before describing a capability as implemented, require all of the following:

1. An accessible, version-pinned runtime repository or vendored implementation.
2. Automated detector/parser/renderer tests and representative fixtures with no customer data.
3. A traceability matrix from each documented check to code and tests.
4. End-to-end execution against a synthetic configuration with reconciled rule/finding counts.
5. Workbook round-trip and visual QA for the reporting profile.
6. A recorded implementation commit SHA in the engagement manifest.

Until those gates pass, describe this package as an audit methodology/skill and reference specification, not as a functional Nipper replacement.
