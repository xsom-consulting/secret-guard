# BMad installation provenance

BMad Method 6.12.1 is reused from the existing Fleet installation at commit
`b1a24df04869324c1d9eb53c266ed52909b1a13c`. The installed `_bmad/`, `.agents/skills/bmad-*` and
`.claude/skills/bmad-*` layout is retained; no planning workflow was regenerated.
Generic templates shipped with BMad are tooling, not project planning documents.

Upstream: https://github.com/bmad-code-org/BMAD-METHOD/tree/v6.12.1
License and attribution: `LICENSE`, `CONTRIBUTORS.md`, `TRADEMARK.md` in this folder.

Only project identity, output destinations and generic maintainer settings are adapted.
Personal `*.user.toml` overrides, environment files and rendered caches are excluded.
`custom/config.toml` is the committed source of repository overrides.
The legacy YAML configuration mirrors its output destinations.

Planning stays in the private product-planning repository. Check it out next to the public repository before running a planning workflow. Verify that the resolved output paths target that private checkout. If it is unavailable, stop; never fall back to writing planning files into the public repository.

The copied manifests describe the original installer distribution. Their historical
installation dates are retained; this is a reuse, not a fresh upstream installation.

Trailing whitespace in three bundled Markdown files was normalized during import;
their instructions and templates are unchanged.
