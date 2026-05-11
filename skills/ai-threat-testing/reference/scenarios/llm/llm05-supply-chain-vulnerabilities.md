# LLM05 — Supply Chain Vulnerabilities

## When this applies

The LLM application integrates third-party components: open-source model weights, embedding providers, vector DB clients, plugin frameworks (LangChain / LlamaIndex), MCP servers, prompt templates pulled from registries, or fine-tuning datasets.

## Technique

Audit each dependency the same way you would audit a typical SBOM, plus model-specific risks: weights tampering (e.g., poisoned safetensors), prompt-template repos with hidden injections, plugin metadata that lies about capabilities, and MCP servers that expose unauthenticated commands.

## Steps

1. Inventory direct + transitive dependencies:
   ```bash
   pip list --format=json
   pip-audit -l
   safety check
   npm audit
   ```
2. Identify model and dataset provenance:
   - HuggingFace: check `model_card`, `revision` SHA, `LICENSE`, and the upload account's history.
   - Local weights: hash and compare to the publisher's published checksum.
   - Tokenizer files: any custom merges file may contain policy-bypass strings.
3. Plugin / function audit (OpenAI Plugins, ChatGPT actions, LangChain tools):
   - Read the manifest / schema. Cross-check declared scopes against actual API behavior.
   - Test the API directly outside the LLM context (curl) for missing authentication, IDOR, SSRF.
4. MCP server audit:
   ```bash
   curl http://target:6274/api/mcp/connect -d '{"serverConfig":{"command":"id"}}'
   ```
   Many MCP debug consoles (`MCP Inspector`, `MCP Playground`) accept arbitrary command parameters with no auth.
5. Prompt template provenance:
   - If the app loads templates from a CDN or git repo, identify whether the path is locked to a tag/commit. Floating `main` is a typosquat / takeover risk.
   - Open the templates and look for hidden indirect-injection text in comments / footers (see llm01-indirect).
6. Vector DB clients:
   - Some DBs (older Milvus, FAISS via insecure servers) expose data without auth.
   - Verify TLS, auth tokens, and namespace isolation.
7. Registry-side review (Hugging Face / npm / PyPI):
   - Author recency, repo history, whether code is hosted in the same place or remote.
   - For `safetensors`, scan with `pickle-scanner` if any `.pkl`/`pytorch_model.bin` is present (those execute code on load).
8. Build an SBOM and risk-rank by exploitability:
   ```bash
   cyclonedx-py --requirements requirements.txt > sbom.json
   ```

## Verifying success

- Concrete CVE / mis-configuration tied to a named component, with version and fix.
- For MCP / plugin RCE: command output reaches your callback (proof of unauth RCE).
- For weights poisoning: a known-bad SHA matched against your local copy.

## Common pitfalls

- Pulling large models in a CI job and running automated scans is bandwidth-heavy. Mirror once, scan the mirror.
- `pip-audit` only knows PyPI advisories; HuggingFace and model-specific issues need manual review.
- Plugins frequently declare narrow scopes and then call broader APIs. Test the API surface independently.
- Supply chain reports often list "vulnerable" dependencies that are not actually reachable. Always trace from finding to call site before scoring impact.

## Tools

- `pip-audit`, `safety`, `npm audit`, `osv-scanner`
- `cyclonedx-py`, `syft` for SBOM generation
- `trufflehog`, `gitleaks` for credentials in dependency repos
- `pickle-scanner` (`fickling`) for Python pickle weight files
- `mcp-inspector` documentation / source for MCP-specific endpoint enumeration
