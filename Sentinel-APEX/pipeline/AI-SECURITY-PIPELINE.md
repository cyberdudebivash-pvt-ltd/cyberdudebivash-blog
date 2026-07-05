# SENTINEL APEX — AI Security Intelligence Pipeline

Dedicated AI Security Intelligence pipeline, run **alongside** (never merged with)
the general cyber intelligence pipeline (`fetch-live-intel.js` / sentinel-apex.yml).

## Why a separate pipeline

1. AI security uses different frameworks (MITRE ATLAS, OWASP LLM Top 10) than
   traditional endpoint/network security, so dedicated analysis is more accurate.
2. It lets Sentinel APEX become a recognized authority in AI security without
   diluting the quality of the broader cyber threat intelligence platform.

Doctrine: `Sentinel-APEX/prompts/ai-security-master-prompt.md` (the Division
Constitution — evidence first, never invent, always assign confidence).

## Pipeline stages

```
AI Security Collection            (dedicated sources: GHSA, NVD, arXiv, community leads)
        │
        ▼
Source Verification               (tiering: authoritative / research / community-lead)
        │
        ▼
AI-Specific Classification        (taxonomy from the Constitution collection targets)
        │
        ▼
Evidence Correlation              (dedup, corroboration count, prior-report linking)
        │
        ▼
MITRE ATLAS Mapping               (rule-based technique mapping)
        │
        ▼
OWASP LLM Top 10 Mapping          (LLM01–LLM10, 2025 list)
        │
        ▼
AI Agent Risk Analysis            (agentic / MCP / RAG / tool-use flags)
        │
        ▼
Enterprise Impact Assessment      (severity, affected products/vendors)
        │
        ▼
Detection Engineering             (behavioral indicators + detection opportunities)
        │
        ▼
Threat Hunting Guidance           (per-category hunting starters)
        │
        ▼
Executive Review                  (optional LLM analyst stage — full Constitution
        │                          report format; runs only when ANTHROPIC_API_KEY
        ▼                          is configured; model: claude-opus-4-8)
Quality Gates                     (Constitution publication rules — leads that fail
        │                          the evidence bar are HELD, not published)
        ▼
Publishing                        (api/intel/ai-security.json + ai-security/intel/)
        │
        ▼
API / Dashboard / Alerts          (JSON feed is the machine-readable product)
```

## Engine

`ai-security-intel-engine.js` (repo root, convention-consistent with
`fetch-live-intel.js`): dependency-free Node ≥ 18, atomic writes, state file
`ai-security-intel-state.json`, memory `ai-security-intel-memory.json`.

Run locally:

```bash
node ai-security-intel-engine.js              # collection → publication
node ai-security-intel-engine.js --dry-run    # no file writes, prints decisions
ANTHROPIC_API_KEY=... node ai-security-intel-engine.js --analyst   # + LLM reports
```

## Quality gates (enforced in code)

An item is **published** only if:
- it passes the AI-relevance gate (must match AI collection-target taxonomy), and
- it has a title, canonical URL, and timestamp, and
- its evidence bar is met:
  - tier-1 authoritative source (GHSA, NVD, vendor/government advisory), or
  - tier-2 research source (arXiv, peer-reviewed) with ≥ 1 corroboration, or
  - tier-3 community lead with ≥ 2 independent corroborations.

Items that fail the bar are retained in state as `leads` (never published,
re-evaluated on later runs when corroboration may have arrived). Every published
item carries a confidence block (source/evidence/overall + rationale) and an
evidence label (`VERIFIED_ADVISORY`, `PUBLISHED_RESEARCH`, `CORROBORATED_LEAD`).

## Scheduling & deploy budget

Workflow: `.github/workflows/ai-security-intel.yml`, cron `0 */2 * * *`
(even UTC hours :00). This lands pushes inside the Vercel deploy window defined
by `vercel-ignore-build.sh` (bot builds allowed only in the first 10 minutes of
even UTC hours), so the pipeline never contributes to deployment rate-limit
exhaustion. Commit prefix `SENTINEL APEX AI-SEC:` is matched by the bot throttle.

## Outputs

| Product | Path |
|---|---|
| Machine-readable feed (API payload) | `api/intel/ai-security.json` |
| Intel listing page | `ai-security/intel/index.html` |
| Full analyst reports (LLM stage, optional) | `ai-security/reports/*.html` + `.json` |
| State / dedup / leads | `ai-security-intel-state.json` |
| Correlation memory | `ai-security-intel-memory.json` |
