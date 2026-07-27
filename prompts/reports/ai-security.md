> ⚠ **Superseded** — see `prompts/README.md`. Canonical equivalent:
> `Sentinel-APEX/prompts/ai-security-master-prompt.md`.

# REPORT TYPE — AI / LLM SECURITY INTELLIGENCE

**Version:** 1.0 · **Layer 3** · Inherits Constitution + Production Workflow
**Use when:** the subject is AI/ML/LLM security — prompt injection, model
supply chain, agentic risk, data poisoning, jailbreaks, AI-enabled attacks.

---

## Objective
Own the AI-security intelligence category with analyst-grade, framework-grounded
coverage — the area most saturated with hype and least served by rigor. Every
claim must map to an authoritative framework or cited research.

## Required frameworks (map explicitly)
- **OWASP Top 10 for LLM Applications** (genai.owasp.org) — for LLM-app risks.
- **MITRE ATLAS** (atlas.mitre.org) — adversarial ML tactics/techniques.
- **NIST AI RMF** — governance and risk-management framing.
- Named vendor/lab research for any specific technique or incident.

## Required inputs (never invent)
- The specific model, framework, library, or agent affected, as reported.
- The class of AI weakness (prompt injection, insecure output handling, model
  poisoning, supply-chain, excessive agency, etc.) mapped to OWASP LLM / ATLAS.
- Any CVE where a concrete software vulnerability exists (then also apply the
  CVE report type's evidence rules).

## Section structure
1. **Executive Risk Snapshot** — what AI capability is at risk and the governing
   control that most reduces it.
2. **Threat Overview** — the AI weakness class in plain terms for a CISO.
3. **Framework Mapping** — OWASP LLM item(s), MITRE ATLAS technique(s), NIST AI
   RMF function(s). Map only what the evidence supports.
4. **Technical Analysis** — how the weakness is reached and abused; distinguish
   demonstrated (research) from theoretical (hypothesis).
5. **Enterprise Exposure** — where this appears in real AI deployments (RAG,
   agents, copilots, model supply chain, MLOps).
6. **Detection & Guardrails** — input/output validation, prompt-injection
   defenses, allow-listing, monitoring, red-teaming; label detection confidence.
7. **Business & AI-Governance Impact** — model risk, data-leak, compliance (EU AI
   Act / sector rules where relevant).
8. **Confidence Block** · 9. **References** (frameworks + research) ·
   10. **Analyst Conclusion.**

## Do not
- Treat marketing "AI security" buzzwords as findings. · Claim a technique works
  in production when only a lab demo exists — label it Research Finding /
  Hypothesis. · Invent ATLAS/OWASP mappings.
