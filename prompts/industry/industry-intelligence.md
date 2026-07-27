> ⚠ **Superseded** — see `prompts/README.md`. Unlike the other files in this
> directory, this one has **no canonical equivalent yet** — Sentinel-APEX has
> no sector/industry-overlay concept today (only free-text "Affected
> Industries" in the report structure). Marked superseded for consistency,
> not because a replacement exists; if a real industry-overlay need arises,
> port this file's content into a new `Sentinel-APEX/prompts/` layer rather
> than reactivating this one.

# INDUSTRY INTELLIGENCE OVERLAY

**Version:** 1.0 · **Layer 4 (optional)** · Applied *on top of* any Report-Type
prompt · Inherits Constitution + Production Workflow

---

## How to use
This overlay does not replace a report type. It **adds sector framing** to a CVE,
ransomware, AI-security, briefing, digest, or landscape report so the analysis
speaks to a specific industry's assets, adversaries, and obligations.

When applied, the report additionally answers, for the chosen sector:
- Which **crown-jewel systems** are exposed?
- Which **threat actors / campaigns** are known to target this sector (evidence-
  labeled — do not invent targeting)?
- Which **compliance/regulatory** obligations are triggered?
- What is the **sector-specific business impact** (safety, availability,
  fraud, patient harm, market integrity, national security)?

Use only sector facts you can support. Sector targeting claims are **Correlated
Observation** or **Research Finding**, never Verified Fact without a source.

---

## Sector profiles

### Finance & Banking
- **Crown jewels:** core banking, payment rails (SWIFT/ACH/UPI), trading systems,
  KYC/AML data, customer PII, market-data feeds.
- **Primary risks:** fraud, wire/BEC, ransomware-driven outage, data theft,
  third-party/fintech supply chain, identity compromise.
- **Compliance:** PCI-DSS, SOX, DORA (EU), RBI/FFIEC guidance, GLBA.
- **Impact framing:** market integrity, fraud loss, regulatory penalty, systemic
  and reputational risk.

### Healthcare
- **Crown jewels:** EHR/EMR, medical devices, PACS/imaging, PHI, pharmacy and
  lab systems.
- **Primary risks:** ransomware causing care disruption (patient-safety event),
  PHI theft, insecure/legacy medical devices, third-party clearinghouses.
- **Compliance:** HIPAA/HITECH, FDA device guidance, GDPR (EU), NIS2.
- **Impact framing:** patient safety and care continuity first, then privacy,
  regulatory, and reputational impact.

### Manufacturing & OT/ICS
- **Crown jewels:** ICS/SCADA, PLCs, MES, safety instrumented systems,
  intellectual property, supply-chain integrations.
- **Primary risks:** OT ransomware/production halt, IT→OT lateral movement,
  legacy/unpatchable controllers, supply-chain compromise.
- **Compliance:** IEC 62443, NIST SP 800-82, NIS2, sector CISA advisories.
- **Impact framing:** safety, production downtime, physical/environmental risk,
  IP theft.

### Government & Public Sector
- **Crown jewels:** citizen data, identity systems, classified/sensitive
  networks, critical services, election infrastructure.
- **Primary risks:** nation-state espionage/APT, supply-chain compromise,
  ransomware on public services, data exfiltration.
- **Compliance:** FISMA/FedRAMP, CISA BOD directives (incl. KEV remediation),
  national data-protection law.
- **Impact framing:** national security, public-service continuity, citizen
  trust, sovereignty.

### Retail & E-commerce
- **Crown jewels:** POS systems, e-commerce platforms, payment processing,
  customer PII/loyalty data, supply-chain/logistics.
- **Primary risks:** card-skimming/Magecart, ATO and credential stuffing,
  ransomware in peak season, third-party/plugin supply chain.
- **Compliance:** PCI-DSS, GDPR/CCPA, breach-notification law.
- **Impact framing:** fraud and chargebacks, seasonal-outage revenue loss,
  customer-trust erosion.

### Critical Infrastructure & Energy
- **Crown jewels:** grid/utility OT, water treatment, pipeline and transport
  control, telecom backbones.
- **Primary risks:** nation-state pre-positioning, OT ransomware, safety-system
  compromise, cascading physical impact.
- **Compliance:** NERC-CIP, TSA directives, IEC 62443, NIS2, CISA CI guidance.
- **Impact framing:** public safety, service availability, national resilience,
  environmental consequence.

---

## Overlay output additions
Add to the base report: a **Sector Exposure** section (crown jewels at risk), a
**Sector Threat Context** note (evidence-labeled targeting), a **Regulatory
Trigger** line (which obligations activate), and sector-specific framing in the
Business Impact and Executive Priorities sections.

### Changelog
- **v1.0** — Six sector profiles (finance, healthcare, manufacturing,
  government, retail, critical infrastructure) + overlay output additions.
