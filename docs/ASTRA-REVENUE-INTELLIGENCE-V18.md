# SENTINEL APEX™ ASTRA Revenue Intelligence Engine v18

## Release objective

v18 optimizes the existing SENTINEL APEX Intel Factory for customer utility,
premium-report yield, and measurable commercial conversion while preserving the
platform's evidence-first safety model. It is an additive orchestration layer,
not a new model provider, billing system, or threat-scoring system.

## Runtime position

Production order:

```text
existing source / ReportX / quota controls
→ v13 capacity-aware allocation
→ v16 zero-cost provider mesh
→ v17 guarded Puter fallback
→ v18 ASTRA runtime
→ Dossier v8 fail-closed integrity
→ Dossier v9/v10 presentation
→ v18 commercial entitlement presentation
→ Blogger fetch-back verification
```

The v18 generation layer therefore consumes the already-approved provider mesh;
it does not own credentials and does not change `ALLOW_PAID_LLM`.

## 1. Commercial delivery priority

A bounded 0–100 **internal delivery score** ranks candidates inside the existing
canonical/family/freshness scheduler. It is computed only from fields already on
`DiscoveredArticle`:

- publication family;
- normalized source-evidence depth;
- structured evidence density;
- verified CISA KEV state when explicitly true;
- supplied CVSS / EPSS values;
- source freshness;
- canonical first-party handoff state;
- presence of productizable evidence categories such as IOC/detection/campaign
  material in the source text.

The score is **not** threat severity, exploit probability, customer exposure,
customer compromise, financial impact, or analytical confidence. Canonical
priority remains the first scheduler sort dimension.

Bands are operational only:

- P0: 75–100
- P1: 60–74
- P2: 40–59
- P3: 0–39

## 2. ASTRA targeted continuation

The unchanged premium public contract remains:

- minimum 2,200 visible words;
- minimum 18 distinct headings;
- minimum 18 substantive paragraphs;
- minimum 18 substantive list items;
- all mandatory canonical report sections;
- ReportX quality/evidence/provenance requirements;
- Dossier v8 prompt-leak and canonical-duplication blockers;
- Blogger artifact fetch-back verification.

When an initial LLM-authored report is below that semantic contract, v18 may run
at most two bounded continuation passes of 1,600 output tokens each. Continuation
is eligible only when normalized source material contains at least 250 words or
at least four structured evidence fields.

Continuation uses the currently installed v16/v17 provider path. It cannot:

- introduce duplicate existing mandatory headings;
- return prompt/model-planning text;
- invent IOCs, CVEs, ATT&CK mappings, exploitation state, affected versions,
  attribution, patches/remediation, victim impact, statistics, customer exposure,
  customer compromise, regulatory applicability, or financial loss;
- convert generated report prose into raw source evidence;
- bypass the downstream premium publication gate.

If continuation still does not satisfy the unchanged contract, the report is
blocked/deferred exactly as before.

## 3. Existing commercial entitlement boundary

v18 does **not** create a second subscription database. It presents and routes to
the entitlements already enforced by `api/_lib/middleware.js`,
`api/_lib/payment-utils.js`, and `api/v1/intel.js`.

| Tier | Current production entitlement surfaced by v18 |
| --- | --- |
| Public / Free | Public evidence-linked dossier; Free API remains rate-limited by existing middleware |
| API Starter — ₹999/month | 5,000 API calls/day, weekly intel digest, one API key |
| SOC Pro — ₹1,499/month | 25,000 API calls/day, IOC access, detection intelligence, full authenticated intel API depth |
| Enterprise — ₹4,999/month | STIX 2.1 export, bulk intelligence access, extended API capacity, priority support |

A public dossier never claims that paying increases factual certainty. Paid
products add operational delivery, volume, machine-readable formats, and support.

## 4. Conversion attribution

Every v18 commercial link includes:

```text
utm_source=sentinel_apex_report
utm_medium=cti_dossier
utm_campaign=astra_revenue_v18
utm_content=<tier>_<report-family>
```

The existing `conversion-engine.js` already recognizes pricing/API/enterprise
links as high-intent interactions and forwards events to the existing GA4 stack.
v18 does not install another analytics vendor.

Server-side run reports record only **generated commercial surfaces**, not clicks,
leads, purchases, or revenue that the factory itself cannot observe.

## 5. v18 run telemetry

`astra_revenue_intelligence_v18` is written into each syndication run report with:

- selected commercial-priority distribution;
- average/max selected delivery value;
- targeted-continuation candidates, attempts, fragments, successes and providers;
- continuation skip/rejection categories;
- commercial panels rendered;
- recommended-tier counts;
- the unchanged public quality floor;
- explicit flags that prompts, generated response bodies, and credentials are not
  included.

## Release gates

v18 may merge only when:

1. Python compile succeeds;
2. the complete Blogger Evidence Integrity suite is green;
3. Security Audit / dependency checks are green;
4. workflow/security gates relevant to modified files are green;
5. PR is conflict-free and no blocking review remains;
6. post-merge production syndication runs on the exact merge SHA;
7. the production run report contains the v18 telemetry block;
8. a generated/published report (when current intelligence supply allows one)
   contains the v18 commercial marker and still passes premium artifact fetch-back;
9. no public quality floor, provider paid-policy, ReportX evidence rule, Dossier v8
   blocker, or Blogger verification invariant is weakened.

## Non-goals for v18

The following remain separate future product releases and are not falsely claimed
by this version:

- persistent customer-specific asset/exposure graph;
- customer-private telemetry processing through free public-model providers;
- Ask SENTINEL APEX conversational retrieval;
- MSSP multi-tenant workspace provisioning;
- a new payment processor or entitlement store;
- guaranteed revenue or market leadership.
