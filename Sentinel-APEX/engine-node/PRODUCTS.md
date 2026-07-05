# Multi-Audience Intelligence Products

The commercial multiplier: **one evidence effort → many deliverables**, each
tailored to a real audience and composed only from artifacts already produced
(reasoning, detections, correlation, IOCs, enrichment). No product introduces a
new claim — each is a re-projection of the same evidence for a different reader.

## Deliverables (`buildProducts(item, memory)`)

| Product | Audience | Contents |
|---|---|---|
| `executiveAdvisory` | CISO / security leadership | situation, business risk, decision matrix (owner / decision / timeline), phased actions |
| `boardBrief` | Board of directors | 4–5 strategic bullets (exposure, regulatory, posture ask) |
| `socBulletin` | SOC / detection eng. | severity, detection coverage, IOCs to block, prioritized actions |
| `huntingGuide` | Threat hunters | per-technique hypotheses + ready KQL/Splunk/OSQuery queries |
| `iocFeed` | Defenders | defanged IOC list with type + confidence |
| `apiPackage` | **MSSP / API customers** | machine-readable JSON intelligence object |

## Machine-readable API package (global customers)

Every detection-worthy report is written to
`api/intel/products/<slug>.json` — a self-describing
`sentinel-apex.intelligence/1.0` object built for SIEM / SOAR / MSSP
integration:

```json
{
  "schema": "sentinel-apex.intelligence/1.0",
  "id": "CVE-2024-4577", "severity": "CRITICAL", "cvss": 9.8, "cisa_kev": true,
  "mitre_attack": [{ "id": "T1490", "name": "Inhibit System Recovery", "tactic": "impact", "confidence": "HIGH" }],
  "iocs": [{ "value": "evil-c2[.]top", "type": "domain", "confidence": 0.9 }],
  "detections": { "sigma": ["..."], "kql": ["..."], "splunk": ["..."], "osquery": ["..."], "suricata": ["..."] },
  "assessment": { "verified_facts": ["..."], "analyst_assessments": [{ "confidence": "HIGH", "text": "..." }],
                  "intelligence_gaps": ["..."], "forward_outlook": [{ "confidence": "HIGH", "text": "..." }] },
  "correlations": ["Technique T1490 was previously observed with: APT41, LockBit, Akira"],
  "provider": "CYBERDUDEBIVASH SENTINEL APEX"
}
```

IOC feeds and human surfaces are **defanged**; functional network rules
(Suricata) inside `detections` intentionally use **live** values because a
network rule must match real traffic.

## Wiring & safety

`fetch-live-intel.js` renders a *Multi-Audience Intelligence Products* section
(Executive Advisory / Board Brief / SOC Bulletin / Threat Hunting Guide + a
link to the JSON package) and writes the API package per report. Both the
render and the file write are fully guarded — any failure is a no-op and never
breaks post generation. An item with no title, CVE, technique, or IOC produces
no products.

## Tests

```bash
cd Sentinel-APEX/engine-node
node --test        # products-engine.test.js (10) + wiring (4)
```
