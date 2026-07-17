/**
 * SENTINEL APEX — Services & Industry Catalog (JS mirror)
 *
 * Node-side mirror of automation/product_recommendations.py's SERVICES
 * and automation/industry_intelligence.py's INDUSTRY_PROFILES, so the
 * content-graph facade (api/_lib/content-graph.js) can expose
 * 'service'/'industry' entities without a Python/Node bridge. Keep in
 * sync manually — same documented cross-file convention already used
 * between product_recommendations.py and monetization_injector.py.
 * Only the fields the graph facade actually needs are mirrored (no
 * article-generation prose).
 */
'use strict';

const SERVICES = {
  threat_intelligence: { name: 'Threat Intelligence', description: 'CTI Advisory & Premium Intel Briefs' },
  ai_security_assessment: { name: 'AI Security Assessment', description: 'LLM · Prompt Injection · Agent Security' },
  vulnerability_assessment: { name: 'Vulnerability Assessment', description: 'API · SaaS · Cloud · Web Security' },
  soc_mssp: { name: 'SOC & MSSP Services', description: 'Co-Managed SOC · Threat Hunting' },
  ai_governance: { name: 'AI Governance Consulting', description: 'NIST AI RMF · ISO 42001 · OWASP LLM' },
  devsecops: { name: 'DevSecOps Optimization', description: 'CI/CD Security · Pipeline Hardening' },
  incident_response: { name: 'Incident Response', description: 'Digital Forensics · IR Retainer' },
  detection_engineering: { name: 'Detection Engineering', description: '2,400+ Sigma · YARA · SIEM Rules' },
  threat_hunting: { name: 'Threat Hunting', description: 'Proactive Compromise Assessment · TTP Sweeps' },
  virtual_ciso: { name: 'Virtual CISO', description: 'Fractional Executive Security Leadership' },
  security_architecture_review: { name: 'Security Architecture Review', description: 'Zero Trust · Cloud & Network Design Audit' },
};

const INDUSTRIES = {
  healthcare: { name: 'Healthcare', services: ['vulnerability_assessment', 'incident_response'] },
  finance: { name: 'Financial Services', services: ['detection_engineering', 'incident_response'] },
  government: { name: 'Government / Public Sector', services: ['vulnerability_assessment', 'detection_engineering'] },
  retail: { name: 'Retail / E-Commerce', services: ['vulnerability_assessment', 'detection_engineering'] },
  manufacturing: { name: 'Manufacturing', services: ['incident_response', 'vulnerability_assessment'] },
  critical_infrastructure: { name: 'Critical Infrastructure', services: ['incident_response', 'detection_engineering'] },
  energy: { name: 'Energy', services: ['incident_response', 'vulnerability_assessment'] },
  technology: { name: 'Technology', services: ['devsecops', 'vulnerability_assessment'] },
  education: { name: 'Education', services: ['incident_response', 'vulnerability_assessment'] },
};

function getService(key) {
  return SERVICES[key] ? { key, ...SERVICES[key] } : null;
}

function getIndustry(key) {
  return INDUSTRIES[key] ? { key, ...INDUSTRIES[key] } : null;
}

module.exports = { SERVICES, INDUSTRIES, getService, getIndustry };
