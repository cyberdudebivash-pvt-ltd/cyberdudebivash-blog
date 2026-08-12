const fs = require('fs');
const path = require('path');
const {
  extractHttpUrls,
  parseCvssFromText,
  hasConfirmedExploitation,
  rssToIntel,
  normalizeSentinelApexRecord,
  qualityGate,
  genBusinessImpact,
  genAttackChain,
  generatePostHTML,
  correlateAndMerge,
} = require('../fetch-live-intel');

describe('SENTINEL APEX evidence-integrity controls', () => {
  test('extracts only valid HTTP references from free-form CISA notes', () => {
    const refs = extractHttpUrls(
      'See vendor guidance; https://example.com/advisory; https://github.com/org/repo/security/advisories/GHSA-1234. Additional text'
    );
    expect(refs).toEqual([
      'https://example.com/advisory',
      'https://github.com/org/repo/security/advisories/GHSA-1234',
    ]);
    refs.forEach(ref => expect(() => new URL(ref)).not.toThrow());
  });

  test('does not invent CVSS from severity, CVE presence, or source type', () => {
    expect(parseCvssFromText('Critical CVE with public exploit')).toBeNull();
    expect(parseCvssFromText('CVSS 9.8 remote code execution')).toBe(9.8);

    const rss = rssToIntel({
      title: 'Critical CVE-2026-99999 exploit released',
      desc: 'Researchers published a proof of concept.',
      link: 'https://example.org/research',
      pubDate: '2026-08-12T00:00:00Z',
    }, 'unit42');
    expect(rss.cvss).toBeNull();

    const native = normalizeSentinelApexRecord({
      id: 'native-1', title: 'Critical security advisory', severity: 'critical',
      description: 'A public exploit proof of concept is available.',
      url: 'https://example.org/advisory',
    }, 'latest');
    expect(native.cvss).toBeNull();
  });

  test('requires explicit observed-exploitation language', () => {
    expect(hasConfirmedExploitation('Exploit proof of concept available for Active Directory')).toBe(false);
    expect(hasConfirmedExploitation('A zero-day vulnerability was disclosed')).toBe(false);
    expect(hasConfirmedExploitation('CISA reports this is actively exploited')).toBe(true);
    expect(hasConfirmedExploitation('Observed exploitation in the wild')).toBe(true);
  });

  test('preserves unknown CVSS through correlation', () => {
    const [merged] = correlateAndMerge([[
      { id: 'CVE-2026-11111', source: 'cisa_kev', title: 'CISA KEV record', desc: 'Confirmed exploitation.', cvss: null, cisaKev: true, refs: ['https://cisa.gov/example'] },
      { id: 'CVE-2026-11111', source: 'unit42', title: 'Coverage without a score', desc: 'Reporting without numeric severity.', cvss: null, refs: ['https://example.org/report'] },
    ]]);
    expect(merged.cvss).toBeNull();
  });

  test('rejects malformed reference-only records', () => {
    const result = qualityGate({
      id: 'TEST-1', title: 'Substantive intelligence title',
      desc: 'A sufficiently long description for validation.',
      source: 'unit42', type: 'ADVISORY', threatLevel: 'MEDIUM',
      priority: 50, refs: ['This vulnerability affects users; https://example.com'],
    });
    // Embedded notes are normalized into a valid URL, so this passes.
    expect(result.pass).toBe(true);

    const invalid = qualityGate({
      id: 'REAL-1', title: 'Substantive intelligence title',
      desc: 'A sufficiently long description for validation.',
      source: 'unit42', type: 'ADVISORY', threatLevel: 'MEDIUM',
      priority: 50, refs: ['not a URL'],
    });
    expect(invalid.pass).toBe(false);
    expect(invalid.reasons).toContain('Missing/invalid: references / link');
  });

  test('does not fabricate an attack chain or complete compromise', () => {
    const item = {
      id: 'CVE-2026-48027', vendor: 'Nx', product: 'Nx Console',
      title: 'Malicious extension harvested credentials',
      desc: 'A supply-chain compromise harvested credentials from developer systems.',
      cisaKev: true, exploited: true,
    };
    const impact = genBusinessImpact(item).join(' ');
    const chain = genAttackChain(item);
    expect(impact).not.toMatch(/complete system compromise|full server takeover/i);
    expect(chain).toEqual(expect.arrayContaining([
      expect.objectContaining({ phase: 'Evidence boundary', tactic: 'Not assigned' }),
    ]));
    expect(JSON.stringify(chain)).not.toMatch(/Shodan|scheduled task|command & control|Mimikatz/i);
  });

  test('renders unknown CVSS and honest commercial/evidence language', () => {
    const { html } = generatePostHTML({
      id: 'CVE-2026-99999', title: 'Example source-attributed advisory',
      desc: 'The primary source describes a vulnerability with prerequisites still under review.',
      source: 'cisa_kev', _sources: ['cisa_kev'], sourceCount: 1,
      refs: ['https://example.org/advisory'], pubDate: '2026-08-12',
      vendor: 'Example', product: 'Example Product', type: 'CVE_REPORT',
      cvss: null, cisaKev: true, exploited: true, ransomware: false,
      iocs: [], cves: ['CVE-2026-99999'], priority: 50, threatLevel: 'MEDIUM',
    });
    expect(html).toContain('CVSS Not assigned');
    expect(html).toContain('Evidence boundary');
    expect(html).toContain('reference draft');
    expect(html).not.toMatch(/10,000\+|48hr pre-disclosure|PRIVATE LIMITED|FP-validated|production-ready/i);
  });
});

describe('publication and acquisition workflow regressions', () => {
  const root = path.join(__dirname, '..');

  test('staged change detection uses valid Git commands', () => {
    const workflow = fs.readFileSync(path.join(root, '.github/workflows/sentinel-apex.yml'), 'utf8');
    expect(workflow).not.toContain('git status --cached');
    expect(workflow).toContain('git diff --cached --name-status');
  });

  test('critical freshness fails and can trigger recovery', () => {
    const workflow = fs.readFileSync(path.join(root, '.github/workflows/freshness-check.yml'), 'utf8');
    expect(workflow).toContain("if (statusLevel === 'CRITICAL') process.exit(2)");
    expect(workflow).toContain('if: failure()');
  });

  test('newsletter uses the first-party endpoint before fallback', () => {
    const engine = fs.readFileSync(path.join(root, 'email-engine.js'), 'utf8');
    const page = fs.readFileSync(path.join(root, 'newsletter.html'), 'utf8');
    expect(engine).toContain("provider: 'resend'");
    expect(engine).toContain("fetch('/api/v1/newsletter'");
    expect(page).not.toMatch(/2,000\+|47%|\d{1,3},\d{3} readers/);
  });
});
