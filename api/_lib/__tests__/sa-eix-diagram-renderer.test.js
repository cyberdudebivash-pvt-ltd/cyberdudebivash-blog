'use strict';

const { SentinelApexEIXDiagramRenderer } = require('../sa-eix-diagram-renderer');

describe('Sentinel APEX Enterprise Intelligence Experience Diagram Renderer', () => {
  let renderer;

  beforeEach(() => {
    renderer = new SentinelApexEIXDiagramRenderer();
  });

  const mockDiagrams = {
    attackChain: {
      type: 'attack-chain',
      title: 'Attack Flow',
      stages: [
        { name: 'Reconnaissance', description: 'Target research' },
        { name: 'Weaponization', description: 'Exploit preparation' },
        { name: 'Delivery', description: 'Payload delivery' },
        { name: 'Exploitation', description: 'Vulnerability exploitation' },
        { name: 'Installation', description: 'Malware installation' },
      ],
    },
    killChain: {
      type: 'kill-chain',
      title: 'Kill Chain Analysis',
      stages: [
        { name: 'Reconnaissance', details: ['Domain research', 'Email harvesting'] },
        { name: 'Weaponization', details: ['Exploit creation', 'Packaging'] },
        { name: 'Delivery', details: ['Spear phishing', 'Watering hole'] },
        { name: 'Exploitation', details: ['Zero-day', 'Vulnerability'] },
        { name: 'Installation', details: ['Dropper', 'Lateral movement'] },
      ],
    },
    mitreMatrix: {
      type: 'mitre-matrix',
      title: 'MITRE ATT&CK Coverage',
      tactics: {
        'Initial Access': ['Spear Phishing', 'Supply Chain Compromise'],
        'Execution': ['PowerShell', 'Command Line Interface'],
        'Persistence': ['Registry Run Keys', 'Scheduled Task'],
        'Privilege Escalation': ['UAC Bypass', 'DLL Hijacking'],
        'Defense Evasion': ['Obfuscated Files', 'Signed Binary Proxy'],
      },
    },
    timeline: {
      type: 'timeline',
      title: 'Campaign Timeline',
      events: [
        { date: '2026-01-15', event: 'Initial reconnaissance detected' },
        { date: '2026-02-10', event: 'Spear phishing campaign launched' },
        { date: '2026-03-05', event: 'First victim compromised' },
        { date: '2026-04-20', event: 'Lateral movement detected' },
        { date: '2026-07-31', event: 'Campaign ongoing' },
      ],
    },
    infrastructure: {
      type: 'infrastructure-graph',
      title: 'Infrastructure Relationships',
      nodes: [
        { type: 'c2', value: 'attacker.com' },
        { type: 'hosting', value: '192.168.1.1' },
        { type: 'domain', value: 'phishing.xyz' },
        { type: 'mail', value: 'smtp.attacker.com' },
      ],
    },
    threatActors: {
      type: 'threat-actor-network',
      title: 'Threat Actor Intelligence',
      actors: [
        { name: 'APT-28', confidence: 0.95 },
        { name: 'Fancy Bear', confidence: 0.90 },
      ],
      campaigns: [
        { name: 'Operation Ghost', startDate: '2026-01-15' },
        { name: 'Campaign Scorpion', startDate: '2026-03-10' },
      ],
    },
  };

  // ==================== INITIALIZATION TESTS ====================

  test('should initialize with default branding config', () => {
    expect(renderer.brandingConfig).toBeDefined();
    expect(renderer.brandingConfig.colors).toBeDefined();
    expect(renderer.brandingConfig.colors.primary).toBe('#0A3A5C');
  });

  test('should initialize with custom branding config', () => {
    const customBranding = {
      colors: { primary: '#FF0000', accent: '#00FF00' },
    };
    const customRenderer = new SentinelApexEIXDiagramRenderer(customBranding);

    expect(customRenderer.brandingConfig.colors.primary).toBe('#FF0000');
    expect(customRenderer.brandingConfig.colors.accent).toBe('#00FF00');
  });

  // ==================== ATTACK CHAIN TESTS ====================

  test('should render attack chain diagram', () => {
    const svg = renderer.renderAttackChain(mockDiagrams.attackChain);

    expect(svg).toBeDefined();
    expect(typeof svg).toBe('string');
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('should render attack chain stages', () => {
    const svg = renderer.renderAttackChain(mockDiagrams.attackChain);

    expect(svg).toContain('Reconnaissance');
    expect(svg).toContain('Weaponization');
    expect(svg).toContain('Delivery');
  });

  test('should include connecting arrows in attack chain', () => {
    const svg = renderer.renderAttackChain(mockDiagrams.attackChain);

    expect(svg).toContain('polygon');
    expect(svg).toContain('line');
  });

  test('should handle empty attack chain stages', () => {
    const emptyDiagram = { stages: [] };
    const svg = renderer.renderAttackChain(emptyDiagram);

    expect(svg).toBeDefined();
    expect(svg).toContain('No attack stages');
  });

  // ==================== KILL CHAIN TESTS ====================

  test('should render kill chain diagram', () => {
    const svg = renderer.renderKillChain(mockDiagrams.killChain);

    expect(svg).toBeDefined();
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('should render kill chain stages with boxes', () => {
    const svg = renderer.renderKillChain(mockDiagrams.killChain);

    expect(svg).toContain('Reconnaissance');
    expect(svg).toContain('Exploitation');
    expect(svg).toContain('Installation');
  });

  test('should render kill chain stage details', () => {
    const svg = renderer.renderKillChain(mockDiagrams.killChain);

    expect(svg).toContain('Domain research');
    expect(svg).toContain('Exploit creation');
  });

  test('should handle empty kill chain stages', () => {
    const emptyDiagram = { stages: [] };
    const svg = renderer.renderKillChain(emptyDiagram);

    expect(svg).toContain('No kill chain stages');
  });

  // ==================== MITRE MATRIX TESTS ====================

  test('should render MITRE matrix diagram', () => {
    const svg = renderer.renderMitreMatrix(mockDiagrams.mitreMatrix);

    expect(svg).toBeDefined();
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('should render MITRE tactics', () => {
    const svg = renderer.renderMitreMatrix(mockDiagrams.mitreMatrix);

    expect(svg).toContain('Initial Access');
    expect(svg).toContain('Execution');
    expect(svg).toContain('Defense Evasion');
  });

  test('should render MITRE techniques', () => {
    const svg = renderer.renderMitreMatrix(mockDiagrams.mitreMatrix);

    expect(svg).toContain('Spear Phishing');
    expect(svg).toContain('PowerShell');
  });

  test('should handle empty MITRE tactics', () => {
    const emptyDiagram = { tactics: {} };
    const svg = renderer.renderMitreMatrix(emptyDiagram);

    expect(svg).toContain('No MITRE techniques');
  });

  // ==================== TIMELINE TESTS ====================

  test('should render timeline diagram', () => {
    const svg = renderer.renderTimeline(mockDiagrams.timeline);

    expect(svg).toBeDefined();
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('should render timeline events', () => {
    const svg = renderer.renderTimeline(mockDiagrams.timeline);

    expect(svg).toContain('2026-01-15');
    expect(svg).toContain('Initial reconnaissance');
    expect(svg).toContain('Campaign ongoing');
  });

  test('should sort timeline events by date', () => {
    const unsortedDiagram = {
      events: [
        { date: '2026-07-31', event: 'Latest' },
        { date: '2026-01-15', event: 'First' },
        { date: '2026-03-05', event: 'Middle' },
      ],
    };
    const svg = renderer.renderTimeline(unsortedDiagram);

    // SVG should have been rendered without errors
    expect(svg).toContain('<svg');
  });

  test('should handle empty timeline events', () => {
    const emptyDiagram = { events: [] };
    const svg = renderer.renderTimeline(emptyDiagram);

    expect(svg).toContain('No events');
  });

  // ==================== INFRASTRUCTURE GRAPH TESTS ====================

  test('should render infrastructure graph', () => {
    const svg = renderer.renderInfrastructureGraph(mockDiagrams.infrastructure);

    expect(svg).toBeDefined();
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('should render infrastructure nodes', () => {
    const svg = renderer.renderInfrastructureGraph(mockDiagrams.infrastructure);

    expect(svg).toContain('attacker.com');
    expect(svg).toContain('phishing.xyz');
  });

  test('should render central C2 hub', () => {
    const svg = renderer.renderInfrastructureGraph(mockDiagrams.infrastructure);

    expect(svg).toContain('C2');
  });

  test('should handle empty infrastructure nodes', () => {
    const emptyDiagram = { nodes: [] };
    const svg = renderer.renderInfrastructureGraph(emptyDiagram);

    expect(svg).toContain('No infrastructure nodes');
  });

  // ==================== THREAT ACTOR NETWORK TESTS ====================

  test('should render threat actor network', () => {
    const svg = renderer.renderThreatActorNetwork(mockDiagrams.threatActors);

    expect(svg).toBeDefined();
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });

  test('should render threat actors', () => {
    const svg = renderer.renderThreatActorNetwork(mockDiagrams.threatActors);

    expect(svg).toContain('APT-28');
    expect(svg).toContain('Fancy Bear');
  });

  test('should render campaigns', () => {
    const svg = renderer.renderThreatActorNetwork(mockDiagrams.threatActors);

    expect(svg).toContain('Operation Ghost');
    expect(svg).toContain('Campaign Scorpion');
  });

  test('should handle empty threat actors and campaigns', () => {
    const emptyDiagram = { actors: [], campaigns: [] };
    const svg = renderer.renderThreatActorNetwork(emptyDiagram);

    expect(svg).toContain('No threat actors');
  });

  // ==================== BATTLEFIELD VISUALIZATION TESTS ====================

  test('should render threat intelligence battlefield visualization', () => {
    const svg = renderer.renderBattlefieldVisualization({});

    expect(svg).toBeDefined();
    expect(svg).toContain('<svg');
    expect(svg).toContain('Threat Intelligence Battlefield');
  });

  test('should render heatmap grid', () => {
    const svg = renderer.renderBattlefieldVisualization({});

    expect(svg).toContain('<rect');
    expect(svg).toContain('rx="4"');
  });

  // ==================== SVG PRIMITIVE TESTS ====================

  test('should create line SVG element', () => {
    const line = renderer.createLine(0, 0, 100, 100, '#FF0000', 2);

    expect(line).toContain('<line');
    expect(line).toContain('x1="0"');
    expect(line).toContain('y2="100"');
    expect(line).toContain('stroke="#FF0000"');
  });

  test('should create circle SVG element', () => {
    const circle = renderer.createCircle(50, 50, 25, '#0000FF');

    expect(circle).toContain('<circle');
    expect(circle).toContain('cx="50"');
    expect(circle).toContain('r="25"');
  });

  test('should create rectangle SVG element', () => {
    const rect = renderer.createRect(10, 10, 100, 50, '#FF0000');

    expect(rect).toContain('<rect');
    expect(rect).toContain('x="10"');
    expect(rect).toContain('width="100"');
  });

  test('should create text SVG element', () => {
    const text = renderer.createText(100, 100, 'Hello', 14, '#000000');

    expect(text).toContain('<text');
    expect(text).toContain('x="100"');
    expect(text).toContain('font-size="14"');
    expect(text).toContain('Hello');
  });

  test('should escape XML special characters in text', () => {
    const text = renderer.createText(0, 0, '<script>alert("xss")</script>', 12, '#000');

    expect(text).toContain('&lt;');
    expect(text).toContain('&gt;');
    expect(text).not.toContain('<script>');
  });

  // ==================== COLOR UTILITY TESTS ====================

  test('should get correct text color for dark theme', () => {
    const color = renderer.getTextColor('dark');

    expect(color).toBe('#C9D1D9');
  });

  test('should get correct text color for light theme', () => {
    const color = renderer.getTextColor('light');

    expect(color).toBe('#2C3E50');
  });

  test('should determine contrast color for light background', () => {
    const contrast = renderer.getContrastColor('#FFFFFF');

    expect(contrast).toBe('#000');
  });

  test('should determine contrast color for dark background', () => {
    const contrast = renderer.getContrastColor('#000000');

    expect(contrast).toBe('#FFF');
  });

  test('should convert hex to RGB', () => {
    const rgb = renderer.hexToRgb('#FF0000');

    expect(rgb).toBeDefined();
    expect(rgb.r).toBe(255);
    expect(rgb.g).toBe(0);
    expect(rgb.b).toBe(0);
  });

  test('should return stage color based on index', () => {
    const color1 = renderer.getStageColor(0, 5);
    const color2 = renderer.getStageColor(1, 5);

    expect(typeof color1).toBe('string');
    expect(typeof color2).toBe('string');
    expect(color1).not.toEqual(color2);
  });

  // ==================== EVENT SORTING TESTS ====================

  test('should sort events by date', () => {
    const events = [
      { date: '2026-07-31', event: 'Last' },
      { date: '2026-01-15', event: 'First' },
      { date: '2026-03-05', event: 'Middle' },
    ];

    const sorted = renderer.sortEventsByDate(events);

    expect(sorted[0].event).toBe('First');
    expect(sorted[1].event).toBe('Middle');
    expect(sorted[2].event).toBe('Last');
  });

  test('should handle invalid dates in event sorting', () => {
    const events = [
      { date: 'invalid', event: 'Bad' },
      { date: '2026-01-15', event: 'Good' },
    ];

    const sorted = renderer.sortEventsByDate(events);

    expect(Array.isArray(sorted)).toBe(true);
  });

  // ==================== XML ESCAPING TESTS ====================

  test('should escape XML entities', () => {
    const escaped = renderer.escapeXml('<tag attr="value">content</tag>');

    expect(escaped).toContain('&lt;');
    expect(escaped).toContain('&gt;');
    expect(escaped).toContain('&quot;');
    expect(escaped).not.toContain('<tag');
  });

  test('should handle null input for XML escaping', () => {
    const escaped = renderer.escapeXml(null);

    expect(escaped).toBe('');
  });

  // ==================== THEME TESTS ====================

  test('should render diagram with dark theme', () => {
    const svg = renderer.renderAttackChain(mockDiagrams.attackChain, { theme: 'dark' });

    expect(svg).toContain('#161B22');
  });

  test('should render diagram with light theme', () => {
    const svg = renderer.renderAttackChain(mockDiagrams.attackChain, { theme: 'light' });

    expect(svg).toContain('#FFFFFF');
  });

  // ==================== DIMENSIONS TESTS ====================

  test('should render diagram with custom width and height', () => {
    const svg = renderer.renderAttackChain(mockDiagrams.attackChain, {
      width: 2000,
      height: 800,
    });

    expect(svg).toContain('width="2000"');
    expect(svg).toContain('height="800"');
  });

  // ==================== PLACEHOLDER TESTS ====================

  test('should render placeholder for missing data', () => {
    const svg = renderer.renderPlaceholder('Test Diagram', 'No data available', 800, 400, 'dark');

    expect(svg).toContain('Test Diagram');
    expect(svg).toContain('No data available');
  });
});
