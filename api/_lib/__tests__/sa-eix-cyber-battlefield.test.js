'use strict';

const { SentinelApexCyberBattlefield } = require('../sa-eix-cyber-battlefield');

describe('SentinelApexCyberBattlefield', () => {
  let battlefield;

  beforeEach(() => {
    battlefield = new SentinelApexCyberBattlefield();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(battlefield).toBeDefined();
      expect(battlefield.designTokens).toBeDefined();
      expect(battlefield.theme).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexCyberBattlefield({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generateAttackSurface', () => {
    test('should generate attack surface with empty assets', () => {
      const surface = battlefield.generateAttackSurface([]);
      expect(surface.type).toBe('attack-surface');
      expect(surface.html).toContain('Attack Surface');
      expect(surface.metadata.totalAssets).toBe(0);
    });

    test('should generate attack surface with assets', () => {
      const assets = [
        { status: 'compromised' },
        { status: 'exposed' },
        { status: 'vulnerable' },
        { status: 'protected' },
      ];
      const surface = battlefield.generateAttackSurface(assets);
      expect(surface.metadata.totalAssets).toBe(4);
      expect(surface.metadata.compromised).toBe(1);
      expect(surface.metadata.exposed).toBe(1);
      expect(surface.metadata.vulnerable).toBe(1);
      expect(surface.metadata.protected).toBe(1);
    });

    test('should calculate risk percentage', () => {
      const assets = [
        { status: 'compromised' },
        { status: 'compromised' },
        { status: 'protected' },
      ];
      const surface = battlefield.generateAttackSurface(assets);
      expect(surface.metadata.riskPercent).toBe(67);
    });

    test('should handle zero assets', () => {
      const surface = battlefield.generateAttackSurface([]);
      expect(surface.metadata.riskPercent).toBe(0);
    });

    test('should display status metrics', () => {
      const assets = [
        { status: 'compromised' },
        { status: 'exposed' },
      ];
      const surface = battlefield.generateAttackSurface(assets);
      expect(surface.html).toContain('Compromised');
      expect(surface.html).toContain('Exposed');
      expect(surface.html).toContain('Vulnerable');
      expect(surface.html).toContain('Protected');
    });

    test('should handle null assets', () => {
      const surface = battlefield.generateAttackSurface(null);
      expect(surface.metadata.totalAssets).toBe(0);
    });
  });

  describe('generateNetworkTopology', () => {
    test('should generate network topology with empty nodes', () => {
      const topology = battlefield.generateNetworkTopology([]);
      expect(topology.type).toBe('network-topology');
      expect(topology.html).toContain('Network Topology');
      expect(topology.metadata.totalNodes).toBe(0);
    });

    test('should generate network topology with nodes', () => {
      const nodes = [
        { type: 'server', criticality: 'critical' },
        { type: 'workstation' },
        { type: 'router', criticality: 'critical' },
      ];
      const topology = battlefield.generateNetworkTopology(nodes);
      expect(topology.metadata.totalNodes).toBe(3);
      expect(topology.metadata.criticalNodes).toBe(2);
    });

    test('should count nodes by type', () => {
      const nodes = [
        { type: 'server' },
        { type: 'server' },
        { type: 'workstation' },
        { type: 'database' },
      ];
      const topology = battlefield.generateNetworkTopology(nodes);
      expect(topology.metadata.nodeDistribution.server).toBe(2);
      expect(topology.metadata.nodeDistribution.workstation).toBe(1);
      expect(topology.metadata.nodeDistribution.database).toBe(1);
    });

    test('should identify node types observed', () => {
      const nodes = [
        { type: 'server' },
        { type: 'workstation' },
        { type: 'router' },
      ];
      const topology = battlefield.generateNetworkTopology(nodes);
      expect(topology.metadata.nodeTypes.includes('server')).toBe(true);
      expect(topology.metadata.nodeTypes.includes('workstation')).toBe(true);
      expect(topology.metadata.nodeTypes.includes('router')).toBe(true);
    });

    test('should display node type information', () => {
      const nodes = [
        { type: 'server' },
        { type: 'workstation' },
      ];
      const topology = battlefield.generateNetworkTopology(nodes);
      expect(topology.html).toContain('Node Types');
    });

    test('should escape node type names', () => {
      const nodes = [{ type: '<img src=x>' }];
      const topology = battlefield.generateNetworkTopology(nodes);
      expect(topology.html).toContain('&lt;img');
    });

    test('should handle null nodes', () => {
      const topology = battlefield.generateNetworkTopology(null);
      expect(topology.metadata.totalNodes).toBe(0);
    });
  });

  describe('generateKillChain', () => {
    test('should generate kill chain with empty techniques', () => {
      const chain = battlefield.generateKillChain([]);
      expect(chain.type).toBe('kill-chain');
      expect(chain.html).toContain('Kill Chain');
      expect(chain.metadata.totalTechniques).toBe(0);
    });

    test('should generate kill chain with techniques', () => {
      const techniques = [
        { tactic: 'initial-access', name: 'Spearphishing' },
        { tactic: 'execution', name: 'Command Line' },
        { tactic: 'persistence', name: 'Registry Run Keys' },
      ];
      const chain = battlefield.generateKillChain(techniques);
      expect(chain.metadata.totalTechniques).toBe(3);
      expect(chain.metadata.tacticsObserved).toBe(3);
    });

    test('should organize techniques by tactic', () => {
      const techniques = [
        { tactic: 'initial-access', name: 'Tech1' },
        { tactic: 'initial-access', name: 'Tech2' },
        { tactic: 'execution', name: 'Tech3' },
      ];
      const chain = battlefield.generateKillChain(techniques);
      expect(chain.metadata.techniquesByTactic['initial-access'].length).toBe(2);
      expect(chain.metadata.techniquesByTactic['execution'].length).toBe(1);
    });

    test('should display all MITRE ATT&CK tactics', () => {
      const chain = battlefield.generateKillChain([]);
      expect(chain.html).toContain('reconnaissance');
      expect(chain.html).toContain('execution');
      expect(chain.html).toContain('persistence');
      expect(chain.html).toContain('impact');
    });

    test('should escape technique names', () => {
      const techniques = [
        { tactic: 'execution', name: '<img src=x>' },
      ];
      const chain = battlefield.generateKillChain(techniques);
      expect(chain.html).toContain('&lt;img');
    });

    test('should handle techniques without tactic', () => {
      const techniques = [{ name: 'Technique' }];
      const chain = battlefield.generateKillChain(techniques);
      expect(chain.metadata.totalTechniques).toBe(1);
    });

    test('should handle null techniques', () => {
      const chain = battlefield.generateKillChain(null);
      expect(chain.metadata.totalTechniques).toBe(0);
    });

    test('should display technique count by tactic', () => {
      const techniques = Array.from({ length: 5 }, (_, i) => ({
        tactic: 'execution',
        name: `Tech${i}`,
      }));
      const chain = battlefield.generateKillChain(techniques);
      expect(chain.metadata.techniquesByTactic.execution.length).toBe(5);
    });
  });

  describe('generateImpactZones', () => {
    test('should generate impact zones with empty zones', () => {
      const zones = battlefield.generateImpactZones([]);
      expect(zones.type).toBe('impact-zones');
      expect(zones.html).toContain('Impact Zones');
      expect(zones.metadata.totalZones).toBe(0);
    });

    test('should generate impact zones with zones', () => {
      const zoneList = [
        { name: 'Zone A', type: 'network', severity: 'critical', affectedCount: 10 },
        { name: 'Zone B', type: 'application', severity: 'high', affectedCount: 5 },
      ];
      const zones = battlefield.generateImpactZones(zoneList);
      expect(zones.metadata.totalZones).toBe(2);
      expect(zones.metadata.criticalZones).toBe(1);
    });

    test('should limit displayed zones to 6', () => {
      const zoneList = Array.from({ length: 10 }, (_, i) => ({
        name: `Zone ${i}`,
        severity: 'medium',
      }));
      const zones = battlefield.generateImpactZones(zoneList);
      expect(zones.metadata.displayedZones).toBe(6);
      expect(zones.metadata.totalZones).toBe(10);
    });

    test('should display zone information', () => {
      const zoneList = [
        { name: 'Production Network', type: 'network', severity: 'critical' },
      ];
      const zones = battlefield.generateImpactZones(zoneList);
      expect(zones.html).toContain('Production Network');
      expect(zones.html).toContain('network');
      expect(zones.html).toContain('CRITICAL');
    });

    test('should escape zone names and types', () => {
      const zoneList = [
        { name: '<img src=x>', type: '&malicious' },
      ];
      const zones = battlefield.generateImpactZones(zoneList);
      expect(zones.html).toContain('&lt;img');
      expect(zones.html).toContain('&amp;malicious');
    });

    test('should display affected asset counts', () => {
      const zoneList = [
        { name: 'Zone A', affectedCount: 15 },
        { name: 'Zone B', affectedCount: 1 },
      ];
      const zones = battlefield.generateImpactZones(zoneList);
      expect(zones.html).toContain('15 assets');
      expect(zones.html).toContain('1 asset');
    });

    test('should handle zones without severity', () => {
      const zoneList = [{ name: 'Zone' }];
      const zones = battlefield.generateImpactZones(zoneList);
      expect(zones.metadata.totalZones).toBe(1);
    });

    test('should handle null zones', () => {
      const zones = battlefield.generateImpactZones(null);
      expect(zones.metadata.totalZones).toBe(0);
    });
  });

  describe('generateCyberBattlefield', () => {
    test('should generate complete cyber battlefield', () => {
      const dashboard = battlefield.generateCyberBattlefield(
        {
          assets: [{ status: 'compromised' }],
          nodes: [{ type: 'server' }],
          impactZones: [{ name: 'Zone A' }],
        },
        {
          techniques: [{ tactic: 'execution', name: 'Tech' }],
        }
      );

      expect(dashboard.type).toBe('cyber-battlefield');
      expect(dashboard.html).toContain('Cyber Battlefield Analysis');
      expect(dashboard.components).toBeDefined();
    });

    test('should include all component types', () => {
      const dashboard = battlefield.generateCyberBattlefield({}, {});
      expect(dashboard.components.attackSurface).toBeDefined();
      expect(dashboard.components.networkTopology).toBeDefined();
      expect(dashboard.components.killChain).toBeDefined();
      expect(dashboard.components.impactZones).toBeDefined();
    });

    test('should include metadata', () => {
      const dashboard = battlefield.generateCyberBattlefield(
        { assets: Array.from({ length: 5 }, () => ({})) },
        { techniques: Array.from({ length: 3 }, () => ({})) }
      );

      expect(dashboard.metadata.totalAssets).toBe(5);
      expect(dashboard.metadata.totalTechniques).toBe(3);
      expect(dashboard.metadata.generatedAt).toBeDefined();
    });

    test('should handle empty investigation and campaign', () => {
      const dashboard = battlefield.generateCyberBattlefield({}, {});
      expect(dashboard.type).toBe('cyber-battlefield');
      expect(dashboard.html).toContain('Cyber Battlefield Analysis');
    });

    test('should include all component HTML', () => {
      const dashboard = battlefield.generateCyberBattlefield(
        {
          assets: [{ status: 'compromised' }],
          nodes: [{ type: 'server' }],
          impactZones: [{ name: 'Zone' }],
        },
        { techniques: [{ name: 'Tech' }] }
      );

      expect(dashboard.html).toContain('Attack Surface');
      expect(dashboard.html).toContain('Network Topology');
      expect(dashboard.html).toContain('Kill Chain');
      expect(dashboard.html).toContain('Impact Zones');
    });

    test('should track node and asset counts', () => {
      const dashboard = battlefield.generateCyberBattlefield(
        {
          assets: Array.from({ length: 7 }, () => ({})),
          nodes: Array.from({ length: 4 }, () => ({})),
        },
        {}
      );

      expect(dashboard.metadata.totalAssets).toBe(7);
      expect(dashboard.metadata.totalNodes).toBe(4);
    });
  });

  describe('Color Utilities', () => {
    test('should return critical color for CRITICAL severity', () => {
      const color = battlefield.getSeverityColor('critical');
      expect(color).toBeDefined();
    });

    test('should return warning color for HIGH severity', () => {
      const color = battlefield.getSeverityColor('high');
      expect(color).toBeDefined();
    });

    test('should return accent color for MEDIUM severity', () => {
      const color = battlefield.getSeverityColor('medium');
      expect(color).toBeDefined();
    });

    test('should return success color for LOW severity', () => {
      const color = battlefield.getSeverityColor('low');
      expect(color).toBeDefined();
    });

    test('should return default color for unknown severity', () => {
      const color = battlefield.getSeverityColor('unknown');
      expect(color).toBeDefined();
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = battlefield.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = battlefield.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = battlefield.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape quotes', () => {
      const escaped = battlefield.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = battlefield.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(battlefield.escapeHtml(null)).toBe('');
      expect(battlefield.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very large asset counts', () => {
      const assets = Array.from({ length: 500 }, (_, i) => ({
        status: i % 4 === 0 ? 'compromised' : 'protected',
      }));
      const surface = battlefield.generateAttackSurface(assets);
      expect(surface.metadata.totalAssets).toBe(500);
    });

    test('should handle very large node counts', () => {
      const nodes = Array.from({ length: 1000 }, (_, i) => ({
        type: ['server', 'workstation', 'router', 'database'][i % 4],
      }));
      const topology = battlefield.generateNetworkTopology(nodes);
      expect(topology.metadata.totalNodes).toBe(1000);
    });

    test('should handle complete kill chain with all tactics', () => {
      const techniques = [
        { tactic: 'reconnaissance', name: 'T1592' },
        { tactic: 'initial-access', name: 'T1566' },
        { tactic: 'execution', name: 'T1059' },
        { tactic: 'persistence', name: 'T1098' },
        { tactic: 'privilege-escalation', name: 'T1055' },
        { tactic: 'defense-evasion', name: 'T1036' },
        { tactic: 'credential-access', name: 'T1110' },
        { tactic: 'discovery', name: 'T1087' },
        { tactic: 'lateral-movement', name: 'T1570' },
        { tactic: 'collection', name: 'T1123' },
        { tactic: 'command-and-control', name: 'T1071' },
        { tactic: 'exfiltration', name: 'T1020' },
        { tactic: 'impact', name: 'T1531' },
      ];
      const chain = battlefield.generateKillChain(techniques);
      expect(chain.metadata.tacticsObserved).toBe(13);
    });

    test('should handle special characters in node types', () => {
      const nodes = [{ type: 'server/workstation' }];
      const topology = battlefield.generateNetworkTopology(nodes);
      expect(topology.html).toContain('server/workstation');
    });

    test('should handle unicode in zone names', () => {
      const zones = [{ name: 'Zone 中文 🔐' }];
      const impactZones = battlefield.generateImpactZones(zones);
      expect(impactZones.html).toContain('中文');
    });

    test('should generate valid HTML structures', () => {
      const surface = battlefield.generateAttackSurface([]);
      expect(surface.html).toMatch(/<div[^>]*>/);
      expect(surface.html).toMatch(/<\/div>/);
    });

    test('should handle zero risk percentage', () => {
      const assets = Array.from({ length: 5 }, () => ({ status: 'protected' }));
      const surface = battlefield.generateAttackSurface(assets);
      expect(surface.metadata.riskPercent).toBe(0);
    });

    test('should handle 100% risk percentage', () => {
      const assets = Array.from({ length: 5 }, () => ({ status: 'compromised' }));
      const surface = battlefield.generateAttackSurface(assets);
      expect(surface.metadata.riskPercent).toBe(100);
    });
  });
});
