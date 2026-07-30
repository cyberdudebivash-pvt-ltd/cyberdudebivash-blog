// Test Fixtures — Reusable test data and constants

export const CONFIDENCE_COMPONENTS = {
  high: {
    sourceReliability: { score: 95, basis: 'Direct observation', weight: 0.25 },
    observationQuality: { score: 90, basis: 'Full behavioral analysis', weight: 0.25 },
    technicalValidation: { score: 95, basis: 'VirusTotal verified', weight: 0.2 },
    analystVerification: { score: 85, basis: 'Senior analyst review', weight: 0.15 },
    independentCorroboration: { score: 80, basis: 'Confirmed by 3 sources', weight: 0.15 },
  },
  medium: {
    sourceReliability: { score: 75, basis: 'Secondary source', weight: 0.25 },
    observationQuality: { score: 75, basis: 'Limited context', weight: 0.25 },
    technicalValidation: { score: 70, basis: 'Partial validation', weight: 0.2 },
    analystVerification: { score: 65, basis: 'Junior analyst review', weight: 0.15 },
    independentCorroboration: { score: 60, basis: 'Confirmed by 1 source', weight: 0.15 },
  },
  low: {
    sourceReliability: { score: 50, basis: 'Unverified claim', weight: 0.25 },
    observationQuality: { score: 40, basis: 'Minimal observation', weight: 0.25 },
    technicalValidation: { score: 30, basis: 'No validation', weight: 0.2 },
    analystVerification: { score: 25, basis: 'Not reviewed', weight: 0.15 },
    independentCorroboration: { score: 20, basis: 'Not confirmed', weight: 0.15 },
  },
};

export const IOC_TYPES = [
  'ipv4',
  'ipv6',
  'domain',
  'url',
  'email',
  'hash_md5',
  'hash_sha1',
  'hash_sha256',
  'hash_ssdeep',
  'file_path',
  'registry_key',
  'user_agent',
  'ja3',
  'ja3s',
  'certificate_hash',
  'service_port',
  'process_name',
  'mutex',
];

export const MITRE_TECHNIQUES = [
  {
    id: 'T1566.002',
    name: 'Phishing: Spearphishing Link',
    tactics: ['Initial Access'],
  },
  {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactics: ['Execution'],
  },
  {
    id: 'T1543.003',
    name: 'Create or Modify System Process: Windows Service',
    tactics: ['Persistence', 'Privilege Escalation'],
  },
  {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactics: ['Discovery'],
  },
  {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactics: ['Exfiltration'],
  },
];

export const MALWARE_FAMILIES = {
  emotet: {
    name: 'Emotet',
    type: 'trojan',
    description: 'Emotet is a modular banking trojan',
    aliases: ['Heodo', 'Geodo', 'Mineloader'],
    firstSeen: new Date('2014-06-01'),
    lastSeen: new Date('2021-01-27'),
  },
  lockbit: {
    name: 'LockBit',
    type: 'ransomware',
    description: 'LockBit is a ransomware-as-a-service operation',
    aliases: ['LockBit 2.0', 'LockBit 3.0'],
    firstSeen: new Date('2019-09-01'),
    lastSeen: new Date('2024-07-30'),
  },
  trickbot: {
    name: 'TrickBot',
    type: 'banking_malware',
    description: 'TrickBot is a modular banking trojan and loader',
    aliases: ['TrickTor', 'Totbrick'],
    firstSeen: new Date('2016-09-01'),
    lastSeen: new Date('2024-07-30'),
  },
};

export const THREAT_ACTORS = {
  evil_corp: {
    name: 'Evil Corp',
    aliases: ['UNC1808', 'FIN7', 'Carbon Spider'],
    country: 'Russia',
    type: 'cybercriminal',
    firstSeen: new Date('2014-01-01'),
  },
  lazarus: {
    name: 'Lazarus Group',
    aliases: ['APT38', 'HIDDEN COBRA'],
    country: 'North Korea',
    type: 'nation_state',
    firstSeen: new Date('2009-01-01'),
  },
};

export const DETECTION_RULE_FORMATS = ['sigma', 'yara', 'suricata', 'siem'];

export const WORKFLOW_STATES = [
  'draft',
  'submitted',
  'in_review',
  'qa_check',
  'approved',
  'published',
  'rejected',
  'retracted',
];

export const APPROVAL_ROLES = ['analyst', 'peer_analyst', 'qa_lead', 'security_officer'];

export const QUALITY_GATES = [
  'missing_metadata',
  'missing_evidence',
  'mitre_validation',
  'confidence_threshold',
  'source_reliability',
  'observation_quality',
  'technical_validation',
  'analyst_verification',
  'independent_corroboration',
];

export const PERFORMANCE_SLA_TARGETS = {
  simpleReportGeneration: 5000, // 5 seconds
  complexReportGeneration: 30000, // 30 seconds
  iocNormalization: 1, // 1ms per IOC
  detectionRuleGeneration: 2, // 2ms per IOC
  governanceTransition: 100, // 100ms
  approvalChain: 500, // 500ms for 4-role chain
  confidenceScoring: 50, // 50ms per object
  auditLogWrite: 10, // 10ms per entry
};

export const LARGE_IOC_CORPUS = {
  count: 5000,
  types: {
    ipv4: 800,
    ipv6: 300,
    domain: 1200,
    url: 1000,
    email: 600,
    hash_md5: 400,
    hash_sha1: 300,
    hash_sha256: 400,
  },
};
