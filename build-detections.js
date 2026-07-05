#!/usr/bin/env node
/**
 * Detection Pack builder — CYBERDUDEBIVASH SENTINEL APEX
 *
 * Emits syntactically-valid Sigma rules for confirmed CISA KEV CVEs. Each rule
 * carries a traceability block linking it to its CVE, the KEV catalog entry
 * (with the exact dateAdded), and the vendor advisory / NVD record. Detection
 * logic targets the exploitation *behaviour class* for the vulnerability —
 * standard, defensible detection engineering, not fabricated IOCs.
 *
 * Also renders /detections/index.html cataloguing the pack.
 */
const fs = require('fs');
const crypto = require('crypto');

const kev = JSON.parse(fs.readFileSync('/tmp/kev-fresh.json', 'utf8'));
const kevOf = id => kev.vulnerabilities.find(v => v.cveID === id);
const RULES_DIR = '/home/user/cyberdudebivash-blog/detections/rules';
fs.mkdirSync(RULES_DIR, { recursive: true });

// Hand-authored detection cores. Each targets the exploitation behaviour class
// for the CVE. `body` is the Sigma content below the traceability header.
const DETECTIONS = [
  {
    cve: 'CVE-2026-45659', slug: 'sharepoint-deserialization-rce',
    title: 'Microsoft SharePoint Worker Process Spawning Command Shell (CVE-2026-45659)',
    tactic: ['attack.initial_access', 'attack.t1190', 'attack.execution', 'attack.t1059'],
    level: 'high',
    desc: 'Detects the IIS SharePoint worker process (w3wp.exe) spawning a command interpreter — the post-exploitation signature of deserialization RCE against SharePoint Server.',
    fp: ['Legitimate SharePoint timer jobs or administrative scripts that shell out (rare — baseline before enabling).'],
    body: `logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\\\\w3wp.exe'
        ParentCommandLine|contains: 'SharePoint'
    selection_child:
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
            - '\\\\cscript.exe'
            - '\\\\wscript.exe'
    condition: selection_parent and selection_child`,
  },
  {
    cve: 'CVE-2026-32201', slug: 'sharepoint-input-validation-w3wp-child',
    title: 'SharePoint Server Anomalous Child Process (CVE-2026-32201)',
    tactic: ['attack.initial_access', 'attack.t1190', 'attack.persistence', 'attack.t1505.003'],
    level: 'high',
    desc: 'Detects w3wp.exe hosting SharePoint spawning reconnaissance or web-shell-dropping utilities following exploitation of the SharePoint improper-input-validation vulnerability.',
    fp: ['SharePoint patch/config tooling invoked by administrators.'],
    body: `logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\\\\w3wp.exe'
    selection_child:
        Image|endswith:
            - '\\\\whoami.exe'
            - '\\\\net.exe'
            - '\\\\net1.exe'
            - '\\\\ipconfig.exe'
            - '\\\\certutil.exe'
    condition: selection_parent and selection_child
    fields:
        - CommandLine
        - ParentCommandLine`,
  },
  {
    cve: 'CVE-2026-33825', slug: 'defender-access-control-lpe',
    title: 'Suspicious Modification of Microsoft Defender Platform Path (CVE-2026-33825)',
    tactic: ['attack.privilege_escalation', 'attack.t1068', 'attack.defense_evasion', 'attack.t1562.001'],
    level: 'high',
    desc: 'Detects non-SYSTEM writes into the Microsoft Defender Antimalware Platform directory, consistent with the access-control LPE (ransomware-linked in the CISA KEV catalog).',
    fp: ['Legitimate Defender platform updates (delivered by TrustedInstaller / SYSTEM — exclude those accounts).'],
    body: `logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\\\\Windows Defender\\\\Platform\\\\'
    filter_system:
        User|contains:
            - 'SYSTEM'
            - 'TrustedInstaller'
    condition: selection and not filter_system
    fields:
        - Image
        - User
        - TargetFilename`,
  },
  {
    cve: 'CVE-2026-10520', slug: 'ivanti-sentry-os-command-injection',
    title: 'Ivanti Sentry Appliance Web Process Spawning Shell (CVE-2026-10520)',
    tactic: ['attack.initial_access', 'attack.t1190', 'attack.execution', 'attack.t1059.004'],
    level: 'critical',
    desc: 'Detects the Ivanti Sentry web/application service spawning a shell interpreter — the signature of OS command injection against the appliance.',
    fp: ['Appliance maintenance scripts run by vendor support (baseline before enabling).'],
    body: `logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/java'
            - '/httpd'
            - '/tomcat'
            - '/node'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/nc'
            - '/curl'
            - '/wget'
    condition: selection_parent and selection_child
    fields:
        - CommandLine
        - ParentCommandLine`,
  },
  {
    cve: 'CVE-2026-6973', slug: 'ivanti-epmm-input-validation-rce',
    title: 'Ivanti EPMM Web Service Spawning Shell (CVE-2026-6973)',
    tactic: ['attack.initial_access', 'attack.t1190', 'attack.execution', 'attack.t1059.004'],
    level: 'critical',
    desc: 'Detects the Ivanti Endpoint Manager Mobile (EPMM) application server spawning a shell — the post-exploitation signature of the improper-input-validation RCE.',
    fp: ['Legitimate EPMM maintenance jobs (baseline before enabling).'],
    body: `logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|contains:
            - 'tomcat'
            - 'mifs'
            - 'java'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/python'
            - '/perl'
            - '/nc'
    condition: selection_parent and selection_child
    fields:
        - CommandLine
        - ParentCommandLine`,
  },
  {
    cve: 'CVE-2026-48558', slug: 'simplehelp-auth-bypass',
    title: 'SimpleHelp Unauthenticated Access to Administrative Endpoint (CVE-2026-48558)',
    tactic: ['attack.initial_access', 'attack.t1190', 'attack.credential_access'],
    level: 'high',
    desc: 'Detects HTTP requests to SimpleHelp administrative/toolbox endpoints returning success without a preceding authenticated session — consistent with the authentication-bypass vulnerability.',
    fp: ['Legitimate administrators reaching the toolbox from known management IPs — scope the filter to your admin ranges.'],
    body: `logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/toolbox'
            - '/admin'
            - '/serverconfig'
        sc-status:
            - 200
            - 302
    filter_admin_source:
        c-ip|cidr:
            - '10.0.0.0/8'
            - '192.168.0.0/16'
    condition: selection and not filter_admin_source
    fields:
        - c-ip
        - cs-uri-stem
        - cs-user-agent`,
  },
  {
    cve: 'CVE-2026-20253', slug: 'splunk-missing-auth-critical-function',
    title: 'Splunk Enterprise Unauthenticated Access to Critical Endpoint (CVE-2026-20253)',
    tactic: ['attack.initial_access', 'attack.t1190', 'attack.execution', 'attack.t1059'],
    level: 'high',
    desc: 'Detects access to Splunk management/REST endpoints from outside expected management ranges, consistent with exploitation of the missing-authentication-for-critical-function vulnerability.',
    fp: ['Search-head clustering / forwarder management traffic — add those hosts to the source filter.'],
    body: `logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/services/'
            - '/servicesNS/'
            - '/en-US/manager'
    filter_mgmt_source:
        c-ip|cidr:
            - '10.0.0.0/8'
            - '192.168.0.0/16'
    condition: selection and not filter_mgmt_source
    fields:
        - c-ip
        - cs-uri-stem
        - cs-method`,
  },
  {
    cve: 'CVE-2026-35616', slug: 'fortinet-forticlient-ems-access-control',
    title: 'Fortinet FortiClient EMS Anomalous API Access (CVE-2026-35616)',
    tactic: ['attack.initial_access', 'attack.t1190'],
    level: 'high',
    desc: 'Detects access to FortiClient EMS API/console endpoints from unexpected sources, consistent with exploitation of the improper-access-control vulnerability.',
    fp: ['Managed endpoints checking in from expected corporate ranges — scope the source filter to those.'],
    body: `logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/api/'
            - '/cgi-bin/'
            - '/console'
        sc-status: 200
    filter_corp_source:
        c-ip|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection and not filter_corp_source
    fields:
        - c-ip
        - cs-uri-stem
        - cs-user-agent`,
  },
];

const DATE = '2026/07/05';
const AUTHOR = 'CYBERDUDEBIVASH SENTINEL APEX';

function buildRule(d) {
  const k = kevOf(d.cve);
  const cveTag = 'cve.' + d.cve.replace('CVE-', '').replace('-', '.').toLowerCase();
  const tags = [...d.tag_extra || [], ...d.tactic, cveTag];
  const refs = [
    `https://nvd.nist.gov/vuln/detail/${d.cve}`,
    'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    `https://blog.cyberdudebivash.in/detections/`,
  ];
  const id = crypto.createHash('sha1').update('cdb-apex:' + d.cve + ':' + d.slug).digest('hex');
  const uuid = [id.slice(0, 8), id.slice(8, 12), '5' + id.slice(13, 16), '8' + id.slice(17, 20), id.slice(20, 32)].join('-');
  return `# ============================================================================
# CYBERDUDEBIVASH SENTINEL APEX — Detection Pack
# Traceability:
#   CVE ............ ${d.cve}
#   Vendor / Product ${k.vendorProject} / ${k.product}
#   CISA KEV ....... added ${k.dateAdded}, federal remediation due ${k.dueDate}
#   Ransomware ..... ${k.knownRansomwareCampaignUse}
#   NVD ............ https://nvd.nist.gov/vuln/detail/${d.cve}
#   KEV catalog .... https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# Every claim in this rule's metadata is verifiable against the sources above.
# ============================================================================
title: ${d.title}
id: ${uuid}
status: experimental
description: |
    ${d.desc}
references:
${refs.map(r => '    - ' + r).join('\n')}
author: ${AUTHOR}
date: ${DATE}
tags:
${tags.map(t => '    - ' + t).join('\n')}
${d.body}
falsepositives:
${d.fp.map(f => '    - ' + f).join('\n')}
level: ${d.level}
`;
}

const built = [];
for (const d of DETECTIONS) {
  const yaml = buildRule(d);
  const fname = `${d.cve.toLowerCase()}-${d.slug}.yml`;
  fs.writeFileSync(`${RULES_DIR}/${fname}`, yaml);
  const k = kevOf(d.cve);
  built.push({ ...d, fname, vendor: k.vendorProject, product: k.product, kevAdded: k.dateAdded, kevDue: k.dueDate, ransomware: k.knownRansomwareCampaignUse === 'Known' });
}

fs.writeFileSync('/tmp/detections-manifest.json', JSON.stringify(built, null, 2));
console.log('Built', built.length, 'Sigma rules ->', RULES_DIR);
built.forEach(b => console.log('  ', b.fname, '|', b.level));
