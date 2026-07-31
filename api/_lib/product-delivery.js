/**
 * SENTINEL APEX — Automated Product Delivery & Fulfillment
 * Delivers digital products automatically after payment confirmation.
 * No manual email required — customers get instant access.
 */
'use strict';

/**
 * Product delivery manifest — maps product_id to delivery strategy.
 * Each product has:
 *   - name: display name
 *   - description: what customer receives
 *   - deliveryType: 'download_link' | 'email_series' | 'api_key' | 'access_token'
 *   - contentPath: S3/R2 key or delivery reference
 *   - expiresIn: TTL in seconds (null = permanent)
 */
const DELIVERY_MANIFEST = {
  'sigma-megapack-2026': {
    name: 'CYBERDUDEBIVASH SENTINEL APEX Sigma Rule Megapack 2026',
    description: '2500+ production-ready Sigma YAML detection rules for SIEM deployment',
    deliveryType: 'download_link',
    contentPath: 'products/sigma-megapack-2026.zip',
    expiresIn: null,
  },
  'ransomware-yara-pack-2026': {
    name: '2026 Ransomware YARA Rule Pack',
    description: '1200+ YARA signatures for ransomware malware detection',
    deliveryType: 'download_link',
    contentPath: 'products/ransomware-yara-pack-2026.zip',
    expiresIn: null,
  },
  'q2-2026-threat-report': {
    name: 'Q2 2026 Threat Landscape Report — Enterprise Edition',
    description: 'PDF: Comprehensive threat intelligence report with APT tracking, zero-day analysis, incident patterns',
    deliveryType: 'download_link',
    contentPath: 'products/q2-2026-threat-report.pdf',
    expiresIn: null,
  },
  'soc-playbook-2026': {
    name: 'SOC Analyst Master Playbook 2026',
    description: 'PDF + runbook templates: Incident response, threat hunting, escalation procedures',
    deliveryType: 'download_link',
    contentPath: 'products/soc-playbook-2026.pdf',
    expiresIn: null,
  },
  'red-team-kit-2026': {
    name: 'Enterprise Red Team Operator Kit 2026',
    description: 'ZIP: Exploitation frameworks, payloads, C2 configs, post-exploitation scripts',
    deliveryType: 'download_link',
    contentPath: 'products/red-team-kit-2026.zip',
    expiresIn: null,
  },
  'soc-automation-bundle': {
    name: 'SOC Automation Scripts Bundle',
    description: 'Python/Bash scripts: Alert correlation, IOC enrichment, SOAR automation',
    deliveryType: 'download_link',
    contentPath: 'products/soc-automation-bundle.zip',
    expiresIn: null,
  },
  'cve-2026-detection-pack': {
    name: 'CVE-2026 Critical Exploit Detection Pack',
    description: 'Sigma rules, YARA signatures, network IDS rules for latest critical CVEs',
    deliveryType: 'download_link',
    contentPath: 'products/cve-2026-detection-pack.zip',
    expiresIn: null,
  },
  'apt-profile-pack-2026': {
    name: 'APT Group Profile Pack — 2026 Edition',
    description: 'Intelligence profiles: TTPs, infrastructure, targets, detection opportunities',
    deliveryType: 'download_link',
    contentPath: 'products/apt-profile-pack-2026.pdf',
    expiresIn: null,
  },
  'ransomware-defense-playbook': {
    name: 'Ransomware Defense Playbook — Enterprise',
    description: 'PDF: Prevention, detection, response, recovery for enterprise ransomware defense',
    deliveryType: 'download_link',
    contentPath: 'products/ransomware-defense-playbook.pdf',
    expiresIn: null,
  },
  'complete-arsenal-bundle': {
    name: 'CYBERDUDEBIVASH SENTINEL APEX Complete Arsenal Bundle',
    description: 'Everything: All rules, playbooks, reports, scripts, and detection packs',
    deliveryType: 'download_link',
    contentPath: 'products/complete-arsenal-bundle.zip',
    expiresIn: null,
  },
  'soc-starter-bundle': {
    name: 'SOC Starter Bundle',
    description: 'Curated essentials: Sigma rules, SOC playbook, threat report',
    deliveryType: 'download_link',
    contentPath: 'products/soc-starter-bundle.zip',
    expiresIn: null,
  },
  'enterprise-detection-bundle': {
    name: 'Enterprise Detection Bundle',
    description: 'Advanced bundle: Sigma rules, YARA pack, threat report, detection pack',
    deliveryType: 'download_link',
    contentPath: 'products/enterprise-detection-bundle.zip',
    expiresIn: null,
  },
};

/**
 * Generate a signed, time-limited download token for a product.
 * Token structure: `<productId>|<purchaseId>|<timestamp>|<signature>`
 */
function generateDownloadToken(productId, purchaseId, secret) {
  if (!secret) throw new Error('Download secret not configured');
  const crypto = require('crypto');
  const ts = Math.floor(Date.now() / 1000);
  const data = `${productId}|${purchaseId}|${ts}`;
  const sig = crypto.createHmac('sha256', secret).update(data).digest('hex');
  return `${data}|${sig}`;
}

/**
 * Verify and decode a download token.
 * Returns { valid: bool, productId, purchaseId, timestamp }
 */
function verifyDownloadToken(token, secret, maxAgeSecs = 7776000) {
  if (!secret) return { valid: false };
  const crypto = require('crypto');
  const parts = String(token || '').split('|');
  if (parts.length !== 4) return { valid: false };
  const [productId, purchaseId, ts, sig] = parts;
  const age = Math.floor(Date.now() / 1000) - parseInt(ts, 10);
  if (age > maxAgeSecs) return { valid: false, reason: 'EXPIRED' };
  const expected = crypto.createHmac('sha256', secret).update(`${productId}|${purchaseId}|${ts}`).digest('hex');
  try {
    const match = crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
    return { valid: match, productId, purchaseId, timestamp: parseInt(ts, 10) };
  } catch (_) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }
}

/**
 * Create delivery record for a purchased product.
 * Called after payment is confirmed.
 * Returns delivery info: { downloadUrl, contentPath, expiresIn, etc }
 */
async function fulfillProduct(email, productId, purchaseId, redis) {
  const manifest = DELIVERY_MANIFEST[productId];
  if (!manifest) throw new Error(`Unknown product: ${productId}`);

  const downloadSecret = process.env.DOWNLOAD_TOKEN_SECRET || '';
  if (!downloadSecret) throw new Error('DOWNLOAD_TOKEN_SECRET not configured');

  const token = generateDownloadToken(productId, purchaseId, downloadSecret);
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://blog.cyberdudebivash.in';
  const downloadUrl = `${baseUrl}/api/v1/customer/download?token=${encodeURIComponent(token)}`;

  try {
    await redis.hmset(`product:purchase:${purchaseId}`, {
      purchaseId,
      email,
      productId,
      productName: manifest.name,
      downloadToken: token,
      downloadUrl,
      contentPath: manifest.contentPath,
      deliveryType: manifest.deliveryType,
      purchasedAt: new Date().toISOString(),
      expiresIn: manifest.expiresIn || 'permanent',
      status: 'delivered',
    });

    if (manifest.expiresIn) {
      await redis.expire(`product:purchase:${purchaseId}`, manifest.expiresIn);
    }

    await redis.zadd('product:purchases', Date.now(), purchaseId);
    await redis.zadd(`product:purchases:${email}`, Date.now(), purchaseId);

    return {
      product_id: productId,
      product_name: manifest.name,
      description: manifest.description,
      download_url: downloadUrl,
      delivery_type: manifest.deliveryType,
      expires_in: manifest.expiresIn ? `${manifest.expiresIn} seconds` : 'Never',
    };
  } catch (e) {
    throw new Error(`Fulfillment failed: ${e.message}`);
  }
}

/**
 * Retrieve all purchases for an email address.
 */
async function getPurchaseHistory(email, redis) {
  try {
    const purchaseIds = await redis.zrange(`product:purchases:${email}`, 0, -1);
    const purchases = [];
    for (const id of purchaseIds) {
      const data = await redis.hgetall(`product:purchase:${id}`);
      if (data && data.length > 0) {
        const obj = {};
        for (let i = 0; i < data.length; i += 2) obj[data[i]] = data[i + 1];
        purchases.push(obj);
      }
    }
    return purchases;
  } catch (e) {
    return [];
  }
}

/**
 * Get download info and content path for a verified token.
 */
async function getDownloadInfo(token, redis, secret) {
  const verified = verifyDownloadToken(token, secret);
  if (!verified.valid) {
    return { error: verified.reason || 'INVALID_TOKEN' };
  }

  try {
    const purchase = await redis.hgetall(`product:purchase:${verified.purchaseId}`);
    if (!purchase || purchase.length === 0) {
      return { error: 'PURCHASE_NOT_FOUND' };
    }
    const obj = {};
    for (let i = 0; i < purchase.length; i += 2) obj[purchase[i]] = purchase[i + 1];
    return {
      valid: true,
      productId: obj.productId,
      productName: obj.productName,
      email: obj.email,
      contentPath: obj.contentPath,
      deliveryType: obj.deliveryType,
    };
  } catch (e) {
    return { error: 'SERVICE_ERROR' };
  }
}

module.exports = {
  DELIVERY_MANIFEST,
  generateDownloadToken,
  verifyDownloadToken,
  fulfillProduct,
  getPurchaseHistory,
  getDownloadInfo,
};
