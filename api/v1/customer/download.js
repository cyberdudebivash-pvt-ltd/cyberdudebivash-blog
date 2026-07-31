/**
 * SENTINEL APEX — Secure Product Download
 * GET /api/v1/customer/download?token={signed_token}
 *
 * Verifies the signed download token and redirects to S3/R2 presigned URL.
 * Token format: `productId|purchaseId|timestamp|signature`
 * Token is valid for 90 days by default.
 */
'use strict';

const redis = require('../../_lib/redis');
const deliveryLib = require('../../_lib/product-delivery');
const { fail, ok } = require('../../_lib/payment-utils');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('X-Powered-By', 'CYBERDUDEBIVASH SENTINEL APEX v4.0');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  }

  const token = String(req.query.token || '').trim();
  if (!token) {
    return fail(res, 400, 'MISSING_TOKEN', 'token query parameter required.');
  }

  const secret = process.env.DOWNLOAD_TOKEN_SECRET;
  if (!secret) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', 'Download service not configured.');
  }

  try {
    /* ── Verify and decode token ─────────────────────────────────── */
    const downloadInfo = await deliveryLib.getDownloadInfo(token, redis, secret);
    if (downloadInfo.error) {
      const statusMap = {
        INVALID_SIGNATURE: 403,
        INVALID_TOKEN: 400,
        EXPIRED: 410,
        PURCHASE_NOT_FOUND: 404,
      };
      return fail(res, statusMap[downloadInfo.error] || 500, downloadInfo.error, 'Token verification failed.');
    }

    /* ── Generate S3/R2 presigned URL ────────────────────────────── */
    const s3Client = getS3Client(); // Configure AWS SDK or use Cloudflare R2
    if (!s3Client) {
      return fail(res, 503, 'CDN_UNAVAILABLE', 'Content delivery not configured. Contact support.');
    }

    const contentPath = downloadInfo.contentPath; // e.g., 'products/sigma-megapack-2026.zip'
    const bucket = process.env.PRODUCTS_BUCKET || 'cyberdudebivash-products';

    try {
      const presignedUrl = await generatePresignedUrl(s3Client, bucket, contentPath);

      /* ── Log the download access ──────────────────────────────── */
      await redis.zadd('product:downloads', Date.now(), JSON.stringify({
        email: downloadInfo.email,
        productId: downloadInfo.productId,
        timestamp: new Date().toISOString(),
      }));

      /* ── Redirect to presigned URL ────────────────────────────── */
      res.setHeader('Location', presignedUrl);
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      return res.status(302).end();

    } catch (e) {
      return fail(res, 503, 'CDN_ERROR', 'Could not generate download link. Please retry or contact support.');
    }

  } catch (e) {
    return fail(res, 500, 'DOWNLOAD_ERROR', 'Download verification failed. Please retry.');
  }
};

/**
 * Initialize S3 client (AWS SDK v3 or compatible R2 client).
 * Uses environment variables:
 *   - AWS_REGION: e.g., 'us-east-1'
 *   - AWS_ACCESS_KEY_ID
 *   - AWS_SECRET_ACCESS_KEY
 *   OR
 *   - R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY
 */
function getS3Client() {
  // For Cloudflare R2:
  if (process.env.R2_ACCOUNT_ID) {
    try {
      const AWS = require('aws-sdk');
      return new AWS.S3({
        endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
        s3ForcePathStyle: true,
        signatureVersion: 'v4',
      });
    } catch (_) {
      return null;
    }
  }

  // For AWS S3:
  if (process.env.AWS_ACCESS_KEY_ID) {
    try {
      const AWS = require('aws-sdk');
      return new AWS.S3({
        region: process.env.AWS_REGION || 'us-east-1',
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      });
    } catch (_) {
      return null;
    }
  }

  return null;
}

/**
 * Generate presigned URL valid for 24 hours.
 * Product is delivered via download manager — downloads are logged.
 */
async function generatePresignedUrl(s3Client, bucket, key) {
  return new Promise((resolve, reject) => {
    const params = {
      Bucket: bucket,
      Key: key,
      Expires: 86400, // 24 hours
    };
    s3Client.getSignedUrl('getObject', params, (err, url) => {
      if (err) reject(err);
      else resolve(url);
    });
  });
}
