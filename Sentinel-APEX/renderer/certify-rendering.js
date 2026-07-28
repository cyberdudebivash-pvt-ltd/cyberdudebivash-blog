'use strict';
/**
 * SENTINEL APEX — Rendering Certification CLI (EICF v1)
 *
 * Thin CLI wrapper around report-renderer.js's checkRendering(). Exists so
 * Sentinel-APEX/engine's certification.py (Python) can get a Rendering
 * Quality verdict on any report by shelling out to this one stable entry
 * point, without either side re-implementing Markdown parsing.
 *
 * Usage: node certify-rendering.js <report.md>
 * Prints a JSON verdict to stdout. Exit 0 if ok, 1 if not, 2 on usage error.
 */

const fs = require('node:fs');
const path = require('node:path');
const { checkRendering } = require('./report-renderer');

function main() {
  const reportPath = process.argv[2];
  if (!reportPath) {
    process.stderr.write('usage: node certify-rendering.js <report.md>\n');
    return 2;
  }
  let text;
  try {
    text = fs.readFileSync(path.resolve(reportPath), 'utf8');
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, issues: [`could not read ${reportPath}: ${e.message}`], warnings: [] }));
    return 1;
  }
  const result = checkRendering(text);
  process.stdout.write(JSON.stringify(result));
  return result.ok ? 0 : 1;
}

if (require.main === module) process.exit(main());

module.exports = { main };
