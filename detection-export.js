/**
 * CYBERDUDEBIVASH — DETECTION EXPORT v1.0
 * One-click copy for every rendered Sigma / YARA / Splunk / KQL / OSQuery /
 * Suricata code block (.code-block), plus a derived quick-search export
 * (Splunk SPL / Sentinel KQL) for generic keyword-only Sigma drafts that
 * have no real per-platform sibling block already rendered on the page.
 *
 * Pure DOM retrofit: scans whatever .code-block elements already exist on
 * the page (produced by fetch-live-intel.js's genSigma/genYARA and
 * genMultiPlatformDetections). Adds no network calls, invents no new
 * detection logic -- the derived SPL/KQL export is a mechanical syntax
 * translation of the exact keywords already visible in the Sigma block,
 * labeled as a quick-search draft rather than a production-tuned rule.
 */
(function () {
  'use strict';

  var COPIED_LABEL = '✓ Copied';
  var COPY_RESET_MS = 1800;

  function escHtml(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function blockLabel(block) {
    var lbl = block.querySelector('.code-lbl');
    return lbl ? lbl.textContent.trim() : '';
  }

  function blockText(block) {
    var clone = block.cloneNode(true);
    var lbl = clone.querySelector('.code-lbl');
    if (lbl) lbl.remove();
    var toolbar = clone.querySelector('.dexp-toolbar');
    if (toolbar) toolbar.remove();
    return (clone.textContent || '').trim();
  }

  function copyToClipboard(text, onDone) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { onDone(true); }, function () { onDone(false); });
      return;
    }
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      onDone(!!ok);
    } catch (e) {
      onDone(false);
    }
  }

  function makeButton(label, title, onClick) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'dexp-btn';
    btn.textContent = label;
    if (title) btn.title = title;
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      onClick(btn);
    });
    return btn;
  }

  function flashCopied(btn, originalLabel) {
    btn.textContent = COPIED_LABEL;
    btn.classList.add('dexp-btn-ok');
    setTimeout(function () {
      btn.textContent = originalLabel;
      btn.classList.remove('dexp-btn-ok');
    }, COPY_RESET_MS);
  }

  // Parses the small subset of Sigma this pipeline actually generates
  // (logsource.category + detection.keywords / condition: keywords) --
  // not a general Sigma parser, just enough to derive a quick search.
  function parseSigmaKeywords(sigmaText) {
    var category = (sigmaText.match(/category:\s*([^\r\n]+)/i) || [])[1];
    var lines = sigmaText.split('\n');
    var inKeywords = false;
    var keywords = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^\s*keywords:\s*$/i.test(line)) { inKeywords = true; continue; }
      if (inKeywords) {
        var m = line.match(/^\s*-\s*['"]?([^'"]+?)['"]?\s*$/);
        if (m) { keywords.push(m[1]); continue; }
        break; // first non-list-item line ends the keywords block
      }
    }
    return { category: category ? category.trim() : '', keywords: keywords };
  }

  // Backslashes must be escaped before quotes -- otherwise a keyword
  // ending in a backslash (e.g. "foo\") would leave the closing quote we
  // add escaped by that backslash instead of terminating the string,
  // letting the rest of the generated query run as unquoted content.
  function quoteTerm(k) {
    return '"' + k.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }

  function deriveSplunkSPL(sigmaText) {
    var parsed = parseSigmaKeywords(sigmaText);
    if (!parsed.keywords.length) return '';
    var terms = parsed.keywords.map(quoteTerm).join(' OR ');
    var src = parsed.category ? 'sourcetype=' + parsed.category + ' ' : '';
    return 'index=* ' + src + '(' + terms + ')';
  }

  function deriveSentinelKQL(sigmaText) {
    var parsed = parseSigmaKeywords(sigmaText);
    if (!parsed.keywords.length) return '';
    var terms = parsed.keywords.map(quoteTerm).join(', ');
    return 'search ' + terms + '\n| where TimeGenerated > ago(30d)';
  }

  function hasRealPlatformBlock(pattern) {
    var blocks = document.querySelectorAll('.code-block .code-lbl');
    for (var i = 0; i < blocks.length; i++) {
      if (pattern.test(blocks[i].textContent || '')) return true;
    }
    return false;
  }

  function enhanceBlock(block) {
    if (block.querySelector('.dexp-toolbar')) return; // already enhanced
    var label = blockLabel(block);
    var toolbar = document.createElement('div');
    toolbar.className = 'dexp-toolbar';

    var copyBtn = makeButton('📋 Copy' + (label ? ' ' + label.split(' ')[0] : ''), 'Copy this rule to clipboard', function (btn) {
      copyToClipboard(blockText(block), function (ok) {
        if (ok) flashCopied(btn, copyBtn._label);
      });
    });
    copyBtn._label = copyBtn.textContent;
    toolbar.appendChild(copyBtn);

    // Only offer a derived SIEM quick-search when this is a generic Sigma
    // draft AND no real, higher-fidelity Splunk/KQL block already exists
    // on this page (genMultiPlatformDetections renders those directly).
    if (/sigma/i.test(label)) {
      var sigmaText = blockText(block);
      if (!hasRealPlatformBlock(/splunk/i)) {
        var spl = deriveSplunkSPL(sigmaText);
        if (spl) {
          toolbar.appendChild(makeButton('⚡ Quick SPL', 'Derived Splunk quick-search from this rule\'s keywords -- not a tuned production query', function (btn) {
            copyToClipboard(spl, function (ok) { if (ok) flashCopied(btn, btn._label); });
          }));
          toolbar.lastChild._label = toolbar.lastChild.textContent;
        }
      }
      if (!hasRealPlatformBlock(/kql|sentinel/i)) {
        var kql = deriveSentinelKQL(sigmaText);
        if (kql) {
          toolbar.appendChild(makeButton('🔷 Quick KQL', 'Derived Microsoft Sentinel quick-search from this rule\'s keywords -- not a tuned production query', function (btn) {
            copyToClipboard(kql, function (ok) { if (ok) flashCopied(btn, btn._label); });
          }));
          toolbar.lastChild._label = toolbar.lastChild.textContent;
        }
      }
    }

    block.appendChild(toolbar);
  }

  function injectStyles() {
    if (document.getElementById('cdb-dexp-styles')) return;
    var css = '<style id="cdb-dexp-styles">' +
      '.code-block{position:relative;padding-bottom:44px !important}' +
      '.dexp-toolbar{position:absolute;bottom:8px;left:16px;right:16px;display:flex;gap:6px;flex-wrap:wrap}' +
      '.dexp-btn{background:#0d1524;border:1px solid #1f2937;color:#8aa0c0;font-size:11px;font-weight:700;' +
      'padding:4px 10px;border-radius:5px;cursor:pointer;font-family:inherit;transition:.15s}' +
      '.dexp-btn:hover{border-color:#00ffe066;color:#00ffe0}' +
      '.dexp-btn-ok{background:#00ffe022;border-color:#00ffe0;color:#00ffe0}' +
      '</style>';
    document.head.insertAdjacentHTML('beforeend', css);
  }

  function run() {
    var blocks = document.querySelectorAll('.code-block');
    if (!blocks.length) return;
    injectStyles();
    for (var i = 0; i < blocks.length; i++) enhanceBlock(blocks[i]);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }

  window.CDBDetectionExport = { run: run };
})();
