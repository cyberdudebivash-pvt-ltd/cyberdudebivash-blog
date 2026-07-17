/**
 * CYBERDUDEBIVASH SENTINEL APEX — Client-Side Search Ranking
 *
 * Weighted relevance scoring + basic synonym support over the existing
 * search-index.json substring-match search (search.html) — no new
 * indexing infrastructure. Works as both a plain <script> global
 * (window.SentinelSearchRanking) and a CommonJS module for tests.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelSearchRanking = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Small, hand-curated synonym set for real cybersecurity terminology
  // used across this platform's content — not a general thesaurus.
  var SYNONYMS = {
    cve: ['vulnerability', 'vuln'],
    vulnerability: ['cve', 'vuln'],
    vuln: ['cve', 'vulnerability'],
    zeroday: ['0day', 'zero-day'],
    '0day': ['zeroday', 'zero-day'],
    ransomware: ['extortion'],
    ai: ['llm', 'artificial intelligence'],
    llm: ['ai', 'large language model'],
    apt: ['nation-state', 'nationstate'],
    breach: ['leak', 'exposure'],
    phishing: ['spearphishing'],
    malware: ['trojan', 'backdoor'],
  };

  function expandWord(word) {
    var alternates = [word];
    if (SYNONYMS[word]) alternates = alternates.concat(SYNONYMS[word]);
    return alternates;
  }

  function daysAgo(dateStr, now) {
    if (!dateStr) return null;
    var parsed = Date.parse(dateStr);
    if (isNaN(parsed)) return null;
    return Math.max(0, Math.floor(((now || Date.now()) - parsed) / 86400000));
  }

  /**
   * Score one index entry {t,s,d,desc,tp} against already-lowercased query
   * words. Returns null if the entry doesn't match — every word slot must
   * match in title or description via some synonym alternate (same AND
   * semantics the substring search already had), never a fabricated
   * relevance number for a non-match.
   */
  function scoreEntry(entry, words, now) {
    var titleLc = (entry.t || '').toLowerCase();
    var descLc = (entry.desc || '').toLowerCase();
    var score = 0;

    for (var i = 0; i < words.length; i++) {
      var alternates = expandWord(words[i]);
      var matchedInTitle = false;
      for (var a = 0; a < alternates.length; a++) {
        if (titleLc.indexOf(alternates[a]) !== -1) { matchedInTitle = true; break; }
      }
      var matchedInDesc = false;
      if (!matchedInTitle) {
        for (var b = 0; b < alternates.length; b++) {
          if (descLc.indexOf(alternates[b]) !== -1) { matchedInDesc = true; break; }
        }
      }
      if (!matchedInTitle && !matchedInDesc) return null;
      score += matchedInTitle ? 20 : 5;
      if (matchedInTitle && titleLc.indexOf(words[i]) === 0) score += 5; // title starts with the literal query word
    }

    if (words.length > 1) {
      var phrase = words.join(' ');
      if (titleLc.indexOf(phrase) !== -1) score += 50; // exact phrase beats separate word matches
    }

    var age = daysAgo(entry.d, now);
    if (age !== null) {
      score += Math.max(0, 10 - Math.floor(age / 90)); // small, capped recency bonus — never dominates relevance
    }

    return score;
  }

  /**
   * Rank a full index against a query + optional type filter. Preserves
   * the existing empty-query behavior (all entries of the filtered type,
   * unscored/unsorted — same as before ranking existed) so search.html's
   * "browse by type with no query" path is unchanged.
   */
  function rankEntries(index, query, typeFilter, now) {
    var words = String(query || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    var scored = [];
    for (var i = 0; i < index.length; i++) {
      var entry = index[i];
      if (typeFilter && typeFilter !== 'ALL' && entry.tp !== typeFilter) continue;
      if (words.length === 0) {
        scored.push({ entry: entry, score: 0 });
        continue;
      }
      var score = scoreEntry(entry, words, now);
      if (score === null) continue;
      scored.push({ entry: entry, score: score });
    }
    scored.sort(function (a, b) { return b.score - a.score; });
    return scored.map(function (s) { return s.entry; });
  }

  return { SYNONYMS: SYNONYMS, expandWord: expandWord, daysAgo: daysAgo, scoreEntry: scoreEntry, rankEntries: rankEntries };
});
