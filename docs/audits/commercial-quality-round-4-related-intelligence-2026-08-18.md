# Commercial Quality — Round 4: Related Intelligence Was a Recency Feed

**Scope:** an external review's specific complaint — "the ransomware victim report's related intelligence contains multiple unrelated critical CVEs... appears to be recency-based recommendation rather than intelligence correlation."

## Root cause

`internal_linker.InternalLinker.build_correlation_block()` ranks shared-CVE matches highest, then falls back to shared-label matches. The fallback's bug: `content_discovery._infer_labels()` puts `"CYBERDUDEBIVASH"` and `"Threat Intelligence"` on **every** article unconditionally, and `rss_aggregator.py` additionally forces `"Global Intel"` onto every RSS-sourced article. Since both the current article and every candidate always share at least these labels, `article_label_set & entry_labels` was **never empty** — the "shared labels" check always passed, sorted only by recency within the tier. Functionally indistinguishable from "show the 5 most recent posts," exactly matching the live symptom.

## Fix

Excluded the three confirmed-universal labels from the match set (`_NON_DISCRIMINATING_LABELS`), so only genuinely topic/actor/campaign-specific labels ("Ransomware", "AI Security", "Vulnerabilities", ...) count as a relationship. When an article shares no real label with anything previously published (and no CVE), `build_correlation_block()` now correctly returns `""` — the function already had this behavior for the empty-match case; it just never used to actually reach it.

## Verification

- 9/9 `test_internal_linker.py` tests pass, including a new one reproducing the exact defect (an unrelated CVE report sharing only universal labels with a ransomware article must not be surfaced as related) and one confirming genuine shared labels (e.g. two ransomware reports) still match correctly.
- 340 tests pass across the root suite.

## Not attempted here

This fixes the *false positive* (unrelated content surfacing as "related"). It does not add the richer correlation ChatGPT's review asked for — same actor, same campaign, same malware family, same technique — since none of that is modeled in `published_posts.json` today (only title/URL/CVEs/labels/date are persisted per post). Building real actor/campaign/technique correlation needs those fields captured at publish time first, a separate, larger piece of work.
