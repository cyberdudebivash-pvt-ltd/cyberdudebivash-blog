@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-BLOG\cyberdudebivash-blog"

git fetch origin main
git add conversion-engine.js ai-monetization-engine.js banner-orchestrator.js index.html
git add api/ posts/ live-intel.json intel-state.json vercel.json api-dashboard.html
git add -A
git commit -m "fix: move all header/hero notifications to bottom of page near footer

- conversion-engine.js: cx4-return-banner repositioned bottom:0, translateY(100%), border-top
- ai-monetization-engine.js: aim-upgrade-strip repositioned bottom:0, translateY(100%), border-top; aim-toast-container moved to right:20px
- banner-orchestrator.js: TOP_BANNERS/PRIORITY pruned; cx4-return-banner + aim-upgrade-strip moved to BOTTOM_BANNERS
- index.html: CSS !important overrides to anchor all promo banners to bottom of viewport; toast container nudge on banner show
- Live intel pipeline: updated CVE data, posts, iocs, ransomware, top-threats"

git rebase origin/main
git push origin main
echo EXIT_CODE=%ERRORLEVEL%
