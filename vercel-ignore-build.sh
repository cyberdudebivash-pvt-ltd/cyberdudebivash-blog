#!/usr/bin/env bash
# Vercel ignoreCommand — exit 0 SKIPS the build, exit 1 PROCEEDS.
#
# Why: sentinel-apex (every 5 min) and blogger-syndication (every 15 min)
# push to main hundreds of times a day. Each push triggered a Vercel build,
# exhausting the Hobby plan's 100 deployments/day quota — which froze ALL
# production deploys, including hotfixes ("Deployment rate limited — retry
# in 24 hours", seen 2026-07-05).
#
# Rule:
#   • Human commits (fixes, features, merges) ALWAYS deploy.
#   • Bot commits deploy only during the first 10 minutes of every even
#     UTC hour (~12 windows/day, a handful of builds each) — enough to
#     keep auto-published content and intel feeds fresh (max ~2h latency)
#     while staying far below the deployment quota.
#
# Any script error exits non-zero, so the safe fallback is "build".

MSG="$(git log -1 --pretty=%B 2>/dev/null || true)"

case "$MSG" in
  "SENTINEL APEX"*|"syndication: auto-published"*|*"🛰 [SENTINEL APEX]"*)
    HOUR=$((10#$(date -u +%H)))
    MIN=$((10#$(date -u +%M)))
    if [ $((HOUR % 2)) -eq 0 ] && [ "$MIN" -lt 10 ]; then
      echo "bot commit inside deploy window (even hour, min ${MIN}) — building"
      exit 1
    fi
    echo "bot commit outside deploy window — skipping build (content ships with the next window)"
    exit 0
    ;;
esac

echo "human commit — building"
exit 1
