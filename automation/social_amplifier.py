"""
CYBERDUDEBIVASH® SENTINEL APEX — Social Amplification Module
Auto-posts threat alerts to Twitter/X via API v2 + OAuth 1.0a.
Multiplies content reach 10x — drives Blogger traffic → AdSense impressions.
"""

import base64
import hashlib
import hmac
import re
import time
import uuid
from typing import Optional
from urllib.parse import quote

import requests

from .config import Config
from .logger import setup_logger

logger = setup_logger("social_amplifier")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _extract_cves(text: str) -> list[str]:
    return _CVE_RE.findall(text)


class SocialAmplifier:
    """Amplifies published posts across social channels. Twitter/X supported."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def amplify(self, post: dict) -> dict:
        """
        Post to all configured social channels.
        Returns dict mapping channel → post_id (or None on skip/failure).
        post dict should contain: title, blogger_title, blogger_url, labels.
        """
        results: dict = {}

        if self._twitter_configured():
            results["twitter"] = self.post_to_twitter(post)
        else:
            logger.info("Twitter credentials not configured — skipping social amplification")

        return results

    def _twitter_configured(self) -> bool:
        return bool(
            self.config.twitter_api_key
            and self.config.twitter_api_secret
            and self.config.twitter_access_token
            and self.config.twitter_access_secret
        )

    def post_to_twitter(self, post: dict) -> Optional[str]:
        """Post a threat alert tweet via Twitter API v2. Returns tweet ID or None."""
        if not self._twitter_configured():
            return None

        tweet_text = self._build_tweet_text(post)
        api_url = "https://api.twitter.com/2/tweets"

        try:
            headers = self._build_oauth1_header("POST", api_url)
            resp = requests.post(
                api_url,
                json={"text": tweet_text},
                headers=headers,
                timeout=20,
            )
            resp.raise_for_status()
            tweet_id = resp.json().get("data", {}).get("id")
            logger.info(
                "Tweet posted",
                extra={
                    "tweet_id": tweet_id,
                    "chars": len(tweet_text),
                    "title": post.get("blogger_title", post.get("title", ""))[:60],
                },
            )
            return tweet_id
        except Exception as e:
            logger.warning("Twitter post failed", extra={"error": str(e)})
            return None

    def _build_tweet_text(self, post: dict) -> str:
        """Craft ≤280-char threat alert tweet with severity prefix and hashtags."""
        title = post.get("blogger_title") or post.get("title", "")
        blogger_url = post.get("blogger_url", "")
        labels = post.get("labels", [])
        label_lower = {lbl.lower() for lbl in labels}

        # Severity-based prefix
        if "cisa kev" in label_lower:
            prefix = "🚨 CISA KEV ALERT:"
        elif "critical cve" in label_lower:
            prefix = "⚠️ CRITICAL CVE:"
        elif "ransomware" in label_lower:
            prefix = "🔒 RANSOMWARE ALERT:"
        elif "apt" in label_lower:
            prefix = "🎯 APT THREAT:"
        elif "ai security" in label_lower:
            prefix = "🤖 AI SECURITY:"
        else:
            prefix = "🛡 THREAT INTEL:"

        # Hashtags (keep to 4 max for space)
        tags = ["#CyberSecurity", "#ThreatIntel", "#CyberDudeBivash"]
        if _extract_cves(title):
            tags.append("#CVE")
        elif "ransomware" in label_lower:
            tags.append("#Ransomware")
        elif "apt" in label_lower:
            tags.append("#APT")
        elif "ai security" in label_lower:
            tags.append("#AISecurity")
        elif "cisa kev" in label_lower:
            tags.append("#CISAKEV")
        else:
            tags.append("#SentinelAPEX")

        hashtag_str = " ".join(tags[:4])

        # Twitter shortens URLs to ~23 chars but we use actual URL
        url_len = len(blogger_url) + 2 if blogger_url else 0
        title_budget = (
            280 - len(prefix) - 1 - 2 - url_len - 2 - len(hashtag_str)
        )
        short_title = (
            title[:title_budget].rsplit(" ", 1)[0]
            if len(title) > title_budget
            else title
        )

        parts = [f"{prefix} {short_title}"]
        if blogger_url:
            parts.append(blogger_url)
        parts.append(hashtag_str)

        return "\n\n".join(parts)[:280]

    def _build_oauth1_header(self, method: str, url: str) -> dict:
        """
        Build RFC 5849 OAuth 1.0a Authorization header for Twitter API v2.
        Uses HMAC-SHA1 signing as required by Twitter OAuth 1.0a user context.
        """
        nonce = uuid.uuid4().hex
        timestamp = str(int(time.time()))

        oauth_params: dict[str, str] = {
            "oauth_consumer_key": self.config.twitter_api_key,
            "oauth_nonce": nonce,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": timestamp,
            "oauth_token": self.config.twitter_access_token,
            "oauth_version": "1.0",
        }

        # Percent-encode keys and values, sort lexicographically
        encoded = sorted(
            (quote(k, safe=""), quote(v, safe=""))
            for k, v in oauth_params.items()
        )
        param_string = "&".join(f"{k}={v}" for k, v in encoded)
        base_string = f"{method}&{quote(url, safe='')}&{quote(param_string, safe='')}"

        # HMAC-SHA1 signing key = consumer_secret&token_secret (percent-encoded)
        signing_key = (
            f"{quote(self.config.twitter_api_secret, safe='')}"
            f"&{quote(self.config.twitter_access_secret, safe='')}"
        )
        sig = hmac.new(
            signing_key.encode("utf-8"),
            base_string.encode("utf-8"),
            hashlib.sha1,
        )
        oauth_params["oauth_signature"] = base64.b64encode(sig.digest()).decode("utf-8")

        # Build Authorization header
        auth_value = "OAuth " + ", ".join(
            f'{quote(k, safe="")}="{quote(v, safe="")}"'
            for k, v in sorted(oauth_params.items())
        )

        return {
            "Authorization": auth_value,
            "Content-Type": "application/json",
        }
