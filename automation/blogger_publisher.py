"""
CYBERDUDEBIVASH® SENTINEL APEX — Blogger Publisher Module
Handles OAuth2 token refresh and article publication to Blogger via API v3.
Implements retry logic, failure recovery, and audit logging.
"""

import time
from typing import Optional

import requests

from .config import Config
from .logger import setup_logger

logger = setup_logger("blogger_publisher")

BLOGGER_API_BASE = "https://www.googleapis.com/blogger/v3"
TOKEN_URL = "https://oauth2.googleapis.com/token"


def _retry_after_seconds(resp: "requests.Response") -> Optional[float]:
    """
    Honor a Retry-After header (seconds, or an HTTP-date) when present —
    more correct than blind exponential backoff since it's the server
    telling us exactly how long its rate-limit window has left. Returns
    None if absent or unparseable, so callers fall back to their own
    backoff schedule.
    """
    raw = resp.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        from datetime import datetime, timezone as _tz

        target = parsedate_to_datetime(raw)
        if target.tzinfo is None:
            target = target.replace(tzinfo=_tz.utc)
        return max(0.0, (target - datetime.now(_tz.utc)).total_seconds())
    except (TypeError, ValueError):
        return None


class BloggerAuthError(Exception):
    pass


class BloggerPublishError(Exception):
    """
    category distinguishes failure types so callers can react differently —
    in particular 'rate_limited' signals the *pipeline* should stop
    attempting further posts this run rather than retry-storm every
    remaining article against an already-exhausted quota (see
    automation/main.py's circuit breaker).
    """

    def __init__(self, message: str, category: str = "unknown") -> None:
        super().__init__(message)
        self.category = category


class BloggerPublisher:
    """Publishes posts to Blogger via API v3 with OAuth2 refresh token auth."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0

    # ------------------------------------------------------------------ #
    # Authentication                                                        #
    # ------------------------------------------------------------------ #

    def _get_access_token(self) -> str:
        """Return a valid access token, refreshing if needed."""
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token

        logger.info("Refreshing Blogger OAuth2 access token")
        resp = requests.post(
            TOKEN_URL,
            data={
                "client_id": self.config.blogger_client_id,
                "client_secret": self.config.blogger_client_secret,
                "refresh_token": self.config.blogger_refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=15,
        )

        if not resp.ok:
            hint = ""
            if "invalid_grant" in resp.text:
                hint = (
                    " — BLOGGER_REFRESH_TOKEN has been revoked or expired by Google "
                    "(commonly triggered by a burst of API calls tripping abuse detection). "
                    "Reauthorize the Blogger OAuth app and rotate the BLOGGER_REFRESH_TOKEN "
                    "GitHub Actions secret to restore publishing."
                )
            raise BloggerAuthError(
                f"Token refresh failed {resp.status_code}: {resp.text[:200]}{hint}"
            )

        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expiry = time.time() + int(data.get("expires_in", 3600))
        logger.info("Access token refreshed successfully")
        return self._access_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------ #
    # Blog metadata                                                         #
    # ------------------------------------------------------------------ #

    def get_blog_info(self) -> dict:
        """Fetch blog metadata to verify connectivity."""
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}"
        resp = requests.get(url, headers=self._headers(), timeout=15)
        resp.raise_for_status()
        return resp.json()

    def list_recent_posts(self, max_results: int = 10) -> list[dict]:
        """List recent Blogger posts for deduplication cross-check."""
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts"
        resp = requests.get(
            url,
            headers=self._headers(),
            params={"maxResults": max_results, "status": "live"},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json().get("items", [])

    # ------------------------------------------------------------------ #
    # Publishing                                                            #
    # ------------------------------------------------------------------ #

    def publish_post(
        self,
        title: str,
        content: str,
        labels: list[str],
        is_draft: bool = False,
    ) -> dict:
        """
        Create a new Blogger post with retry logic.
        Returns the created post object from the Blogger API.
        """
        payload = {
            "kind": "blogger#post",
            "title": title,
            "content": content,
            "labels": labels,
        }

        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts"
        params = {"isDraft": "true" if is_draft else "false", "fetchBody": "false"}

        last_error = "no attempt made"
        last_category = "unknown"
        auth_refreshed = False

        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                resp = requests.post(
                    url,
                    headers=self._headers(),
                    json=payload,
                    params=params,
                    timeout=30,
                )

                if resp.status_code == 429:
                    last_error = f"HTTP 429 rate limited: {resp.text[:300]}"
                    last_category = "rate_limited"
                    wait = _retry_after_seconds(resp) or self.config.retry_base_delay * (2 ** attempt)
                    logger.warning(
                        "Blogger API rate limited — backing off",
                        extra={"attempt": attempt, "wait_seconds": wait, "body": resp.text[:300]},
                    )
                    time.sleep(wait)
                    continue

                if resp.status_code == 401:
                    # Refresh once; a second 401 means the credential itself is
                    # rejected (revoked refresh token, wrong scope, blog access
                    # removed) — retrying cannot fix that.
                    if auth_refreshed:
                        raise BloggerAuthError(
                            f"Blogger API rejected refreshed token (HTTP 401): {resp.text[:300]}"
                        )
                    logger.info("Access token rejected, refreshing once")
                    last_error = f"HTTP 401 unauthorized: {resp.text[:300]}"
                    last_category = "auth_error"
                    self._access_token = None
                    auth_refreshed = True
                    continue

                if not resp.ok:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
                    last_category = "http_error"
                resp.raise_for_status()
                post_data = resp.json()

                logger.info(
                    "Post published successfully",
                    extra={
                        "post_id": post_data.get("id"),
                        "url": post_data.get("url"),
                        "title": title[:60],
                        "attempt": attempt,
                    },
                )
                return post_data

            except requests.RequestException as e:
                last_error = str(e)
                last_category = "network_error"
                if attempt == self.config.retry_attempts:
                    raise BloggerPublishError(
                        f"Failed after {attempt} attempts: {last_error}", category=last_category
                    ) from e
                wait = self.config.retry_base_delay * (2 ** attempt)
                logger.warning(
                    "Publish attempt failed, retrying",
                    extra={"attempt": attempt, "error": last_error, "wait": wait},
                )
                time.sleep(wait)

        raise BloggerPublishError(
            f"All retry attempts exhausted — last error: {last_error}", category=last_category
        )

    def update_post(self, post_id: str, title: str, content: str, labels: list[str]) -> dict:
        """Update an existing Blogger post."""
        payload = {
            "kind": "blogger#post",
            "id": post_id,
            "title": title,
            "content": content,
            "labels": labels,
        }
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts/{post_id}"
        resp = requests.put(url, headers=self._headers(), json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def health_check(self) -> bool:
        """Verify Blogger API connectivity and credentials."""
        try:
            info = self.get_blog_info()
            logger.info(
                "Blogger health check passed",
                extra={"blog_name": info.get("name"), "blog_id": info.get("id")},
            )
            return True
        except Exception as e:
            logger.error("Blogger health check failed", extra={"error": str(e)})
            return False
