"""
CYBERDUDEBIVASH® SENTINEL APEX — Configuration Module
Central configuration loaded from environment variables.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    # Blogger OAuth2
    blogger_client_id: str = ""
    blogger_client_secret: str = ""
    blogger_refresh_token: str = ""
    blogger_blog_id: str = ""

    # Anthropic Claude AI
    anthropic_api_key: str = ""
    claude_model: str = "claude-opus-4-8"

    # Google Search Console
    google_search_console_key: str = ""

    # Source platform
    source_rss_url: str = "https://blog.cyberdudebivash.in/rss.xml"
    source_live_intel_url: str = "https://blog.cyberdudebivash.in/live-intel.json"
    source_sitemap_url: str = "https://blog.cyberdudebivash.in/sitemap.xml"
    source_base_url: str = "https://blog.cyberdudebivash.in"

    # Target Blogger
    target_blog_url: str = "https://cyberbivash.blogspot.com"
    blogger_api_base: str = "https://www.googleapis.com/blogger/v3"

    # Pipeline control
    max_posts_per_run: int = 5
    max_article_age_hours: int = 48
    retry_attempts: int = 3
    retry_base_delay: float = 2.0

    # State persistence
    state_file: str = "data/published_posts.json"
    logs_dir: str = "logs"

    # Brand
    brand_name: str = "CYBERDUDEBIVASH®"
    brand_tagline: str = "Defending the Future with AI-Powered Cybersecurity"
    brand_url: str = "https://cyberdudebivash.com"
    sentinel_apex_url: str = "https://intel.cyberdudebivash.com"
    api_url: str = "https://intel.cyberdudebivash.com/api"
    tools_url: str = "https://tools.cyberdudebivash.com"
    corporate_url: str = "https://cyberdudebivash.in"
    contact_email: str = "bivash@cyberdudebivash.com"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            blogger_client_id=os.environ.get("BLOGGER_CLIENT_ID", ""),
            blogger_client_secret=os.environ.get("BLOGGER_CLIENT_SECRET", ""),
            blogger_refresh_token=os.environ.get("BLOGGER_REFRESH_TOKEN", ""),
            blogger_blog_id=os.environ.get("BLOGGER_BLOG_ID", ""),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            google_search_console_key=os.environ.get("GOOGLE_SEARCH_CONSOLE_KEY", ""),
            max_posts_per_run=int(os.environ.get("MAX_POSTS_PER_RUN", "5")),
        )

    def validate(self) -> list[str]:
        """Return list of missing required config keys."""
        missing = []
        if not self.blogger_client_id:
            missing.append("BLOGGER_CLIENT_ID")
        if not self.blogger_client_secret:
            missing.append("BLOGGER_CLIENT_SECRET")
        if not self.blogger_refresh_token:
            missing.append("BLOGGER_REFRESH_TOKEN")
        if not self.blogger_blog_id:
            missing.append("BLOGGER_BLOG_ID")
        return missing
