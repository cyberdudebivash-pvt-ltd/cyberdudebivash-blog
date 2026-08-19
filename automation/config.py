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

    # LLM providers — tried in priority order: Groq → DeepSeek → OpenRouter → Anthropic
    groq_api_key: str = ""
    deepseek_api_key: str = ""
    openrouter_api_key: str = ""
    anthropic_api_key: str = ""

    # External data source API keys
    nvd_api_key: str = ""
    alienvault_otx_key: str = ""

    # Model selection per provider
    llm_model_groq: str = "llama-3.3-70b-versatile"
    llm_model_deepseek: str = "deepseek-chat"
    llm_model_openrouter: str = "deepseek/deepseek-chat"
    # COMMERCIAL-QUALITY-2026-08-19: was "claude-opus-4-8", a model ID that
    # does not exist in the current Claude lineup -- confirmed via a live
    # dry-run trigger of blogger-syndication.yml once GROQ/DEEPSEEK/
    # OPENROUTER keys were actually wired through: those three reached real
    # HTTP calls for the first time (no longer no_api_key) and failed on
    # their own account-side issues (Groq 404 likely a retired model ID on
    # Groq's side, DeepSeek/OpenRouter 402 Payment Required -- neither
    # fixable from this repository). ANTHROPIC_API_KEY was unset in that
    # run, so this stale ID was never actually exercised live, but it would
    # fail identically the moment a real key is added. "claude-opus-5" keeps
    # the same Opus-tier choice the original default signaled, updated to a
    # real, current model ID.
    claude_model: str = "claude-opus-5"

    # Google Search Console
    google_search_console_key: str = ""

    # Social amplification — Twitter/X API v2 (OAuth 1.0a)
    twitter_api_key: str = ""
    twitter_api_secret: str = ""
    twitter_access_token: str = ""
    twitter_access_secret: str = ""

    # Newsletter (link to signup page — Substack, ConvertKit, etc.)
    newsletter_signup_url: str = "https://cyberdudebivash.substack.com"

    # Source platform
    source_rss_url: str = "https://blog.cyberdudebivash.in/rss.xml"
    source_live_intel_url: str = "https://blog.cyberdudebivash.in/live-intel.json"
    source_sitemap_url: str = "https://blog.cyberdudebivash.in/sitemap.xml"
    source_base_url: str = "https://blog.cyberdudebivash.in"

    # Target Blogger
    target_blog_url: str = "https://cyberbivash.blogspot.com"
    blogger_api_base: str = "https://www.googleapis.com/blogger/v3"

    # Pipeline control — production observations show Blogger accepts five
    # consecutive writes before quota throttling. Stay below that boundary.
    max_posts_per_run: int = 5
    max_article_age_hours: int = 72
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
            groq_api_key=os.environ.get("GROQ_API_KEY", ""),
            deepseek_api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
            openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            nvd_api_key=os.environ.get("NVD_API_KEY", ""),
            alienvault_otx_key=os.environ.get("ALIENVAULT_OTX_KEY", ""),
            google_search_console_key=os.environ.get("GOOGLE_SEARCH_CONSOLE_KEY", ""),
            twitter_api_key=os.environ.get("TWITTER_API_KEY", ""),
            twitter_api_secret=os.environ.get("TWITTER_API_SECRET", ""),
            twitter_access_token=os.environ.get("TWITTER_ACCESS_TOKEN", ""),
            twitter_access_secret=os.environ.get("TWITTER_ACCESS_SECRET", ""),
            newsletter_signup_url=os.environ.get("NEWSLETTER_SIGNUP_URL", "https://cyberdudebivash.substack.com"),
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
