"""
CYBERDUDEBIVASH® SENTINEL APEX — Multi-Provider LLM Client
Priority chain: Groq → DeepSeek → OpenRouter → Anthropic (future) → None
All current providers use the OpenAI-compatible chat completions API.
"""

import requests
from typing import Optional
from .config import Config
from .logger import setup_logger

logger = setup_logger("llm_client")

# Provider definitions — tried in order listed
_PROVIDERS = [
    {
        "name": "groq",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "model_attr": "llm_model_groq",
        "key_attr": "groq_api_key",
        "headers": {},
    },
    {
        "name": "deepseek",
        "url": "https://api.deepseek.com/v1/chat/completions",
        "model_attr": "llm_model_deepseek",
        "key_attr": "deepseek_api_key",
        "headers": {},
    },
    {
        "name": "openrouter",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "model_attr": "llm_model_openrouter",
        "key_attr": "openrouter_api_key",
        "headers": {
            "HTTP-Referer": "https://blog.cyberdudebivash.in",
            "X-Title": "CYBERDUDEBIVASH SENTINEL APEX",
        },
    },
    {
        "name": "anthropic",
        "url": "https://api.anthropic.com/v1/messages",
        "model_attr": "claude_model",
        "key_attr": "anthropic_api_key",
        "headers": {},
        "is_anthropic": True,
    },
]


def call_llm(
    config: Config,
    prompt: str,
    max_tokens: int = 3000,
    attempts: Optional[list] = None,
) -> Optional[tuple[str, str]]:
    """
    Try each configured LLM provider in priority order.
    Returns (content, provider_name) on first success, or None if all fail.

    If `attempts` is provided, every provider considered is appended to it as
    {"provider": name, "ok": bool, "error": str | None} — including providers
    skipped for having no API key configured. This lets a caller persist
    *why* a run fell back to the template (no key vs. rate limit vs. other
    API failure) instead of only recording *that* it did, which the run
    report previously had no way to distinguish.
    """
    for provider in _PROVIDERS:
        name = provider["name"]
        api_key = getattr(config, provider["key_attr"], "")
        if not api_key:
            if attempts is not None:
                attempts.append({"provider": name, "ok": False, "error": "no_api_key"})
            continue

        model = getattr(config, provider["model_attr"], "")

        try:
            if provider.get("is_anthropic"):
                content = _call_anthropic(api_key, model, prompt, max_tokens)
            else:
                content = _call_openai_compat(
                    url=provider["url"],
                    api_key=api_key,
                    model=model,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    extra_headers=provider.get("headers", {}),
                )

            if content:
                logger.info(
                    "LLM call succeeded",
                    extra={"provider": name, "model": model, "chars": len(content)},
                )
                if attempts is not None:
                    attempts.append({"provider": name, "ok": True, "error": None})
                return content, name

            if attempts is not None:
                attempts.append({"provider": name, "ok": False, "error": "empty_response"})

        except Exception as e:
            logger.warning(
                "LLM provider failed, trying next",
                extra={"provider": name, "error": str(e)},
            )
            if attempts is not None:
                attempts.append({"provider": name, "ok": False, "error": str(e)[:200]})
            continue

    logger.info("No LLM provider available — using template fallback")
    return None


def _call_openai_compat(
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
) -> Optional[str]:
    """Call any OpenAI-compatible chat completions endpoint."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **extra_headers,
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def _call_anthropic(api_key: str, model: str, prompt: str, max_tokens: int) -> Optional[str]:
    """Call Anthropic Messages API (non-OpenAI format)."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text.strip()
    except ImportError:
        # anthropic package not installed — use raw HTTP
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            json=payload,
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"].strip()
