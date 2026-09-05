"""P0 v10 runtime-binding correction for Stage-5 premium capacity recovery.

Production run #8623 proved that Stage-5/v9 was installed but unreachable from
AuthorityTransformer. premium_publication._install_transform_overrides() copies
``premium_publication._premium_llm_call`` into ``authority_transformer.call_llm``
by object reference. Later Stage-4 wraps that live authority binding. Stage-5
then patched only ``premium_publication._premium_llm_call``; replacing that
module attribute cannot retroactively replace the already-copied function object
held by ``authority_transformer.call_llm``.

This installer runs after Stage-5 and binds capacity recovery around the actual
live Stage-4 authority call path. It deliberately preserves Stage-4 as the inner
call so every primary generation candidate remains evidence-admission gated,
while Stage-5 continues to apply its own evidence check to combined continuation
candidates before accepting them.
"""
from __future__ import annotations

from . import authority_transformer as _authority
from . import premium_capacity_recovery as _capacity
from .logger import setup_logger

logger = setup_logger("premium_capacity_runtime_binding")

MARKER = "CDB-PREMIUM-CAPACITY-RUNTIME-BINDING-V10"
_INSTALLED = False


def install_capacity_runtime_binding_fix() -> None:
    """Bind Stage-5 to the live AuthorityTransformer LLM consumer exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return

    active = _authority.call_llm
    if active is _capacity.capacity_aware_premium_llm:
        _INSTALLED = True
        return

    # Stage-5 must wrap the live Stage-4 admission function, not the stale
    # premium_publication module attribute that was copied earlier in startup.
    _capacity._ORIGINAL_PREMIUM_LLM_CALL = active
    _authority.call_llm = _capacity.capacity_aware_premium_llm

    if _authority.call_llm is not _capacity.capacity_aware_premium_llm:
        raise RuntimeError("P0 capacity recovery failed to bind to authority_transformer.call_llm")

    _INSTALLED = True
    logger.info(
        "P0 v10 premium capacity runtime binding installed",
        extra={
            "marker": MARKER,
            "live_consumer": "authority_transformer.call_llm",
            "wrapped_inner": getattr(active, "__name__", type(active).__name__),
            "stage5_callable": _capacity.capacity_aware_premium_llm.__name__,
        },
    )
