"""Check registry — decorator registers (snapshot) -> list[NormalizedFinding] callables."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.schemas import NormalizedFinding

CheckFn = Callable[[dict[str, Any]], list[NormalizedFinding]]

_REGISTRY: dict[str, CheckFn] = {}


def register_check(check_id: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        _REGISTRY[check_id] = fn
        fn.check_id = check_id  # type: ignore[attr-defined]
        return fn

    return decorator


def get_registered_checks() -> dict[str, CheckFn]:
    return dict(_REGISTRY)


def clear_registry() -> None:
    _REGISTRY.clear()
