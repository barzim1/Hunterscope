"""Config loading: packaged defaults, optionally deep-merged with a user file."""

from __future__ import annotations

from copy import deepcopy
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _load(name: str, user_path: Path | None) -> dict[str, Any]:
    default = resources.files("hunterscope.config").joinpath(name).read_text(encoding="utf-8")
    cfg: dict[str, Any] = yaml.safe_load(default) or {}
    if user_path is not None:
        cfg = _deep_merge(cfg, yaml.safe_load(Path(user_path).read_text(encoding="utf-8")) or {})
    return cfg


def load_rules_config(path: Path | None = None) -> dict[str, Any]:
    return _load("rules.yaml", path)


def load_redactor_config(path: Path | None = None) -> dict[str, Any]:
    return _load("redactor.yaml", path)
