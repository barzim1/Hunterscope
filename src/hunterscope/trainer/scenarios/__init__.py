"""Scenario generation. A scenario is fully determined by its token: `<seed>-<template>-<difficulty>-<mix>`.

`mix` picks how often each verdict occurs: `p` = practice (balanced, so you see plenty of true positives), `s` = shift
(realistic: most alerts are false positives or benign). The verdict is derived from the seed, so the token alone
does not reveal it and the server can regenerate the scenario instead of storing it.
"""

from __future__ import annotations

import random

from hunterscope.trainer.model import Scenario

# Importing the modules registers their templates.
from hunterscope.trainer.scenarios import endpoint, eset_scenarios, identity, network  # noqa: F401
from hunterscope.trainer.scenarios.base import REGISTRY, Builder
from hunterscope.trainer.world import World, anchor

MIX = {
    "p": {"tp": 0.45, "fp": 0.40, "btp": 0.15},
    "s": {"tp": 0.12, "fp": 0.68, "btp": 0.20},
}


def make_token(seed: int, template: str, difficulty: int, mix: str = "p") -> str:
    return f"{seed}-{template}-{difficulty}-{mix}"


def parse_token(token: str) -> tuple[int, str, int, str]:
    try:
        seed, template, difficulty, mix = token.split("-")
        d = int(difficulty)
        if template not in REGISTRY or mix not in MIX or d not in (1, 2, 3):
            raise ValueError
        return int(seed), template, d, mix
    except ValueError:
        raise ValueError(f"invalid scenario token: {token!r}") from None


def variant_for(seed: int, template: str, mix: str) -> str:
    tpl = REGISTRY[template]
    weights = [(v, MIX[mix][v]) for v in tpl.variants]
    roll = random.Random(f"variant:{seed}:{template}").random() * sum(wt for _, wt in weights)
    for variant, wt in weights:
        roll -= wt
        if roll <= 0:
            return variant
    return weights[-1][0]


def generate(token: str) -> Scenario:
    seed, template, difficulty, mix = parse_token(token)
    rng = random.Random(f"scenario:{token}")
    world = World(rng, token)
    builder = Builder(token, template, difficulty, rng, world, anchor(rng, 10))
    tpl = REGISTRY[template]
    tpl.build(builder, variant_for(seed, template, mix))
    assert builder.result is not None, f"template {template} did not call finish()"
    return builder.result


def templates() -> list[dict]:
    return [{"id": t.id, "title": t.lessons.title, "category": t.lessons.category} for t in REGISTRY.values()]
