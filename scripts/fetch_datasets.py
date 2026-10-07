"""Fetch the public datasets used by `hunterscope coverage` into data/external/ (git-ignored).

Needs only `git` and network access to github.com. Sparse + blobless clones keep the download small
(about 125 MB for OTRF's Windows sets and 60 MB for EVTX-ATTACK-SAMPLES). Nothing is redistributed
from this repository: the datasets carry their own licences (OTRF MIT, EVTX-ATTACK-SAMPLES GPL-3.0).

    python scripts/fetch_datasets.py            # both
    python scripts/fetch_datasets.py otrf       # only OTRF
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

DEST = Path(__file__).resolve().parent.parent / "data" / "external"
SOURCES = {
    "otrf": ("https://github.com/OTRF/Security-Datasets", "security-datasets",
             ["datasets/atomic/_metadata", "datasets/atomic/windows"]),
    "evtx": ("https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", "evtx-attack-samples", []),
}


def git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(["git", "-c", "gc.auto=0", *args], cwd=cwd, check=True)


def fetch(name: str) -> None:
    url, folder, paths = SOURCES[name]
    target = DEST / folder
    if (target / ".git").exists():
        print(f"[{name}] already present at {target}; updating")
        git("pull", "--ff-only", cwd=target)
        return
    DEST.mkdir(parents=True, exist_ok=True)
    print(f"[{name}] cloning {url}")
    git("clone", "--depth", "1", "--filter=blob:none", "--no-checkout", url, str(target))
    if paths:
        git("sparse-checkout", "init", "--cone", cwd=target)
        git("sparse-checkout", "set", *paths, cwd=target)
    git("checkout", "HEAD", cwd=target)
    print(f"[{name}] done -> {target}")


def main() -> int:
    wanted = sys.argv[1:] or list(SOURCES)
    unknown = [w for w in wanted if w not in SOURCES]
    if unknown:
        print(f"unknown source(s): {', '.join(unknown)}; choose from {', '.join(SOURCES)}", file=sys.stderr)
        return 2
    for name in wanted:
        fetch(name)
    print("\nNext:\n  pip install -e '.[bench]'\n  hunterscope coverage --otrf data/external/security-datasets "
          "--evtx data/external/evtx-attack-samples -o docs/coverage.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
