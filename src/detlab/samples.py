"""Download public attack samples, pinned to a commit and verified by SHA-256.

The samples are not stored in this repository (their datasets have their own
licences). ``datasets.yml`` says where each dataset lives and which commit to
use; each test case gives the file and its SHA-256. A downloaded file whose hash
does not match is rejected, so tests always run on exactly the same bytes.
"""

from __future__ import annotations

import hashlib
import shutil
import urllib.request
from pathlib import Path
from urllib.parse import quote

import yaml

CACHE_DIR = Path(".cache") / "samples"


class SampleIntegrityError(Exception):
    pass


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_datasets(root: Path) -> dict:
    return yaml.safe_load((root / "datasets.yml").read_text(encoding="utf-8"))


def fetch(root: Path, source: str, file: str, sha256: str) -> Path:
    """Return a local path to the sample, downloading and verifying it if needed."""
    dataset = load_datasets(root)[source]
    commit = dataset["commit"]
    target = root / CACHE_DIR / source / commit / file
    if target.exists() and sha256_of(target) == sha256:
        return target

    url = dataset["url"].format(commit=commit, file=quote(file))
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "detlab"})
    with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as out:
        shutil.copyfileobj(response, out)

    actual = sha256_of(partial)
    if actual != sha256:
        partial.unlink()
        raise SampleIntegrityError(
            f"SHA-256 mismatch for {source}:{file}\n  expected {sha256}\n  got      {actual}"
        )
    partial.replace(target)
    return target
