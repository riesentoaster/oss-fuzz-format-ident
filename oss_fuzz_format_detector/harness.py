"""Fuzz harness discovery from build artifacts."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

VALID_TARGET_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
BLOCKLISTED_TARGET_NAME_REGEX = re.compile(r'^(jazzer_driver.*)$')
ALLOWED_FUZZ_TARGET_EXTENSIONS = ('', '.exe')
FUZZ_TARGET_SEARCH_STRING = b'LLVMFuzzerTestOneInput'

HARNESS_BLOCKLIST_PREFIXES = ('afl-',)
HARNESS_BLOCKLIST_NAMES = frozenset({
    'centipede',
    'llvm-symbolizer',
})


@dataclass(frozen=True)
class Harness:
    project: str
    name: str
    executable_path: Path
    seed_corpus_path: Path | None
    dict_path: Path | None


def _is_blocklisted_name(name: str) -> bool:
    if name in HARNESS_BLOCKLIST_NAMES:
        return True
    if name.startswith('jazzer_'):
        return True
    return any(name.startswith(prefix) for prefix in HARNESS_BLOCKLIST_PREFIXES)


def _is_regular_file(file_path: Path) -> bool:
    if not file_path.is_file():
        return False
    return stat.S_ISREG(file_path.stat().st_mode)


def is_fuzz_target(file_path: Path) -> bool:
    """Return whether file_path is a fuzz target binary."""
    filename = file_path.name
    stem, extension = os.path.splitext(filename)
    if not VALID_TARGET_NAME_REGEX.match(stem):
        return False
    if BLOCKLISTED_TARGET_NAME_REGEX.match(stem):
        return False
    if extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
        return False
    if _is_blocklisted_name(stem):
        return False
    if not _is_regular_file(file_path):
        return False

    # Build zips from GCS do not preserve the executable bit.
    if stem.endswith('_fuzzer'):
        return True

    try:
        data = file_path.read_bytes()
    except OSError:
        return False
    return FUZZ_TARGET_SEARCH_STRING in data


def _resolve_seed_corpus(out_dir: Path, harness_name: str) -> Path | None:
    specific = out_dir / f'{harness_name}_seed_corpus.zip'
    if specific.is_file():
        return specific
    shared = out_dir / 'seed_corpus.zip'
    if shared.is_file():
        return shared
    return None


def _resolve_dict(out_dir: Path, harness_name: str) -> Path | None:
    specific = out_dir / f'{harness_name}.dict'
    if specific.is_file():
        return specific
    return None


def find_harnesses(project: str, out_dir: Path) -> list[Harness]:
    """Enumerate harnesses as executables in an unpacked build out/ directory."""
    harnesses: list[Harness] = []
    if not out_dir.is_dir():
        return harnesses

    for entry in sorted(out_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix in {'.zip', '.dict', '.options'}:
            continue
        if not is_fuzz_target(entry):
            continue
        harnesses.append(
            Harness(
                project=project,
                name=entry.name,
                executable_path=entry,
                seed_corpus_path=_resolve_seed_corpus(out_dir, entry.name),
                dict_path=_resolve_dict(out_dir, entry.name),
            )
        )
    return harnesses
