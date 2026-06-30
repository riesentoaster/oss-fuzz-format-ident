"""Observation extractors for harness format detection."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .harness import Harness

logger = logging.getLogger(__name__)

COMPOUND_EXTENSIONS = (
    '.tar.gz',
    '.tar.bz2',
    '.tar.xz',
    '.tar.zst',
    '.json.gz',
    '.xml.gz',
)

# Harness-name noise words — not a format list.
NAME_STOPWORDS = frozenset({
    'fuzzer', 'fuzz', 'parse', 'parser', 'test', 'target', 'llvm',
    'lib', 'run', 'one', 'input', 'data', 'file', 'read', 'decode',
})

DICT_TOKEN_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
CAMEL_RE = re.compile(r'([a-z0-9])([A-Z])')


@dataclass
class Observations:
    seed_extensions: dict[str, int] = field(default_factory=dict)
    seed_types: list[str] = field(default_factory=list)
    magic_prefixes: list[str] = field(default_factory=list)
    dict_tokens: list[str] = field(default_factory=list)
    dict_name: str | None = None
    name_tokens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {
            'seed_extensions': self.seed_extensions,
            'seed_types': self.seed_types,
            'magic_prefixes': self.magic_prefixes,
            'dict_tokens': self.dict_tokens,
            'name_tokens': self.name_tokens,
        }
        if self.dict_name is not None:
            result['dict_name'] = self.dict_name
        return result


def _extension_from_basename(basename: str) -> str:
    lower = basename.lower()
    for compound in COMPOUND_EXTENSIONS:
        if lower.endswith(compound):
            return compound
    if '.' not in basename:
        return ''
    return '.' + basename.rsplit('.', 1)[-1].lower()


def _magic_prefix(data: bytes, length: int = 8) -> str:
    return data[:length].hex()


def _run_file_brief(path: Path) -> str | None:
    file_bin = shutil.which('file')
    if not file_bin:
        return None
    try:
        proc = subprocess.run(
            [file_bin, '--brief', str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _limited_members(members: list[str], max_seeds: int | None) -> list[str]:
    if max_seeds is None:
        return members
    return members[:max_seeds]


def extract_seed_signals(harness: Harness, max_seeds: int | None = None) -> Observations:
    """Analyze paired seed corpus: extensions, magic bytes, file types."""
    obs = Observations()
    if harness.seed_corpus_path is None:
        return obs

    extensions: Counter[str] = Counter()
    magics: Counter[str] = Counter()
    file_types: Counter[str] = Counter()

    try:
        with zipfile.ZipFile(harness.seed_corpus_path) as zf:
            all_members = [m for m in zf.namelist() if not m.endswith('/')]
            members = _limited_members(all_members, max_seeds)

            for member in members:
                basename = member.rsplit('/', 1)[-1]
                if basename:
                    extensions[_extension_from_basename(basename)] += 1

            for member in members:
                try:
                    data = zf.read(member)
                except (KeyError, RuntimeError):
                    continue
                if not data:
                    continue
                magic = _magic_prefix(data)
                magics[magic] += 1
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(data)
                    tmp_path = Path(tmp.name)
                try:
                    file_type = _run_file_brief(tmp_path)
                finally:
                    tmp_path.unlink(missing_ok=True)
                if file_type:
                    file_types[file_type] += 1
    except (OSError, zipfile.BadZipFile) as exc:
        logger.warning('Bad seed corpus for %s/%s: %s', harness.project, harness.name, exc)
        return obs

    if not extensions:
        return obs

    obs.seed_extensions = dict(extensions)
    obs.magic_prefixes = [m for m, _ in magics.most_common(20)]
    obs.seed_types = [t for t, _ in file_types.most_common(20)]
    return obs


def _parse_dict_tokens(dict_path: Path) -> list[str]:
    try:
        text = dict_path.read_text(errors='replace')
    except OSError:
        return []
    tokens = []
    for match in DICT_TOKEN_RE.finditer(text):
        token = match.group(1)
        if '\\' in token:
            token = token.encode('utf-8').decode('unicode_escape')
        tokens.append(token)
    return tokens


def extract_dict_signals(harness: Harness) -> Observations:
    obs = Observations()
    if harness.dict_path is None:
        return obs
    obs.dict_tokens = _parse_dict_tokens(harness.dict_path)
    if harness.dict_path.name.endswith('.dict'):
        obs.dict_name = harness.dict_path.name[:-5]
    return obs


def _split_name_tokens(harness_name: str) -> list[str]:
    stem = harness_name[:-4] if harness_name.endswith('.exe') else harness_name
    parts: list[str] = []
    for chunk in re.split(r'[_\-.]+', stem):
        parts.extend(CAMEL_RE.sub(r'\1 \2', chunk).split())
    tokens = []
    for part in parts:
        token = part.lower()
        if token and token not in NAME_STOPWORDS and token not in tokens:
            tokens.append(token)
    return tokens


def extract_all(harness: Harness, max_seeds: int | None = None) -> Observations:
    obs = Observations()
    for part in (
        extract_seed_signals(harness, max_seeds),
        extract_dict_signals(harness),
        Observations(name_tokens=_split_name_tokens(harness.name)),
    ):
        obs.seed_extensions.update(part.seed_extensions)
        for item in part.magic_prefixes:
            if item not in obs.magic_prefixes:
                obs.magic_prefixes.append(item)
        for item in part.seed_types:
            if item not in obs.seed_types:
                obs.seed_types.append(item)
        for item in part.dict_tokens:
            if item not in obs.dict_tokens:
                obs.dict_tokens.append(item)
        for item in part.name_tokens:
            if item not in obs.name_tokens:
                obs.name_tokens.append(item)
        if part.dict_name and obs.dict_name is None:
            obs.dict_name = part.dict_name
    return obs
