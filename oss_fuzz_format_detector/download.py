"""Download and cache OSS-Fuzz builds from GCS."""

from __future__ import annotations

import io
import logging
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

GCS_BASE_URL = 'https://storage.googleapis.com/'
CLUSTERFUZZ_BUILDS = 'clusterfuzz-builds'

logger = logging.getLogger(__name__)


def _url_join(*parts: str) -> str:
    return '/'.join(part.strip('/') for part in parts)


def get_latest_build_name(project: str, sanitizer: str = 'address') -> str | None:
    """Fetch the latest build zip filename for a project."""
    version_file = f'{project}-{sanitizer}-latest.version'
    version_url = _url_join(GCS_BASE_URL, CLUSTERFUZZ_BUILDS, project, version_file)
    try:
        with urllib.request.urlopen(version_url, timeout=60) as response:
            return response.read().decode().strip()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            logger.debug('No build for %s (%s)', project, sanitizer)
            return None
        raise


def download_build_zip(project: str, build_name: str) -> bytes:
    """Download a build zip from GCS."""
    build_url = _url_join(GCS_BASE_URL, CLUSTERFUZZ_BUILDS, project, build_name)
    with urllib.request.urlopen(build_url, timeout=300) as response:
        return response.read()


def unpack_build_to_out(build_zip: bytes, out_dir: Path) -> None:
    """Unpack build zip contents into out_dir (flat layout)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(build_zip)) as zf:
        for member in zf.namelist():
            if member.endswith('/'):
                continue
            target = out_dir / Path(member).name
            target.write_bytes(zf.read(member))


def ensure_project_build(
    project: str,
    cache_dir: Path,
    sanitizer: str = 'address',
) -> tuple[str | None, Path | None]:
    """Download and cache a project build if needed.

    Returns (build_name, out_dir) or (None, None) if unavailable.
    """
    build_name = get_latest_build_name(project, sanitizer)
    if not build_name:
        return None, None

    project_cache = cache_dir / project
    marker = project_cache / 'build_name.txt'
    out_dir = project_cache / 'out'

    if marker.is_file() and marker.read_text().strip() == build_name and out_dir.is_dir():
        if any(out_dir.iterdir()):
            return build_name, out_dir

    logger.info('Downloading %s build %s', project, build_name)
    build_zip = download_build_zip(project, build_name)
    if out_dir.exists():
        for child in out_dir.iterdir():
            if child.is_file():
                child.unlink()
            elif child.is_symlink():
                child.unlink()
    unpack_build_to_out(build_zip, out_dir)
    project_cache.mkdir(parents=True, exist_ok=True)
    marker.write_text(build_name + '\n')
    return build_name, out_dir
