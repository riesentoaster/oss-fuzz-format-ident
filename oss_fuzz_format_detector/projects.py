"""OSS-Fuzz project enumeration."""

from __future__ import annotations

import os
from pathlib import Path


def list_projects(oss_fuzz_dir: str | Path) -> list[str]:
    """Return sorted project names from oss-fuzz/projects/*/project.yaml."""
    projects_dir = Path(oss_fuzz_dir) / 'projects'
    if not projects_dir.is_dir():
        raise FileNotFoundError(f'projects directory not found: {projects_dir}')

    projects = []
    for entry in sorted(projects_dir.iterdir()):
        if entry.is_dir() and (entry / 'project.yaml').is_file():
            projects.append(entry.name)
    return projects
