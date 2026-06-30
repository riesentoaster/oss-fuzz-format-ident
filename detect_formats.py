#!/usr/bin/env python3
"""Detect OSS-Fuzz harness input formats from infra-published builds."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from oss_fuzz_format_detector.download import ensure_project_build
from oss_fuzz_format_detector.extractors import extract_all
from oss_fuzz_format_detector.harness import find_harnesses
from oss_fuzz_format_detector.labeler import label_observations
from oss_fuzz_format_detector.projects import list_projects

DEFAULT_OSS_FUZZ_DIR = Path.home() / 'oss-fuzz'
DEFAULT_CACHE_DIR = Path.home() / '.cache' / 'oss-fuzz-format-detector'
DEFAULT_OUTPUT = Path('harness_formats.jsonl')
DEFAULT_FORMATS_OUTPUT = Path('format_index.json')


def write_format_index(jsonl_path: Path, formats_path: Path) -> dict[str, int]:
    """Group harness_formats.jsonl into format -> [{project, harness}, ...]."""
    index: dict[str, list[dict]] = {}
    with jsonl_path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = record.get('label', 'unknown')
            entry = {
                'project': record['project'],
                'harness': record['harness'],
            }
            if confidence := record.get('confidence'):
                entry['confidence'] = confidence
            index.setdefault(label, []).append(entry)

    for entries in index.values():
        entries.sort(key=lambda e: (e['project'], e['harness']))

    formats_path.write_text(
        json.dumps(dict(sorted(index.items())), indent=2, ensure_ascii=False) + '\n',
        encoding='utf-8',
    )
    return {label: len(entries) for label, entries in index.items()}


@dataclass
class ProjectResult:
    project: str
    build: str | None
    harness_records: list[dict]
    error: str | None = None


def _process_project(
    project: str,
    cache_dir: Path,
    sanitizer: str,
    max_seeds: int | None,
) -> ProjectResult:
    try:
        build_name, out_dir = ensure_project_build(project, cache_dir, sanitizer)
    except Exception as exc:  # pylint: disable=broad-except
        return ProjectResult(project=project, build=None, harness_records=[], error=str(exc))

    if not build_name or out_dir is None:
        return ProjectResult(project=project, build=None, harness_records=[])

    records = []
    for harness in find_harnesses(project, out_dir):
        observations = extract_all(harness, max_seeds)
        records.append({
            'project': project,
            'harness': harness.name,
            'build': build_name,
            'observations': observations.to_dict(),
            **label_observations(observations),
        })
    return ProjectResult(project=project, build=build_name, harness_records=records)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oss-fuzz-dir', type=Path, default=DEFAULT_OSS_FUZZ_DIR)
    parser.add_argument('--cache-dir', type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        '--formats-output',
        type=Path,
        default=None,
        help='Format index output (default: format_index.json beside --output)',
    )
    parser.add_argument('--sanitizer', default='address')
    parser.add_argument('--jobs', type=int, default=os.cpu_count() or 1)
    parser.add_argument('--projects', nargs='*')
    parser.add_argument('--limit', type=int, default=0)
    parser.add_argument(
        '--max-seeds',
        type=int,
        default=0,
        help='Max seed files per corpus to analyze (0 = no limit)',
    )
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args(argv)


def _completed_projects(output_path: Path) -> set[str]:
    if not output_path.is_file():
        return set()
    projects: set[str] = set()
    with output_path.open(encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if project := record.get('project'):
                projects.add(project)
    return projects


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s',
    )

    max_seeds = args.max_seeds or None

    projects = args.projects or list_projects(args.oss_fuzz_dir)
    if args.limit:
        projects = projects[:args.limit]

    if args.resume and args.output.is_file():
        done = _completed_projects(args.output)
        before = len(projects)
        projects = [p for p in projects if p not in done]
        logging.info('Resume: skipping %d, %d remaining', before - len(projects), len(projects))

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output_mode = 'a' if args.resume and args.output.is_file() else 'w'

    builds_ok = harness_count = labeled_high = 0
    total = len(projects)

    with args.output.open(output_mode, encoding='utf-8') as out_handle:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {
                pool.submit(_process_project, p, args.cache_dir, args.sanitizer, max_seeds): p
                for p in projects
            }
            for i, future in enumerate(as_completed(futures), 1):
                project = futures[future]
                result = future.result()
                if result.error:
                    logging.warning('Project %s failed: %s', project, result.error)
                elif result.build:
                    builds_ok += 1
                for record in result.harness_records:
                    out_handle.write(json.dumps(record, ensure_ascii=False) + '\n')
                    harness_count += 1
                    if record.get('confidence') == 'high':
                        labeled_high += 1
                logging.info('Progress %d/%d: %s (%d harnesses)', i, total, project, len(result.harness_records))

    logging.info('Done: %s', json.dumps({
        'projects_total': total,
        'projects_with_build': builds_ok,
        'harnesses_total': harness_count,
        'harnesses_high_confidence': labeled_high,
        'output': str(args.output),
    }))

    formats_output = args.formats_output or args.output.with_name('format_index.json')
    if args.output.is_file():
        counts = write_format_index(args.output, formats_output)
        logging.info('Wrote %d formats to %s', len(counts), formats_output)

    return 0


if __name__ == '__main__':
    sys.exit(main())
