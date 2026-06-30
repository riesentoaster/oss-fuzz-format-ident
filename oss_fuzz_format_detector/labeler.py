"""Derive best-guess labels from observations only — no format lookup tables."""

from __future__ import annotations

from .extractors import Observations


def _dominant_extension(obs: Observations) -> tuple[str | None, float]:
    if not obs.seed_extensions:
        return None, 0.0
    ranked = sorted(obs.seed_extensions.items(), key=lambda x: (-x[1], x[0]))
    total = sum(obs.seed_extensions.values())
    top_ext, top_count = ranked[0]
    return top_ext, top_count / total


def _extension_agrees_with_file(ext: str, file_type: str) -> bool:
    stem = ext.lstrip('.').lower()
    return bool(stem) and stem in file_type.lower()


def _name_agrees_with_extension(obs: Observations, ext: str) -> bool:
    stem = ext.lstrip('.').lower()
    if not stem:
        return False
    return stem in obs.name_tokens


def label_observations(obs: Observations) -> dict:
    """Pick a label from raw observations. No hand-maintained format list."""
    ext, ext_ratio = _dominant_extension(obs)
    file_type = obs.seed_types[0] if obs.seed_types else None
    magic = obs.magic_prefixes[0] if obs.magic_prefixes else None

    ext_label = None
    if ext is not None and ext_ratio >= 0.5:
        ext_label = ext if ext else '(no extension)'

    signals: dict[str, str] = {}
    if ext_label is not None:
        signals['extension'] = ext_label
    if file_type:
        signals['content'] = file_type
    if magic:
        signals['magic'] = magic

    evidence: list[str] = []
    if ext_label is not None:
        pct = int(round(ext_ratio * 100))
        evidence.append(f'{pct}% {ext_label} seed extensions')
    if file_type:
        evidence.append(f'file type: {file_type}')
    if magic:
        evidence.append(f'magic prefix: {magic}')

    if ext_label is not None:
        label = ext_label
        confidence = 'high' if ext_ratio >= 0.9 else 'medium'
        if file_type and _extension_agrees_with_file(ext or '', file_type):
            confidence = 'high'
        elif _name_agrees_with_extension(obs, ext or ''):
            confidence = 'high' if ext_ratio >= 0.5 else 'medium'
            evidence.append(f'name token matches {ext_label}')
        return {
            'label': label,
            'confidence': confidence,
            'evidence': evidence,
            'signal_labels': signals,
        }

    if file_type:
        return {
            'label': file_type,
            'confidence': 'medium',
            'evidence': evidence,
            'signal_labels': signals,
        }

    if magic:
        return {
            'label': f'magic:{magic}',
            'confidence': 'low',
            'evidence': evidence,
            'signal_labels': signals,
        }

    return {
        'label': 'unknown',
        'confidence': None,
        'evidence': evidence,
        'signal_labels': signals,
    }
