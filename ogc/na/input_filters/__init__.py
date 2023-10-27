from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Any, IO, TextIO

from ogc.na.util import deep_update


def apply_input_filter(stream: IO | bytes | str | Path, filters: dict[str, dict]) -> dict[str, Any] | list:
    filter_name, filter_conf = next(iter(filters.items()))

    metadata = {
        'filter': {
            'name': filter_name,
            'conf': filter_conf,
        },
    }

    try:
        filter_mod = import_module(f"ogc.na.input_filters.{filter_name}")
    except ImportError:
        raise ValueError(f'Cannot find input filter with name "{filter_name}"')

    if isinstance(stream, Path) or isinstance(stream, str):
        with open(stream, 'rb') as f:
            content = f.read()
        metadata['filename'] = str(stream)
    elif isinstance(stream, TextIO):
        content = stream.read().encode('utf-8')
    else:
        content = stream.read()

    data, filter_metadata = filter_mod.apply_filter(content, filter_conf)
    if filter_metadata:
        deep_update(metadata, filter_metadata, replace=True)

    return {
        'metadata': metadata,
        'data': data,
    }
