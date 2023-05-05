from __future__ import annotations

from importlib import import_module
from io import BytesIO
from pathlib import Path
from typing import Any, IO, TextIO


def apply_input_filter(stream: IO | bytes | str | Path, filters: dict[str, dict]) -> dict[str, Any] | list:
    filter_name, filter_conf = filters.popitem()
    try:
        filter_mod = import_module(f"ogc.na.input_filters.{filter_name}")
    except ImportError:
        raise ValueError(f'Cannot find input filter with name "{filter_name}"')

    content: bytes | None = None
    if isinstance(stream, Path) or isinstance(stream, str):
        with open(stream, 'rb') as f:
            content = f.read()
    elif isinstance(stream, TextIO):
        content = stream.read().encode('utf-8')
    else:
        content = stream.read()

    return filter_mod.apply_filter(content, filter_conf)
