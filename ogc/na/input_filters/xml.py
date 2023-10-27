"""
XML Input filter for ingest_json.

Processes XML files with [xmltodict](https://pypi.org/project/xmltodict/).

Configuration values:

* `process-namespaces` (default: `False`): Whether to process and expand namespaces (see xmltodict documentation)
* `namespaces` (default: `None`): Namespace to prefix mappings dict in `url: prefix` format.
"""
from __future__ import annotations

from io import StringIO
from typing import Any
import xmltodict

from ogc.na import util

DEFAULT_CONF = {
    'process-namespaces': False,
    'namespaces': None,
}


def apply_filter(content: bytes, conf: dict[str, Any] | None) -> tuple[dict[str, Any] | list, dict[str, Any] | None]:
    conf = util.deep_update(DEFAULT_CONF, conf) if conf else DEFAULT_CONF

    metadata = {
        'filter': {
            'conf': conf,
        },
    }

    textio = StringIO(content.decode('utf-8'))
    result = xmltodict.parse(textio.read(),
                             process_namespaces=conf['process-namespaces'],
                             namespaces=conf['namespaces'])

    return result, metadata
