"""
CSV Input filter for ingest_json.

Returns CSV rows as a list. Values will always be strings (no type inference or coercion is performed).

Configuration values:

* `rows` (default: `dict`): type of elements in the result list:
    * `dict`: elements will be dictionaries, with the keys taken from the `header-row`.
    * `list`: each resulting row will be an array values.
* `header-row` (default: `0`): if `rows` is `dict`, the (0-based) index of the header row. All rows before the
    header row will be skipped.
* `skip-rows` (default: `0`): number of rows to skip at the beginning of the file (apart from the header and pre-header
    ones if `rows` is `dict`).
* `delimiter` (default: `,`): field separator character
* `quotechar` (default: `"`): char used to quote (enclose) field values
* `skip-empty-rows` (default: `True`): whether to omit empty rows (i.e., those with no values) from the result
* `trim-values` (default: `False`): whether to apply `.strip()` to the resulting values
"""
from __future__ import annotations

import csv
from io import BytesIO, TextIOWrapper, StringIO
from typing import IO, Any

from ogc.na import util

DEFAULT_CONF = {
    'rows': 'dict',
    'header-row': 0,
    'skip-rows': 0,
    'delimiter': ',',
    'quotechar': '"',
    'skip-empty-rows': True,
    'trim-values': False,
}


def apply_filter(content: bytes, conf: dict[str, Any] | None) -> dict[str, Any] | list:
    conf = util.deep_update(DEFAULT_CONF, conf) if conf else DEFAULT_CONF

    textio = StringIO(content.decode('utf-8'))
    reader = csv.reader(textio, delimiter=conf['delimiter'], quotechar=conf['quotechar'])

    headers = None
    if conf['rows'] == 'dict':
        header_row = max(conf['header-row'], 0)
        # Skip to header row
        for i in range(header_row):
            next(reader, None)
        headers = next(reader, [])
        if not headers:
            return []

    # Skip requested rows
    for i in range(conf['skip-rows']):
        next(reader, None)

    result = []
    for row in reader:
        if not row and conf['skip-empty-rows']:
            # skip empty rows
            continue
        if conf['trim-values']:
            row = [v.strip() for v in row]
        if conf['rows'] == 'list':
            result.append(row)
        else:
            result.append(dict(zip(headers, row)))

    return result
