"""
Excel (XLSX) Input filter for ingest_json.

Processes Excel XLSX files with [openpyxl](https://openpyxl.readthedocs.io/en/stable/).

Configuration values:

* `worksheet` (default: `None`): The name of the worksheet to process. If `None`, the default one will be used.
* `rows` (default: `dict`): type of elements in the result list:
    * `dict`: elements will be dictionaries, with the keys taken from the `header-row`.
    * `list`: each resulting row will be an array values.
* `header-row` (default: `0`): if `rows` is `dict`, the (0-based) index of the header row. All rows before the
    header row will be skipped.
* `skip-rows` (default: `0`): number of rows to skip at the beginning of the file (apart from the header and pre-header
    ones if `rows` is `dict`).
* `skip-empty-rows` (default: `True`): whether to omit empty rows (i.e., those with no values) from the result.
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any
from openpyxl import load_workbook
from openpyxl.cell import Cell

from ogc.na import util

DEFAULT_CONF = {
    'worksheet': None,
    'rows': 'dict',
    'header-row': 0,
    'skip-rows': 0,
    'skip-empty-rows': True,
}


def _cell_to_json(c: Cell) -> str | float | int | None:
    if isinstance(c.value, datetime):
        return c.value.isoformat()
    return c.value


def apply_filter(content: bytes, conf: dict[str, Any] | None) -> tuple[dict[str, Any] | list, dict[str, Any] | None]:
    conf = util.deep_update(DEFAULT_CONF, conf) if conf else DEFAULT_CONF

    metadata = {
        'filter': {
            'conf': conf,
        },
    }

    wb = load_workbook(filename=BytesIO(content), read_only=True)
    if conf['worksheet']:
        ws = wb[conf['worksheet']]
    else:
        ws = wb.worksheets[0]
    rows = ws.rows
    metadata['worksheet'] = ws.title

    headers = None
    if conf['rows'] == 'dict':
        header_row = max(conf['header-row'], 0)
        # Skip to header row
        for i in range(header_row):
            next(rows, None)
        headers = next(rows, [])
        if not headers:
            return [], None
        else:
            headers = [_cell_to_json(c) for c in headers]
        metadata['headers'] = headers

    for i in range(conf['skip-rows']):
        next(rows, None)

    result = []
    for row in rows:
        row_values = [_cell_to_json(c) for c in row]
        if conf['skip-empty-rows'] and not any(c is not None for c in row_values):
            # skip empty rows
            continue
        if conf['rows'] == 'list':
            result.append(row_values)
        else:
            result.append(dict(zip(headers, row_values)))

    return result, metadata
