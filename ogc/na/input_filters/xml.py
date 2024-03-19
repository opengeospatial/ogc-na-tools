"""
XML Input filter for ingest_json.

Processes XML files with [xmltodict](https://pypi.org/project/xmltodict/). Attributes are prefixed with `_` instead
of `@` by default.

Configuration values:

* `process-namespaces` (default: `False`): Whether to process and expand namespaces (see xmltodict documentation)
* `namespaces` (default: `None`): Namespace to prefix mappings dict in `url: prefix` format.
* `attr-prefix` (default: `_`): Prefix that will be used for attributes (in order to avoid potential clashes with
  element names).
* `namespace-separator` (default `:`): String that will be used to separate the namespace prefix and the local name
  when processing namespaces.
* `text-property` (default: `_`): property name that will be used to put the element's text content into
* `disable-entities` (default: `True`): disable processing of XML entities (to avoid XXE injections when parsing
  untrusted data)
"""
from __future__ import annotations

from io import StringIO
from typing import Any
import xmltodict

from ogc.na import util

DEFAULT_CONF = {
    'process-namespaces': False,
    'namespaces': None,
    'attr-prefix': '_',
    'namespace-separator': ':',
    'text-property': '_',
    'disable-entities': True,
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
                             namespaces=conf['namespaces'],
                             attr_prefix=conf['attr-prefix'],
                             namespace_separator=conf['namespace-separator'],
                             cdata_key=conf['text-property'],
                             disable_entities=conf['disable-entities'],
                             )

    return result, metadata
