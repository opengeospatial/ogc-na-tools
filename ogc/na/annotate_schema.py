#!/usr/bin/env python3
"""
This module offers functionality to semantically enrich JSON Schemas
by using `x-jsonld-context` annotations pointing to JSON-LD context documents,
and also to build ready-to-use JSON-LD contexts from annotated JSON Schemas.

An example of an annotated JSON schema:

```yaml
"$schema": https://json-schema.org/draft/2020-12/schema
"x-jsonld-context": observation.context.jsonld
title: Observation
type: object
required:
  - featureOfInterest
  - hasResult
  - resultTime
properties:
  featureOfInterest:
    type: string
  hasResult:
    type: object
  resultTime:
    type: string
    format: date-time
  observationCollection:
    type: string
```

... and its linked `x-jsonld-context`:

```json
{
  "@context": {
    "@version": 1.1,
    "sosa": "http://www.w3.org/ns/sosa/",
    "featureOfInterest": "sosa:featureOfInterest",
    "hasResult": "sosa:hasResult",
    "resultTime": "sosa:resultTime"
  }
}
```

A `SchemaAnnotator` instance would then generate the following annotated JSON schema:

```yaml
$schema: https://json-schema.org/draft/2020-12/schema
title: Observation
type: object
required:
- featureOfInterest
- hasResult
- observationTime
properties:
  featureOfInterest:
    'x-jsonld-id': http://www.w3.org/ns/sosa/featureOfInterest
    type: string
  hasResult:
    'x-jsonld-id': http://www.w3.org/ns/sosa/hasResult
    type: object
  observationCollection:
    type: string
  observationTime:
    'x-jsonld-id': http://www.w3.org/ns/sosa/resultTime
    format: date-time
    type: string
```

This schema can then be referenced from other entities that follow it (e.g., by using
[FG-JSON](https://github.com/opengeospatial/ogc-feat-geo-json) "definedby" links).

A client can then build a full JSON-LD `@context` (by using a `ContextBuilder` instance)
and use it when parsing plain-JSON entities:

```json
{
  "@context": {
    "featureOfInterest": "http://www.w3.org/ns/sosa/featureOfInterest",
    "hasResult": "http://www.w3.org/ns/sosa/hasResult",
    "observationTime": "http://www.w3.org/ns/sosa/resultTime"
  }
}
```

A JSON schema can be in YAML or JSON format (the annotated schema will use the same format
as the input one).

JSON schemas need to follow some rules to work with this tool:

* No nested `properties` are allowed. If they are needed, they should be put in a different
schema, and a `$ref` to it used inside the appropriate property definition.
* `allOf`/`someOf` root properties can be used to import other schemas (as long as they
contain `$ref`s to them).

This module can be run as a script, both for schema annotation and for context generation.

To annotate a schema (that already contains a `x-jsonld-context` to a JSON-LD context resource):

```shell
python -m ogc.na.annotate_schema --file path/to/schema.file.yaml
```

This will generate a new `annotated` directory replicating the layout of the input file
path (`/annotated/path/to/schema.file.yaml` in this example).

JSON-LD contexts can be built by adding a `-c` flag:

```shell
python -m ogc.na.annotate_schema -c --file annotated/path/to/schema.file.yaml
```

The resulting context will be printed to the standard output.

"""

from __future__ import annotations
import argparse
import dataclasses
import functools
import json
import logging
import sys
from pathlib import Path
from typing import Any, AnyStr
from urllib.parse import urlparse, urljoin
import yaml
import requests
from ogc.na.util import is_url, merge_dicts, load_yaml

try:
    from yaml import CLoader as YamlLoader, CDumper as YamlDumper
except ImportError:
    from yaml import Loader as YamlLoader, Dumper as YamlDumper

logger = logging.getLogger(__name__)

ANNOTATION_CONTEXT = 'x-jsonld-context'
ANNOTATION_ID = 'x-jsonld-id'
ANNOTATION_TYPE = 'x-jsonld-type'
REF_ROOT_MARKER = '$_ROOT_/'


@dataclasses.dataclass
class AnnotatedSchema:
    source: str | Path
    is_json: bool
    schema: dict


def read_contents(fn: Path | str | None = None, url: str | None = None) -> tuple[AnyStr | bytes, str]:
    """
    Reads contents from a file or URL

    @param fn: filename to load
    @param url: URL to load
    @return: a tuple with the loaded data (str or bytes) and the base URL, if any
    """
    if not fn and not url:
        raise ValueError('Either fn or url must be provided')

    if fn:
        fn = Path(fn)
        base_url = None
        logger.info('Reading file contents from %s', fn)
        with open(fn) as f:
            contents = f.read()
    else:
        base_url = url
        r = requests.get(url)
        r.raise_for_status()
        contents = r.content

    return contents, base_url


def load_json_yaml(contents: str | bytes) -> tuple[Any, bool]:
    """
    Loads either a JSON or a YAML file

    :param contents: contents to load
    :return: a tuple with the loaded document, and whether the detected format was JSON (True) or YAML (False)
    """
    try:
        obj = json.loads(contents)
        is_json = True
    except ValueError:
        obj = load_yaml(content=contents)
        is_json = False

    return obj, is_json


def resolve_ref(ref: str, fn_from: str | Path | None = None, url_from: str | None = None,
                base_url: str | None = None, ref_root: Path | None = None) -> tuple[Path | None, str | None]:
    """
    Resolves a `$ref`
    :param ref: the `$ref` to resolve
    :param fn_from: original name of the file containing the `$ref` (when it is a file)
    :param url_from: original URL of the document containing the `$ref` (when it is a URL)
    :param base_url: base URL of the document containing the `$ref` (if any)
    :param ref_root: base path to resolve $_ROOT_ refs
    :return: a tuple of (Path, str) with only one None entry (the Path if the resolved
    reference is a file, or the str if it is a URL)
    """
    if ref.startswith(REF_ROOT_MARKER):
        if not ref_root:
            ref_root = Path()
        return ref_root / ref[len(REF_ROOT_MARKER):], None

    base_url = base_url or url_from
    if is_url(ref):
        return None, ref
    elif base_url:
        return None, urljoin(base_url, ref)
    else:
        fn_from = fn_from if isinstance(fn_from, Path) else Path(fn_from)
        ref = (fn_from.resolve().parent / ref).resolve()
        return ref, None


@functools.lru_cache(maxsize=20)
def read_context_terms(file: Path | str = None, url: str = None) -> dict[str, str]:
    """
    Reads all the terms from a JSON-LD context document.

    :param file: file path to load
    :param url: URL to load
    :return: a dictionary with term -> URI mappings
    """
    context: dict[str, Any] | None = None

    if file:
        with open(file) as f:
            context = json.load(f).get('@context')
    elif url:
        r = requests.get(url)
        r.raise_for_status()
        context = r.json().get('@context')

    if not context:
        return {}

    result: dict[str, str] = {}
    pending: dict[str, list] = {}

    vocab = context.get('@vocab')

    for term, term_val in context.items():
        if not term.startswith("@"):
            # assume term
            if isinstance(term_val, str):
                term_id = term_val
            elif isinstance(term_val, dict):
                term_id = term_val.get('@id')
            else:
                term_id = None

            if term_id:
                if ':' in term_id:
                    # either URI or prefix:suffix
                    pref, suf = term_id.split(':', 1)
                    if suf.startswith('//'):
                        # assume URI -> add to result
                        result[term] = term_id
                    else:
                        # prefix:suffix -> add to pending for expansion
                        pending[term] = [pref, suf]
                elif vocab:
                    # append term_val to vocab to get URI
                    result[term] = f"{vocab}{term_id}"

    for term, term_val in pending.items():
        pref, suf = term_val
        if pref in result:
            result[term] = f"{result[pref]}{suf}"

    return result


class SchemaAnnotator:
    """
    Builds a set of annotated JSON schemas from a collection of input schemas
    that have `x-jsonld-context`s to JSON-LD context documents.

    The results will be stored in the `schemas` property (a dictionary of
    schema-path-or-url -> AnnotatedSchema mappings).
    """

    def __init__(self, fn: Path | str | None = None, url: str | None = None,
                 follow_refs: bool = True, ref_root: Path | str | None = None):
        """
        :param fn: file path to load (root schema)
        :param url: URL to load (root schema)
        :follow_refs: whether to follow `$ref`s (otherwise just annotate the provided root schema)
        """
        self.schemas: dict[str | Path, AnnotatedSchema] = {}
        self.bundled_schema = None
        self.ref_root = Path(ref_root) if ref_root else None
        self._follow_refs = follow_refs

        self._process_schema(fn, url)

    def _process_schema(self, fn: Path | str | None = None, url: str | None = None):
        contents, base_url = read_contents(fn, url)
        schema, is_json = load_json_yaml(contents)

        context_fn = schema.get(ANNOTATION_CONTEXT)
        schema.pop(ANNOTATION_CONTEXT, None)

        base_url = schema.get('$id', base_url)

        if not context_fn:
            terms = {}
        elif base_url:
            context_fn = urljoin(base_url, context_fn)
            terms = read_context_terms(url=context_fn)
        else:
            context_fn = Path(fn).parent / context_fn
            terms = read_context_terms(file=context_fn)

        def process_properties(obj: dict):
            properties: dict[str, dict] = obj.get('properties') if obj else None
            if not properties:
                return

            empty_properties = []
            for prop, prop_value in properties.items():
                if not prop_value:
                    empty_properties.append(prop)
                    continue
                if prop in terms:
                    prop_value[ANNOTATION_ID] = terms[prop]
                if '$ref' in prop_value:

                    ref_fn, ref_url = resolve_ref(prop_value['$ref'], fn, url, base_url)
                    ref = ref_fn or ref_url

                    if ref in self.schemas:
                        logger.info(' >> Found $ref to already-processed schema: %s', ref)
                    else:
                        logger.info(' >> Found $ref to new schema: %s', prop_value['$ref'])
                        if ref_url:
                            self._process_schema(url=ref)
                        else:
                            self._process_schema(fn=ref)

            properties.update({p: {ANNOTATION_ID: terms[p]} for p in empty_properties})

        schema_type = schema.get('type')

        if schema_type == 'object':
            process_properties(schema)
        elif schema_type == 'array':
            for k in ('prefixItems', 'items', 'contains'):
                process_properties(schema.get(k))

        self.schemas[fn or url] = AnnotatedSchema(
            source=fn or url,
            is_json=is_json,
            schema=schema
        )


class ContextBuilder:
    """
    Builds a JSON-LD context from a set of annotated JSON schemas.
    """

    def __init__(self, fn: Path | str | None = None, url: str | None = None,
                 compact: bool = True):
        """
        :param fn: file to load the annotated schema from
        :param url: URL to load the annotated schema from
        """
        self.context = {'@context': {}}
        self._parsed_schemas: dict[str | Path, dict] = {}
        self.compact = compact

        context = self._build_context(fn, url)
        self.context = {'@context': context}

    def _build_context(self, fn: Path | str | None = None, url: str | None = None) -> dict:
        parsed = self._parsed_schemas.get(fn, self._parsed_schemas.get(url))
        if parsed:
            return parsed

        contents, base_url = read_contents(fn, url)
        schema = load_json_yaml(contents)[0]

        base_url = schema.get('$id', base_url)

        own_context = {}

        def read_properties(where: dict):
            if not isinstance(where, dict):
                return
            for prop, prop_val in where.get('properties', {}).items():
                if ANNOTATION_ID in prop_val:
                    prop_context = {
                        '@id': prop_val[ANNOTATION_ID]
                    }
                    if ANNOTATION_TYPE in prop_val:
                        prop_context['@type'] = prop_val[ANNOTATION_TYPE]

                    if '$ref' in prop_val:
                        ref_fn, ref_url = resolve_ref(prop_val['$ref'], fn, url, base_url)
                        prop_context['@context'] = self._build_context(ref_fn, ref_url)

                    if len(prop_context) == 1:
                        # shorten to just the id
                        prop_context = next(iter(prop_context.values()))

                    own_context[prop] = prop_context

        for i in ('allOf', 'anyOf', 'oneOf'):
            l = schema.get(i)
            if isinstance(l, list):
                for sub_schema in l:
                    if isinstance(sub_schema, dict):
                        if '$ref' in sub_schema:
                            ref_fn, ref_url = resolve_ref(sub_schema['$ref'], fn, url, base_url)
                            merge_dicts(self._build_context(ref_fn, ref_url), own_context)
                        else:
                            read_properties(sub_schema)

        read_properties(schema)

        if self.compact:
            context_props = set(own_context.keys())
            compact_context = {}
            for prop, prop_val in own_context.items():
                compact_context[prop] = prop_val
                if not isinstance(prop_val, dict):
                    continue
                prop_context = prop_val.pop('@context', None)
                if not isinstance(prop_context, dict):
                    continue
                for term, term_val in prop_context.items():
                    if not term.startswith('@') and term in context_props:
                        compact_context.setdefault(prop, {}).setdefault('@context', {})[term] = term_val
                    else:
                        compact_context[term] = term_val
                if len(compact_context[prop]) == 1 and '@id' in compact_context[prop]:
                    compact_context[prop] = compact_context[prop]['@id']

            own_context = compact_context

        self._parsed_schemas[fn or url] = own_context
        return own_context


def dump_annotated_schemas(annotator: SchemaAnnotator, subdir: Path | str = 'annotated',
                           root_dir: Path | str | None = None) -> list[Path]:
    """
    Creates a "mirror" directory (named `annotated` by default) with the resulting
    schemas annotated by a `SchemaAnnotator`.

    :param annotator: a `SchemaAnnotator` with the annotated schemas to read
    :param subdir: a name for the mirror directory
    :param root_dir: root directory for computing relative paths to schemas
    """
    wd = (Path(root_dir) if root_dir else Path()).resolve()
    subdir = subdir if isinstance(subdir, Path) else Path(subdir)
    result = []
    for path, schema in annotator.schemas.items():

        if isinstance(path, Path):
            outputfn = path.resolve().relative_to(wd)
        else:
            parsed = urlparse(str(path))
            outputfn = parsed.path

        outputfn = subdir / outputfn
        outputfn.parent.mkdir(parents=True, exist_ok=True)

        with open(outputfn, 'w') as f:
            if schema.is_json:
                json.dump(schema.schema, f, indent=2)
            else:
                yaml.dump(schema.schema, f, sort_keys=False)

        result.append(outputfn)

    return result


def _main():
    parser = argparse.ArgumentParser(
        prog='JSON Schema @id injector'
    )

    parser.add_argument(
        '--file',
        required=False,
        help='Entrypoint JSON Schema (filename)',
    )

    parser.add_argument(
        '--url',
        required=False,
        help='Entrypoint JSON Schema (URL)',
    )

    parser.add_argument(
        '-c',
        '--build-context',
        help='Build JSON-LD context fron annotated schemas',
        action='store_true'
    )

    parser.add_argument(
        '-F',
        '--no-follow-refs',
        help='Do not follow $ref\'s',
        action='store_true'
    )

    parser.add_argument(
        '-o',
        '--output',
        help='Output directory where to put the annotated schemas',
        default='annotated'
    )

    parser.add_argument(
        '-b',
        '--context-batch',
        help="Write JSON-LD context to a file with the same name and .jsonld extension (implies --build-context)",
        action='store_true',
    )

    args = parser.parse_args()

    if not args.file and not args.url:
        print('Error: no file and no URL provided', file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        sys.exit(2)

    if args.build_context or args.context_batch:
        ctx_builder = ContextBuilder(fn=args.file, url=args.url)
        if args.context_batch:
            fn = Path(args.file).with_suffix('.jsonld')
            with open(fn, 'w') as f:
                json.dump(ctx_builder.context, f, indent=2)
        else:
            print(json.dumps(ctx_builder.context, indent=2))
    else:
        annotator = SchemaAnnotator(fn=args.file, url=args.url, follow_refs=not args.no_follow_refs)
        dump_annotated_schemas(annotator, args.output)


if __name__ == '__main__':
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format='%(asctime)s,%(msecs)d %(levelname)-5s [%(filename)s:%(lineno)d] %(message)s',
    )

    _main()
