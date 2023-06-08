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
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, AnyStr, Callable
from urllib.parse import urlparse, urljoin

import jsonschema
import requests_cache

from ogc.na.util import is_url, merge_dicts, load_yaml, LRUCache, dump_yaml

logger = logging.getLogger(__name__)

ANNOTATION_CONTEXT = 'x-jsonld-context'
ANNOTATION_ID = 'x-jsonld-id'
ANNOTATION_TYPE = 'x-jsonld-type'
ANNOTATION_PREFIXES = 'x-jsonld-prefixes'
ANNOTATION_EXTRA_TERMS = 'x-jsonld-extra-terms'
REF_ROOT_MARKER = '$_ROOT_/'

context_term_cache = LRUCache(maxsize=20)
requests_session = requests_cache.CachedSession('ogc.na.annotate_schema', backend='memory', expire_after=180)


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
        r = requests_session.get(url)
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


def read_context_terms(ctx: Path | str | dict) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """
    Reads all the terms from a JSON-LD context document.

    :param ctx: file path (Path), URL (str) or dictionary (dict) to load
    :return: a dictionary with term -> URI mappings
    """

    cached = context_term_cache.get(ctx)
    if cached:
        return cached

    context: dict[str, Any] | None = None

    if isinstance(ctx, Path):
        with open(ctx) as f:
            context = json.load(f).get('@context')
    elif isinstance(ctx, str):
        r = requests_session.get(ctx)
        r.raise_for_status()
        context = r.json().get('@context')
    elif ctx:
        context = ctx.get('@context')

    if not context:
        return {}, {}, {}

    result: dict[str, str | tuple[str, str]] = {}
    types: dict[str, str | tuple[str, str]] = {}

    vocab = context.get('@vocab')

    def expand_uri(uri: str) -> str | tuple[str, str] | None:
        if not uri:
            return None

        if ':' in uri:
            # either URI or prefix:suffix
            pref, suf = uri.split(':', 1)
            if suf.startswith('//') or pref == 'urn':
                # assume full URI
                return uri
            else:
                # prefix:suffix -> add to pending for expansion
                return pref, suf
        elif vocab:
            # append term_val to vocab to get URI
            return f"{vocab}{term_id}"
        else:
            return uri

    for term, term_val in context.items():
        if not term.startswith("@"):
            # assume term
            term_type = None
            if isinstance(term_val, str):
                term_id = term_val
            elif isinstance(term_val, dict):
                term_id = term_val.get('@id')
                term_type = term_val.get('@type')
            else:
                term_id = None

            expanded_id = expand_uri(term_id)
            if expanded_id:
                result[term] = expanded_id
            expanded_type = expand_uri(term_type)
            if expanded_type:
                types[term] = expanded_type

    prefixes = {}

    def expand_result(d: dict[str, str | tuple[str, str]]) -> dict[str, str]:
        r = {}
        for term, term_val in d.items():
            if isinstance(term_val, str):
                r[term] = term_val
            else:
                pref, suf = term_val
                if pref in result:
                    r[term] = f"{result[pref]}{suf}"
                    prefixes[pref] = result[pref]
        return r

    expanded_types = expand_result(types)
    expanded_terms = expand_result(result)

    context_term_cache[ctx] = expanded_terms, prefixes, expanded_types
    return expanded_terms, prefixes, expanded_types


def validate_schema(schema: Any):
    jsonschema.validators.validator_for(schema).check_schema(schema)


class SchemaAnnotator:
    """
    Builds a set of annotated JSON schemas from a collection of input schemas
    that have `x-jsonld-context`s to JSON-LD context documents.

    The results will be stored in the `schemas` property (a dictionary of
    schema-path-or-url -> AnnotatedSchema mappings).
    """

    def __init__(self, fn: Path | str | None = None, url: str | None = None,
                 follow_refs: bool = True, ref_root: Path | str | None = None,
                 context: str | Path | dict | None = None,
                 ref_mapper: Callable[[str, Any], str] | None = None):
        """
        :param fn: file path to load (root schema)
        :param url: URL to load (root schema)
        :follow_refs: whether to follow `$ref`s (otherwise just annotate the provided root schema)
        """
        self.schemas: dict[str | Path, AnnotatedSchema] = {}
        self.bundled_schema = None
        self.ref_root = Path(ref_root) if ref_root else None
        self._follow_refs = follow_refs
        self._provided_context = context
        self._ref_mapper = ref_mapper

        self._process_schema(fn, url)

    def _follow_ref(self, subschema, schema_fn: Path, schema_url: str, base_url: str | None):
        if not isinstance(subschema, dict) or '$ref' not in subschema:
            return

        if self._ref_mapper:
            subschema['$ref'] = self._ref_mapper(subschema['$ref'], subschema)

        if not self._follow_refs:
            return

        ref_fn, ref_url = resolve_ref(subschema['$ref'], schema_fn, schema_url, base_url)
        ref = ref_fn or ref_url

        if ref in self.schemas:
            logger.info(' >> Found $ref to already-processed schema: %s', ref)
        else:
            logger.info(' >> Found $ref to new schema: %s', ref)
            self._process_schema(url=ref_url, fn=ref_fn)

    def _process_schema(self, fn: Path | str | None = None, url: str | None = None):
        contents, base_url = read_contents(fn, url)
        schema, is_json = load_json_yaml(contents)

        try:
            if '$schema' in schema and all(x not in schema for x in ('schema', 'openapi')):
                validate_schema(schema)
        except jsonschema.exceptions.SchemaError as e:
            if fn:
                msg = f"Could not parse schema from file {fn}"
            else:
                msg = f"Could not parse schema from URL {url}"
            raise ValueError(msg) from e

        context_fn = schema.get(ANNOTATION_CONTEXT)
        schema.pop(ANNOTATION_CONTEXT, None)

        base_url = schema.get('$id', base_url)

        terms = {}
        prefixes = {}
        types = {}
        used_terms = set()

        if context_fn != self._provided_context or not (isinstance(context_fn, Path)
                                                        and isinstance(self._provided_context, Path)
                                                        and self._provided_context.resolve() == context_fn.resolve()):
            # Only load the provided context if it's different from the schema-referenced one
            terms, prefixes, types = read_context_terms(self._provided_context)

        if context_fn:
            if base_url:
                context_fn = urljoin(base_url, str(context_fn))
            else:
                context_fn = Path(fn).parent / context_fn

            for e in zip((terms, prefixes, types), read_context_terms(context_fn)):
                e[0].update(e[1])

        def process_properties(obj: dict):
            properties: dict[str, dict] = obj.get('properties') if obj else None
            if not properties:
                return
            if not isinstance(properties, dict):
                raise ValueError('"properties" must be a dictionary')

            empty_properties = []
            for prop, prop_value in properties.items():
                if not prop_value or prop_value is True:
                    empty_properties.append(prop)
                    continue
                if prop in terms:
                    prop_value[ANNOTATION_ID] = terms[prop]
                    used_terms.add(prop)
                    if prop in types:
                        prop_value[ANNOTATION_TYPE] = types[prop]

                process_subschema(prop_value)

            properties.update({p: {ANNOTATION_ID: terms[p]} for p in empty_properties if p in terms})

        def process_subschema(subschema):

            if not subschema:
                return

            self._follow_ref(subschema, fn, url, base_url)

            # Annotate oneOf, allOf, anyOf
            for p in ('oneOf', 'allOf', 'anyOf'):
                collection = subschema.get(p)
                if collection and isinstance(collection, list):
                    for entry in collection:
                        process_subschema(entry)

            # Annotate main schema
            schema_type = subschema.get('type')
            if not schema_type and 'properties' in subschema:
                schema_type = 'object'

            if schema_type == 'object':
                process_properties(subschema)
            elif schema_type == 'array':
                for k in ('prefixItems', 'items', 'contains'):
                    process_subschema(subschema.get(k))

            # Annotate $defs
            for defs_prop in ('$defs', 'definitions'):
                defs_value = subschema.get(defs_prop)
                if isinstance(defs_value, dict):
                    for defs_entry in defs_value.values():
                        process_subschema(defs_entry)

        process_subschema(schema)

        if prefixes:
            schema[ANNOTATION_PREFIXES] = prefixes

        unused_terms = set(terms) - set(prefixes) - used_terms
        extra_terms = {t: terms[t] for t in unused_terms}
        schema[ANNOTATION_EXTRA_TERMS] = extra_terms

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
                 compact: bool = True, ref_mapper: Callable[[str], str] | None = None):
        """
        :param fn: file to load the annotated schema from
        :param url: URL to load the annotated schema from
        """
        self.context = {'@context': {}}
        self._parsed_schemas: dict[str | Path, dict] = {}
        self._ref_mapper = ref_mapper

        context = self._build_context(fn, url, compact)
        self.context = {'@context': context}

    def _build_context(self, fn: Path | str | None = None,
                       url: str | None = None,
                       compact: bool = True) -> dict:
        parsed = self._parsed_schemas.get(fn, self._parsed_schemas.get(url))
        if parsed:
            return parsed

        contents, base_url = read_contents(fn, url)
        schema = load_json_yaml(contents)[0]

        base_url = schema.get('$id', base_url)

        prefixes = schema.get(ANNOTATION_PREFIXES, {}).items()
        rev_prefixes = {v: k for k, v in prefixes}

        def compact_uri(uri: str) -> str:
            if uri.startswith('@'):
                # JSON-LD keyword
                return uri
            parts = urlparse(uri)
            if parts.fragment:
                pref, suf = uri.rsplit('#', 1)
                pref += '#'
            elif len(parts.path) > 1:
                pref, suf = uri.rsplit('/', 1)
                pref += '/'
            else:
                return uri

            if pref in rev_prefixes:
                return f"{rev_prefixes[pref]}:{suf}"
            else:
                return uri

        own_context = {}

        if prefixes:
            own_context.update(prefixes)

        def read_properties(where: dict, into_context: dict):
            if not isinstance(where, dict):
                return
            for prop, prop_val in where.get('properties', {}).items():
                if isinstance(prop_val, dict):
                    prop_context: dict[str, Any] = {'@context': {}}
                    if ANNOTATION_ID in prop_val:
                        prop_context['@id'] = compact_uri(prop_val[ANNOTATION_ID])
                        if ANNOTATION_TYPE in prop_val:
                            prop_context['@type'] = compact_uri(prop_val[ANNOTATION_TYPE])

                    process_subschema(prop_val, prop_context['@context'])

                    if not prop_context['@context']:
                        prop_context.pop('@context', None)

                    if prop_context:
                        into_context[prop] = prop_context

        def process_subschema(ss, into_context: dict):

            if isinstance(ss, dict):
                if '$ref' in ss and ss['$ref'][0] != '#':
                    # we skip local $refs
                    ref_fn, ref_url = resolve_ref(ss['$ref'], fn, url, base_url)

                    if ref_fn or re.sub(r'#.*', '', ref_url) != url:
                        # Only follow ref if it's not to this same document
                        merge_dicts(self._build_context(ref_fn, ref_url, False), own_context)

                read_properties(ss, into_context)

                for i in ('allOf', 'anyOf', 'oneOf'):
                    l = ss.get(i)
                    if isinstance(l, list):
                        for sub_schema in l:
                            process_subschema(sub_schema, into_context)

                for i in ('$defs', 'definitions'):
                    d = ss.get(i)
                    if isinstance(d, dict):
                        for sub_schema in d.values():
                            process_subschema(sub_schema, into_context)

        process_subschema(schema, own_context)

        if ANNOTATION_EXTRA_TERMS in schema:
            for term, term_context in schema[ANNOTATION_EXTRA_TERMS].items():
                if term not in own_context:
                    if isinstance(term_context, str):
                        own_context[term] = compact_uri(term_context)
                    else:
                        own_context[term] = term_context

        if compact:

            def compact_branch(branch, existing_terms):

                for term in list(branch.keys()):
                    if term[0] == '@':
                        # skip special terms
                        continue
                    if term in existing_terms and existing_terms[term] == branch[term]:
                        # same term exists in ancestor -> delete
                        del branch[term]

                for term in list(branch.keys()):
                    term_value = branch[term]
                    if isinstance(term_value, dict):
                        if len(term_value) == 1 and '@id' in term_value:
                            branch[term] = term_value['@id']
                        elif '@context' in term_value:
                            compact_branch(term_value['@context'], {**existing_terms, **branch})

            compact_branch(own_context, {})

        self._parsed_schemas[fn or url] = own_context
        return own_context


def dump_annotated_schemas(annotator: SchemaAnnotator, subdir: Path | str = 'annotated',
                           root_dir: Path | str | None = None,
                           output_fn_transform: Callable[[Path], Path] | None = None) -> list[Path]:
    """
    Creates a "mirror" directory (named `annotated` by default) with the resulting
    schemas annotated by a `SchemaAnnotator`.

    :param annotator: a `SchemaAnnotator` with the annotated schemas to read
    :param subdir: a name for the mirror directory
    :param root_dir: root directory for computing relative paths to schemas
    :param output_fn_transform: optional callable to transform the output path
    """
    wd = (Path(root_dir) if root_dir else Path()).resolve()
    subdir = subdir if isinstance(subdir, Path) else Path(subdir)
    result = []
    for path, schema in annotator.schemas.items():

        if isinstance(path, Path):
            output_fn = path.resolve().relative_to(wd)
        else:
            parsed = urlparse(str(path))
            output_fn = parsed.path

        output_fn = subdir / output_fn
        if output_fn_transform:
            output_fn = output_fn_transform(output_fn)
        output_fn.parent.mkdir(parents=True, exist_ok=True)

        if schema.is_json:
            with open(output_fn, 'w') as f:
                json.dump(schema.schema, f, indent=2)
        else:
            dump_yaml(schema.schema, output_fn)

        result.append(output_fn)

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

    parser.add_argument(
        '--stdout',
        action='store_true',
        help='Dump schemas to stdout'
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
        if args.stdout:
            write_separator = len(annotator.schemas) > 1
            for path, schema in annotator.schemas.items():
                if write_separator:
                    print('---')
                print('#', path)
                print(dump_yaml(schema.schema))
        else:
            dump_annotated_schemas(annotator, args.output)


if __name__ == '__main__':
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format='%(asctime)s,%(msecs)d %(levelname)-5s [%(filename)s:%(lineno)d] %(message)s',
    )

    _main()
