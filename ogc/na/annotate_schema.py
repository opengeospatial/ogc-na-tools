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

from ogc.na.util import is_url, load_yaml, LRUCache, dump_yaml, merge_contexts

logger = logging.getLogger(__name__)

ANNOTATION_PREFIX = 'x-jsonld-'
ANNOTATION_CONTEXT = 'x-jsonld-context'
ANNOTATION_ID = 'x-jsonld-id'
ANNOTATION_PREFIXES = 'x-jsonld-prefixes'
ANNOTATION_EXTRA_TERMS = 'x-jsonld-extra-terms'

context_term_cache = LRUCache(maxsize=20)
requests_session = requests_cache.CachedSession('ogc.na.annotate_schema', backend='memory', expire_after=180)


@dataclasses.dataclass
class AnnotatedSchema:
    source: str | Path
    is_json: bool
    schema: dict


@dataclasses.dataclass
class ReferencedSchema:
    location: str | Path
    fragment: str | None = None
    subschema: dict | None = None
    full_contents: dict | None = None
    chain: list = dataclasses.field(default_factory=list)
    ref: str | Path = None


class SchemaResolver:

    def __init__(self, working_directory=Path()):
        self.working_directory = working_directory.resolve()
        self._schema_cache: dict[str | Path, dict] = {}

    @staticmethod
    def _get_branch(schema: dict, ref: str):
        path = re.sub(r'^#?/?', '', ref).split('/')
        pointer = schema
        for item in path:
            if path:
                pointer = pointer[item]
        return pointer

    def _load_contents(self, s: str | Path) -> dict:
        contents = self._schema_cache.get(s)
        if contents is None:
            contents = load_json_yaml(read_contents(s)[0])[0]
            self._schema_cache[s] = contents
        return contents

    def resolve(self, ref: str | Path, from_schema: ReferencedSchema | None = None) -> ReferencedSchema:
        fragment = None
        chain = from_schema.chain + [from_schema] if from_schema else []
        try:
            if isinstance(ref, Path):
                if ref.is_absolute():
                    schema_source = ref
                elif not from_schema:
                    schema_source = self.working_directory / ref
                elif not isinstance(from_schema.location, Path):
                    schema_source = urljoin(from_schema.location, str(ref))
                else:
                    schema_source = from_schema.location.resolve().parent.joinpath(ref).resolve()

            elif isinstance(ref, str):
                # Resolve local ref or URL
                if ref.startswith('#'):
                    # Relative to current schema
                    if not from_schema:
                        raise ValueError('Local ref provided without an anchor: ' + ref)
                    return ReferencedSchema(location=from_schema.location,
                                            fragment=ref[1:],
                                            subschema=SchemaResolver._get_branch(from_schema.full_contents, ref),
                                            full_contents=from_schema.full_contents,
                                            chain=chain,
                                            ref=ref)
                elif is_url(ref):
                    # Absolute URL, download and parse
                    s = ref.split('#', 1)
                    url = s[0]
                    fragment = s[1] if len(s) > 1 else None
                    schema_source = url

                else:
                    # str with a relative or absolute path, and with or without a fragment
                    s = ref.split('#', 1)
                    path = Path(s[0])
                    fragment = s[1] if len(s) > 1 else None
                    if path.is_absolute():
                        # Load the schema
                        schema_source = path.resolve()
                    elif not from_schema:
                        schema_source = self.working_directory / path.resolve()
                    elif isinstance(from_schema.location, Path):
                        # Resolve relative path
                        schema_source = from_schema.location.resolve().parent.joinpath(path).resolve()
                    else:
                        # Resolve relative URL
                        schema_source = urljoin(from_schema.location, str(path))
            else:
                raise ValueError(f'Unexpected ref type {type(ref).__name__}')

            contents = self._load_contents(schema_source)
            if fragment:
                return ReferencedSchema(location=schema_source, fragment=fragment,
                                        subschema=SchemaResolver._get_branch(contents, fragment),
                                        full_contents=contents,
                                        chain=chain,
                                        ref=ref)
            else:
                return ReferencedSchema(location=schema_source,
                                        subschema=contents,
                                        full_contents=contents,
                                        chain=chain,
                                        ref=ref)
        except Exception as e:
            f = f" from {from_schema.location}" if from_schema else ''
            raise IOError(f"Error resolving reference {ref}{f}") from e


def read_contents(location: Path | str | None) -> tuple[AnyStr | bytes, str]:
    """
    Reads contents from a file or URL

    @param location: filename or URL to load
    @return: a tuple with the loaded data (str or bytes) and the base URL, if any
    """
    if not location:
        raise ValueError('A location must be provided')

    if isinstance(location, Path) or not is_url(location):
        fn = Path(location)
        base_url = None
        logger.info('Reading file contents from %s', fn)
        with open(fn) as f:
            contents = f.read()
    else:
        base_url = location
        r = requests_session.get(location)
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
                base_url: str | None = None) -> tuple[Path | None, str | None]:
    """
    Resolves a `$ref`
    :param ref: the `$ref` to resolve
    :param fn_from: original name of the file containing the `$ref` (when it is a file)
    :param url_from: original URL of the document containing the `$ref` (when it is a URL)
    :param base_url: base URL of the document containing the `$ref` (if any)
    :return: a tuple of (Path, str) with only one None entry (the Path if the resolved
    reference is a file, or the str if it is a URL)
    """

    base_url = base_url or url_from
    if is_url(ref):
        return None, ref
    elif base_url:
        return None, urljoin(base_url, ref)
    else:
        fn_from = fn_from if isinstance(fn_from, Path) else Path(fn_from)
        ref = (fn_from.resolve().parent / ref).resolve()
        return ref, None


def read_context_terms(ctx: Path | str | dict) -> tuple[dict[str, str], dict[str, str], dict[str, dict[str, Any]]]:
    """
    Reads all the terms from a JSON-LD context document.

    :param ctx: file path (Path), URL (str) or dictionary (dict) to load
    :return: a tuple with 1) a dict with term to URI mappings, 2) a dict with prefix to URI mappings,
      and 3) a nested dict with property to keyword-value mappings
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
    keywords: dict[str, dict[str, Any]] = {}

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
            if isinstance(term_val, str):
                term_id = term_val
            elif isinstance(term_val, dict):
                term_id = term_val.get('@id')
                keywords[term] = {k: v for k, v in term_val.items() if k.startswith('@') and k not in ('@id', '@context')}
            else:
                term_id = None

            expanded_id = expand_uri(term_id)
            if expanded_id:
                result[term] = expanded_id

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

    for keyword, keyword_val in keywords.items():
        if keyword_val.get('@type'):
            if isinstance(keyword_val['@type'], str):
                keyword_val['@type'] = expand_uri(keyword_val['@type'])
            elif isinstance(keyword_val['@type'], list):
                keyword_val['@type'] = [expand_uri(t) for t in keyword_val['@type']]

    expanded_terms = expand_result(result)

    context_term_cache[ctx] = expanded_terms, prefixes, keywords
    return expanded_terms, prefixes, keywords


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
        contents, base_url = read_contents(fn or url)
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
        keywords = {}
        used_terms = set()

        if context_fn != self._provided_context or not (isinstance(context_fn, Path)
                                                        and isinstance(self._provided_context, Path)
                                                        and self._provided_context.resolve() == context_fn.resolve()):
            # Only load the provided context if it's different from the schema-referenced one
            terms, prefixes, keywords = read_context_terms(self._provided_context)

        if context_fn:
            if base_url:
                context_fn = urljoin(base_url, str(context_fn))
            else:
                context_fn = Path(fn).parent / context_fn

            for e in zip((terms, prefixes, keywords), read_context_terms(context_fn)):
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
                    if keywords.get(prop):
                        for kw, kw_term in keywords[prop].items():
                            prop_value[ANNOTATION_PREFIX + kw[1:]] = kw_term

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
        if extra_terms:
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

        self._resolver = SchemaResolver()

        self.location = fn or url

        context = self._build_context(self.location, compact)
        self.context = {'@context': context}

    def _build_context(self, schema_location: str | Path,
                       compact: bool = True) -> dict:

        parsed = self._parsed_schemas.get(schema_location)
        if parsed:
            return parsed

        root_schema = self._resolver.resolve(schema_location)

        prefixes = {}

        own_context = {}

        if prefixes:
            own_context.update(prefixes)

        def read_properties(subschema: dict, from_schema: ReferencedSchema,
                            property_chain: list) -> dict | None:
            if not isinstance(subschema, dict):
                return None
            if subschema.get('type', 'object') != 'object':
                return None
            subschema_context = {}
            for prop, prop_val in subschema.get('properties', {}).items():
                if not isinstance(prop_val, dict):
                    continue
                prop_context = {}
                for term, term_val in prop_val.items():
                    if term.startswith(ANNOTATION_PREFIX) and term != ANNOTATION_CONTEXT:
                        prop_context['@' + term[len(ANNOTATION_PREFIX):]] = term_val
                inner_context = process_subschema(prop_val, from_schema, property_chain + ['properties', prop])
                if inner_context:
                    prop_context['@context'] = inner_context
                if isinstance(prop_context.get('@id'), str):
                    subschema_context[prop] = prop_context
                elif inner_context:
                    subschema_context = merge_contexts(subschema_context, inner_context, from_schema, property_chain)

            return subschema_context

        def process_subschema(subschema, from_schema, property_chain=None) -> dict | None:

            if property_chain is None:
                property_chain = []

            if not isinstance(subschema, dict):
                return None

            if '$ref' in subschema:
                referenced_schema = self._resolver.resolve(subschema['$ref'], from_schema)
                subschema = referenced_schema.subschema
                from_schema = referenced_schema

            if not subschema:
                return None

            sub_context = read_properties(subschema, from_schema, property_chain)

            for i in ('allOf', 'anyOf', 'oneOf'):
                l = subschema.get(i)
                if isinstance(l, list):
                    for idx, sub_subschema in enumerate(l):
                        sub_context = merge_contexts(sub_context,
                                                     process_subschema(sub_subschema,
                                                                       from_schema,
                                                                       property_chain + [f"{i}[{idx}]"]),
                                                     from_schema, property_chain)

            for i in ('prefixItems', 'items', 'contains'):
                l = subschema.get(i)
                if isinstance(l, dict):
                    items_ctx = process_subschema(l, from_schema, property_chain + [i])
                    sub_context = merge_contexts(sub_context, items_ctx, from_schema, property_chain)

            if ANNOTATION_EXTRA_TERMS in subschema:
                for extra_term, extra_term_context in subschema[ANNOTATION_EXTRA_TERMS].items():
                    if extra_term not in sub_context:
                        if isinstance(extra_term_context, str):
                            extra_term_context = {'@id': extra_term_context}
                        sub_context[extra_term] = extra_term_context

            if sub_context:
                fixed_sub_context = {}
                for prop, prop_ctx in sub_context.items():
                    if prop.startswith('@'):
                        continue
                    if '@id' in prop_ctx:
                        fixed_sub_context[prop] = prop_ctx
                    elif prop_ctx.get('@context'):
                        merge_contexts(fixed_sub_context, prop_ctx['@context'], from_schema, property_chain)
                sub_context = fixed_sub_context

            sub_prefixes = subschema.get(ANNOTATION_PREFIXES)
            if isinstance(sub_prefixes, dict):
                prefixes.update(sub_prefixes)

            return sub_context

        own_context = merge_contexts(own_context, process_subschema(root_schema.subschema, root_schema),
                                     root_schema)

        if compact:

            rev_prefixes = {v: k for k, v in prefixes.items()}

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
                            branch[term] = compact_uri(term_value['@id'])
                        elif '@context' in term_value:
                            compact_branch(term_value['@context'], {**existing_terms, **branch})

            compact_branch(own_context, {})

        self._parsed_schemas[schema_location] = own_context
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
