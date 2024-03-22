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
import csv
import dataclasses
import json
import logging
import re
import sys
from collections import deque
from operator import attrgetter
from pathlib import Path
from typing import Any, AnyStr, Callable, Sequence, Iterable
from urllib.parse import urlparse, urljoin

import jsonschema
import requests_cache

from ogc.na.util import is_url, load_yaml, LRUCache, dump_yaml, merge_contexts, merge_dicts, dict_contains

logger = logging.getLogger(__name__)

ANNOTATION_PREFIX = 'x-jsonld-'
ANNOTATION_CONTEXT = f'{ANNOTATION_PREFIX}context'
ANNOTATION_ID = f'{ANNOTATION_PREFIX}id'
ANNOTATION_PREFIXES = f'{ANNOTATION_PREFIX}prefixes'
ANNOTATION_EXTRA_TERMS = f'{ANNOTATION_PREFIX}extra-terms'
ANNOTATION_BASE = f'{ANNOTATION_PREFIX}base'

ANNOTATION_IGNORE_EXPAND = [ANNOTATION_CONTEXT, ANNOTATION_EXTRA_TERMS, ANNOTATION_PREFIXES]

CURIE_TERMS = '@id', '@type', '@index'

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
    is_json: bool = False


@dataclasses.dataclass
class ResolvedContext:
    context: dict[str, Any] = dataclasses.field(default_factory=dict)
    prefixes: dict[str, str] = dataclasses.field(default_factory=dict)


class SchemaResolver:

    def __init__(self, working_directory=Path()):
        self.working_directory = working_directory.resolve()
        self._schema_cache: dict[str | Path, tuple[Any, bool]] = {}

    @staticmethod
    def _get_branch(schema: dict, ref: str):
        path = re.sub(r'^#?/?', '', ref).split('/')
        pointer = schema
        for item in path:
            if item:
                pointer = pointer[item]
        return pointer

    def load_contents(self, s: str | Path) -> tuple[dict, bool]:
        """
        Load the contents of a schema. Can be overriden by subclasses to alter the loading process.
        """
        contents, is_json = self._schema_cache.get(s, (None, False))
        if contents is None:
            contents, is_json = load_json_yaml(read_contents(s)[0])
            self._schema_cache[s] = contents, is_json
        return contents, is_json

    def resolve_ref(self, ref: str | Path, from_schema: ReferencedSchema | None = None) -> tuple[Path | str, str]:
        location = ref
        fragment = None
        if isinstance(location, str):
            s = location.split('#', 1)
            fragment = s[1] if len(s) > 1 else None
            location = s[0]
            if not location:
                return location, fragment
            if not is_url(location):
                location = Path(location)

        if isinstance(location, Path):
            if location.is_absolute():
                location = location.resolve()
            elif not from_schema:
                location = self.working_directory.joinpath(location).resolve()
            elif from_schema.full_contents.get('$id'):
                location = urljoin(from_schema.full_contents['$id'], str(location))
            elif not isinstance(from_schema.location, Path):
                location = urljoin(from_schema.location, str(location))
            else:
                location = from_schema.location.resolve().parent.joinpath(location).resolve()

        if location is None:
            raise ValueError(f'Unexpected ref type {type(ref).__name__}')

        return location, fragment

    def resolve_schema(self, ref: str | Path, from_schema: ReferencedSchema | None = None) -> ReferencedSchema | None:
        chain = from_schema.chain + [from_schema] if from_schema else []
        try:
            schema_source, fragment = self.resolve_ref(ref, from_schema)
            if from_schema:
                for ancestor in from_schema.chain:
                    if (not schema_source or ancestor.location == schema_source) and ancestor.fragment == fragment:
                        return None

            if not schema_source:
                if not from_schema:
                    raise ValueError('Local ref provided without an anchor: ' + ref)
                return ReferencedSchema(location=from_schema.location,
                                        fragment=ref[1:],
                                        subschema=SchemaResolver._get_branch(from_schema.full_contents, ref),
                                        full_contents=from_schema.full_contents,
                                        chain=chain,
                                        ref=ref,
                                        is_json=from_schema.is_json)

            contents, is_json = self.load_contents(schema_source)
            if fragment:
                return ReferencedSchema(location=schema_source, fragment=fragment,
                                        subschema=SchemaResolver._get_branch(contents, fragment),
                                        full_contents=contents,
                                        chain=chain,
                                        ref=ref,
                                        is_json=is_json)
            else:
                return ReferencedSchema(location=schema_source,
                                        subschema=contents,
                                        full_contents=contents,
                                        chain=chain,
                                        ref=ref,
                                        is_json=is_json)
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


def resolve_context(ctx: Path | str | dict | list, expand_uris=True) -> ResolvedContext:
    if not ctx:
        return ResolvedContext()

    prefixes = {}

    def expand_uri(curie, ctx_stack):
        if not expand_uris or not ctx_stack or not curie or curie[0] == '@':
            return curie
        if ':' in curie:
            prefix, localpart = curie.split(':', 1)
        else:
            prefix, localpart = None, None
        for c in reversed(ctx_stack):
            if localpart:
                # prefix:localpart format
                if prefix in c:
                    term_val = c[prefix]
                    prefix_uri = term_val if isinstance(term_val, str) else term_val.get('@id')
                    prefixes[prefix] = prefix_uri
                    return f"{prefix_uri}{localpart}"
            elif '@vocab' in c:
                # look for @vocab
                return f"{c['@vocab']}{curie}"

        return curie

    def resolve_prop(term_val, ctx_stack):
        if isinstance(term_val, str):
            return expand_uri(term_val, ctx_stack)
        elif not isinstance(term_val, dict):
            return term_val
        for curie_term in CURIE_TERMS:
            curie_val = term_val.get(curie_term)
            if isinstance(curie_val, str):
                term_val[curie_term] = expand_uri(curie_val, ctx_stack)
        term_ctx = term_val.get('@context')
        if term_ctx:
            term_val['@context'] = resolve_inner(term_ctx, ctx_stack).context
        return term_val

    def resolve_inner(inner_ctx, ctx_stack=None) -> ResolvedContext | None:
        resolved = None
        if isinstance(inner_ctx, Path) or (isinstance(inner_ctx, str) and not is_url(inner_ctx)):
            resolved = resolve_context(load_yaml(filename=ctx).get('@context'))
        elif isinstance(inner_ctx, str):
            r = requests_session.get(ctx)
            r.raise_for_status()
            fetched = r.json().get('@context')
            if fetched:
                resolved = resolve_context(fetched)
        elif isinstance(inner_ctx, Sequence):
            resolved_ctx = {}
            inner_prefixes = {}
            for ctx_entry in inner_ctx:
                resolved_entry = resolve_context(ctx_entry)
                inner_prefixes.update(resolved_entry.prefixes)
                resolved = ResolvedContext(merge_dicts(resolved_entry.context, resolved_ctx), inner_prefixes)
        else:
            if '@context' in inner_ctx:
                inner_ctx = inner_ctx['@context']
            resolved = ResolvedContext(inner_ctx, {})

        if not resolved or not resolved.context:
            return resolved

        if not ctx_stack:
            ctx_stack = [resolved.context]
        else:
            ctx_stack = ctx_stack + [resolved.context]

        for term in resolved.context.keys():
            term_val = resolved.context[term]
            resolved.context[term] = resolve_prop(term_val, ctx_stack)

        return resolved

    resolved_inner = resolve_inner(ctx)
    if not resolved_inner:
        return ResolvedContext()
    for p, puri in resolved_inner.prefixes.items():
        if p not in prefixes:
            prefixes[p] = puri

    return ResolvedContext(context=resolved_inner.context, prefixes=prefixes)


def validate_schema(schema: Any):
    jsonschema.validators.validator_for(schema).check_schema(schema)


class SchemaAnnotator:
    """
    Builds a set of annotated JSON schemas from a collection of input schemas
    that have `x-jsonld-context`s to JSON-LD context documents.

    The results will be stored in the `schemas` property (a dictionary of
    schema-path-or-url -> AnnotatedSchema mappings).
    """

    def __init__(self, schema_resolver: SchemaResolver | None = None,
                 ref_mapper: Callable[[str, Any], str] | None = None,
                 ignore_existing: bool = False):
        """
        :schema_resolver: an optional SchemaResolver to resolve references
        :ref_mapper: an optional function to map JSON `$ref`'s before resolving them
        """
        self.schema_resolver = schema_resolver or SchemaResolver()
        self._ref_mapper = ref_mapper
        self.ignore_existing = ignore_existing

    def process_schema(self, location: Path | str | None,
                       default_context: str | Path | dict | None = None,
                       contents: dict | None = None) -> AnnotatedSchema | None:
        resolved_schema = self.schema_resolver.resolve_schema(location)
        if contents:
            # overriden
            schema = contents
        else:
            schema = resolved_schema.subschema

        if all(x not in schema for x in ('schema', 'openapi')):
            validate_schema(schema)

        context_fn = schema.get(ANNOTATION_CONTEXT)
        schema.pop(ANNOTATION_CONTEXT, None)

        context = {}
        prefixes = {}

        if default_context and (context_fn != default_context
                                or not (isinstance(context_fn, Path)
                                        and isinstance(default_context, Path)
                                        and default_context.resolve() == context_fn.resolve())):
            # Only load the provided context if it's different from the schema-referenced one
            resolved_default_context = resolve_context(default_context)
            context, prefixes = attrgetter('context', 'prefixes')(resolved_default_context)

        if context_fn:
            context_fn, fragment = self.schema_resolver.resolve_ref(context_fn, resolved_schema)
            schema_context = resolve_context(context_fn)

            context = merge_contexts(context, schema_context.context)
            prefixes = prefixes | schema_context.prefixes

        updated_refs: set[int] = set()

        def find_prop_context(prop, context_stack) -> dict | None:
            for ctx in reversed(context_stack):
                vocab = ctx.get('@vocab')
                if prop in ctx:
                    prop_ctx = ctx[prop]
                    if isinstance(prop_ctx, str):
                        if vocab and ':' not in prop_ctx and prop_ctx[0] != '@':
                            prop_ctx = f"{vocab}{prop_ctx}"
                        return {'@id': prop_ctx}
                    elif '@id' not in prop_ctx and not vocab:
                        raise ValueError(f'Missing @id for property {prop} in context {json.dumps(ctx, indent=2)}')
                    else:
                        result = {k: v for k, v in prop_ctx.items() if k.startswith('@')}
                        if vocab:
                            prop_id = result.get('@id')
                            if not prop_id:
                                result['@id'] = f"{vocab}{prop}"
                            elif ':' not in prop_id and prop_id[0] != '@':
                                result['@id'] = f"{vocab}{prop_id}"
                        return result
                elif '@vocab' in ctx:
                    return {'@id': f"{ctx['@vocab']}{prop}"}

        def process_properties(obj: dict, context_stack: list[dict[str, Any]],
                               from_schema: ReferencedSchema, level) -> Iterable[str]:

            properties: dict[str, dict] = obj.get('properties') if obj else None
            if not properties:
                return ()
            if not isinstance(properties, dict):
                raise ValueError('"properties" must be a dictionary')

            used_terms = set()
            for prop in list(properties.keys()):
                if prop[0] == '@':
                    # skip JSON-LD keywords
                    continue
                prop_value = properties[prop]

                if not isinstance(prop_value, dict):
                    continue

                for key in list(prop_value.keys()):
                    if self.ignore_existing and key.startswith(ANNOTATION_PREFIX):
                        prop_value.pop(key, None)

                prop_ctx = find_prop_context(prop, context_stack)
                if prop_ctx:
                    used_terms.add(prop)
                    prop_schema_ctx = {f"{ANNOTATION_PREFIX}{k[1:]}": v
                                       for k, v in prop_ctx.items()
                                       if k[0] == '@' and k != '@context'}
                    prop_ctx_base = prop_ctx.get('@context', {}).get('@base')
                    if prop_ctx_base:
                        prop_schema_ctx[ANNOTATION_BASE] = prop_ctx_base

                    if not prop_value or prop_value is True:
                        properties[prop] = prop_schema_ctx
                    else:
                        for k, v in prop_schema_ctx.items():
                            prop_value.setdefault(k, v)

                if prop_ctx and '@context' in prop_ctx:
                    prop_context_stack = context_stack + [prop_ctx['@context']]
                else:
                    prop_context_stack = context_stack
                used_terms.update(process_subschema(prop_value, prop_context_stack, from_schema, level))

            return used_terms

        def process_subschema(subschema, context_stack, from_schema: ReferencedSchema, level=1) -> Iterable[str]:
            if not subschema or not isinstance(subschema, dict):
                return ()

            used_terms = set()

            if '$ref' in subschema and id(subschema) not in updated_refs:
                if self._ref_mapper:
                    subschema['$ref'] = self._ref_mapper(subschema['$ref'], subschema)
                if subschema['$ref'].startswith('#/') or subschema['$ref'].startswith(f"{from_schema.location}#/"):
                    target_schema = self.schema_resolver.resolve_schema(subschema['$ref'], from_schema)
                    if target_schema:
                        used_terms.update(process_subschema(target_schema.subschema, context_stack,
                                                            target_schema, level + 1))
                updated_refs.add(id(subschema))

            # Annotate oneOf, allOf, anyOf
            for p in ('oneOf', 'allOf', 'anyOf'):
                collection = subschema.get(p)
                if collection and isinstance(collection, list):
                    for entry in collection:
                        used_terms.update(process_subschema(entry, context_stack, from_schema, level + 1))

            # Annotate definitions and $defs
            for p in ('definitions', '$defs'):
                defs = subschema.get(p)
                if defs and isinstance(defs, dict):
                    for entry in defs.values():
                        used_terms.update(process_subschema(entry, context_stack, from_schema, level + 1))

            for p in ('then', 'else', 'additionalProperties'):
                branch = subschema.get(p)
                if branch and isinstance(branch, dict):
                    used_terms.update(process_subschema(branch, context_stack, from_schema, level))

            for pp in subschema.get('patternProperties', {}).values():
                if pp and isinstance(pp, dict):
                    used_terms.update(process_subschema(pp, context_stack, from_schema, level + 1))

            # Annotate main schema
            schema_type = subschema.get('type')
            if not schema_type and 'properties' in subschema:
                schema_type = 'object'

            if schema_type == 'object':
                used_terms.update(process_properties(subschema, context_stack, from_schema, level + 1))
            elif schema_type == 'array':
                for k in ('prefixItems', 'items', 'contains'):
                    used_terms.update(process_subschema(subschema.get(k), context_stack, from_schema, level + 1))

            # Get prefixes
            for p, bu in subschema.get(ANNOTATION_PREFIXES, {}).items():
                if p not in prefixes:
                    prefixes[p] = bu

            if len(context_stack) == level and context_stack[-1]:
                extra_terms = {}
                for k, v in context_stack[-1].items():
                    if k[0] != '@' and k not in prefixes and k not in used_terms:
                        if isinstance(v, dict):
                            if len(v) == 1 and '@id' in v:
                                v = v['@id']
                            else:
                                v = {f"{ANNOTATION_PREFIX}{vk[1:]}": vv for vk, vv in v.items() if vk[0] == '@'}
                        if isinstance(v, str) and v[-1] in ('#', '/', ':'):
                            prefixes[k] = v
                        else:
                            extra_terms[k] = v
                if extra_terms:
                    subschema.setdefault(ANNOTATION_EXTRA_TERMS, {}).update(extra_terms)

            return used_terms

        process_subschema(schema, [context], resolved_schema)

        if prefixes:
            schema[ANNOTATION_PREFIXES] = prefixes

        return AnnotatedSchema(
            source=location,
            is_json=resolved_schema.is_json,
            schema=schema
        )


class ContextBuilder:
    """
    Builds a JSON-LD context from a set of annotated JSON schemas.
    """

    def __init__(self, location: Path | str = None,
                 compact: bool = True,
                 schema_resolver: SchemaResolver = None,
                 version=1.1):
        """
        :param location: file or URL load the annotated schema from
        :param compact: whether to compact the resulting context (remove redundancies, compact CURIEs)
        :ref_mapper: an optional function to map JSON `$ref`'s before resolving them
        """
        self.context = {'@context': {}}
        self._parsed_schemas: dict[str | Path, dict] = {}

        self.schema_resolver = schema_resolver or SchemaResolver()

        self.location = location

        self.visited_properties: dict[str, str | None] = {}
        self._missed_properties: dict[str, Any] = {}  # Dict instead of set to keep order of insertion
        context = self._build_context(self.location, compact)
        if context:
            context['@version'] = version
        self.context = {'@context': context}

    def _build_context(self, schema_location: str | Path,
                       compact: bool = True) -> dict:

        parsed = self._parsed_schemas.get(schema_location)
        if parsed:
            return parsed

        root_schema = self.schema_resolver.resolve_schema(schema_location)

        prefixes = {}

        own_context = {}

        if prefixes:
            own_context.update(prefixes)

        def read_properties(subschema: dict, from_schema: ReferencedSchema,
                            onto_context: dict, schema_path: list[str]) -> dict | None:
            if schema_path:
                schema_path_str = '/' + '/'.join(schema_path)
            else:
                schema_path_str = ''
            if not isinstance(subschema, dict):
                return None
            if subschema.get('type', 'object') != 'object':
                return None
            for prop, prop_val in subschema.get('properties', {}).items():
                full_property_path = schema_path + [prop]
                full_property_path_str = f"{schema_path_str}/{prop}"
                self.visited_properties.setdefault(full_property_path_str, None)
                if from_schema == root_schema:
                    self._missed_properties.setdefault(full_property_path_str, True)
                if not isinstance(prop_val, dict):
                    continue
                prop_context = {'@context': {}}
                for term, term_val in prop_val.items():
                    if term == ANNOTATION_BASE:
                        prop_context.setdefault('@context', {})['@base'] = term_val
                    elif term.startswith(ANNOTATION_PREFIX) and term not in ANNOTATION_IGNORE_EXPAND:
                        if term == ANNOTATION_ID:
                            self.visited_properties[full_property_path_str] = term_val
                            self._missed_properties[full_property_path_str] = False
                        prop_context['@' + term[len(ANNOTATION_PREFIX):]] = term_val

                if isinstance(prop_context.get('@id'), str):
                    self.visited_properties[full_property_path_str] = prop_context['@id']
                    self._missed_properties[full_property_path_str] = False
                    if prop_context['@id'] == '@nest':
                        process_subschema(prop_val, from_schema, onto_context, full_property_path)
                    else:
                        process_subschema(prop_val, from_schema, prop_context['@context'], full_property_path)
                    if prop not in onto_context or isinstance(onto_context[prop], str):
                        onto_context[prop] = prop_context
                    else:
                        merge_contexts(onto_context[prop], prop_context)
                else:
                    process_subschema(prop_val, from_schema, onto_context, full_property_path)

        imported_prefixes: dict[str | Path, dict[str, str]] = {}
        imported_extra_terms: dict[str | Path, dict[str, str]] = {}

        def process_subschema(subschema: dict, from_schema: ReferencedSchema, onto_context: dict,
                              schema_path: list[str]) -> dict | None:

            if not isinstance(subschema, dict):
                return None

            if subschema.get(ANNOTATION_BASE):
                onto_context['@base'] = subschema[ANNOTATION_BASE]

            read_properties(subschema, from_schema, onto_context, schema_path)

            if '$ref' in subschema:
                ref = subschema['$ref']
                referenced_schema = self.schema_resolver.resolve_schema(ref, from_schema)
                if referenced_schema:
                    process_subschema(referenced_schema.subschema, referenced_schema, onto_context,
                                      schema_path)

            for i in ('allOf', 'anyOf', 'oneOf'):
                l = subschema.get(i)
                if isinstance(l, list):
                    for idx, sub_subschema in enumerate(l):
                        process_subschema(sub_subschema, from_schema, onto_context,
                                          schema_path)

            for i in ('prefixItems', 'items', 'contains', 'then', 'else', 'additionalProperties'):
                l = subschema.get(i)
                if isinstance(l, dict):
                    process_subschema(l, from_schema, onto_context, schema_path)

            for pp_k, pp in subschema.get('patternProperties', {}).items():
                if isinstance(pp, dict):
                    process_subschema(pp, from_schema, onto_context, schema_path + [pp_k])

            if ANNOTATION_EXTRA_TERMS in subschema:
                for extra_term, extra_term_context in subschema[ANNOTATION_EXTRA_TERMS].items():
                    if extra_term not in onto_context:
                        if isinstance(extra_term_context, dict):
                            extra_term_context = {f"@{k[len(ANNOTATION_PREFIX):]}": v
                                                  for k, v in extra_term_context.items()}
                        onto_context[extra_term] = extra_term_context

            if from_schema:
                current_ref = f"{from_schema.location}{from_schema.ref}"
                if current_ref not in imported_prefixes:
                    sub_prefixes = subschema.get(ANNOTATION_PREFIXES, {})
                    sub_prefixes |= from_schema.full_contents.get(ANNOTATION_PREFIXES, {})
                    if sub_prefixes:
                        imported_prefixes[current_ref] = sub_prefixes

                if current_ref not in imported_extra_terms:
                    sub_extra_terms = from_schema.full_contents.get(ANNOTATION_EXTRA_TERMS)
                    if sub_extra_terms:
                        imported_extra_terms[current_ref] = sub_extra_terms
            else:
                sub_prefixes = subschema.get(ANNOTATION_PREFIXES)
                if isinstance(sub_prefixes, dict):
                    prefixes.update({k: v for k, v in sub_prefixes.items() if k not in prefixes})

        process_subschema(root_schema.subschema, root_schema, own_context, [])

        for imported_et in imported_extra_terms.values():
            for term, v in imported_et.items():
                if term not in own_context:
                    if isinstance(v, dict):
                        v = {f"@{k[len(ANNOTATION_PREFIX):]}": val for k, val in v.items()}
                    own_context[term] = v

        for imported_prefix in imported_prefixes.values():
            for p, v in imported_prefix.items():
                if p not in prefixes:
                    prefixes[p] = v

        for prefix in list(prefixes.keys()):
            if prefix not in own_context:
                own_context[prefix] = {'@id': prefixes[prefix]}
            else:
                del prefixes[prefix]

        if compact:

            def compact_uri(uri: str) -> str:
                if uri.startswith('@'):
                    # JSON-LD keyword
                    return uri

                for pref, pref_uri in prefixes.items():
                    if uri.startswith(pref_uri) and len(pref_uri) < len(uri):
                        local_part = uri[len(pref_uri):]
                        if local_part.startswith('//'):
                            return uri
                        return f"{pref}:{local_part}"

                return uri

            def compact_branch(branch, context_stack=None) -> bool:
                child_context_stack = context_stack + [branch] if context_stack else [branch]
                terms = list(k for k in branch.keys() if k[0] != '@')

                changed = False
                for term in terms:
                    term_value = branch[term]

                    if isinstance(term_value, dict) and '@context' in term_value:
                        if not term_value['@context']:
                            del term_value['@context']
                        else:
                            while True:
                                if not compact_branch(term_value['@context'], child_context_stack):
                                    break

                    if context_stack:
                        for ctx in context_stack:
                            if term not in ctx:
                                continue
                            other = ctx[term]
                            if isinstance(term_value, str):
                                term_value = {'@id': term_value}
                            if isinstance(other, str):
                                other = {'@id': other}
                            if dict_contains(other, term_value):
                                del branch[term]
                                changed = True
                                break

                return changed

            def compact_uris(branch, context_stack=None):
                child_context_stack = context_stack + [branch] if context_stack else [branch]
                terms = list(k for k in branch.keys() if k[0] != '@')
                for term in terms:
                    term_value = branch.get(term)
                    if isinstance(term_value, str):
                        branch[term] = compact_uri(term_value)
                    elif isinstance(term_value, dict):
                        if '@id' in term_value:
                            term_value['@id'] = compact_uri(term_value['@id'])
                        if len(term_value) == 1 and '@id' in term_value:
                            branch[term] = term_value['@id']
                        elif '@context' in term_value:
                            compact_uris(term_value['@context'], child_context_stack)

            compact_branch(own_context)
            compact_uris(own_context)

        self._parsed_schemas[schema_location] = own_context
        return own_context

    @property
    def missed_properties(self):
        return [k for (k, v) in self._missed_properties.items() if v]


def dump_annotated_schema(schema: AnnotatedSchema, subdir: Path | str = 'annotated',
                          root_dir: Path | str | None = None,
                          output_fn_transform: Callable[[Path], Path] | None = None) -> None:
    """
    Creates a "mirror" directory (named `annotated` by default) with the resulting
    schemas annotated by a `SchemaAnnotator`.

    :param schema: the `AnnotatedSchema` to dump
    :param subdir: a name for the mirror directory
    :param root_dir: root directory for computing relative paths to schemas
    :param output_fn_transform: optional callable to transform the output path
    """
    wd = (Path(root_dir) if root_dir else Path()).resolve()
    subdir = subdir if isinstance(subdir, Path) else Path(subdir)
    path = schema.source
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
        logger.info(f'Writing output schema to {output_fn}')
        with open(output_fn, 'w') as f:
            json.dump(schema.schema, f, indent=2)
    else:
        dump_yaml(schema.schema, output_fn)


def _main():
    parser = argparse.ArgumentParser(
    )

    parser.add_argument(
        'schema',
        help='Entrypoint JSON Schema (filename or URL)',
    )

    parser.add_argument(
        '--context',
        required=False,
        help='Manually provided JSON-LD context (filename or URL)',
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
        '--dump-visited',
        help='Dump visited properties and their ids to a file',
    )

    parser.add_argument(
        '--ignore-existing',
        help="Ignore existing x-jsonld- properties when annotating",
        action='store_true',
    )

    args = parser.parse_args()

    if not args.schema:
        print('Error: no file and no URL provided', file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        sys.exit(2)

    if args.build_context or args.context_batch:
        ctx_builder = ContextBuilder(args.schema)
        if args.context_batch:
            fn = Path(args.file).with_suffix('.jsonld')
            with open(fn, 'w') as f:
                json.dump(ctx_builder.context, f, indent=2)
        else:
            print(json.dumps(ctx_builder.context, indent=2))
        if args.dump_visited:
            def write_visited(stream):
                writer = csv.writer(stream, delimiter='\t')
                writer.writerow(['path', '@id'])
                writer.writerows(ctx_builder.visited_properties.items())

            if args.dump_visited == '-':
                write_visited(sys.stdout)
            else:
                with open(args.dump_visited, 'w', newline='') as f:
                    write_visited(f)
    else:
        annotator = SchemaAnnotator(ignore_existing=args.ignore_existing)
        annotated = annotator.process_schema(args.schema, args.context)
        print(dump_yaml(annotated.schema))


if __name__ == '__main__':
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format='%(asctime)s,%(msecs)d %(levelname)-5s [%(filename)s:%(lineno)d] %(message)s',
    )

    _main()
