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
import copy
import dataclasses
import json
import logging
import re
import sys
from builtins import isinstance
from collections import deque
from operator import attrgetter
from pathlib import Path
from typing import Any, AnyStr, Callable, Sequence, Iterable
from urllib.parse import urlparse, urljoin

import jsonpointer
import jsonschema
import requests_cache

from ogc.na.exceptions import ContextLoadError, SchemaLoadError
from ogc.na.util import is_url, load_yaml, LRUCache, dump_yaml, \
    merge_contexts, merge_dicts, dict_contains, JSON_LD_KEYWORDS, UNDEFINED, prune_context, fix_nest

logger = logging.getLogger(__name__)

ANNOTATION_PREFIX = 'x-jsonld-'
ANNOTATION_CONTEXT = f'{ANNOTATION_PREFIX}context'
ANNOTATION_ID = f'{ANNOTATION_PREFIX}id'
ANNOTATION_PREFIXES = f'{ANNOTATION_PREFIX}prefixes'
ANNOTATION_EXTRA_TERMS = f'{ANNOTATION_PREFIX}extra-terms'
ANNOTATION_BASE = f'{ANNOTATION_PREFIX}base'
ANNOTATION_VOCAB = f'{ANNOTATION_PREFIX}vocab'

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
    anchors: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ResolvedContext:
    context: dict[str, Any] = dataclasses.field(default_factory=dict)
    prefixes: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ResolvedProperty:
    """
    A property encountered during ContextBuilder traversal, with its resolved
    semantic annotations and schema metadata merged across all $ref branches.
    """
    path: list[str]
    id: str | None
    jsonld_type: str | list[str] | None
    vocab: str | None
    title: str | None
    description: str | None
    required: bool
    schema_type: str | list[str] | None = None
    format: str | None = None
    enum: list | None = None
    deprecated: bool = False
    read_only: bool = False
    write_only: bool = False
    sources: list[str | Path] = dataclasses.field(default_factory=list)
    keyword: str | None = None
    ref: str | None = None

    @property
    def effective_id(self) -> str | None:
        """Explicit @id, or vocab + property name if under @vocab."""
        if self.id:
            return self.id
        if self.vocab and self.path:
            return self.vocab + self.path[-1]
        return None

    @staticmethod
    def _normalize_type(t: str | list[str] | None) -> set[str] | None:
        if t is None:
            return None
        return {t} if isinstance(t, str) else set(t)

    @staticmethod
    def _pack_type(s: set[str]) -> str | list[str] | None:
        if not s:
            return None  # empty intersection = incompatible types
        if len(s) == 1:
            return next(iter(s))
        return sorted(s)

    def merge(self, other: ResolvedProperty) -> None:
        """Merge another occurrence of the same property path into this one."""
        if self.id is None:
            self.id = other.id
        if self.jsonld_type is None:
            self.jsonld_type = other.jsonld_type
        if self.vocab is None:
            self.vocab = other.vocab
        if self.title is None:
            self.title = other.title
        if self.description is None:
            self.description = other.description
        if self.format is None:
            self.format = other.format
        a, b = self._normalize_type(self.schema_type), self._normalize_type(other.schema_type)
        if a is None:
            self.schema_type = other.schema_type
        elif b is not None:
            self.schema_type = self._pack_type(a & b)
        if self.enum is None:
            self.enum = other.enum
        elif other.enum is not None:
            other_set = set(other.enum)
            self.enum = [v for v in self.enum if v in other_set]
        self.required = self.required or other.required
        self.deprecated = self.deprecated or other.deprecated
        self.read_only = self.read_only or other.read_only
        self.write_only = self.write_only or other.write_only
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)


class SchemaResolver:

    def __init__(self, working_directory=Path()):
        self.working_directory = working_directory.absolute()
        self._schema_cache: dict[str | Path, Any] = {}

    @staticmethod
    def _get_branch(schema: dict, ref: str, anchors: dict[str, Any] = None):
        ref = re.sub('^#', '', ref)
        if anchors and ref in anchors:
            return anchors[ref]
        if not ref.startswith('/'):
             raise ValueError(f'Invalid anchor reference: #{ref}')
        return jsonpointer.resolve_pointer(schema, ref)

    @staticmethod
    def _find_anchors(schema: dict) -> dict[str, Any]:
        anchors = {}

        pending = deque((schema,))
        while pending:
            current = pending.popleft()
            if isinstance(current, dict):
                if '$anchor' in current:
                    anchors[current['$anchor']] = current
                pending.extend(current.values())
            elif isinstance(current, list):
                pending.extend(current)

        return anchors

    def load_contents(self, s: str | Path) -> tuple[dict, bool]:
        """
        Load the contents of a schema. Can be overriden by subclasses to alter the loading process.
        """
        contents = self._schema_cache.get(s)
        if contents is None:
            try:
                contents = read_contents(s)[0]
                self._schema_cache[s] = contents
            except Exception as e:
                raise SchemaLoadError(f'Error loading schema from schema source "{s}"') from e
        return load_json_yaml(contents)

    def resolve_ref(self, ref: str | Path, from_schema: ReferencedSchema | None = None) -> tuple[Path | str, str]:
        location = ref
        fragment = None
        if isinstance(location, str):
            s = location.split('#', 1)
            fragment = s[1] if len(s) > 1 else None
            location = s[0]
            if not location:
                return from_schema.location if from_schema else location, fragment
            if not is_url(location):
                location = Path(location)

        if isinstance(location, Path):
            if location.is_absolute():
                location = location.absolute()
            elif not from_schema:
                location = self.working_directory.joinpath(location).absolute()
            elif from_schema.full_contents.get('$id'):
                location = urljoin(from_schema.full_contents['$id'], str(location))
            elif not isinstance(from_schema.location, Path):
                location = urljoin(from_schema.location, str(location))
            else:
                location = from_schema.location.absolute().parent.joinpath(location).absolute()

        if location is None:
            raise ValueError(f'Unexpected ref type {type(ref).__name__}')

        return location, fragment

    def resolve_schema(self, ref: str | Path, from_schema: ReferencedSchema | None = None,
                       force_contents: dict | str | None = None, return_none_on_loop=True) -> ReferencedSchema | None:
        chain = from_schema.chain + [from_schema] if from_schema else []
        try:
            schema_source, fragment = self.resolve_ref(ref, from_schema)
            if from_schema and return_none_on_loop:
                for ancestor in from_schema.chain:
                    if (not schema_source or ancestor.location == schema_source) and ancestor.fragment == fragment:
                        return None

            if not schema_source:
                if not from_schema:
                    raise ValueError('Local ref provided without an anchor: ' + ref)
                return ReferencedSchema(location=from_schema.location,
                                        fragment=ref[1:],
                                        subschema=SchemaResolver._get_branch(from_schema.full_contents, ref,
                                                                             from_schema.anchors),
                                        full_contents=from_schema.full_contents,
                                        chain=chain,
                                        ref=ref,
                                        is_json=from_schema.is_json,
                                        anchors=from_schema.anchors)
            if force_contents:
                is_json = False
                if isinstance(force_contents, str):
                    try:
                        contents = load_yaml(content=force_contents)
                    except Exception as e:
                        raise SchemaLoadError('Error loading schema from string contents') from e
                else:
                    contents = force_contents
            elif from_schema and schema_source == from_schema.location:
                contents, is_json = from_schema.full_contents, from_schema.is_json
            else:
                contents, is_json = self.load_contents(schema_source)
            anchors = SchemaResolver._find_anchors(contents)
            if fragment:
                return ReferencedSchema(location=schema_source, fragment=fragment,
                                        subschema=SchemaResolver._get_branch(contents, fragment, anchors),
                                        full_contents=contents,
                                        chain=chain,
                                        ref=ref,
                                        is_json=is_json,
                                        anchors=anchors)
            else:
                return ReferencedSchema(location=schema_source,
                                        subschema=contents,
                                        full_contents=contents,
                                        chain=chain,
                                        ref=ref,
                                        is_json=is_json,
                                        anchors=anchors)
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
        ref = (fn_from.absolute().parent / ref).absolute()
        return ref, None


def resolve_context(ctx: Path | str | dict | list, expand_uris=True,
                    _base_path: Path | None = None) -> ResolvedContext:
    if not ctx:
        return ResolvedContext()

    prefixes = {}

    def expand_uri(curie, ctx_stack):
        if not expand_uris or not ctx_stack or not curie or curie in JSON_LD_KEYWORDS:
            return curie
        if ':' in curie:
            prefix, localpart = curie.split(':', 1)
        else:
            prefix, localpart = None, None

        vocab = UNDEFINED
        for c in reversed(ctx_stack):
            if localpart:
                # prefix:localpart format
                if prefix in c:
                    term_val = c[prefix]
                    prefix_uri = term_val if isinstance(term_val, str) else term_val.get('@id')
                    prefixes[prefix] = prefix_uri
                    return f"{prefix_uri}{localpart}"

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
            try:
                if not isinstance(inner_ctx, Path):
                    inner_ctx = Path(inner_ctx)
                if not inner_ctx.is_absolute() and _base_path:
                    inner_ctx = (_base_path / inner_ctx).resolve()
                file_base_path = inner_ctx.resolve().parent
                resolved = resolve_context(load_yaml(filename=inner_ctx).get('@context'),
                                           expand_uris=expand_uris, _base_path=file_base_path)
            except Exception as e:
                raise ContextLoadError(f'Error resolving context document in file "{inner_ctx}"') from e
        elif isinstance(inner_ctx, str):
            try:
                r = requests_session.get(inner_ctx)
                r.raise_for_status()
                fetched = r.json().get('@context')
                if fetched:
                    resolved = resolve_context(fetched)
            except Exception as e:
                raise ContextLoadError(f'Error resolving context document at URL "{inner_ctx}"') from e

        elif isinstance(inner_ctx, Sequence):
            resolved_ctx = {}
            inner_prefixes = {}
            for ctx_entry in inner_ctx:
                if isinstance(ctx_entry, dict):
                    # Array entries must be wrapped with @context
                    resolved_entry = resolve_context({'@context': ctx_entry}, _base_path=_base_path)
                else:
                    resolved_entry = resolve_context(ctx_entry, _base_path=_base_path)
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
        resolved_schema = self.schema_resolver.resolve_schema(location, force_contents=contents)
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
                                        and default_context.absolute() == context_fn.absolute())):
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
                if prop in ctx:
                    prop_ctx = ctx[prop]
                    if isinstance(prop_ctx, str):
                        return {'@id': prop_ctx}
                    elif '@id' not in prop_ctx and '@reverse' not in prop_ctx:
                        raise ValueError(f'Missing @id for property {prop} in context {json.dumps(ctx, indent=2)}')
                    else:
                        result = {k: v for k, v in prop_ctx.items() if k in JSON_LD_KEYWORDS}
                        return result

        def process_properties(obj: dict, context_stack: list[dict[str, Any]],
                               from_schema: ReferencedSchema, level) -> Iterable[str]:

            properties: dict[str, dict] = obj.get('properties') if obj else None
            if not properties:
                return ()
            if not isinstance(properties, dict):
                raise ValueError('"properties" must be a dictionary')

            used_terms = set()
            for prop in list(properties.keys()):
                if prop in JSON_LD_KEYWORDS:
                    # skip JSON-LD keywords
                    continue
                prop_value = properties[prop]

                if isinstance(prop_value, bool):
                    prop_value = {} if prop_value else {'not': True}
                    properties[prop] = prop_value
                elif not isinstance(prop_value, dict):
                    continue

                for key in list(prop_value.keys()):
                    if self.ignore_existing and key.startswith(ANNOTATION_PREFIX):
                        prop_value.pop(key, None)

                prop_ctx = find_prop_context(prop, context_stack)
                if prop_ctx:
                    used_terms.add(prop)
                    prop_schema_ctx = {f"{ANNOTATION_PREFIX}{k[1:]}": v
                                       for k, v in prop_ctx.items()
                                       if k in JSON_LD_KEYWORDS and k != '@context'}
                    inner_ctx = prop_ctx.get('@context') if isinstance(prop_ctx.get('@context'), dict) else {}
                    prop_ctx_base = inner_ctx.get('@base')
                    if prop_ctx_base:
                        prop_schema_ctx[ANNOTATION_BASE] = prop_ctx_base
                    if '@vocab' in inner_ctx:
                        prop_schema_ctx[ANNOTATION_VOCAB] = inner_ctx['@vocab']

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

        def process_subschema(subschema, context_stack, from_schema: ReferencedSchema, level=1,
                              in_defs=False) -> Iterable[str]:
            if not subschema or not isinstance(subschema, dict):
                return ()

            used_terms = set()

            # Annotate definitions and $defs - can later be overridden if referenced from a different path
            for p in ('definitions', '$defs'):
                defs = subschema.get(p)
                if defs and isinstance(defs, dict):
                    for entry in defs.values():
                        # Do not add to used_terms if only used in $defs
                        process_subschema(entry, context_stack, from_schema, level + 1, in_defs=True)

            if '$ref' in subschema and id(subschema) not in updated_refs:
                if self._ref_mapper:
                    subschema['$ref'] = self._ref_mapper(subschema['$ref'], subschema)
                if subschema['$ref'].startswith('#/') or subschema['$ref'].startswith(f"{from_schema.location}#/"):
                    target_schema = self.schema_resolver.resolve_schema(subschema['$ref'], from_schema)
                    if target_schema:
                        new_terms = process_subschema(target_schema.subschema, context_stack,
                                                            target_schema, level + 1, in_defs=in_defs)
                        if not in_defs:
                            used_terms.update(new_terms)
                updated_refs.add(id(subschema))

            # Annotate oneOf, allOf, anyOf
            for p in ('oneOf', 'allOf', 'anyOf'):
                collection = subschema.get(p)
                if collection and isinstance(collection, list):
                    for entry in collection:
                        new_terms = process_subschema(entry, context_stack, from_schema, level + 1, in_defs=in_defs)
                        if not in_defs:
                            used_terms.update(new_terms)

            for p in ('then', 'else', 'additionalProperties', 'unevaluatedProperties'):
                branch = subschema.get(p)
                if branch and isinstance(branch, dict):
                    new_terms = process_subschema(branch, context_stack, from_schema, level, in_defs=in_defs)
                    if not in_defs:
                        used_terms.update(new_terms)

            for pp in subschema.get('patternProperties', {}).values():
                if pp and isinstance(pp, dict):
                    new_terms = process_subschema(pp, context_stack, from_schema, level + 1, in_defs=in_defs)
                    if not in_defs:
                        used_terms.update(new_terms)

            # Annotate main schema
            schema_type = subschema.get('type')
            if not schema_type and 'properties' in subschema:
                schema_type = 'object'

            if schema_type == 'object':
                new_terms = process_properties(subschema, context_stack, from_schema, level + 1)
                if not in_defs:
                    used_terms.update(new_terms)
            elif schema_type == 'array':
                for k in ('prefixItems', 'items', 'contains'):
                    new_terms = process_subschema(subschema.get(k), context_stack, from_schema, level + 1,
                                                  in_defs=in_defs)
                    if not in_defs:
                        used_terms.update(new_terms)

            # Get prefixes
            for p, bu in subschema.get(ANNOTATION_PREFIXES, {}).items():
                if p not in prefixes:
                    prefixes[p] = bu

            if len(context_stack) == level and context_stack[-1]:
                extra_terms = {}
                for k, v in context_stack[-1].items():
                    if k not in JSON_LD_KEYWORDS and k not in prefixes and k not in used_terms:
                        if isinstance(v, dict):
                            if len(v) == 1 and '@id' in v:
                                v = v['@id']
                            else:
                                v = {f"{ANNOTATION_PREFIX}{vk[1:]}": vv
                                     for vk, vv in v.items()
                                     if vk in JSON_LD_KEYWORDS}
                        if isinstance(v, str) and v[-1] in ('#', '/', ':'):
                            prefixes[k] = v
                        else:
                            extra_terms[k] = v
                if extra_terms:
                    subschema.setdefault(ANNOTATION_EXTRA_TERMS, {}).update(extra_terms)

            return used_terms

        process_subschema(schema, [context], resolved_schema)

        for key in ('@base', '@vocab'):
            if context.get(key):
                schema[f"{ANNOTATION_PREFIX}{key[1:]}"] = context[key]

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

    def __init__(self, location: Path | str,
                 schema_resolver: SchemaResolver = None,
                 contents: dict | str | None = None,
                 version=1.1):
        """
        :param location: file or URL to load the annotated schema from
        :param schema_resolver: an optional SchemaResolver to resolve references
        :param contents: optional schema contents (overrides loading from location)
        :param version: JSON-LD @version to set on the generated context (default: 1.1)
        """
        self.context = {'@context': {}}
        self._parsed_schemas: dict[str | Path, dict] = {}

        self.schema_resolver = schema_resolver or SchemaResolver()

        self.location = location

        self.visited_properties: dict[str, tuple[str | None, str]] = {}
        self._missed_properties: dict[str, Any] = {}  # Dict instead of set to keep order of insertion
        self._resolved_properties: dict[str, ResolvedProperty] = {}
        self._resolved_property_defs: dict[str, list[ResolvedProperty]] = {}
        context = self._build_context(self.location, contents=contents)
        if context:
            context['@version'] = version
        self.context = {'@context': context}

    def _build_context(self, schema_location: str | Path,
                       contents: dict | str | None = None) -> dict:

        parsed = self._parsed_schemas.get(schema_location)
        if parsed:
            return parsed

        root_schema = self.schema_resolver.resolve_schema(schema_location, force_contents=contents)

        prefixes = {}

        own_context = {}

        def read_properties(subschema: dict, from_schema: ReferencedSchema,
                            onto_context: dict, schema_path: list[str],
                            is_vocab=False, current_vocab: str | None = None) -> dict | None:
            if schema_path:
                schema_path_str = '/' + '/'.join(schema_path)
            else:
                schema_path_str = ''
            if not isinstance(subschema, dict):
                return None
            schema_type = subschema.get('type')
            if schema_type and schema_type != 'object' and not (isinstance(schema_type, list) and 'object' in schema_type):
                return None
            for prop, prop_val in subschema.get('properties', {}).items():
                if prop in JSON_LD_KEYWORDS:
                    # Skip reserved JSON-LD keywords
                    continue
                full_property_path = schema_path + [prop]
                full_property_path_str = f"{schema_path_str}/{prop}"
                path_key = '\x00'.join(full_property_path)
                self.visited_properties.setdefault(full_property_path_str, (None, from_schema.location))
                if from_schema == root_schema:
                    self._missed_properties.setdefault(full_property_path_str, True)
                if not isinstance(prop_val, dict):
                    continue
                prop_context: dict[str, Any] = {'@context': {}}
                new_vocab = is_vocab
                for term, term_val in prop_val.items():
                    if term == ANNOTATION_BASE:
                        prop_context.setdefault('@context', {})['@base'] = term_val
                    elif term == ANNOTATION_VOCAB:
                        new_vocab = term_val is not None
                        prop_context.setdefault('@context', {})['@vocab'] = term_val
                    elif term.startswith(ANNOTATION_PREFIX) and term not in ANNOTATION_IGNORE_EXPAND:
                        if term == ANNOTATION_ID:
                            self.visited_properties[full_property_path_str] = (term_val, from_schema.location)
                            self._missed_properties[full_property_path_str] = False
                        prop_context['@' + term[len(ANNOTATION_PREFIX):]] = term_val

                if isinstance(prop_context.get('@id'), str) or isinstance(prop_context.get('@reverse'), str):
                    prop_id_value = prop_context.get('@id', prop_context.get('@reverse'))
                    self.visited_properties[full_property_path_str] = (prop_id_value, from_schema.location)
                    self._missed_properties[full_property_path_str] = False
                else:
                    prop_id_value = UNDEFINED

                resolved = ResolvedProperty(
                    path=full_property_path,
                    id=prop_id_value if prop_id_value is not UNDEFINED else None,
                    jsonld_type=prop_context.get('@type'),
                    vocab=current_vocab,
                    title=prop_val.get('title'),
                    description=prop_val.get('description'),
                    required=prop in subschema.get('required', []),
                    schema_type=prop_val.get('type'),
                    format=prop_val.get('format'),
                    enum=prop_val.get('enum'),
                    deprecated=bool(prop_val.get('deprecated', False)),
                    read_only=bool(prop_val.get('readOnly', False)),
                    write_only=bool(prop_val.get('writeOnly', False)),
                    sources=[from_schema.location],
                )
                if path_key in self._resolved_properties:
                    self._resolved_properties[path_key].merge(resolved)
                else:
                    self._resolved_properties[path_key] = resolved

                if (prop_id_value in ('@nest', '@graph')
                        or (prop_id_value == UNDEFINED and from_schema == root_schema)
                        or (not prop_id_value and is_vocab)):
                    if prop_id_value == UNDEFINED or (not prop_id_value and is_vocab):
                        prop_context.pop('@id', None)
                    merge_contexts(prop_context['@context'] if is_vocab else onto_context,
                                   process_subschema(prop_val, from_schema,
                                                     full_property_path, is_vocab=new_vocab,
                                                     local_refs_only='@id' not in prop_context and not is_vocab))
                else:
                    merge_contexts(prop_context['@context'],
                                   process_subschema(prop_val, from_schema,
                                                     full_property_path, is_vocab=new_vocab,
                                                     local_refs_only='@id' not in prop_context))
                if prop_context and ('@context' not in prop_context
                                     or ('@context' in prop_context
                                         and (len(prop_context) > 1 or prop_context['@context']))):
                    if prop not in onto_context:
                        onto_context[prop] = prop_context
                    elif isinstance(onto_context[prop], str):
                        onto_context[prop] = {
                            '@id': prop_context.pop('@id', prop_id_value or onto_context[prop]),
                            **prop_context,
                        }
                    else:
                        merge_contexts(onto_context[prop], prop_context)

        imported_prefixes: dict[str | Path, dict[str, str]] = {}
        imported_extra_terms: dict[str | Path, dict[str, str]] = {}

        cached_schema_contexts = {}
        cached_schema_paths: dict[str, list[str]] = {}
        copy_log: list[tuple[list[str], list[str], str]] = []

        # ------------------------------------------------------------------

        def copy_resolved_props(src_path: list[str], dst_path: list[str]) -> None:
            """
            Copy all ResolvedProperty entries rooted at *src_path* to *dst_path*.
            Fallback for $ref cache-hits at unnamed nodes (allOf / root) where there
            is no rp entry to hang a `ref` pointer on.
            """
            if src_path == dst_path:
                return
            sep = '\x00'
            src_len = len(src_path)
            for k, v in list(self._resolved_properties.items()):
                if len(v.path) > src_len and v.path[:src_len] == src_path:
                    new_path = dst_path + v.path[src_len:]
                    new_key = sep.join(new_path)
                    if new_key in self._resolved_properties:
                        merged = copy.deepcopy(v)
                        merged.path = new_path
                        self._resolved_properties[new_key].merge(merged)
                    else:
                        new_rp = copy.deepcopy(v)
                        new_rp.path = new_path
                        self._resolved_properties[new_key] = new_rp

        # ------------------------------------------------------------------

        def process_subschema(subschema: dict, from_schema: ReferencedSchema,
                              schema_path: list[str], is_vocab=False, local_refs_only=False,
                              current_vocab: str | None = None) -> dict:

            onto_context = {}

            if not isinstance(subschema, dict):
                return {}

            for key in (ANNOTATION_BASE, ANNOTATION_VOCAB):
                top_level_value = subschema.get(key)
                if top_level_value:
                    onto_context[f"@{key[len(ANNOTATION_PREFIX):]}"] = top_level_value
            if ANNOTATION_VOCAB in subschema:
                is_vocab = subschema[ANNOTATION_VOCAB] is not None
                current_vocab = subschema[ANNOTATION_VOCAB]
            else:
                is_vocab = is_vocab or bool(onto_context.get('@vocab'))
            if is_vocab:
                local_refs_only = False

            if '$ref' in subschema:
                ref = subschema['$ref']
                if not local_refs_only or ref.startswith('#'):
                    referenced_schema = self.schema_resolver.resolve_schema(ref, from_schema)
                    if referenced_schema:
                        cache_key = f"{referenced_schema.location}#{referenced_schema.fragment}"
                        ref_ctx = copy.deepcopy(cached_schema_contexts.get(cache_key))
                        if ref_ctx is None:
                            cached_schema_paths[cache_key] = schema_path
                            ref_ctx = process_subschema(referenced_schema.subschema,
                                                        referenced_schema, schema_path,
                                                        is_vocab=is_vocab, local_refs_only=local_refs_only,
                                                        current_vocab=current_vocab)
                        else:
                            if cache_key in cached_schema_paths:
                                src = cached_schema_paths[cache_key]
                                copy_resolved_props(src, schema_path)
                                copy_log.append((list(src), list(schema_path), cache_key))
                        merge_contexts(onto_context, ref_ctx)
                else:
                    # local_refs_only blocks this ref's context contribution, but we still
                    # traverse it so that resolved_properties captures its properties.
                    referenced_schema = self.schema_resolver.resolve_schema(ref, from_schema)
                    if referenced_schema:
                        process_subschema(referenced_schema.subschema, referenced_schema, schema_path,
                                          is_vocab=is_vocab, local_refs_only=False,
                                          current_vocab=current_vocab)
                        # result intentionally discarded: no context contribution

            # allOf: merge into current path (additive composition, no branch node)
            allof = subschema.get('allOf')
            if isinstance(allof, list):
                for sub_subschema in allof:
                    merge_contexts(onto_context,
                                   process_subschema(sub_subschema, from_schema,
                                                     schema_path, is_vocab=is_vocab,
                                                     local_refs_only=local_refs_only,
                                                     current_vocab=current_vocab))

            # anyOf / oneOf: group node for the keyword + a virtual node per branch
            for kw in ('anyOf', 'oneOf'):
                branches = subschema.get(kw)
                if not isinstance(branches, list):
                    continue
                # Single branch: no visual value, treat like allOf
                if len(branches) == 1:
                    merge_contexts(onto_context,
                                   process_subschema(branches[0], from_schema,
                                                     schema_path, is_vocab=is_vocab,
                                                     local_refs_only=local_refs_only,
                                                     current_vocab=current_vocab))
                    continue
                group_path = schema_path + [f'_{kw}']
                group_key = '\x00'.join(group_path)
                if group_key not in self._resolved_properties:
                    self._resolved_properties[group_key] = ResolvedProperty(
                        path=group_path,
                        id=None, jsonld_type=None, vocab=None,
                        title=None, description=None,
                        required=False, keyword=kw,
                        sources=[from_schema.location],
                    )
                for idx, branch_schema in enumerate(branches):
                    branch_path = group_path + [str(idx)]
                    branch_key = '\x00'.join(branch_path)
                    if branch_key not in self._resolved_properties:
                        branch_title = None
                        if isinstance(branch_schema, dict):
                            branch_title = branch_schema.get('title')
                        if not branch_title:
                            branch_title = chr(ord('a') + idx) if idx < 26 else str(idx)
                        self._resolved_properties[branch_key] = ResolvedProperty(
                            path=branch_path,
                            id=None, jsonld_type=None, vocab=None,
                            title=branch_title, description=None,
                            required=False, keyword='branch',
                            sources=[from_schema.location],
                        )
                    merge_contexts(onto_context,
                                   process_subschema(branch_schema, from_schema,
                                                     branch_path, is_vocab=is_vocab,
                                                     local_refs_only=local_refs_only,
                                                     current_vocab=current_vocab))

            for i in ('prefixItems', 'items', 'contains', 'additionalProperties', 'unevaluatedProperties'):
                l = subschema.get(i)
                if isinstance(l, dict):
                    merge_contexts(onto_context, process_subschema(l, from_schema,
                                                                   schema_path, is_vocab=is_vocab,
                                                                   local_refs_only=local_refs_only,
                                                                   current_vocab=current_vocab))

            # then / else: each gets a virtual node (if is ignored as per design)
            for kw in ('then', 'else'):
                branch_schema = subschema.get(kw)
                if not isinstance(branch_schema, dict):
                    continue
                branch_path = schema_path + [f'_{kw}']
                path_key = '\x00'.join(branch_path)
                if path_key not in self._resolved_properties:
                    branch_title = branch_schema.get('title')
                    self._resolved_properties[path_key] = ResolvedProperty(
                        path=branch_path,
                        id=None, jsonld_type=None, vocab=None,
                        title=branch_title, description=None,
                        required=False, keyword=kw,
                        sources=[from_schema.location],
                    )
                merge_contexts(onto_context,
                               process_subschema(branch_schema, from_schema,
                                                 branch_path, is_vocab=is_vocab,
                                                 local_refs_only=local_refs_only,
                                                 current_vocab=current_vocab))

            for pp_k, pp in subschema.get('patternProperties', {}).items():
                if isinstance(pp, dict):
                    merge_contexts(onto_context, process_subschema(pp, from_schema,
                                                                   schema_path + [pp_k],
                                                                   is_vocab=is_vocab,
                                                                   local_refs_only=local_refs_only,
                                                                   current_vocab=current_vocab))

            if ANNOTATION_EXTRA_TERMS in subschema:
                for extra_term, extra_term_context in subschema[ANNOTATION_EXTRA_TERMS].items():
                    if (extra_term not in onto_context
                        or onto_context[extra_term] is UNDEFINED
                        or (isinstance(onto_context[extra_term], dict)
                            and onto_context[extra_term].get('@id') is UNDEFINED)):
                        if isinstance(extra_term_context, dict):
                            extra_term_context = {f"@{k[len(ANNOTATION_PREFIX):]}": v
                                                  for k, v in extra_term_context.items()}
                        onto_context[extra_term] = extra_term_context

            read_properties(subschema, from_schema, onto_context, schema_path, is_vocab=is_vocab,
                            current_vocab=current_vocab)

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

            cached_schema_contexts[f"{from_schema.location}#{from_schema.fragment}"] = onto_context
            return onto_context

        merge_contexts(own_context, process_subschema(root_schema.subschema, root_schema, []))
        self._hoist_common_branch_properties()
        self._dedup_to_defs(copy_log)

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

        prune_context(own_context)
        fix_nest(own_context)

        def compact_uri(uri: str) -> str:
            if uri in JSON_LD_KEYWORDS:
                # JSON-LD keyword
                return uri

            for pref, pref_uri in prefixes.items():
                if uri.startswith(pref_uri) and len(pref_uri) < len(uri):
                    local_part = uri[len(pref_uri):]
                    if local_part.startswith('//'):
                        return uri
                    return f"{pref}:{local_part}"

            return uri

        def compact_branch(branch, context_stack=None, is_vocab=False) -> bool:
            is_vocab = is_vocab or bool(branch.get('@vocab'))
            child_context_stack = context_stack + [branch] if context_stack else [branch]
            terms = list(k for k in branch.keys() if k not in JSON_LD_KEYWORDS)

            changed = False
            for term in terms:
                term_value = branch[term]

                if isinstance(term_value, dict) and not term_value:
                    branch.pop(term, None)
                    changed = True
                    continue

                if isinstance(term_value, dict) and '@context' in term_value:
                    if not term_value['@context']:
                        term_value.pop('@context', None)
                        changed = True
                    elif is_vocab or term_value.get('@id', term_value.get('@reverse')):
                        term_is_vocab = (is_vocab
                                         and ('@vocab' not in term_value['@context']
                                              or term_value['@context']['@vocab'] is not None))
                        while True:
                            if not compact_branch(term_value['@context'],
                                                  child_context_stack,
                                                  is_vocab=term_is_vocab):
                                break
                            else:
                                changed = True
                    else:
                        # Context branch without an @id - remove
                        branch.pop(term, None)
                        changed = True
                        continue

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
                            branch.pop(term, None)
                            changed = True
                            break

            return changed

        def compact_uris(branch, context_stack=None):
            child_context_stack = context_stack + [branch] if context_stack else [branch]
            terms = list(k for k in branch.keys() if k not in JSON_LD_KEYWORDS)
            for term in terms:
                term_value = branch.get(term)
                if isinstance(term_value, str):
                    branch[term] = compact_uri(term_value)
                elif isinstance(term_value, dict):
                    for k in CURIE_TERMS:
                        if k in term_value:
                            term_value[k] = compact_uri(term_value[k])
                    if len(term_value) == 1 and '@id' in term_value:
                        branch[term] = term_value['@id']
                    elif '@context' in term_value:
                        compact_uris(term_value['@context'], child_context_stack)

        while True:
            if not compact_branch(own_context):
                break
        compact_uris(own_context)

        self._parsed_schemas[schema_location] = own_context
        return own_context

    def _hoist_common_branch_properties(self) -> None:
        """
        For each anyOf/oneOf group node, find leaf properties that appear in every
        branch with compatible definitions and move them to the parent scope.
        Empty branch/group nodes are removed afterwards.
        """
        rp = self._resolved_properties
        sep = '\x00'

        # Build parent→children index for O(1) lookups instead of O(N) scans.
        # children[parent_key] = {child_name: child_key}
        children: dict[str, dict[str, str]] = {}
        for k, v in rp.items():
            if v.path:
                pk = sep.join(v.path[:-1])
                children.setdefault(pk, {})[v.path[-1]] = k

        def _del(k: str) -> ResolvedProperty:
            v = rp.pop(k)
            pk = sep.join(v.path[:-1])
            if pk in children:
                children[pk].pop(v.path[-1], None)
                if not children[pk]:
                    del children[pk]
            return v

        def _add(new_rp: ResolvedProperty) -> None:
            k = sep.join(new_rp.path)
            if k in rp:
                rp[k].merge(new_rp)
            else:
                rp[k] = new_rp
            pk = sep.join(new_rp.path[:-1])
            children.setdefault(pk, {})[new_rp.path[-1]] = k

        def _all_descendants(key: str) -> list[tuple[str, ResolvedProperty]]:
            """BFS via children index — O(descendants), not O(|rp|)."""
            result = []
            stack = list(children.get(key, {}).values())
            while stack:
                k = stack.pop()
                if k in rp:
                    result.append((k, rp[k]))
                    stack.extend(children.get(k, {}).values())
            return result

        # Process deepest groups first so inner groups are cleaned up before outer
        # groups inspect their branches (avoids stale keys after re-pathing).
        group_keys = sorted(
            [k for k, v in rp.items() if v.keyword in ('anyOf', 'oneOf')],
            key=lambda k: len(rp[k].path),
            reverse=True,
        )

        for group_key in group_keys:
            group = rp.get(group_key)
            if not group:
                continue
            group_path = group.path
            parent_path = group_path[:-1]

            # Direct branch children of this group (O(branches), not O(|rp|))
            branch_keys = [
                ck for ck in children.get(group_key, {}).values()
                if rp[ck].keyword == 'branch'
            ]
            if len(branch_keys) < 2:
                continue

            # Branches that use a ref have their content in defs — skip hoisting for
            # the whole group if any branch has a ref (can't inspect their inline content).
            any_ref = any(rp[bk].ref for bk in branch_keys if bk in rp)

            if not any_ref:
                # Direct non-virtual property children per branch
                branch_props = {
                    bk: {
                        name: ck
                        for name, ck in children.get(bk, {}).items()
                        if not rp[ck].keyword
                    }
                    for bk in branch_keys
                }

                common_names = set.intersection(*(set(bp.keys()) for bp in branch_props.values()))

                for name in list(common_names):
                    # Skip properties that have children (nested objects); hoist only leaves
                    if any(branch_props[bk][name] in children for bk in branch_keys):
                        continue

                    branch_resolved = [rp[branch_props[bk][name]] for bk in branch_keys]
                    first = branch_resolved[0]
                    if not all(
                        r.schema_type == first.schema_type and r.id == first.id
                        for r in branch_resolved[1:]
                    ):
                        continue

                    parent_prop_path = parent_path + [name]
                    merged = copy.deepcopy(first)
                    merged.path = parent_prop_path
                    for other in branch_resolved[1:]:
                        merged.merge(other)

                    _add(merged)
                    for bk in branch_keys:
                        _del(branch_props[bk][name])

            # Remove branch nodes that are now empty; keep those with a ref (content in defs)
            for bk in list(branch_keys):
                if bk in rp and bk not in children and not rp[bk].ref:
                    _del(bk)

            remaining = [
                k for k in branch_keys
                if k in rp and rp[k].keyword == 'branch'
            ]

            if len(remaining) <= 1:
                if len(remaining) == 1:
                    sole_key = remaining[0]
                    if rp[sole_key].ref:
                        # Sole remaining branch is ref'd: can't inline-unwrap, leave as-is
                        pass
                    else:
                        sole_path = rp[sole_key].path
                        for k, v in _all_descendants(sole_key):
                            _del(k)
                            new_rp = copy.deepcopy(v)
                            new_rp.path = parent_path + v.path[len(sole_path):]
                            _add(new_rp)
                        _del(sole_key)
                        if group_key in rp:
                            _del(group_key)
                elif group_key in rp:
                    _del(group_key)

    def _dedup_to_defs(self, copy_log: list[tuple[list[str], list[str], str]]) -> None:
        """
        Post-hoist deduplication: for each (src_path, dst_path, cache_key) in copy_log,
        if the dst subtree still has entries (not all hoisted), move the src subtree
        into _resolved_property_defs[cache_key] with relative paths and replace both
        the src and dst nodes with ``ref`` pointers.
        """
        if not copy_log:
            return

        rp = self._resolved_properties
        sep = '\x00'

        # Build a parent→{child_name: child_key} index for O(1) lookups.
        children: dict[str, dict[str, str]] = {}
        for k, v in rp.items():
            if v.path:
                pk = sep.join(v.path[:-1])
                children.setdefault(pk, {})[v.path[-1]] = k

        def _get_descendants(path: list[str]) -> list[tuple[str, ResolvedProperty]]:
            result = []
            stack = list(children.get(sep.join(path), {}).values())
            while stack:
                k = stack.pop()
                if k in rp:
                    result.append((k, rp[k]))
                    stack.extend(children.get(k, {}).values())
            return result

        def _remove_descendants(path: list[str]) -> None:
            path_key = sep.join(path)
            stack = list(children.get(path_key, {}).values())
            while stack:
                k = stack.pop()
                stack.extend(children.get(k, {}).values())
                rp.pop(k, None)
                children.pop(k, None)
            children.pop(path_key, None)

        for src_path, dst_path, cache_key in copy_log:
            if not src_path or not dst_path or src_path == dst_path:
                continue

            dst_key = sep.join(dst_path)
            dst_descendants = _get_descendants(dst_path)
            if not dst_descendants:
                continue  # all hoisted away; nothing to dedup

            if cache_key not in self._resolved_property_defs:
                src_descendants = _get_descendants(src_path)
                if not src_descendants:
                    continue
                src_len = len(src_path)
                def_entries = []
                for _, v in src_descendants:
                    entry = copy.deepcopy(v)
                    entry.path = v.path[src_len:]
                    def_entries.append(entry)
                self._resolved_property_defs[cache_key] = def_entries
                _remove_descendants(src_path)
                src_key = sep.join(src_path)
                if src_key in rp:
                    rp[src_key].ref = cache_key

            _remove_descendants(dst_path)
            if dst_key in rp:
                rp[dst_key].ref = cache_key

    @property
    def missed_properties(self):
        return [k for (k, v) in self._missed_properties.items() if v]

    @property
    def resolved_properties(self) -> dict[str, ResolvedProperty]:
        return self._resolved_properties

    @property
    def resolved_property_defs(self) -> dict[str, list[ResolvedProperty]]:
        return self._resolved_property_defs


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
    wd = (Path(root_dir) if root_dir else Path()).absolute()
    subdir = subdir if isinstance(subdir, Path) else Path(subdir)
    path = schema.source
    if isinstance(path, Path):
        output_fn = path.absolute().relative_to(wd)
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
                writer.writerow(['path', '@id', 'from_schema'])
                writer.writerows((k, *v) for k, v in ctx_builder.visited_properties.items())

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
