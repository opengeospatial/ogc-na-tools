#!/usr/bin/env python3
"""
This module contains classes to perform JSON-LD uplifting operations, facilitating
the conversion of standard JSON into JSON-LD.

JSON-LD uplifting is done in 4 steps:

* Input filter pre-processing (e.g., csv). This step is *optional*.
* Initial transformation using [jq](https://stedolan.github.io/jq/manual/) expressions (`transform`).
* Class annotation (adding `@type` to the root object and/or to specific nodes, using
  [jsonpath-ng](https://pypi.org/project/jsonpath-ng/) expressions) (`types`).
* Injecting custom JSON-LD `@context` either globally or inside specific nodes (using
  [jsonpath-ng](https://pypi.org/project/jsonpath-ng/) expressions (`context`).

The details for each of these operations are declared inside context definition files,
which are YAML documents containing specifications for the uplift workflow. For each input
JSON file, its corresponding YAML context definition is detected at runtime:

1. A [domain configuration][ogc.na.domain_config.DomainConfiguration] can be used,
which is a JSON (or YAML) document that defines JSON file to context definition mappings.
2. If no registry is used or the input file is not in the registry, a file with the same
name but `.yml` extension will be used, if it exists.
3. Otherwise, a `_json-context.yml` file in the same directory will be used, if it exists.

If no context definition file is found after performing the previous 3 steps, then the file will
be skipped.
"""
from __future__ import annotations
import argparse
import functools
import json
import logging
import os
import os.path
import re
import sys
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from os import scandir
from pathlib import Path
from typing import Union, Optional, Sequence, cast, Iterable, Any

import jq
from jsonpath_ng.ext import parse as json_path_parse
from jsonschema import validate as json_validate
from rdflib import Graph, DC, DCTERMS, SKOS, OWL, RDF, RDFS, XSD, DCAT
from rdflib.namespace import Namespace, DefinedNamespace

from ogc.na import util, profile
from ogc.na.domain_config import UpliftConfigurationEntry, DomainConfiguration
from ogc.na.provenance import ProvenanceMetadata, FileProvenanceMetadata, generate_provenance
from ogc.na.input_filters import apply_input_filter
from ogc.na.util import is_iri

logger = logging.getLogger(__name__)

DEFAULT_NAMESPACES: dict[str, Union[str, DefinedNamespace]] = {
    "dc": DC,
    "xsd": XSD,
    "dct": DCTERMS,
    "skos": SKOS,
    "owl": OWL,
    "rdf": RDF,
    "rdfs": RDFS,
    "dcat": DCAT,
    "iso": 'http://iso.org/tc211/',
    "spec": "http://www.opengis.net/def/ont/modspec/",
    "specrel": "http://www.opengis.net/def/ont/specrel/",
    "ogcna": "http://www.opengis.net/def/metamodel/ogc-na/",
    "prov": "http://www.w3.org/ns/prov#"
}

VOCAB_DELIMITERS = {"#", "/", ":"}

UPLIFT_CONTEXT_SCHEMA = {
    "type": "object",
    "properties": {
        "input-filter": {
            "type": "object",
            "maxProperties": 1,
            "minProperties": 1,
        },
        "path-scope": {
            "type": "string",
            "enum": ["graph", "document"],
        },
        "transform": {
            "anyOf": [
                {
                    "type": "string",
                },
                {
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
            ],
        },
        "types": {
            "type": "object",
            "patternProperties": {
                ".+": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}}
                    ],
                },
            },
        },
        "base-uri": {
            "type": "string",
        },
        "context": {
            "type": "object",
        },
        "context-position": {
            "type": "string",
            "enum": ["before", "after"],
        }
    },
}


class ValidationError(Exception):

    def __init__(self, cause: Exception = None, msg: str = None,
                 property: str = None, value: str = None,
                 index: int = None):
        self.cause = cause
        self.msg = msg
        self.property = property
        self.value = value
        self.index = index


class MissingContextException(Exception):
    pass


@dataclass
class UpliftResult:
    input_file: Path = None
    uplifted_json: dict | list = None
    graph: Graph = None
    output_files: list[Path] = field(default_factory=list)


def validate_context(context: Union[dict, str] = None,
                     filename: Union[str, Path] = None,
                     transform_args: dict | None = None) -> dict:
    if not context and not filename:
        return {}
    if bool(context) == bool(filename):
        raise ValueError("Only one of context or filename required")

    if not isinstance(context, dict):
        context = util.load_yaml(filename=filename, content=context)

    try:
        json_validate(context, UPLIFT_CONTEXT_SCHEMA)
    except Exception as e:
        raise ValidationError(cause=e)

    transform = context.get('transform', [])
    if isinstance(transform, str):
        transform = [transform]
    for i, t in enumerate(transform):
        try:
            jq.compile(t, args=transform_args)
        except Exception as e:
            raise ValidationError(cause=e,
                                  msg=f"Error compiling jq expression for transform at index {i}",
                                  property="transform",
                                  value=t,
                                  index=i)
    for json_path in context.get('types', {}).keys():
        if json_path in ('.', '$'):
            continue
        try:
            json_path_parse(json_path)
        except Exception as e:
            raise ValidationError(cause=e,
                                  msg=f"Error parsing jsonpath-ng path '{json_path}' in types",
                                  property="types",
                                  value=json_path)

    return context


def add_jsonld_provenance(json_doc: Union[dict, list], metadata: ProvenanceMetadata = None) -> list:
    if not metadata:
        return json_doc

    g = generate_provenance(metadata=metadata)
    prov = json.loads(g.serialize(format='json-ld'))
    if not isinstance(json_doc, list):
        json_doc = [json_doc]
    json_doc.extend(prov)
    return json_doc


def uplift_json(data: dict | list, context: dict,
                fetch_url_whitelist: Optional[Union[Sequence, bool]] = None,
                transform_args: dict | None = None) -> dict:
    """
    Transform a JSON document loaded in a dict, and embed JSON-LD context into it.

    WARNING: This function modifies the input dict. If that is not desired, make a copy
    before invoking.

    :param data: the JSON document in dict format
    :param context: YAML context definition
    :param fetch_url_whitelist: list of regular expressions to filter referenced JSON-LD context URLs before
        retrieving them. If None, it will not be used; if empty sequence or False, remote fetching operations will
        throw an exception.
    :param transform_args: Additional arguments to pass as variables to the jq transform
    :return: the transformed and JSON-LD-enriched data
    """

    context_position = context.get('position', 'before')

    validate_context(context, transform_args=transform_args)

    # Check whether @graph scoping is necessary for transformations and paths
    scoped_graph = context.get('scope', 'graph') == 'graph' and '@graph' in data
    data_graph = data['@graph'] if scoped_graph else data

    # Check if pre-transform necessary
    transform = context.get('transform')
    if transform:
        # Allow for transform lists to do sequential transformations
        if isinstance(transform, str):
            transform = (transform,)
        for i, t in enumerate(transform):
            tranformed_txt = jq.compile(t, args=transform_args).input(data_graph).text()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug('After transform %d:\n%s', i + 1, tranformed_txt)
            data_graph = json.loads(tranformed_txt)

    # Add types
    types = context.get('types', {})
    for loc, type_list in types.items():
        items = json_path_parse(loc).find(data_graph)
        if isinstance(type_list, str):
            type_list = [type_list]
        for item in items:
            existing = item.value.setdefault('@type', [])
            if isinstance(existing, str):
                item.value['@type'] = [existing] + type_list
            else:
                item.value['@type'].extend(type_list)
            item_types = item.value.get('@type')
            if not item_types:
                item.value.pop('@type', None)
            elif isinstance(item_types, Sequence) and not isinstance(item_types, str) and len(item_types) == 1:
                item.value['@type'] = item_types[0]

    # Add contexts
    context_list = context.get('context', {})
    global_context = None
    for loc, val in context_list.items():
        if not loc or loc in ['.', '$']:
            global_context = val
        else:
            items = json_path_parse(loc).find(data_graph)
            for item in items:
                item.value['@context'] = _get_injected_context(item.value, val, context_position)

    if isinstance(data_graph, dict):
        data_context = data_graph.pop('@context', None)
        if data_context:
            if not global_context:
                global_context = data_context
            elif isinstance(global_context, list):
                global_context.extend(data_context)
            else:
                global_context = [data_context, global_context]

    if (global_context and not isinstance(data_graph, dict)) or scoped_graph:
        return {
            '@context': _get_injected_context(data, global_context, context_position),
            '@graph': data_graph,
        }
    else:
        if global_context:
            return {
                '@context': _get_injected_context(data, global_context, context_position),
                **data_graph
            }
        return data_graph


def _get_injected_context(node: dict, ctx: Union[dict, list] = None, position: str = 'before') -> Union[dict, list]:
    if not ctx:
        return node.get('@context')

    prev_ctx = node.get('@context') if isinstance(node, dict) else None
    if prev_ctx:
        result = []

        if not isinstance(ctx, list):
            ctx = [ctx]

        # Add existing context
        if isinstance(prev_ctx, dict):
            result.append(prev_ctx)
        elif isinstance(prev_ctx, list):
            result.extend(prev_ctx)

        # Add the new @context before or after existing
        if not position or position == 'before':
            result = ctx + result
        elif position == 'after':
            result.extend(ctx)
        else:
            raise ValueError('position must be "before" or "after" ("{}" found)'.format(position))
    else:
        result = ctx

    return result


def generate_graph(input_data: dict | list,
                   context: dict[str, Any] | Sequence[dict] = None,
                   base: str | None = None,
                   fetch_url_whitelist: Sequence[str] | bool | None = None,
                   transform_args: dict | None = None) -> UpliftResult:
    """
    Create a graph from an input JSON document and a YAML context definition file.

    :param input_data: input JSON data in dict or list format
    :param context: context definition in dict format, or list thereof
    :param base: base URI for JSON-LD context
    :param fetch_url_whitelist: list of regular expressions to filter referenced JSON-LD context URLs before
        retrieving them. If None, it will not be used; if empty sequence or False, remote fetching operations will
        throw an exception.
    :param transform_args: Additional arguments to pass as variables to the jq transform
    :return: a tuple with the resulting RDFLib Graph and the JSON-LD enriched file name
    """

    if not isinstance(input_data, dict) and not isinstance(input_data, list):
        raise ValueError('input_data must be a list or dictionary')

    g = Graph()
    jdoc_ld = input_data
    if context:
        base_uri = None
        for prefix, ns in DEFAULT_NAMESPACES.items():
            g.bind(prefix, Namespace(ns))

        context_list = context if isinstance(context, Sequence) else (context,)
        for context_entry in context_list:
            base_uri = context_entry.get('base-uri', base_uri)
            jdoc_ld = uplift_json(input_data, context_entry,
                                  transform_args=transform_args)
            if 'context' in context_entry:
                if '$' in context_entry['context']:
                    root_ctx = context_entry['context']['$']
                elif '.' in context_entry['context']:
                    root_ctx = context_entry['context']['.']
                else:
                    continue

                if isinstance(root_ctx, dict):
                    for term, term_val in root_ctx.items():
                        if not term.startswith('@') \
                                and isinstance(term_val, str) \
                                and re.match(r'.+[#/:]$', term_val) \
                                and is_iri(term_val):
                            g.bind(term, term_val)

        if not base:
            if base_uri:
                base = context['base-uri']
            elif '@context' in jdoc_ld:
                # Try to extract from @context
                # If it is a list, iterate until @base is found
                base = None
                if isinstance(jdoc_ld['@context'], list):
                    for entry in jdoc_ld['@context']:
                        if not isinstance(entry, dict):
                            continue
                        base = entry.get('@base')
                        if base:
                            break
                else:
                    # If not a list, just look @base up
                    base = jdoc_ld['@context'].get('@base')
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('Uplifted JSON:\n%s', json.dumps(jdoc_ld, indent=2))

    def remote_context_url_filter(url_whitelist: str | list[str], url: str):
        if url_whitelist is False:
            return False
        if url_whitelist is True or url_whitelist is None:
            return True
        if isinstance(url_whitelist, str):
            url_whitelist = re.compile(url_whitelist)
        else:
            url_whitelist = [re.compile(x) for x in url_whitelist if x]
        return any(re.match(r, url) for r in url_whitelist)

    g.parse(data=json.dumps(jdoc_ld), format='json-ld', base=base,
            remote_context_url_filter=functools.partial(remote_context_url_filter, fetch_url_whitelist))

    return UpliftResult(graph=g, uplifted_json=jdoc_ld)


def process_file(input_fn: str | Path,
                 jsonld_fn: str | Path | bool | None = False,
                 ttl_fn: str | Path | bool | None = False,
                 context_fn: str | Path | Sequence[str | Path] | None = None,
                 domain_cfg: DomainConfiguration | None = None,
                 base: str | None = None,
                 provenance_base_uri: str | bool | None = None,
                 provenance_process_id: str | None = None,
                 fetch_url_whitelist: bool | Sequence[str] | None = None,
                 transform_args: dict | None = None) -> UpliftResult | None:
    """
    Process input file and generate output RDF files.

    :param input_fn: input filename
    :param jsonld_fn: output JSON-lD filename (None for automatic).
        If False, no JSON-LD output will be generated
    :param ttl_fn: output Turtle filename (None for automatic).
        If False, no Turtle output will be generated.
    :param context_fn: YAML context filename. If None, will be autodetected:
        1. From a file with the same name but yml/yaml extension (test.json -> test.yml)
        2. From the domain_cfg
        3. From a _json-context.yml/_json-context.yaml file in the same directory
    :param domain_cfg: domain configuration with uplift definition locations
    :param base: base URI for JSON-LD
    :param provenance_base_uri: base URI for provenance resources
    :param provenance_process_id: process identifier for provenance tracking
    :param fetch_url_whitelist: list of regular expressions to filter referenced JSON-LD context URLs before
        retrieving them. If None, it will not be used; if empty sequence or False, remote fetching operations will
        throw an exception
    :param transform_args: Additional arguments to pass as variables to the jq transform
    :return: List of output files created
    """

    start_time = datetime.now()

    if not isinstance(input_fn, Path):
        input_fn = Path(input_fn)

    if not input_fn.is_file():
        raise IOError(f'Input is not a file ({input_fn})')

    contexts = []
    provenance_contexts = []
    if not context_fn:
        for found_context in (find_contexts(input_fn, domain_config=domain_cfg) or ()):
            if isinstance(found_context, Path):
                contexts.append(util.load_yaml(filename=found_context))
            else:
                # Profile URI
                artifact_urls = domain_cfg.profile_registry.get_artifacts(found_context, profile.ROLE_SEMANTIC_UPLIFT)
                if artifact_urls:
                    for a in artifact_urls:
                        contexts.append(util.load_yaml(a))
                        provenance_contexts.append(a)

    elif not isinstance(context_fn, Sequence) or isinstance(context_fn, str):
        provenance_contexts = (context_fn,)
        contexts = (util.load_yaml(context_fn),)
    else:
        provenance_contexts = context_fn
        contexts = [util.load_yaml(fn) for fn in context_fn]

    if not contexts:
        raise MissingContextException('No context file provided and one could not be discovered automatically')

    # Apply input filter of first context only (if any)
    input_filters = contexts[0].get('input-filter')
    if input_filters:
        if not isinstance(input_filters, dict):
            raise ValueError('input-filter must be an object')
        input_data = apply_input_filter(input_fn, input_filters)
    else:
        # Accept both JSON and YAML
        input_data = util.load_yaml(input_fn)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug('Input data:\n%s', json.dumps(input_data, indent=2))

    provenance_metadata: ProvenanceMetadata | None = None
    if provenance_base_uri is not False:
        used = [FileProvenanceMetadata(filename=input_fn, mime_type='application/json')]
        used.extend(FileProvenanceMetadata(filename=c, mime_type='application/yaml') for c in provenance_contexts)
        provenance_metadata = ProvenanceMetadata(
            used=used,
            batch_activity_id=provenance_process_id,
            base_uri=provenance_base_uri,
            root_directory=os.getcwd(),
            start=start_time,
            end_auto=True,
        )

    if transform_args is None:
        transform_args = {}
    transform_args['_filename'] = str(input_fn.resolve())
    transform_args['_basename'] = str(input_fn.name)
    transform_args['_dirname'] = str(input_fn.resolve().parent)
    transform_args['_relname'] = os.path.relpath(input_fn)

    if not base:
        base = str(input_fn)

    uplift_result = generate_graph(input_data,
                                   context=contexts,
                                   base=base,
                                   fetch_url_whitelist=fetch_url_whitelist,
                                   transform_args=transform_args)

    uplift_result.input_file = input_fn

    # False = do not generate
    # None = auto filename
    # - = stdout
    if ttl_fn is not False:
        if ttl_fn == '-':
            if provenance_metadata:
                provenance_metadata.output = FileProvenanceMetadata(mime_type='text/turtle', use_bnode=False)
                generate_provenance(uplift_result.graph, provenance_metadata)
            print(uplift_result.graph.serialize(format='ttl'))
        else:
            if not ttl_fn:
                ttl_fn = input_fn.with_suffix('.ttl') \
                    if input_fn.suffix != '.ttl' \
                    else input_fn.with_suffix(input_fn.suffix + '.ttl')
            if provenance_metadata:
                provenance_metadata.output = FileProvenanceMetadata(filename=ttl_fn,
                                                                    mime_type='text/turtle',
                                                                    use_bnode=False)
                generate_provenance(uplift_result.graph, provenance_metadata)
            uplift_result.graph.serialize(destination=ttl_fn, format='ttl')
            uplift_result.output_files.append(ttl_fn)

    # False = do not generate
    # None = auto filename
    # "-" = stdout
    if jsonld_fn is not False:
        if jsonld_fn == '-':
            print(json.dumps(uplift_result.uplifted_json, indent=2))
        else:
            if not jsonld_fn:
                jsonld_fn = input_fn.with_suffix('.jsonld') \
                    if input_fn.suffix != '.jsonld' \
                    else input_fn.with_suffix(input_fn.suffix + '.jsonld')

            with open(jsonld_fn, 'w') as f:
                json.dump(uplift_result.uplifted_json, f, indent=2)
            uplift_result.output_files.append(jsonld_fn)

    return uplift_result


def find_contexts(filename: Path | str,
                  domain_config: DomainConfiguration | None = None) -> list[Path | str] | None:
    """
    Find the YAML context file for a given filename, with the following precedence:
        1. Search in registry (if provided)
        2. Search file with same base name but with yaml/yml or "-uplift.yml" extension.
        3. Find _json-context.yml/yaml file in same directory
    :param filename: the filename for which to find the context
    :param domain_config: an optional filename:yamlContextFile mapping
    :return: the YAML context definition paths (Path) and/or profile URIs (str)
    """

    if not isinstance(filename, Path):
        filename = Path(filename)

    # 1. Registry lookup
    if domain_config:
        entry: UpliftConfigurationEntry = domain_config.uplift_entries.find_entry_for_file(filename)
        if entry:
            return entry.uplift_definitions

    # 2. Same filename with yml/yaml extension or autodetect in dir
    for context_path in (
        filename.with_name(filename.stem + '-uplift.yml'),
        filename.with_name(filename.stem + '-uplift.yaml'),
        filename.with_suffix('.yml'),
        filename.with_suffix('.yaml'),
        filename.with_suffix('').with_suffix('.yml'),
        filename.with_suffix('').with_suffix('.yaml'),
        filename.parent / '_json-context.yml',
        filename.parent / '_json-context.yaml',
    ):
        if filename == context_path:
            continue
        if context_path.is_file() and not (filename.suffix == '.jsonld' and filename.with_suffix('.json').is_file()):
            logger.info(f'Autodetected context {context_path} for file {filename}')
            return [context_path]


def filenames_from_context(context_fn: Path | str,
                           domain_config: DomainConfiguration | None) -> list[Path]:
    """
    Tries to find a JSON/JSON-LD file from a given YAML context definition filename.
    Priority:
      1. Context file with same name as JSON doc (e.g. test.yml/test.json)
      2. Context file in domain configuration (if one provided)
      3. Context file in directory (_json-context.yml or _json-context.yaml)
    :param context_fn: YAML context definition filename
    :param domain_config: dict of jsonFile:yamlContextFile mappings
    :return: corresponding JSON/JSON-LD filename, if found
    """

    result = set()

    if not isinstance(context_fn, Path):
        context_fn = Path(context_fn)

    # 1. Lookup by matching filename
    if re.match(r'.*\.json-?(ld)?$', context_fn.stem):
        # If removing extension results in a JSON/JSON-LD
        # filename, try it
        json_fn = context_fn.with_suffix('')
        if json_fn.is_file():
            result.add(json_fn)
    # Otherwise check with appended JSON/JSON-LD extensions
    for suffix in ('.json', '.jsonld', '.json-ld'):
        json_fn = context_fn.with_suffix(suffix)
        if json_fn.is_file():
            result.add(json_fn)

    # 2. Reverse lookup in registry
    if domain_config:
        result.update(domain_config.uplift_entries.find_files_by_context_fn(context_fn))

    # 3. If directory context file, all .json files in directory
    # NOTE: no .jsonld or .json-ld files, since those could come
    #   from the output of this very script
    # NOTE: excluding those files present in the registry
    if context_fn.stem == '_json-context':
        with scandir(context_fn.parent) as it:
            return [x.path for x in cast(it, Iterable)
                    if x.is_file() and x.name.endswith('.json')]

    return list(result)


def process(input_files: str | Path | Sequence[str | Path],
            domain_cfg: DomainConfiguration | None = None,
            context_fn: str | Path | None = None,
            jsonld_fn: bool | str | Path | None = False,
            ttl_fn: bool | str | Path | None = False,
            batch: bool = False,
            base: str = None,
            skip_on_missing_context: bool = False,
            provenance_base_uri: Optional[Union[str, bool]] = None,
            fetch_url_whitelist: Optional[Union[Sequence, bool]] = None,
            transform_args: dict | None = None,
            file_filter: str | re.Pattern = None) -> list[UpliftResult]:
    """
    Performs the JSON-LD uplift process.

    :param input_files: list of input, plain JSON files
    :param domain_cfg: domain configuration including uplift definition locations
    :param context_fn: used to force the YAML context file name for the uplift. If `None`,
           it will be autodetected
    :param jsonld_fn: output file name for the JSON-LD content. If it is `False`, no JSON-LD
           output will be generated. If it is `None`, output will be written to stdout.
    :param ttl_fn: output file name for the Turtle RDF content. If it is `False`, no Turtle
           output will be generated. If it is `None`, output will be written to stdout.
    :param batch: in batch mode, all JSON input files are obtained from the context registry
           and processed
    :param base: base URI to employ
    :param skip_on_missing_context: whether to silently fail if no context file is found
    :param provenance_base_uri: base URI for provenance resources
    :param fetch_url_whitelist: list of regular expressions to filter referenced JSON-LD context URLs before
        retrieving them. If None, it will not be used; if empty sequence or False, remote fetching operations will
        throw an exception
    :param transform_args: Additional arguments to pass as variables to the jq transform
    :param file_filter: Filename filter for input files
    :return: a list of JSON-LD and/or Turtle output files
    """
    result: list[UpliftResult] = []
    process_id = str(uuid.uuid4())
    workdir = Path()
    if isinstance(input_files, str) or not isinstance(input_files, Sequence):
        input_files = (input_files,)
    if batch:
        logger.info("Input files: %s", input_files)
        remaining_fn: deque = deque()
        for input_file in input_files:
            if isinstance(input_file, str):
                for x in filter(lambda x: x, input_file.split(',')):
                    if '?' in x or '#' in x:
                        remaining_fn.extend(workdir.glob(x))
                    else:
                        remaining_fn.append(x)
            else:
                remaining_fn.append(input_file)
        while remaining_fn:
            fn = str(remaining_fn.popleft())

            if not fn or not os.path.isfile(fn):
                continue

            if file_filter and not re.search(file_filter, fn):
                continue

            if re.match(r'.*\.ya?ml$', fn):
                # Check whether this is a context definition or a doc to uplift
                has_context = bool(find_contexts(fn, domain_cfg))

                if not has_context:
                    # Potential context file found, try to find corresponding JSON/JSON-LD file(s)
                    logger.info('Potential YAML context file found: %s', fn)
                    remaining_fn.extend(filenames_from_context(fn, domain_config=domain_cfg) or [])
                    continue

            logger.info('File %s matches, processing', fn)
            try:
                result.append(process_file(
                    fn,
                    jsonld_fn=False if jsonld_fn is False else None,
                    ttl_fn=False if ttl_fn is False else None,
                    context_fn=None,
                    base=base,
                    provenance_base_uri=provenance_base_uri,
                    provenance_process_id=process_id,
                    fetch_url_whitelist=fetch_url_whitelist,
                    domain_cfg=domain_cfg,
                    transform_args=transform_args,
                ))
            except MissingContextException as e:
                if skip_on_missing_context or batch:
                    logger.warning("Error processing JSON/JSON-LD file, skipping: %s", getattr(e, 'msg', str(e)))
                else:
                    raise
    else:
        for input_file in input_files:
            try:
                result.append(process_file(
                    input_file,
                    jsonld_fn=jsonld_fn if jsonld_fn is not None else '-',
                    ttl_fn=ttl_fn if ttl_fn is not None else '-',
                    context_fn=context_fn,
                    base=base,
                    provenance_base_uri=provenance_base_uri,
                    provenance_process_id=process_id,
                    fetch_url_whitelist=fetch_url_whitelist,
                    domain_cfg=domain_cfg,
                    transform_args=transform_args,
                ))
            except Exception as e:
                if skip_on_missing_context:
                    logger.warning("Error processing JSON/JSON-LD file, skipping: %s", getattr(e, 'msg', str(e)))
                else:
                    raise

    return result


def _process_cmdln():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "input",
        nargs='*',
        help="Source file (instead of service)",
    )

    parser.add_argument(
        '-j',
        '--json-ld',
        action='store_true',
        help="Generate JSON-LD output file",
    )

    parser.add_argument(
        '--json-ld-file',
        help='JSON-LD output filename',
    )

    parser.add_argument(
        '-t',
        '--ttl',
        action='store_true',
        help='Generate TTL output file',
    )

    parser.add_argument(
        "--ttl-file",
        help="TTL output filename",
    )

    parser.add_argument(
        '-c',
        '--context',
        help='YAML context file (instead of autodetection)',
    )

    parser.add_argument(
        '-s',
        '--skip-on-missing-context',
        action='store_true',
        help='Skip files for which a context definition cannot be found (instead of failing)',
    )

    parser.add_argument(
        '--batch',
        help='Batch processing where input file is one or more files separated by commas, context files are '
             'autodiscovered and output file names are always auto generated',
        action='store_true'
    )

    parser.add_argument(
        '--fs',
        help='File separator for formatting list of output files (no output by default)',
    )

    parser.add_argument(
        '-d',
        '--domain-config',
        help='Domain configuration to use for locating uplift contexts'
    )

    parser.add_argument(
        '--no-provenance',
        action='store_true',
        help='Do not add provenance metadata to the output RDF'
    )

    parser.add_argument(
        '--provenance-base-uri',
        help='Base URI to employ for provenance metadata generation (from working directory)'
    )

    parser.add_argument(
        '--url-whitelist',
        nargs='*',
        help='Regular expression for URL whitelisting'
    )

    parser.add_argument(
        '--use-git-status',
        action='store_true',
        help='Use git status for obtaining batch filenames'
    )

    parser.add_argument(
        '-a',
        '--all',
        action='store_true',
        help='Run uplift for all catalog files in batch mode'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )

    parser.add_argument(
        '-w',
        '--work-dir',
        help='Set root directory for globs in domain configurations'
    )

    parser.add_argument(
        '--transform-arg',
        nargs='*',
        help='Additional argument to pass to the jq transforms in the form variable=value'
    )

    parser.add_argument(
        '--file-filter',
        help='Regular expression to filter input filenames',
    )

    args = parser.parse_args()

    if args.domain_config:
        domain_cfg = DomainConfiguration(args.domain_config, args.work_dir)
    else:
        domain_cfg = None

    input_files = args.input
    if args.batch:
        if args.use_git_status:
            git_status = util.git_status()
            input_files = git_status['added'] + git_status['modified'] + [r[1] for r in git_status['renamed']]
        elif args.all:
            input_files = list(set(fn for fn in domain_cfg.uplift_entries.find_all()))
    elif not input_files:
        print("Error: no input files provided")
        sys.exit(1)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    transform_args = None
    if args.transform_arg:
        transform_args = dict((e.split('=', 1) for e in args.transform_arg))

    result = process(input_files,
                     context_fn=args.context,
                     domain_cfg=domain_cfg,
                     jsonld_fn=args.json_ld_file if args.json_ld else False,
                     ttl_fn=args.ttl_file if args.ttl else False,
                     batch=args.batch,
                     skip_on_missing_context=args.skip_on_missing_context,
                     provenance_base_uri=False if args.no_provenance else args.provenance_base_uri,
                     fetch_url_whitelist=args.url_whitelist,
                     transform_args=transform_args,
                     file_filter=args.file_filter,
             )

    if args.fs:
        print(args.fs.join(str(output_file) for r in result for output_file in r.output_files))


if __name__ == '__main__':

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format='%(asctime)s,%(msecs)d %(levelname)-5s [%(filename)s:%(lineno)d] %(message)s',
    )

    _process_cmdln()
