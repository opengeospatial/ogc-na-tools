#!/usr/bin/env python3

import argparse
import dataclasses
import functools
import json
import logging
import os.path
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urljoin
import yaml
import requests
from ogc.na.util import is_url, merge_dicts

try:
    from yaml import CLoader as YamlLoader, CDumper as YamlDumper
except ImportError:
    from yaml import Loader as YamlLoader, Dumper as YamlDumper

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class AnnotatedSchema:
    source: str | Path
    is_json: bool
    schema: dict


def read_contents(fn: Path | str | None = None, url: str | None = None):
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


def load_json_yaml(contents: str | bytes) -> tuple[dict, bool]:
    try:
        obj = json.loads(contents)
        is_json = True
    except ValueError:
        obj = yaml.load(contents, Loader=YamlLoader)
        is_json = False

    return obj, is_json


def resolve_ref(ref: str, fn_from: str | Path | None = None, url_from: str | None = None,
                base_url: str | None = None) -> tuple[Path | None, str | None]:
    base_url = base_url or url_from
    if is_url(ref):
        return None, ref
    elif base_url:
        return None, urljoin(base_url, ref)
    else:
        fn_from = fn_from if isinstance(fn_from, Path) else Path(fn_from)
        ref = (fn_from.parent / ref).resolve()
        return ref, None


@functools.lru_cache(maxsize=20)
def read_context_terms(file: Path | str = None, url: str = None) -> dict[str, str]:
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

    def __init__(self, fn: Path | str | None = None, url: str | None = None,
                 follow_refs: bool = True):
        self.schemas: dict[str | Path, AnnotatedSchema] = {}
        self.bundled_schema = None
        self._follow_refs = follow_refs

        self._process_schema(fn, url)

    def _process_schema(self, fn: Path | str | None = None, url: str | None = None):
        contents, base_url = read_contents(fn, url)
        schema, is_json = load_json_yaml(contents)

        contextfn = schema.get('@modelReference')
        if not contextfn:
            return None

        del schema['@modelReference']

        base_url = schema.get('$id', base_url)

        if base_url:
            contextfn = urljoin(base_url, contextfn)
            terms = read_context_terms(url=contextfn)
        else:
            contextfn = fn.parent / contextfn
            terms = read_context_terms(file=contextfn)

        def process_properties(obj: dict):
            properties: dict[str, dict] = obj.get('properties') if obj else None
            if not properties:
                return

            for prop, prop_value in properties.items():
                if prop in terms:
                    prop_value['@id'] = terms[prop]
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

    def __init__(self, fn: Path | str | None = None, url: str | None = None):
        self.context = {'@context': {}}
        self._parsed_schemas: dict[str | Path, dict] = {}

        self.context = {'@context': self._build_context(fn, url)}

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
                if '@id' in prop_val:
                    prop_context = {
                        '@id': prop_val['@id']
                    }
                    if '@type' in prop_val:
                        prop_context['@type'] = prop_val['@type']

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
                for schema_ref in l:
                    if isinstance(schema_ref, dict) and '$ref' in schema_ref:
                        ref_fn, ref_url = resolve_ref(schema_ref['$ref'], fn, url, base_url)
                        merge_dicts(self._build_context(ref_fn, ref_url), own_context)

        read_properties(schema)

        self._parsed_schemas[fn or url] = own_context
        return own_context


def dump_annotated_schemas(annotator: SchemaAnnotator, subdir: Path | str = 'annotated'):
    wd = Path().resolve()
    subdir = subdir if isinstance(subdir, Path) else Path(subdir)
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
                yaml.dump(schema.schema, f)


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

    args = parser.parse_args()

    if not args.file and not args.url:
        print('Error: no file and no URL provided', file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        sys.exit(2)

    if args.build_context:
        ctx_builder = ContextBuilder(fn=args.file, url=args.url)
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
