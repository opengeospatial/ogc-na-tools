#!/usr/bin/env python3
"""
General utilities module.
"""
from __future__ import annotations

import argparse
import os.path
import shlex
from glob import glob, iglob
from pathlib import Path
from time import time
from typing import Optional, Union, Any, Mapping, Hashable

import requests
import rfc3987

from rdflib import Graph
from pyshacl import validate as shacl_validate
from urllib.parse import urlparse

from ogc.na.models import ValidationReport

import yaml

try:
    from yaml import CLoader as YamlLoader, CSafeLoader as SafeYamlLoader, CDumper as YamlDumper
except ImportError:
    from yaml import Loader as YamlLoader, SafeLoader as SafeYamlLoader, Dumper as YamlDumper


class ContextMergeError(Exception):
    pass


def copy_triples(src: Graph, dst: Optional[Graph] = None) -> Graph:
    """
    Copies all triples from one graph onto another (or a new, empty [Graph][rdflib.Graph]
    if none is provided).

    :param src: the source Graph
    :param dst: the destination Graph (or `None` to create a new one)
    :return: the destination Graph
    """
    if dst is None:
        dst = Graph()
    for triple in src:
        dst.add(triple)
    return dst


def parse_resources(src: Union[str, Graph, list[Union[str, Graph]]]) -> Graph:
    """
    Join one or more RDF documents or [Graph][rdflib.Graph]'s together into
    a new Graph.
    :param src: a path or [Graph][rdflib.Graph], or list thereof
    :return: a union Graph
    """
    if not isinstance(src, list):
        src = [src]

    result = Graph()
    for s in src:
        if not isinstance(s, Graph):
            s = Graph().parse(s)
        copy_triples(s, result)

    return result


def entail(g: Graph,
           rules: Graph,
           extra: Optional[Graph] = None,
           inplace: bool = True) -> Graph:
    """
    Performs SHACL entailments on a data [Graph][rdflib.Graph].

    :param g: input data Graph
    :param rules: SHACL Graph for entailments
    :param extra: Graph with additional ontological information for entailment
    :param inplace: if `True`, the source Graph will be modified, otherwise a new
           Graph will be created
    :return: the resulting Graph
    """
    entailed_extra = None
    if extra:
        entailed_extra = copy_triples(extra)
        shacl_validate(entailed_extra, shacl_graph=rules, ont_graph=None, advanced=True, inplace=True)

    if not inplace:
        g = copy_triples(g)
    shacl_validate(g, shacl_graph=rules, ont_graph=extra, advanced=True, inplace=True)

    if entailed_extra:
        for triple in entailed_extra:
            g.remove(triple)

    return g


def validate(g: Graph, shacl_graph: Graph, extra: Optional[Graph] = None,
             **kwargs) -> ValidationReport:
    """
    Perform SHACL validation on a data [Graph][rdflib.Graph].

    :param g: input data Graph
    :param shacl_graph: SHACL graph for validation
    :param extra: Graph with additional ontological information for validation
    :return: the resulting [][ogc.na.validation.ValidationReport]
    """
    return ValidationReport(shacl_validate(data_graph=g,
                                           shacl_graph=shacl_graph,
                                           ont_graph=extra,
                                           inference='rdfs',
                                           advanced=True,
                                           **kwargs))


def is_url(url: str, http_only: bool = False) -> bool:
    """
    Checks whether a string is a valid URL.

    :param url: the input string
    :param http_only: whether to only accept HTTP and HTTPS URLs as valid
    :return: `True` if this is a valid URL, otherwise `False`
    """
    if not url:
        return False

    parsed = urlparse(url)
    if not parsed.scheme or not (parsed.netloc or parsed.path):
        return False

    if http_only and parsed.scheme not in ('http', 'https'):
        return False

    return True


def load_yaml(filename: str | Path | None = None,
              content: Any | None = None,
              url: str | None = None,
              safe: bool = True) -> dict:
    """
    Loads a YAML file either from a file, a string or a URL.

    :param filename: YAML document file name
    :param content: str with YAML contents
    :param url: url from which to retrieve the contents
    :param safe: whether to use safe YAMl loading
    :return: a dict with the loaded data
    """

    if bool(filename) + bool(content) + bool(url) > 1:
        raise ValueError("One (and only one) of filename, contents and url must be provided")

    if filename:
        with open(filename, 'r') as f:
            return yaml.load(f, Loader=SafeYamlLoader if safe else YamlLoader)
    else:
        if url:
            content = requests.get(url).text
        return yaml.load(content, Loader=SafeYamlLoader if safe else YamlLoader)


def dump_yaml(content: Any, filename: str | Path | None = None,
              ignore_alises=True,
              **kwargs) -> str | None:
    """
    Generates YAML output.

    :param content: content to convert to YAML.
    :param filename: optional filename to dump the content into. If None, string content will be returned.
    :param kwargs: other args to pass to `yaml.dump()`
    """
    kwargs.setdefault('sort_keys', False)
    if ignore_alises:
        class Dumper(YamlDumper):
            def ignore_aliases(self, data) -> bool:
                return True
    else:
        Dumper = YamlDumper
    if filename:
        with open(filename, 'w') as f:
            return yaml.dump(content, f, Dumper=Dumper, **kwargs)
    else:
        return yaml.dump(content, Dumper=Dumper, **kwargs)


def is_iri(s: str) -> bool:
    try:
        return rfc3987.parse(s, rule='IRI') is not None
    except ValueError:
        return False


def merge_dicts(src: dict, dst: dict) -> dict:
    if not src:
        return dst
    for k, v in src.items():
        if isinstance(v, dict):
            node = dst.setdefault(k, {})
            merge_dicts(v, node)
        elif isinstance(dst, dict):
            dst[k] = v
        else:
            dst = {k: v}
    return dst


def glob_list_split(s: str, exclude_dirs: bool = True, recursive: bool = False) -> list[str]:
    result = []
    for e in shlex.split(s):
        if is_url(s):
            result.append(s)
        else:
            for fn in glob(e, recursive=recursive):
                if not exclude_dirs or os.path.isfile(fn):
                    result.append(fn)
    return result


class LRUCache:

    def __init__(self, maxsize: int = 10):
        self._cache: dict[Hashable, Any] = {}
        self._last_access: dict[Hashable, float] = {}
        self._maxsize = maxsize

    def __contains__(self, item):
        return item in self._cache

    def __len__(self):
        return len(self._cache)

    def get(self, key, default=None):
        if not isinstance(key, Hashable):
            return default
        return self._cache.get(key, default)

    def __setitem__(self, key, value):
        if not isinstance(key, Hashable):
            return
        if len(self._cache) >= self._maxsize and key not in self._cache:
            key_to_remove = min(self._last_access, key=self._last_access.get)
            del self._cache[key_to_remove]
            del self._last_access[key_to_remove]
        self._cache[key] = value
        self._last_access[key] = time()


def deep_update(orig_dict: dict, with_dict: Mapping, replace: bool = False) -> dict:
    if not isinstance(orig_dict, Mapping):
        return with_dict
    dest = orig_dict if replace else {**orig_dict}
    for k, v in with_dict.items():
        if isinstance(v, Mapping):
            dest[k] = deep_update(orig_dict.get(k, {}), v, replace)
        else:
            dest[k] = v
    return dest


def git_status(repo_path: str | Path = '.'):
    import git
    repo = git.Repo(repo_path)
    added = repo.untracked_files
    modified = []
    deleted = []
    renamed = []
    for diff in repo.head.commit.diff(None):
        if diff.change_type == 'D':
            deleted.append(diff.a_path)
        elif diff.change_type == 'M':
            modified.append(diff.a_path)
        elif diff.change_type == 'R':
            renamed.append((diff.a_path, diff.b_path))
    return {
        'added': added,
        'modified': modified,
        'deleted': deleted,
        'renamed': renamed,
    }


def merge_contexts(a: dict, b: dict, fix_nest=True) -> dict[str, Any]:
    if not b:
        return a
    if not a:
        if isinstance(a, dict):
            a.update(b)
            return a
        return b
    for term in list(a.keys()):
        va = a[term]
        vb = b.get(term)
        if term[0] != '@':
            if isinstance(va, str):
                va = {'@id': va}
                a[term] = va
            if isinstance(vb, str):
                vb = {'@id': vb}
            if vb:
                for vb_term, vb_term_val in vb.items():
                    if vb_term != '@context':
                        va[vb_term] = vb_term_val
                if '@context' in vb:
                    if '@context' not in va:
                        va['@context'] = vb['@context']
                    elif isinstance(va['@context'], list):
                        if isinstance(vb['@context'], list):
                            va['@context'].extend(vb['@context'])
                        else:
                            va['@context'].append(vb['@context'])
                    elif isinstance(vb['@context'], list):
                        va['@context'] = [va['@context'], *vb['@context']]
                    else:
                        va['@context'] = merge_contexts(va['@context'], vb['@context'])
        elif vb:
            a[term] = vb
    for t, tb in b.items():
        if t not in a:
            a[t] = tb

    if fix_nest:
        # fix nested @context inside @nest terms
        # spec is unclear, but our tooling of interest (json-ld playground, rdflib) do not support it
        # see: https://github.com/json-ld/json-ld.org/issues/737
        pending_merges = []
        for term in list(a.keys()):
            if isinstance(a[term], dict) and a[term].get('@id') == '@nest':
                nested_ctx = a[term].pop('@context', None)
                if nested_ctx:
                    pending_merges.append(nested_ctx)
                a[term] = '@nest'
        for pm in pending_merges:
            a = merge_contexts(a, pm)

    return a


def dict_contains(greater: dict, smaller: dict):
    for k, v in smaller.items():
        if k not in greater:
            return False
        gv = greater[k]
        if isinstance(v, dict):
            if not isinstance(gv, dict) or not dict_contains(gv, v):
                return False
        elif gv != v:
            return False
    return True


def cmd_join(args):
    g = Graph()
    for src in args.input:
        g.parse(src)

    if args.output:
        g.serialize(args.output, format=args.format or 'ttl')
    else:
        print(g.serialize(format=args.format or 'ttl'))


def _main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    join_parser = subparsers.add_parser('join', help='Join RDF files')
    join_parser.add_argument('input', nargs='+')
    join_parser.add_argument('-o', '--output', help='Output file')
    join_parser.add_argument('-f', '--format', help='Output format')

    args = parser.parse_args()

    if args.command == 'join':
        cmd_join(args)


if __name__ == '__main__':
    _main()