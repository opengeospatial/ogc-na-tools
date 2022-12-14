#!/usr/bin/env python3
"""
General utilities module.
"""
from pathlib import Path
from typing import Optional, Union
from rdflib import Graph
from pyshacl import validate as shacl_validate
from urllib.parse import urlparse

from ogc.na.validation import ValidationReport


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


def validate(g: Graph, shacl_graph: Graph, extra: Optional[Graph] = None) -> ValidationReport:
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
                                           advanced=True))


def isurl(url: str, http_only: bool = False) -> bool:
    """
    Checks whether a string is a valid URL.

    :param url: the input string
    :param http_only: whether to only accept HTTP and HTTPS URL's as valid
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


def load_yaml(filename: Union[str, Path] = None, content: str = None) -> dict:
    """
    Loads a YAML file either from a file or from a string.

    :param filename: YAML document file name
    :param content: str with YAML contents
    :return: a dict with the loaded data
    """

    if bool(filename) == bool(content):
        raise ValueError("One (and only one) of filename or contents required")

    from yaml import load
    try:
        from yaml import CLoader as Loader
    except ImportError:
        from yaml import Loader
    if filename:
        with open(filename, 'r') as f:
            return load(f, Loader=Loader)
    else:
        return load(content, Loader=Loader)
