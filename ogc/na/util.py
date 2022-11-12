from typing import Optional, Union
from rdflib import Graph
from pyshacl import validate as shacl_validate
from urllib.parse import urlparse

from ogc.na.validation import ValidationReport


def copy_triples(src: Graph, dst: Optional[Graph] = None) -> Graph:
    if dst is None:
        dst = Graph()
    for triple in src:
        dst.add(triple)
    return dst


def parse_resources(src: Union[str, Graph, list[Union[str, Graph]]]) -> Graph:
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
    return ValidationReport(shacl_validate(data_graph=g,
                                           shacl_graph=shacl_graph,
                                           ont_graph=extra,
                                           inference='rdfs',
                                           advanced=True))


def isurl(url: str, http_only: bool = False) -> bool:
    if not url:
        return False

    parsed = urlparse(url)
    if not parsed.scheme or not (parsed.netloc or parsed.path):
        return False

    if http_only and parsed.scheme not in ('http', 'https'):
        return False

    return True
