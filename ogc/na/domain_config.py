#!/usr/bin/env python3
import os
from glob import glob
from pathlib import Path
from typing import Union, Optional
from typing.io import IO
from rdflib import Graph, Namespace, RDF, RDFS
from rdflib.term import Node
import logging

DOMAINCFG = Namespace('urn:ogc:na/domaincfg#')
logger = logging.getLogger('domain_config')

class DomainConfiguration:

    def __init__(self,
                 working_directory: Union[str, Path] = None):
        self.working_directory = (Path(working_directory) if working_directory else Path()).resolve()
        logger.debug("Working directory: %s", self.working_directory)
        self.entries: dict[str, list[DomainConfigurationEntry]] = {}

    def clear(self):
        self.entries = {}

    def _load_rule_collection(self, g: Graph, n: Node, seen: set = None) -> list[str]:
        if seen is None:
            seen = set((n,))
        rules = list(g.objects(n, DOMAINCFG.hasFile))
        for imp in g.objects(n, DOMAINCFG.imports):
            if imp in seen:
                raise Exception(f'Recursive import detected: {imp}')
            rules.extend(self._load_rule_collection(g, imp, seen))
            seen.add(imp)
        return rules

    def load(self, source: Union[Graph, str, IO], domain: Union[str, Path] = None):
        '''
        Load from a Graph or Turtle document.
        :param source: Graph or Turtle file to load
        :param domain: Domain path filter
        :return:
        '''
        g = Graph().parse(source)

        domain = None if not domain else Path(domain).resolve()

        for cfg in g.subjects(RDF.type, DOMAINCFG.DomainConfiguration):
            localpath = Path(str(g.value(cfg, DOMAINCFG.path)))
            path = (self.working_directory / localpath).resolve()
            if domain is not None and path != domain:
                continue
            entry = DomainConfigurationEntry(
                localpath=localpath,
                working_directory=self.working_directory,
                path=path,
                comment=str(g.value(cfg, RDFS.comment)),
                glob=str(g.value(cfg, DOMAINCFG.glob)),
                uri_root_filter=str(g.value(cfg, DOMAINCFG.uriRootFilter)),
            )
            for r in g.objects(cfg, DOMAINCFG.rules):
                entry.rules.extend(self._load_rule_collection(g, r))
            for r in g.objects(cfg, DOMAINCFG.validator):
                entry.validator.extend(self._load_rule_collection(g, r))
            for r in g.objects(cfg, DOMAINCFG.extraOntology):
                entry.extra_ontology.extend(self._load_rule_collection(g, r))
            for r in g.objects(cfg, DOMAINCFG.annotation):
                entry.annotation.extend(self._load_rule_collection(g, r))
            self.entries.setdefault(path, []).append(entry)

        if domain:
            logger.info("Found %d domain configuration entries for domain %s:\n - %s",
                        len(self.entries), domain,
                        '\n - '.join([e.glob for entries in self.entries.values() for e in entries]))
        else:
            logger.info("Found %d domain configurations:\n - %s",
                        len(self.entries), '\n - '.join([os.path.relpath(p) for p in self.entries.keys()]))
        return self

    def find_file(self, fn: Union[str, Path]) -> 'DomainConfigurationEntry':
        if not isinstance(fn, Path):
            fn = Path(fn)
        for entryList in self.entries.values():
            for entry in entryList:
                if entry.matches(fn):
                    return entry.load()

    def find_files(self, fns: list[Union[str, Path]]) -> 'dict[Path, DomainConfigurationEntry]':
        result = {}
        for fn in fns:
            p = Path(fn).resolve()
            e = self.find_file(p)
            if e:
                result[p] = e
        return result

    def find_domain_entries(self, path: Union[str, Path]) -> 'list[DomainConfigurationEntry]':
        if not isinstance(path, Path):
            path = Path(path)
        path = path.resolve()
        for domain, entries in self.entries.items():
            if domain == path:
                return [entry.load() for entry in entries]

    def find_all(self) -> 'dict[Path, DomainConfigurationEntry]':
        r = {}
        for entryList in self.entries.values():
            for entry in entryList:
                r.update({p: entry for p in entry.load().find_all()})
        return r

    def __len__(self):
        return len(self.entries)


class DomainConfigurationEntry:

    def __init__(self,
                 working_directory: Path,
                 rules: Union[list[Union[str, Path]], Graph] = None,
                 validator: Union[list[Union[str, Path]], Graph] = None,
                 extra_ontology: Union[list[Union[str, Path]], Graph] = None,
                 annotation: Union[list[Union[str, Path]], Graph] = None,
                 **kwargs):
        self.working_directory = working_directory
        self.rules = rules or []
        self.validator = validator or []
        self.extra_ontology = extra_ontology or []
        self.annotation = annotation or []
        for arg in ('localpath', 'path', 'comment', 'glob', 'uri_root_filter'):
            setattr(self, arg, kwargs.get(arg))
        self.path = self.path.resolve()
        self._loaded = False

    def load(self):
        if not self._loaded:

            for prop in ('rules', 'validator', 'extra_ontology', 'annotation'):
                val = getattr(self, prop)
                if isinstance(val, Graph):
                    setattr(self, f'{prop}_path', None)
                g = Graph()
                for fn in val:
                    g.parse(self.working_directory / fn)
                setattr(self, prop, g)
                setattr(self, f'{prop}_path', val)

            self._loaded = True

        return self

    def find_all(self):
        return list(self.path.glob(self.glob))

    def matches(self, fn: Union[str, Path]):
        if not isinstance(fn, Path):
            fn = Path(fn)
        if self.path != fn.parent.resolve():
            return False
        return fn.match(self.glob)

