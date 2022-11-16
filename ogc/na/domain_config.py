#!/usr/bin/env python3
import logging
import os
import re
from pathlib import Path
from typing import Union, Optional, Sequence, cast

from rdflib import Graph, Namespace, URIRef, RDF, DCTERMS
from typing.io import IO

DCFG = Namespace('http://www.example.org/ogc/domain-cfg#')

DOMAIN_CFG_QUERY = re.sub(r' {2,}|\n', ' ', """
    PREFIX dcfg: <http://www.example.org/ogc/domain-cfg#>
    PREFIX dct: <http://purl.org/dc/terms/>
    CONSTRUCT {
        ?domainCfg a dcfg:DomainConfiguration ;
            dcfg:localPath ?localPath ;
            dcfg:glob ?glob ;
            dcfg:uriRootFilter ?uriRootFilter ;
            dct:conformsTo ?profile ;
    } WHERE {
        __SERVICE__ {
            ?domainCfg dcfg:localPath ?localPath ;
                dcfg:glob ?glob .
            OPTIONAL {
                ?domainCfg dcfg:uriRootFilter ?uriRootFilter .
            }
            OPTIONAL {
                ?domainCfg dct:conformsTo ?profile
            }
        }
  }
""")

logger = logging.getLogger('domain_config')


class DomainConfiguration:

    def __init__(self, working_directory: Union[str, Path] = None):
        self.working_directory = (Path(working_directory) if working_directory else Path()).resolve()
        logger.debug("Working directory: %s", self.working_directory)
        self.entries: dict[Path, list[DomainConfigurationEntry]] = {}

    def clear(self):
        self.entries = {}

    def load(self, source: Union[Graph, str, IO], domain: Union[str, Path] = None):
        """
        Load from a Graph or Turtle document.
        :param source: Graph or Turtle file to load
        :param domain: Domain path filter
        :return:
        """
        service = ''
        if isinstance(source, Graph):
            g = source
        elif isinstance(source, str) and source.startswith('sparql:'):
            service = source[len('sparql:'):]
            g = Graph()
        else:
            g = Graph().parse(source)

        domain = None if not domain else Path(domain).resolve()

        cfggraph = g.query(DOMAIN_CFG_QUERY.replace('__SERVICE__', service)).graph

        for cfg_ref in cfggraph.subjects(RDF.type, DCFG.DomainConfiguration):

            globs = [str(g) for g in cfggraph.objects(cfg_ref, DCFG.glob)]
            uri_root_filter = cfggraph.value(cfg_ref, DCFG.uriRootFilter)
            profile_refs = cast(list[URIRef], list(cfggraph.objects(cfg_ref, DCTERMS.conformsTo)))

            for localpath in cfggraph.objects(cfg_ref, DCFG.localPath):
                localpath = Path(str(localpath))
                path = (self.working_directory / localpath).resolve()
                if domain is not None and path != domain:
                    continue

                entry = DomainConfigurationEntry(
                    working_directory=self.working_directory,
                    localpath=localpath,
                    glob=globs,
                    uri_root_filter=uri_root_filter,
                    conforms_to=profile_refs,
                )
                self.entries.setdefault(path, []).append(entry)

        if domain:
            logger.info("Found %d domain configuration entries for domain %s:\n - %s",
                        len(self.entries), domain,
                        '\n - '.join([g for entries in self.entries.values() for e in entries for g in e.glob]))
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
                    return entry

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
                return entries

    def find_all(self) -> 'dict[Path, DomainConfigurationEntry]':
        r = {}
        for entryList in self.entries.values():
            for entry in entryList:
                r.update({p: entry for p in entry.find_all()})
        return r

    def __len__(self):
        return len(self.entries)


class DomainConfigurationEntry:

    def __init__(self,
                 working_directory: Path,
                 localpath: Path,
                 glob: Sequence[str],
                 uri_root_filter: Optional[str] = None,
                 conforms_to: Optional[Sequence[URIRef]] = None):
        self.working_directory = working_directory
        self.localpath = localpath
        self.path = (working_directory / localpath).resolve()
        self.glob = glob if not isinstance(glob, str) else [glob]
        self.uri_root_filter = uri_root_filter
        self.conforms_to = [conforms_to] if isinstance(conforms_to, str) else conforms_to

    def find_all(self):
        return [item for g in self.glob for item in self.path.glob(g)]

    def matches(self, fn: Union[str, Path]):
        if not isinstance(fn, Path):
            fn = Path(fn)
        if self.path != fn.parent.resolve():
            return False
        return any(fn.match(g) for g in self.glob)
