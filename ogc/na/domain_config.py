#!/usr/bin/env python3
"""
This module contains classes to load RDF domain configuration files (DCAT-like catalogs)
defining how to find and select files for processing.
"""

from __future__ import annotations
import logging
import os
from pathlib import Path
from typing import Union, Optional, Sequence, cast, IO, TypeVar, Iterable

import wcmatch.glob
from rdflib import Graph, Namespace, URIRef, DCTERMS, DCAT, Literal
from wcmatch.glob import globmatch

from ogc.na.profile import ProfileRegistry

DCFG = Namespace('http://www.example.org/ogc/domain-cfg#')

CE = TypeVar('CE', bound='ConfigurationEntry')

DOMAIN_CFG_QUERY = """
    PREFIX dcat: <http://www.w3.org/ns/dcat#>
    PREFIX dcfg: <http://www.example.org/ogc/domain-cfg#>
    PREFIX dct: <http://purl.org/dc/terms/>
    CONSTRUCT {
        ?catalog dcat:dataset ?domainCfg ;
            dcfg:localArtifactMapping ?mapping ;
            dcfg:hasProfileSource ?profileSource ;
            dcfg:ignoreProfileArtifactErrors ?ignoreProfileArtifactErrors .
        ?domainCfg a ?configType ;
            dcfg:glob ?glob ;
            dcfg:uriRootFilter ?uriRootFilter ;
            dct:conformsTo ?profile ;
            dcfg:hasUpliftDefinition ?upliftDefinition ;
            dct:identifier ?identifier .
        ?upliftDefinition dcfg:file ?upliftFile ;
            dcfg:profile ?upliftProfile ;
            dcfg:order ?upliftOrder .
        ?mapping dcfg:baseURI ?mappingBaseURI ;
            dcfg:localPath ?mappingLocalPath .
    } WHERE {
        __SERVICE__ {
            ?catalog dcat:dataset ?domainCfg .
            {
                ?domainCfg a dcfg:DomainConfiguration ;
                    dcfg:glob ?glob .
                BIND(dcfg:DomainConfiguration as ?configType)
                OPTIONAL {
                    ?domainCfg dcfg:uriRootFilter ?uriRootFilter .
                }
                OPTIONAL {
                    ?domainCfg dct:conformsTo ?profile
                }
            } UNION {
                ?domainCfg a dcfg:UpliftConfiguration ;
                    dcfg:glob ?glob ;
                    dcfg:hasUpliftDefinition ?upliftDefinition .
                BIND(dcfg:UpliftConfiguration as ?configType)
                {
                    ?upliftDefinition dcfg:file ?upliftFile
                } UNION {
                    ?upliftDefinition dcfg:profile ?upliftProfile
                }
                OPTIONAL {
                    ?upliftDefinition dcfg:order ?upliftOrder
                }
            }
            OPTIONAL {
                ?domainCfg dct:identifier ?identifier
            }
            OPTIONAL {
                ?catalog dcfg:localArtifactMapping ?mapping .
                ?mapping dcfg:baseURI ?mappingBaseURI ;
                    dcfg:localPath ?mappingLocalPath .
            }
            OPTIONAL {
                ?catalog dcfg:hasProfileSource ?profileSource
            }
            OPTIONAL {
                ?catalog dcfg:ignoreProfileArtifactErrors ?ignoreProfileArtifactErrors
            }
        }
  }
"""

logger = logging.getLogger('ogc.na.domain_config')


class DomainConfiguration:
    """
    The DomainConfiguration class can load a collection of ConfigurationEntry's
    detailing which files need to be processed and where they can be found, as well
    as including a list of profiles for entailment, validation, and (potentially)
    other operations.

    Domain configurations use the `http://www.example.org/ogc/domain-cfg#` (dcfg) prefix.

    A domain configuration must include, at least, a `dcfg:glob` (glob expression to find/filter
    files inside the base directory). If present, a `dcfg:uriRootFilter` will be used to determine
    which is the main concept scheme in the file (if more than one is found). Profiles for
    validation, entailment, etc. can be specified using `dcterms:conformsTo`.

    `dcfg:hasUpliftDefinition` can also be used to declare (ordered) semantic uplift definitions, either
    from profile artifacts or from files.
    """

    def __init__(self, source: Union[Graph, str, Path, IO], working_directory: str | Path = None,
                 profile_sources: str | Path | Iterable[str | Path] | None = None,
                 ignore_artifact_errors=False, local_artifacts_mappings: dict | None = None):
        """
        Creates a new DomainConfiguration, optionally specifying the working directory.

        :param source: Graph or Turtle file to load
        :param working_directory: the working directory to use for local paths.
        """
        if working_directory:
            self.working_directory = Path(working_directory).resolve()
        elif isinstance(source, str) or isinstance(source, Path):
            self.working_directory = Path(source).parent.resolve()
        else:
            self.working_directory = Path().resolve()
        logger.info("Working directory: %s", self.working_directory)
        self.entries = ConfigurationEntryList()
        self.uplift_entries = UpliftConfigurationEntryList()
        self.local_artifacts_mappings = {}
        if local_artifacts_mappings:
            self.local_artifacts_mappings.update(local_artifacts_mappings)
        self.profile_registry: ProfileRegistry | None = None
        self._profile_sources = profile_sources
        self._ignore_artifact_errors = ignore_artifact_errors

        self._load(source)

    def _load(self, source: Union[Graph, str, IO]):
        """
        Load entries from a Graph or Turtle document.

        :param source: Graph or Turtle file to load
        :return: this DomainConfiguration instance
        """
        service = ''
        if isinstance(source, Graph):
            g = source
        elif isinstance(source, str) and source.startswith('sparql:'):
            service = source[len('sparql:'):]
            g = Graph()
        else:
            g = Graph().parse(source)

        cfg_graph = g.query(DOMAIN_CFG_QUERY.replace('__SERVICE__', service)).graph

        ignore_profile_artifact_errors = self._ignore_artifact_errors

        prof_sources: set[str | Path] = set()
        for catalog_ref in cfg_graph.subjects(DCAT.dataset):
            logger.debug("Found catalog %s", catalog_ref)

            if bool(cfg_graph.value(catalog_ref, DCFG.ignoreProfileArtifactErrors)):
                ignore_profile_artifact_errors = True

            # Local artifacts mapping
            for mapping_ref in cfg_graph.objects(catalog_ref, DCFG.localArtifactMapping):
                base_uri = str(cfg_graph.value(mapping_ref, DCFG.baseURI))
                if base_uri in self.local_artifacts_mappings:
                    logger.debug("Local artifact mapping for %s overriden", base_uri)
                    # Overriden
                    continue
                local_path = Path(str(cfg_graph.value(mapping_ref, DCFG.localPath)))
                logger.debug("Found local artifact mapping: %s -> %s", base_uri, local_path)
                self.local_artifacts_mappings[base_uri] = local_path

            # Profile sources
            for p in cfg_graph.objects(catalog_ref, DCFG.hasProfileSource):
                if not isinstance(p, Literal):
                    continue
                if p.value.startswith('sparql:'):
                    prof_sources.add(p.value)
                else:
                    prof_sources.update(self.working_directory.glob(p.value))

            if self._profile_sources:
                prof_sources.update(self._profile_sources)

        self.profile_registry = ProfileRegistry(prof_sources,
                                                ignore_artifact_errors=ignore_profile_artifact_errors,
                                                local_artifact_mappings=self.local_artifacts_mappings)

        for cfg_ref in cfg_graph.objects(predicate=DCAT.dataset):

            globs = [str(g) for g in cfg_graph.objects(cfg_ref, DCFG.glob)]

            # DomainConfigurationEntry specific properties
            uri_root_filter = cfg_graph.value(cfg_ref, DCFG.uriRootFilter)
            profile_refs = cast(list[URIRef], list(cfg_graph.objects(cfg_ref, DCTERMS.conformsTo)))

            # UpliftConfigurationEntry specific properties
            found_uplift_defs = []
            max_order = None
            for uplift_def_ref in cfg_graph.objects(cfg_ref, DCFG.hasUpliftDefinition):
                order = cfg_graph.value(uplift_def_ref, DCFG.order)
                if order is not None and (max_order is None or int(order) > max_order):
                    max_order = int(order)
                target_prof = cfg_graph.value(uplift_def_ref, DCFG.profile)
                target_file = cfg_graph.value(uplift_def_ref, DCFG.file)
                if target_prof:
                    found_uplift_defs.append([order, target_prof])
                elif target_file:
                    found_uplift_defs.append([order, self.working_directory.joinpath(str(target_file)).resolve()])
            uplift_defs = [p[1] for p in
                           sorted(found_uplift_defs,
                                  key=lambda u: u[0] if u[0] is not None else max_order + 1)]

            identifier = cfg_graph.value(cfg_ref, DCTERMS.identifier) or str(cfg_ref)

            if profile_refs:
                self.entries.append(DomainConfigurationEntry(
                    working_directory=self.working_directory,
                    glob=globs,
                    identifier=identifier,
                    uri_root_filter=uri_root_filter,
                    conforms_to=profile_refs,
                ))

            if uplift_defs:
                self.uplift_entries.append(UpliftConfigurationEntry(
                    working_directory=self.working_directory,
                    glob=globs,
                    identifier=identifier,
                    uplift_definitions=uplift_defs,
                ))

        logger.info("Found %d domain configurations and %d uplift configurations",
                    len(self.entries),
                    len(self.uplift_entries))

        return self

    def __len__(self):
        return len(self.entries) + len(self.uplift_entries)


class ConfigurationEntry:

    def __init__(self,
                 working_directory: Path,
                 glob: Sequence[str],
                 identifier: str):
        if not isinstance(working_directory, Path):
            working_directory = Path(working_directory)
        self.working_directory = working_directory.resolve()
        self.globs = glob if not isinstance(glob, str) else [glob]
        self.identifier = identifier

    def find_all(self) -> set[Path]:
        return set(item for g in self.globs for item in self.working_directory.glob(g))

    def matches(self, fn: str | Path) -> bool:
        if not isinstance(fn, Path):
            fn = Path(fn)
        fn = os.path.relpath(fn.resolve(), self.working_directory)
        return globmatch(fn, self.globs, flags=wcmatch.glob.G)


class DomainConfigurationEntry(ConfigurationEntry):

    def __init__(self,
                 working_directory: Path,
                 glob: Sequence[str],
                 identifier: str,
                 uri_root_filter: Optional[str] = None,
                 conforms_to: Optional[Sequence[URIRef]] = None):
        super().__init__(working_directory, glob, identifier)
        self.uri_root_filter = uri_root_filter
        self.conforms_to = [conforms_to] if isinstance(conforms_to, str) else conforms_to


class UpliftConfigurationEntry(ConfigurationEntry):

    def __init__(self,
                 working_directory: Path,
                 glob: Sequence[str],
                 identifier: str,
                 uplift_definitions: Sequence[str | Path]):
        super().__init__(working_directory, glob, identifier)
        self.uplift_definitions = list(uplift_definitions)
        self.context_filenames = set(f for f in uplift_definitions if isinstance(f, Path))


class ConfigurationEntryList(list[CE]):

    def find_entry_for_file(self, fn: str | Path) -> ConfigurationEntry | None:
        """
        Find the configuration entry that corresponds to a file, if any.

        :param fn: the file name
        :return: a DomainConfigurationEntry, or None if none is found
        """
        if not isinstance(fn, Path):
            fn = Path(fn)

        for entry in self:
            if entry.matches(fn):
                return entry

    def find_entries_for_files(self, fns: list[str | Path]) -> 'dict[Path, ConfigurationEntry]':
        """
        Find the configuration entries associated to a list of files. Similar
        to [find_entry_for_file()][ogc.na.domain_config.ConfigurationEntryList.find_entry_for_file]
        but with a list of files.

        :param fns: a list of files to find
        :return: a path \u2192 DomainConfigurationEntry dict for each file that is found
        """
        result: dict[Path, ConfigurationEntry] = {}
        for fn in fns:
            p = Path(fn).resolve()
            e = self.find_entry_for_file(p)
            if e:
                result[p] = e
        return result

    def find_all(self) -> 'dict[Path, ConfigurationEntry]':
        """
        Find all the files referenced by this configuration entry list, including
        their DomainConfigurationEntry.

        :return: a path to DomainConfigurationEntry mapping (dict) including all files
        """
        r = {}
        for entry in self:
            r.update({p: entry for p in entry.find_all()})
        return r


class UpliftConfigurationEntryList(ConfigurationEntryList[UpliftConfigurationEntry]):

    def find_files_by_context_fn(self, context_fn: Path) -> set[Path]:
        context_fn = context_fn.resolve()
        result: set[Path] = set()
        for entry in self:
            if context_fn in entry.context_filenames:
                result.update(entry.find_all())
        return result
