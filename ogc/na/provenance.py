#!/usr/bin/env python3
from __future__ import annotations
import mimetypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Union, Optional, Sequence

from rdflib.term import Node

try:
    import git
except ImportError:
    git = None
from rdflib import Graph, URIRef, Literal, DCTERMS, RDF, RDFS, PROV, BNode
from requests.utils import requote_uri

from ogc.na import __version__, __url__


@dataclass
class FileProvenanceMetadata:
    filename: Union[str, Path] = None
    uri: str = None
    mime_type: str = None
    use_bnode: bool = True
    label: str = None


@dataclass
class ProvenanceMetadata:
    used: Union[FileProvenanceMetadata, list[FileProvenanceMetadata]] = None
    generated: Union[FileProvenanceMetadata, list[FileProvenanceMetadata]] = None
    start: datetime = None
    end: datetime = None
    end_auto: bool = False
    root_directory: Union[str, Path] = None
    base_uri: str = None
    batch_activity_id: str = None
    activity_label: str = None
    comment: str = None


def add_provenance_agent(g: Graph, module_name: str = None) -> Node:
    agent = BNode()
    g.add((agent, RDFS.seeAlso, URIRef(__url__)))
    g.add((agent, RDF.type, PROV.Agent))
    g.add((agent, RDF.type, URIRef('https://schema.org/SoftwareApplication')))
    g.add((agent, RDFS.label, Literal("OGC-NA tools")))
    if module_name:
        g.add((agent, RDFS.comment, Literal("{} version {}".format(module_name, __version__))))
    g.add((agent, DCTERMS.hasVersion, Literal(__version__)))
    return agent


def add_provenance_entity(g: Graph, metadata: FileProvenanceMetadata = None,
                          root_directory: Optional[Union[str, Path]] = None,
                          base_uri: Optional[str] = None) -> URIRef:
    entity = None
    mime = None
    if metadata:
        mime = metadata.mime_type

        if metadata.uri:
            metadata_uri = requote_uri(metadata.uri)
            if metadata.use_bnode:
                entity = BNode()
                g.add((entity, RDFS.seeAlso, URIRef(metadata_uri)))
            else:
                entity = URIRef(metadata_uri)
        elif metadata.filename:
            filename = Path(metadata.filename).resolve()
            uri = None

            if not mime:
                try:
                    mime = mimetypes.guess_type(filename)[0]
                except:
                    pass

            if root_directory and base_uri:
                root_directory = Path(root_directory).resolve()
                if filename.is_relative_to(root_directory):
                    rel = filename.relative_to(root_directory)
                    uri = f"{base_uri}{'/' if '#' not in base_uri and not base_uri.endswith('/') else ''}{rel}"

            uri = requote_uri(uri) if uri else filename.as_uri()
            if metadata.use_bnode:
                entity = BNode()
                g.add((entity, RDFS.seeAlso, URIRef(uri)))
            else:
                entity = URIRef(uri)

            if git:
                try:
                    git_repo = git.Repo(filename, search_parent_directories=True)
                    g.add((entity, DCTERMS.hasVersion, Literal(f"git:{git_repo.head.object.hexsha}")))
                except:
                    pass

    if not entity:
        entity = BNode()

    g.add((entity, RDF.type, PROV.Entity))

    if mime:
        g.add((entity, DCTERMS.format, Literal(mime)))

    if metadata.label:
        g.add((entity, RDFS.label, Literal(metadata.label)))

    return entity


def generate_provenance(g: Graph = None,
                        metadata: ProvenanceMetadata = None,
                        module_name: str = None) -> Graph:
    if g is None:
        g = Graph()

    if not metadata:
        metadata = ProvenanceMetadata()

    activity = BNode()

    agent = add_provenance_agent(g, module_name)

    if metadata.used:
        for used in metadata.used if isinstance(metadata.used, Sequence) else (metadata.used,):
            used = add_provenance_entity(g, metadata=used,
                                         root_directory=metadata.root_directory,
                                         base_uri=metadata.base_uri)
            g.add((activity, PROV.used, used))

    if metadata.generated:
        for generated in metadata.used if isinstance(metadata.generated, Sequence) else (metadata.generated,):
            generated = add_provenance_entity(g, metadata=generated,
                                              root_directory=metadata.root_directory,
                                              base_uri=metadata.base_uri)
            g.add((generated, PROV.wasGeneratedBy, activity))
            g.add((generated, PROV.wasAttributedTo, agent))

    g.add((activity, RDF.type, PROV.Activity))
    if metadata.activity_label:
        g.add((activity, RDFS.label, Literal(metadata.activity_label)))
    if metadata.start:
        g.add((activity, PROV.startedAtTime, Literal(metadata.start)))

    if metadata.end or metadata.end_auto:
        end = metadata.end if metadata.end else datetime.now()
        g.add((activity, PROV.endedAtTime, Literal(end)))
    if metadata.batch_activity_id:
        batch_activity = BNode()
        g.add((batch_activity, DCTERMS.identifier, Literal(metadata.batch_activity_id)))
        g.add((activity, PROV.wasInformedBy, batch_activity))
    if metadata.comment:
        g.add((activity, RDFS.comment, Literal(metadata.comment)))

    g.add((activity, PROV.wasAssociatedWith, agent))

    return g
