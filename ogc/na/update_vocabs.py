#!/usr/bin/env python3
"""
Implements an entailment + validation workflow.

`update_vocabs` starts by loading one or more
[DomainConfiguration's][ogc.na.domain_config.DomainConfiguration] from
RDF files and/or SPARQL endpoints, and a series of profile definitions
(also from a list of RDF files and/or SPARQL endpoints).
From there, individual or batch processing of files can be done,
as well as uploading the results to a target triplestore.

This script can be used as a library, or run directly from the cli;
please refer to the
[OGC NamingAuthority repository](https://github.com/opengeospatial/NamingAuthority)
for usage details on the latter.
"""

from __future__ import annotations
import argparse
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Union, Generator

import requests
from rdflib import Graph, RDF, SKOS

from ogc.na import util
from ogc.na.domain_config import DomainConfiguration, DomainConfigurationEntry
from ogc.na.provenance import generate_provenance, ProvenanceMetadata, FileProvenanceMetadata

logger = logging.getLogger('ogc.na.update_vocabs')

ENTAILED_FORMATS = [
    {'extension': 'ttl', 'format': 'ttl', 'mime': 'text/turtle'},
    {'extension': 'rdf', 'format': 'xml', 'mime': 'application/rdf+xml'},
    {'extension': 'jsonld', 'format': 'json-ld', 'mime': 'application/ld+json'},
]

DEFAULT_ENTAILED_DIR = 'entailed'


def setup_logging(debug: bool = False):
    """
    Sets up logging level and handlers (logs WARNING and ERROR
    to stderr).

    :param debug: whether to set DEBUG level
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

    fmt = logging.Formatter(fmt='%(name)s [%(levelname)s] %(message)s')

    handler_out = logging.StreamHandler(sys.stdout)
    handler_out.setLevel(logging.DEBUG)
    handler_out.setFormatter(fmt)
    handler_out.addFilter(lambda rec: rec.levelno <= logging.INFO)

    handler_err = logging.StreamHandler(sys.stderr)
    handler_err.setLevel(logging.WARNING)
    handler_err.setFormatter(fmt)

    root_logger.addHandler(handler_out)
    root_logger.addHandler(handler_err)


def load_vocab(vocab: Union[Graph, str, Path], graph_uri: str,
               graph_store: str, auth_details: tuple[str] = None) -> None:
    """
    Loads a vocabulary onto a triplestore using the [SPARQL Graph Store
    protocol](https://www.w3.org/TR/sparql11-http-rdf-update/).

    :param vocab: the file or Graph to load
    :param graph_uri: a target graph URI
    :param graph_store: the target SPARQL Graph Store protocol URL
    :param auth_details: a `(username, password)` tuple for authentication
    :return:
    """
    # PUT is equivalent to DROP GRAPH + INSERT DATA
    # Graph is automatically created per Graph Store spec

    if isinstance(vocab, Graph):
        content = vocab.serialize(format='ttl')
    else:
        with open(vocab, 'rb') as f:
            content = f.read()

    r = requests.put(
        graph_store,
        params={
            'graph': graph_uri,
        },
        auth=auth_details,
        headers={
            'Content-type': 'text/turtle',
        },
        data=content
    )
    logger.debug('HTTP status code: %d', r.status_code)
    r.raise_for_status()


def get_graph_uri_for_vocab(g: Graph = None) -> Generator[str, None, None]:
    """
    Find a target graph URI in a vocabulary [Graph][rdflib.Graph].

    In effect, this function merely looks for
    [SKOS ConceptScheme's](https://www.w3.org/TR/2008/WD-skos-reference-20080829/skos.html#ConceptScheme).

    :param g: the [Graph][rdflib.Graph] for which to find the target URI
    :return: a [Node][rdflib.term.Node] generator
    """
    for s in g.subjects(predicate=RDF.type, object=SKOS.ConceptScheme):
        yield str(s)


def get_entailed_base_path(f: Path, g: Graph, rootpattern: Union[str, None] = None,
                           entailed_dir: str = DEFAULT_ENTAILED_DIR) -> tuple:
    """
    Tries to find the base output file path for an entailed version of a source Graph.

    :param f: the original path of the source file
    :param g: the [Graph][rdflib.Graph] loaded from the source file
    :param rootpattern: a root pattern to filter candidate URIs
    :param entailed_dir: the name of the base entailed files directory
    """

    if not rootpattern:
        # just assume filename is going to be fine
        return (f.parent / entailed_dir / f.name,
                f.name, next(get_graph_uri_for_vocab(g), None))

    canonical_filename = None
    conceptscheme = None
    multiple_cs_warning = True
    for graphuri in get_graph_uri_for_vocab(g):

        if rootpattern in graphuri:
            cs_filename = graphuri.rsplit(rootpattern)[1].split('#', 1)[0]
            conceptscheme = graphuri
        else:
            logger.info('File %s: ignoring concept scheme %s not matching domain path %s',
                        str(f), graphuri, rootpattern)
            continue

        if canonical_filename and canonical_filename != cs_filename and multiple_cs_warning:
            multiple_cs_warning = False
            logger.warning("File %s contains multiple concept schemes", str(f))

        canonical_filename = cs_filename

    if not canonical_filename:
        logger.warning('File %s contains no concept schemes matching domain path %s; using filename',
                       str(f), rootpattern)
        canonical_filename = f.name
    elif canonical_filename.startswith('/'):
        canonical_filename = canonical_filename[1:]

    return (f.parent / entailed_dir / Path(canonical_filename),
            canonical_filename, conceptscheme)


def make_rdf(filename: Union[str, Path], g: Graph, rootpath: Union[str, None] = None,
             entailment_directory: Union[str, Path] = DEFAULT_ENTAILED_DIR,
             provenance_metadata: ProvenanceMetadata = None,) -> Path:
    """
    Serializes entailed RDF graphs in several output formats for a given input
    graph.

    :param filename: the original source filename
    :param g: [Graph][rdflib.Graph] loaded from the source file
    :param rootpath: a path to filter concept schemes inside the Graph and infer the main one
    :param provenance_metadata: provenance metadata (None to ignore)
    :param entailment_directory: name for the output subdirectory for entailed files
    :return: the output path for the Turtle version of the entailed files
    """
    if not isinstance(filename, Path):
        filename = Path(filename)
    filename = filename.resolve()

    if isinstance(entailment_directory, Path):
        entailment_directory = entailment_directory.resolve()

    loadable_ttl = None
    newbasepath, canonical_filename, conceptschemeuri = \
        get_entailed_base_path(filename, g, rootpath, entailment_directory)
    if newbasepath:
        newbasepath.parent.mkdir(parents=True, exist_ok=True)
    for entailed_format in ENTAILED_FORMATS:
        if newbasepath:
            newpath = newbasepath.with_suffix('.' + entailed_format['extension'])
            if provenance_metadata:
                provenance_metadata.generated = FileProvenanceMetadata(filename=newpath,
                                                                       mime_type=entailed_format['mime'],
                                                                       use_bnode=False)
                g = generate_provenance(g + Graph(), provenance_metadata, 'ogc.na.update_vocabs')
            g.serialize(destination=newpath, format=entailed_format['format'])
            if entailed_format['format'] == 'ttl':
                loadable_ttl = newpath

    if filename.stem != canonical_filename:
        logger.info("New file name %s -> %s for %s",
                    filename.stem, canonical_filename, conceptschemeuri)

    return loadable_ttl


def _main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-p",
        "--profile-source",
        nargs="*",
        default=[],
        help=("Profile source (can be a local or remote RDF file, "
              "or a SPARQL endpoint in the form 'sparql:http://example.org/sparql')"),
    )

    parser.add_argument(
        "domain_cfg",
        metavar="domain-cfg",
        help=("Domain configuration (can be a local or remote RDF file, "
              "or a SPARQL endpoint in the form 'sparql:http://example.org/sparql')"),
    )

    parser.add_argument(
        "-m",
        "--modified",
        help="Vocabs to be updated in the DB",
    )

    parser.add_argument(
        "-a",
        "--added",
        help="Vocabs to be added to the DB",
    )

    parser.add_argument(
        "-r",
        "--removed",
        help="Vocabs to be removed from the DB",
    )

    parser.add_argument(
        "-d",
        "--domain",
        help="Batch process specific domain",
    )

    parser.add_argument(
        "-i",
        "--initialise",
        help="Initialise Database",
    )

    parser.add_argument(
        "-u",
        "--update",
        action='store_true',
        help="Update triplestore",
    )

    parser.add_argument(
        "-b",
        "--batch",
        action='store_true',
        help="Batch entail all vocabs",
    )

    parser.add_argument(
        "-s",
        "--graph-store",
        default=os.environ.get("SPARQL_ENDPOINT"),
        help="SPARQL Graph Store-compatible endpoint (when --update enabled)"
    )

    parser.add_argument(
        "-w",
        "--working-directory",
        help="Change base working directory for domain configuration"
    )

    parser.add_argument(
        "-e",
        "--entailment-directory",
        default=DEFAULT_ENTAILED_DIR,
        help="Name of the subdirectory that entailed files will be written to",
    )

    parser.add_argument(
        "-l",
        "--local-artifact-mappings",
        nargs="*",
        help="Local path artifact mappings in the form baseURL=localPath",
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help="Enable debugging"
    )

    parser.add_argument(
        '-o',
        '--output-directory',
        help='Output directory where new files will be generated',
    )

    parser.add_argument(
        '--no-provenance',
        help='Do not add provenance metadata to output files',
    )

    parser.add_argument(
        '--base-uri',
        default='https://raw.githubusercontent.com/opengeospatial/NamingAuthority/master/',
        help='Base URI for provenance metadata',
    )

    parser.add_argument(
        '--use-git-status',
        action='store_true',
        help='Use git status for obtaining batch filenames'
    )

    parser.add_argument(
        '--auth',
        help="Authentication for uploading data to the triplestore in 'username:password' format. "
             "Alternatively, you can set the DB_USERNAME and DB_PASSWORD env variables."
    )

    parser.add_argument(
        '--ignore-artifact-errors',
        action='store_true',
        help='Ignore errors when retrieving profile artifacts'
    )

    args = parser.parse_args()

    setup_logging(args.debug)

    graph_store = args.graph_store or os.environ.get('SPARQL_GRAPH_STORE')

    if args.update and not graph_store:
        print("ERROR: --update requires a SPARQL Graph Store endpoint", file=sys.stderr)
        sys.exit(-1)

    authdetails = None
    if args.auth:
        authdetails = tuple(args.auth.split(':', maxsplit=1))
    elif 'DB_USERNAME' in os.environ:
        authdetails = (os.environ["DB_USERNAME"], os.environ.get("DB_PASSWORD", ""))

    if graph_store:
        logger.info(f"Using SPARQL graph store %s with{'' if authdetails else 'out'} authentication", graph_store)

    mod_list = []
    add_list = []

    if args.use_git_status:
        git_status = util.git_status()
        add_list = git_status['added']
        mod_list = git_status['modified'] + [r[1] for r in git_status['renamed']]
        logger.info("Using git status\n - added: %s\n - modified: %s", add_list, mod_list)
    else:
        if args.modified:
            mod_list = args.modified.split(",")
            logger.info("Modified: %s", mod_list)

        if args.added:
            add_list = args.added.split(",")
            logger.info("Added: %s", add_list)

        if args.removed:
            dellist = args.removed.split(',')
            logger.info("Removed: %s", dellist)

    local_artifacts_mappings = {}
    if args.local_artifact_mappings:
        for mappingstr in args.local_artifact_mappings:
            mapping = mappingstr.split('=', 1)
            if len(mapping) < 2:
                raise Exception(f"Invalid local artifact mapping: {mappingstr}")
            local_artifacts_mappings[mapping[0]] = mapping[1]

    domain_cfg = DomainConfiguration(args.domain_cfg, working_directory=args.working_directory,
                                     profile_sources=args.profile_source,
                                     ignore_artifact_errors=args.ignore_artifact_errors,
                                     local_artifacts_mappings=local_artifacts_mappings)
    cfg_entries = domain_cfg.entries
    if not len(cfg_entries):
        if args.domain:
            logger.warning('No configuration found in %s for domain %s, exiting',
                           args.domain_cfg, args.domain)
        else:
            logger.warning('No configuration found in %s exiting', args.domain_cfg)
        sys.exit(1)

    profile_registry = domain_cfg.profile_registry

    modified: dict[Path, DomainConfigurationEntry]
    added: dict[Path, DomainConfigurationEntry]
    if args.batch:
        modified = cfg_entries.find_all()
        added = {}
    else:
        modified = cfg_entries.find_entries_for_files(mod_list)
        added = cfg_entries.find_entries_for_files(add_list)

    output_path = Path(args.output_directory) if args.output_directory else None

    report = {}
    activity_id = str(uuid.uuid4())
    cmdline = 'python ogc.na.update_vocabs ' + " ".join(sys.argv[1:])
    for collection in (modified, added):
        report_cat = 'modified' if collection == modified else 'added'
        for doc, cfg in collection.items():
            logger.info("Processing %s", doc)

            if args.no_provenance:
                provenance_metadata = None
            else:
                provenance_metadata = ProvenanceMetadata(
                    used=[FileProvenanceMetadata(filename=doc),
                          FileProvenanceMetadata(filename=args.domain_cfg)],
                    start=datetime.now(),
                    end_auto=True,
                    root_directory=domain_cfg.working_directory,
                    batch_activity_id=activity_id,
                    activity_label='Entailment and validation',
                    comment=cmdline,
                    base_uri=args.base_uri,
                )

            origg = Graph().parse(doc)
            newg, entail_artifacts = profile_registry.entail(origg, cfg.conforms_to)
            validation_result = profile_registry.validate(newg, cfg.conforms_to, log_artifact_errors=True)

            if provenance_metadata:
                def add_artifact(a: Union[str, Path]):
                    if isinstance(a, Path):
                        provenance_metadata.used.append(FileProvenanceMetadata(filename=a))
                    else:
                        provenance_metadata.used.append(FileProvenanceMetadata(uri=a))
                for ea in entail_artifacts or ():
                    add_artifact(ea)
                for res in validation_result.used_resources or ():
                    add_artifact(res)

            docrelpath = Path(os.path.relpath(doc, args.working_directory))
            if output_path:
                output_doc = output_path.resolve() / docrelpath
                entailment_dir = output_doc.parent / args.entailment_directory
            else:
                entailment_dir = DEFAULT_ENTAILED_DIR

            loadable_path = make_rdf(doc, newg, cfg.uri_root_filter,
                                     entailment_dir, provenance_metadata)
            with open(loadable_path.with_suffix('.txt'), 'w') as validation_file:
                validation_file.write(validation_result.text)

            if args.update:
                loadables = {
                    loadable_path: loadable_path
                }
                for p, g in profile_registry.get_annotations(newg).items():
                    if p != loadable_path:
                        loadables[p] = g

                graphname = next(get_graph_uri_for_vocab(newg), None)
                if not graphname:
                    logger.warning("No graph name could be deduced from the vocabulary")
                    # Create graph name from a colon-separated list of
                    # path components relative to the working directory
                    urnpart = ':'.join(p for p in docrelpath.parts if p and p != '..')
                    graphname = "x-urn:{}".format(urnpart)
                logger.info("Using graph name %s for %s", graphname, str(doc))

                versioned_gname = graphname
                for n, (path, loadable) in enumerate(loadables.items()):
                    try:
                        load_vocab(loadable, versioned_gname,
                                   args.graph_store, authdetails)
                        logging.info("Uploaded %s for %s to SPARQL graph store",
                                     str(path), str(doc))
                    except Exception as e:
                        logging.error("Failed to upload %s for %s: %s",
                                      str(path), str(doc), str(e))
                        raise e
                    versioned_gname = f'{graphname}{n + 1}'

            report.setdefault(cfg.identifier, {}) \
                .setdefault(report_cat, []).append(os.path.relpath(doc))

    for scope, scopereport in report.items():
        logger.info("Scope: %s\n  added: %s\n  modified: %s",
                    scope, scopereport.get('added', []), scopereport.get('modified', []))


if __name__ == "__main__":
    _main()
