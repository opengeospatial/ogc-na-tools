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

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Union, Generator

import requests
from rdflib import Graph, RDF, SKOS

from ogc.na.domain_config import DomainConfiguration, DomainConfigurationEntry
from ogc.na.profile import ProfileRegistry

logger = logging.getLogger('update_vocabs')

# extension: rdflib format
ENTAILED_FORMATS = {
    'ttl': 'ttl',
    'rdf': 'xml',
    'jsonld': 'json-ld'
}

DEFAULT_ENTAILED_DIR = 'entailed'


def setup_logging(debug: bool = False):
    """
    Sets up logging level and handlers (logs WARNING and ERROR
    to stderr).

    :param debug: whether to set DEBUG level
    """
    rootlogger = logging.getLogger()
    rootlogger.setLevel(logging.DEBUG if debug else logging.INFO)

    fmt = logging.Formatter(fmt='%(name)s [%(levelname)s] %(message)s')

    hout = logging.StreamHandler(sys.stdout)
    hout.setLevel(logging.DEBUG)
    hout.setFormatter(fmt)
    hout.addFilter(lambda rec: rec.levelno <= logging.INFO)

    herr = logging.StreamHandler(sys.stderr)
    herr.setLevel(logging.WARNING)
    herr.setFormatter(fmt)

    rootlogger.addHandler(hout)
    rootlogger.addHandler(herr)


def load_vocab(vocab: Union[Graph, str, Path], graph_uri: str,
               graph_store: str, authdetails: tuple[str] = None) -> None:
    """
    Loads a vocabulary onto a triplestore using the [SPARQL Graph Store
    protocol](https://www.w3.org/TR/sparql11-http-rdf-update/).

    :param vocab: the file or Graph to load
    :param graph_uri: a target graph URI
    :param graph_store: the target SPARQL Graph Store protocol URL
    :param authdetails: a `(username, password)` tuple for authentication
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
        auth=authdetails,
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


def get_entailed_path(f: Path, g: Graph, extension: str, rootpattern: str = '/def/',
                      entailed_dir: str = DEFAULT_ENTAILED_DIR):
    """
    Tries to find the output file path for an entailed version of a source Graph.

    :param f: the original path of the source file
    :param g: the [Graph][rdflib.Graph] loaded from the source file
    :param extension: a filename extension (e.g., 'ttl' for Turtle)
    :param rootpattern: a root pattern to filter candidate URIs
    :param entailed_dir: the name of the base entailed files directory
    """
    if not rootpattern:
        # just assume filename is going to be fine
        return (f.parent / entailed_dir / f.with_suffix('.' + extension).name,
                f.name, get_graph_uri_for_vocab(g))

    canonical_filename = None
    conceptscheme = None
    for graphuri in get_graph_uri_for_vocab(g):
        if canonical_filename:
            logger.warning("File %s contains multiple concept schemes", str(f))

        if rootpattern in graphuri:
            canonical_filename = graphuri.rsplit(rootpattern)[1]
            conceptscheme = graphuri
        else:
            logger.info('File %s: ignoring concept scheme %s not matching domain path %s',
                        str(f), graphuri, rootpattern)

    if not canonical_filename:
        logger.warning('File %s contains no concept schemes matching domain path %s; using filename',
                       str(f), rootpattern)
        canonical_filename = f.name

    return (f.parent / entailed_dir / Path(canonical_filename).with_suffix('.' + extension),
            canonical_filename, conceptscheme)


def make_rdf(filename: Union[str, Path], g: Graph, rootpath='/def/',
             entailment_directory: Union[str, Path] = DEFAULT_ENTAILED_DIR) -> Path:
    """
    Serializes entailed RDF graphs in several output formats for a given input
    graph.

    :param filename: the original source filename
    :param g: [Graph][rdflib.Graph] loaded from the source file
    :param rootpath: a path to filter concept schemes inside the Graph and infer the main one
    :param entailment_directory: name for the output subdirectory for entailed files
    :return: the output path for the Turtle version of the entailed files
    """
    if not isinstance(filename, Path):
        filename = Path(filename)
    filename = filename.resolve()

    loadable_ttl = None
    canonical_filename = None
    conceptschemeuri = None
    for extension, fmt in ENTAILED_FORMATS.items():
        newpath, canonical_filename, conceptschemeuri = \
            get_entailed_path(filename, g, extension, rootpath, entailment_directory)

        if newpath:
            newpath.parent.mkdir(parents=True, exist_ok=True)
            g.serialize(destination=newpath, format=fmt)
            if fmt == 'ttl':
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
        nargs="+",
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
        help="Batch entail all vocabs ( use -f to force overwrite of existing entailments )",
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

    args = parser.parse_args()

    setup_logging(args.debug)

    graph_store = args.graph_store or os.environ.get('SPARQL_GRAPH_STORE')

    if args.update and not graph_store:
        print("ERROR: --update requires a SPARQL Graph Store endpoint", file=sys.stderr)
        sys.exit(-1)

    authdetails = None
    if 'DB_USERNAME' in os.environ:
        authdetails = (os.environ["DB_USERNAME"], os.environ.get("DB_PASSWORD", ""))

    if graph_store:
        logger.info(f"Using SPARQL graph store %s with{'' if authdetails else 'out'} authentication", graph_store)

    modlist = []
    addlist = []
    dellist = []

    if args.modified:
        modlist = args.modified.split(",")
        logger.info("Modified: %s", modlist)

    if args.added:
        addlist = args.added.split(",")
        logger.info("Added: %s", addlist)

    if args.removed:
        dellist = args.removed.split(',')
        logger.info("Removed: %s", dellist)

    domaincfg = DomainConfiguration(args.working_directory)
    for dcfg in args.domain_cfg:
        domaincfg.load(dcfg, domain=args.domain)
    if not len(domaincfg):
        if args.domain:
            logger.warning('No configuration found in %s for domain %s, exiting',
                           args.domaincfg, args.domain)
        else:
            logger.warning('No configuration found in %s exiting', args.domaincfg)
        sys.exit(1)

    artifact_mappings = dict(domaincfg.local_artifacts_mapping)
    if args.local_artifact_mappings:
        for mappingstr in args.local_artifact_mappings:
            mapping = mappingstr.split('=', 1)
            if len(mapping < 2):
                raise Exception(f"Invalid local artifact mapping: {mappingstr}")
            artifact_mappings[mapping[0]] = mapping[1]

    profile_registry = ProfileRegistry(args.profile_source,
                                       local_artifact_mappings=artifact_mappings,
                                       ignore_artifact_errors=True)

    modified: dict[Path, DomainConfigurationEntry]
    added: dict[Path, DomainConfigurationEntry]
    if args.batch:
        modified = domaincfg.find_all()
        added = {}
    else:
        modified = domaincfg.find_files(modlist)
        added = domaincfg.find_files(addlist)

    output_path = Path(args.output_directory) if args.output_directory else None

    report = {}
    for collection in (modified, added):
        report_cat = 'modified' if collection == modified else 'added'
        for doc, cfg in collection.items():
            logger.info("Processing %s", doc)
            origg = Graph().parse(doc)
            newg = profile_registry.entail(origg, cfg.conforms_to)
            validation_result = profile_registry.validate(newg, cfg.conforms_to)

            docrelpath = Path(os.path.relpath(doc, args.working_directory))
            if output_path:
                output_doc = output_path / docrelpath
                entailment_dir = (output_doc.parent / args.entailment_directory).resolve()
            else:
                entailment_dir = args.entailment_directory
                output_doc = doc

            os.makedirs(output_doc.parent, exist_ok=True)
            os.makedirs(entailment_dir, exist_ok=True)

            with open(output_doc.with_suffix('.txt'), 'w') as validation_file:
                validation_file.write(validation_result.text)

            loadable_path = make_rdf(doc, newg, cfg.uri_root_filter,
                                     entailment_dir)

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
                    versioned_gname = f'{graphname}{n + 1}'

            report.setdefault(os.path.relpath(cfg.localpath), {}) \
                .setdefault(report_cat, []).append(os.path.relpath(doc))

    for scope, scopereport in report.items():
        logger.info("Scope: %s\n  added: %s\n  modified: %s",
                    scope, scopereport.get('added', []), scopereport.get('modified', []))


if __name__ == "__main__":
    _main()
