#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Union

import httpx
from pyshacl import validate
from rdflib import Graph, URIRef, RDF, SKOS

from ogc.na.domain_config import DomainConfiguration

logger = logging.getLogger('update_vocabs')

# extension: rdflib format
ENTAILED_FORMATS = {
    'ttl': 'ttl',
    'rdf': 'xml',
    'jsonld': 'json-ld'
}

DEFAULT_ENTAILED_DIR = 'entailed'


def _copy_triples(src: Graph, dst: Optional[Graph] = None):
    if dst is None:
        dst = Graph()
    for s, p, o in src:
        dst.add((s, p, o))
    return dst


def setup_logging(debug: bool = False):
    '''
    Sets up logging level and handlers (logs WARNING and ERROR
    to stderr)

    :param debug: whether to set DEBUG level
    '''
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


def load_vocab(vocab: Path, graph_uri: str,
               graph_store: str, authdetails: tuple[str] = None) -> None:

    # PUT is equivalent to DROP GRAPH + INSERT DATA
    # Graph is automatically created per Graph Store spec
    with open(vocab, 'rb') as f:
        r = httpx.put(
            graph_store,
            params={
                'graph': graph_uri,
            },
            auth=authdetails,
            headers={
                'Content-type': 'text/turtle',
            },
            content=f.read()
        )
    logger.debug('HTTP status code: %d', r.status_code)
    r.raise_for_status()


def get_graph_uri_for_vocab(g: Graph = None) -> URIRef:
    """
    We can get the Graph URI for a vocab using assumption that
    the ConceptScheme is declared in the graph being processed.
    """
    for s in g.subjects(predicate=RDF.type, object=SKOS.ConceptScheme):
        yield str(s)


def get_entailed_path(f: Path, g: Graph, extension, rootpattern='/def/',
                      entailed_dir=DEFAULT_ENTAILED_DIR):

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
             entailment_directory=DEFAULT_ENTAILED_DIR) -> Path:

    if not isinstance(filename, Path):
        filename = Path(filename)
    filename = filename.resolve()

    loadable_ttl = None
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


def perform_entailments(g: Graph,
                        rules: Graph,
                        extra: Optional[Graph] = None):
    entailed_extra = None
    if extra:
        entailed_extra = _copy_triples(extra)
        validate(entailed_extra, shacl_graph=rules, ont_graph=None, advanced=True, inplace=True)

    validate(g, shacl_graph=rules, ont_graph=extra, advanced=True, inplace=True)

    if entailed_extra:
        for s, p, o in entailed_extra:
            g.remove((s, p, o))

    return g


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "domaincfg",
        metavar="domain-cfg",
        help="Domain configuration Turtle file",
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

    # parser.add_argument(
    #     "-f",
    #     "--force",
    #     action='store_true',
    #     help="force overwrite of existing entailments",
    # )

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
        help="Name of the subdirectory that entailed files will be written to"
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help="Enable debugging"
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

    domaincfg = (DomainConfiguration(args.working_directory)
                 .load(args.domaincfg, domain=args.domain))

    if not len(domaincfg):
        if args.domain:
            logger.warning('No configuration found in %s for domain %s, exiting',
                           args.domaincfg, args.domain)
        else:
            logger.warning('No configuration found in %s exiting', args.domaincfg)

        sys.exit(1)

    if args.batch:
        modified = domaincfg.find_all()
        added = {}
    else:
        modified = domaincfg.find_files(modlist)
        added = domaincfg.find_files(addlist)

    report = {}
    for collection in (modified, added):
        report_cat = 'modified' if collection == modified else 'added'
        for doc, cfg in collection.items():
            origg = Graph().parse(doc)
            newg = perform_entailments(origg,
                                       cfg.rules,
                                       extra=cfg.extra_ontology)
            validation_result = validate(data_graph=newg,
                             ont_graph=cfg.extra_ontology,
                             inference='rdfs',
                             shacl_graph=cfg.validator)

            with open(doc.with_suffix('.txt'), 'w') as validation_file:
                validation_file.write(validation_result[2])

            loadable_path = make_rdf(doc, newg, cfg.uri_root_filter)

            if args.update:
                loadables = {
                    loadable_path: loadable_path
                }
                if cfg.annotation:
                    loadables[cfg.annotation_path] = cfg.annotation

                graphname = next(get_graph_uri_for_vocab(newg), None)
                if not graphname:
                    logger.warning("No graph name could be deduced from the vocabulary")
                    # Create graph name from a colon-separated list of
                    # path components relative to the working directory
                    relpath = Path(os.path.relpath(doc, args.working_directory))
                    urnpart = ':'.join(p for p in relpath.parts if p and p != '..')
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
                    versioned_gname = f'{graphname}{n+1}'

            report.setdefault(os.path.relpath(cfg.localpath), {}) \
                .setdefault(report_cat, []).append(os.path.relpath(doc))

    for scope, scopereport in report.items():
        logger.info("Scope: %s\n  added: %s\n  modified: %s",
                    scope, scopereport.get('added', []), scopereport.get('modified', []))
