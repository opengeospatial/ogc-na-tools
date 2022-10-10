#!/usr/bin/env python3
import logging
import sys
from glob import glob
from typing import Optional, Union
import argparse
from pathlib import Path
from urllib.parse import quote_plus

import httpx
from pyshacl import validate
from rdflib import Graph, URIRef, RDF, SKOS
import os

from ogc.na.domain_config import DomainConfiguration, DomainConfigurationEntry

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


def load_vocab(vocab: Path, guri, authdetails: tuple[str] = None):
    context = "{}/rdf4j-server/repositories/{}/statements?context=<{}>".format(RDF4JSERVER, REPO, quote_plus(guri))

    r = httpx.delete(
        context,
        auth=authdetails
    )
    r = httpx.post(
        context,
        params={"graph":  guri },
        headers={"Content-Type": "application/x-turtle;charset=UTF-8"},
        content=open(vocab, "rb").read(),
        auth= authdetails
    )
    assert 200 <= r.status_code <= 300, "Status code was {}".format(r.status_code)
    return context


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
             entailment_directory=DEFAULT_ENTAILED_DIR):

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
        "--sparql-endpoint",
        default=os.environ.get("SPARQL_ENDPOINT"),
        help="SPARQL endpoint (when --update enabled)"
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

    sparql_endpoint = args.sparql_endpoint or os.environ.get('SPARQL_ENDPOINT')

    if args.update and not sparql_endpoint:
        print("ERROR: --update requires a SPARQL endpoint", file=sys.stderr)
        sys.exit(-1)

    authdetails = None
    if 'DB_USERNAME' in os.environ:
        authdetails = (os.environ["DB_USERNAME"], os.environ.get("DB_PASSWORD", ""))

    if sparql_endpoint:
        logger.info(f"Using SPARQL endpoint %s with{'' if authdetails else 'out'} authentication", sparql_endpoint)

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
                # TODO: Implement
                pass

            report.setdefault(os.path.relpath(cfg.localpath), {}) \
                .setdefault(report_cat, []).append(os.path.relpath(doc))

    for scope, scopereport in report.items():
        logger.info("Scope: %s\n  added: %s\n  modified: %s",
                    scope, scopereport.get('added', []), scopereport.get('modified', []))

    sys.exit(0)


    for scopepath in DOMAIN_CFG.keys():
        cfglist = DOMAIN_CFG[scopepath]
        if not isinstance( cfglist,list) :
            cfglist = [cfglist]
        for cfg in cfglist:
            try:
                annotations = cfg['annotations']
            except:
                annotations = []

            if args.domain and args.domain != scopepath:
                continue
            modified = []
            domainlist = [os.path.normpath(i) for i in glob(scopepath+cfg['glob'])]

            if args.batch:
                # update modified list to be everything missing, or everything if -f
                if args.force :
                    modified = domainlist
                else:
                    # fix - this will be broken for globbing pattern
                    modified = list ( set(domainlist) - set(glob(scopepath+ "/entailed" + cfg['glob'])))


            for f in modlist:
                # if the file matches the glob using the scopepath and glob pattern  it's a vocab file
                if f.startswith(scopepath) and f.endswith(".ttl") and os.path.normpath(f) in domainlist:
                    modified.append(Path(f))

            added = []
            for f in addedlist:
                if f.startswith(scopepath) and f.endswith(".ttl") and os.path.normpath(f) in domainlist:
                    p = Path(f)
                    added.append(p)
            if modified + added :
                if 'extraont' in cfg and cfg['extraont'] :
                    extra_ont = get_closure_graph(cfg['extraont'])
                else:
                    extra_ont = None


            for f in modified + added:
                try:
                    newg = perform_entailments(cfg['rulelist'],f,extra=extra_ont, anno=annotations)
                    v = validate(data_graph=newg, ont_graph=extra_ont , inference='rdfs', shacl_graph=cfg['validator'])
                    if True or not v[0]:
                        with open( str(f).replace('.ttl','.txt') , "w" ) as vr:
                            vr.write(v[2])
                    loadable_path = make_rdf(f, g=newg,
                                             rootpath=cfg['uri_root_filter'],
                                             entailment_directory=args.entailment_directory)
                    if args.update:
                        loadlist = [loadable_path]
                        if annotations:
                            loadlist += annotations
                        try:
                            gname = list(get_graph_uri_for_vocab(None, newg))[0]
                        except:
                            gname = "x-urn:{}".format(str(f).replace('\\', ':'))
                        for n,loadable in enumerate(loadlist):
                            try:
                                # need to add annotations to a new context
                                loc = load_vocab( loadable, gname)
                                log("Uploaded {} for {} to   {} ".format(loadable, f, loc))
                            except  Exception as e:
                                log("Failed to upload {} for {} : ( {} )".format(loadable, f, e))
                            if n == 0 :
                                gname = gname+str(n+1)
                            else:
                                gname = gname[:-1] +str(n+1)
                except Exception as e:
                    log("Failed to generate {} : ( {}  )".format(f, e))

            removed = []
            if args.removed:
                for f in args.removed.split(","):
                    # if the file is in the vocabularies/ folder and ends with .ttl, it's a vocab file
                    if f.startswith(scopepath) and f.endswith(".ttl"):
                        p = Path(f)
                        removed.append(p)

            # print for testing
            print ( "Scope : {}".format(scopepath))
            if modified:
                print("modified:")
                print([str(x) for x in modified])
            if added:
                print("added:")
                print([str(x) for x in added])
            if removed:
                print("removed:")
                print([str(x) for x in removed])

