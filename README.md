# ogc-na-tools

## TL;DR

You can install the tools with `pip`:

```shell
pip install ogc-na
```

## Purpose
This repository contains tools used to maintain controlled vocabularies and knowledge assets managed by the OGC Naming Authority. Such tools may have wider general applicability and be refactored into tool specific repositories.

## Scope
The tools here manage ETL processes for ingesting source data into a dynamic knowledge graph. Whilst this is quite a generic scope, this provides examples of how to use a range of resources that others may reuse to achieve similar results.

## Highlights

* JSON ingest and conversion to RDF using semantic annotations and conversions to a target model schema.
* entailment and validation pipeline for RDF resources.
* specific scripts to convert OGC source material into a form compatible with the OGC Linked Data environment
* tutorial for docker deployment and testing of available tools.

## Documentation and tools

The full documentation can be found [here](https://opengeospatial.github.io/ogc-na-tools/).

The following tools are currently available:

* `ingest_json`: Performs JSON-to-JSON-LD semantic uplifts [(read more)](https://opengeospatial.github.io/ogc-na-tools/reference/ogc/na/ingest_json/) 
* `update_vocabs`: Allows defining RDF entailment + validation + upload pipelines [(read more)](https://opengeospatial.github.io/ogc-na-tools/reference/ogc/na/update_vocabs/)
* `annotate_schema`: Annotates JSON schemas by leveraging `@modelReference` links to JSON-LD contexts [(read more)](https://opengeospatial.github.io/ogc-na-tools/reference/ogc/na/annotate_schema/)

## Development

Note: This is only necessary if you are going to work *on* the tools themselves, not *with* them (see [TL;DR](#tldr)
above). 

To install runtime and development dependencies, run:

```shell
pip install -e .[dev]
```

### Building the documentation

`mkdocs` is used for generating documentation pages.

* To build the documentation (will be written to the `site/` directory): `mkdocs build`
* To deploy to GitHub pages: `mkdocs gh-deploy`
