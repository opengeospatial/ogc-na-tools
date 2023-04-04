# Examples

## Sample domain configuration

The following example shows a [domain configuration][ogc.na.domain_config] in Turtle format:

```turtle
@prefix dcfg: <http://www.example.org/ogc/domain-cfg#> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix profiles: <http://www.opengis.net/def/metamodel/profiles/> .

_:OGC-NA-Catalog a dcat:Catalog ;
  dct:title "OGC Naming Authority catalog" ;
  rdfs:label "OGC Naming Authority catalog" ;
                 
  # Map http://defs-dev.opengis.net/ogc-na/x/y/z.ttl to 
  # ./x/y/z.ttl
  dcfg:localArtifactMapping [
    dcfg:baseURI "http://defs-dev.opengis.net/ogc-na/" ;
    dcfg:localPath "./" ;
  ] ;
  
  # Link to enabled domain and uplift configurations
  dcat:dataset _:conceptSchemes, _:semanticUplift ;

  dcfg:hasProfileSource
    "sparql:https://example.org/sparql",
    "path/to/profile.ttl" ;
.

_:conceptSchemes a dcat:Dataset, dcfg:DomainConfiguration ;
  dct:identifier "conceptSchemes" ;
  dct:description "Set of terms registered with OGC NA not covered by specialised domains" ;
  
  # Which files to include
  dcfg:glob "definitions/conceptSchemes/*.ttl" ;
                 
  # URI root filter for detecting the main ConceptScheme in
  # the source files
  dcfg:uriRootFilter "/def/" ;
                 
  # Profile conformance can optionally be declared in the DomainConfiguration
  # as well as in the source data itself
  dct:conformsTo profiles:vocprez_ogc, profiles:skos_conceptscheme ;
.

_:semanticUplift a dcat:Dataset, dcfg:UpliftConfiguration;
  dct:identifier "semanticUplift" ;
  dct:description "Semantic uplift configuration" ;
  
  # Which files to include
  dcfg:glob "domain1/*.json", "domain2/*.json" ;

  # List of profiles (with semantic uplift artifacts) and/or files to 
  # use as uplift definitions
  dcfg:hasUpliftDefinition
    [ dcfg:order 1; dcfg:file "path/to/file.yaml" ],             # Local file
    [ dcfg:order 2; dcfg:profile profiles:vocprez_ogc ],         # Profile
    [ dcfg:order 3; dcfg:file "path/to/another/definition.yaml"] # Local file
  ;
.
```

## Sample JSON-LD uplift context

```yaml
# Sample single-file JSON-LD context
# Processing order is transform -> types -> context

# `path-scope` affects how ingest_json treats JSON-LD documents (e.g. when chaining uplifts).
# It can be `graph` (transformations and paths act on `@graph`, if any, instead of on the
# whole file) or `document` (do not treat JSON-LD files differently, process "as is").
# Default is `graph`.
path-scope: graph

# `transform` uses jq expressions for light data transformations
#   see: https://pypi.org/project/jq/
#   see: https://stedolan.github.io/jq/manual/
# This `transform` converts `"key": { ...value }` objects into an array
#   with `[{ "@id" : "#key", ...value }, ...]` items, and also adds
#   types `MyType` and `skos:Concept` to each of them
transform: '[to_entries[]|.value+{"@id":("#"+.key),"@type":["MyType", "skos:Concept"]}]'

# `types` adds @type annotations to nodes represented by a jsonpath-ng expression
# (note: expressions are matched against *transformed* data)
#   see: https://pypi.org/project/jsonpath-ng/
types:
  '$[?type="IS"]': [AddedClass, ISClass]
  '$[?type="DP"]': [AddedClass, DPClass]

# `base-uri` sets the base uri that will be used for JSON-LD.
#  This is sometimes necessary since pyld ignores the @base in the root @context
#   see: https://github.com/digitalbazaar/pyld/issues/143
base-uri: http://example.org/vocab#

# `context` adds JSON-LD @context to the root element (empty key, '.' or '$')
# or to specific elements using jsonpath-ng expressions (note: expressions are
# matched against *transformed* data
#   see: https://pypi.org/project/jsonpath-ng/
context:
  # global context
  '$': [
    # dcterms profile
    "http://defs-dev.opengis.net/ogc-na/definitions/profiles/resources/dcterms.jsonld",
    # skos profile
    "http://defs-dev.opengis.net/ogc-na/definitions/profiles/resources/skos.jsonld",

    # custom context for bibliography
    {
      "skos": "http://www.w3.org/2004/02/skos/core#",
      "@vocab": "http://example.org/vocab#",
      "type": "http://www.opengis.net/def/metamodel/ogc-na/doctype",
      "alternative": "skos:altLabel",
      "title": "skos:definition",
      "description": "rdfs:comment",
      "date": "dct:created",
      "URL": "rdfs:seeAlso"
    }
  ]

  # scoped context for elements with "type" = "IS"
  '$[?type="IS"]': {
    "@vocab": "http://example.org/vocab3#"
  }

# `context-position` dictates where the new context will be added if `@context` is already present
# at any of the specified paths. Can be `before` (a new entry, with lower precedence, will be preprended
# to any existing `@context`) or `after` (a new entry, with higher precedence, will be appended to any
# existing `@context`). It has no effect for plan JSON documents. 
context-position: before
```

## Sample JSON-LD context registry

The following example defines 3 profile sources (two from local files and one from a SPARQL endpoint),
and 3 domain configurations for semantic uplifts:

* One for JSON documents inside `domain1` and all its subdirectories, using a definition from a profile (`profileY`)
  and then another from a file. 
* Another one for JSON documents inside `domain2` (but not its subdirectories), using only a definition from a file
  (`profileZ`).
* A third one for JSON documents inside `domain3`, using two profile definitions sequentially (first from `profileQ`
and then from `profileR`).

Additionally, 2 local artifact mappings are declared, telling the profile artifact resolver to map
the `http://example.com/base/1` URL to the `artifacts/base/1` directory, and `http://example.com/another/base/`
to `artifacts/another/base`.

```json
{
  "contexts": {
    "domain1/**/*.json": [
      { "profile": "http://example.com/profileY" },
      { "file": "domain1/common.yml" }
    ],
    "domain2/*.json": { "profile": "http://example.com/profileZ" },
    "domain3/*.json": [
      { "profile": "http://example.com/profileQ" },
      { "profile": "http://example.com/profileR" }
    ]
  },
  
  "profileSources": [
    { "file": "profiles/my-profile.ttl" },
    { "file": "also-supports-globs/*.ttl" },
    { "sparql":  "http://example.com/sparql" }
  ],
  
  "localArtifactMappings": [
      { "http://example.com/base/1": "artifacts/base/1" },
      { "http://example.com/another/base/": "artifacts/another/base" }
  ]
}
```

YAML syntax is also supported.

**Note**: The use of profiles is optional for context registries and can be omitted.