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
  
  # Link to enabled DomainConfiguration's
  dcat:dataset _:conceptSchemes ;
.

_:conceptSchemes a dcat:Dataset, dcfg:DomainConfiguration ;
  dct:description "Set of terms registered with OGC NA not covered by specialised domains" ;
  
  # Where (from the working directory) to look for source files
  dcfg:localPath "definitions/conceptschemes" ;
                 
  # Which files to include
  dcfg:glob "*.ttl" ;
                 
  # URI root filter for detecting the main ConceptScheme in
  # the source files
  dcfg:uriRootFilter "/def/" ;
                 
  # Profiles conformance can optionally be declated in the DomainConfiguration
  # as well as in the source data itself
  dct:conformsTo profiles:vocprez_ogc, profiles:skos_conceptscheme ;
.
```