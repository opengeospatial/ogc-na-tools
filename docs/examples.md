# Examples

## Sample domain configuration

The following example shows a [domain configuration][ogc.na.domain_config] in Turtle format:

```turtle
@prefix dcfg: <http://www.example.org/ogc/domain-cfg#> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix profiles: <http://www.opengis.net/def/metamodel/profiles/> .

_:OGC-NA-Catalog a dcat:Catalog, dcfg:DomainConfiguration ;
  dct:title "OGC Naming Authority catalog" ;
  rdfs:label "OGC Naming Authority catalog" ;
  dcat:dataset _:entities ;
.

_:entities a dcat:Dataset, dcfg:DomainConfiguration ;
  dct:title "Entities" ;
  rdfs:label "Entities" ;
  dcfg:localPath "entities/" ;
  dcfg:glob "*.ttl" ;
  dcfg:uriRootFilter "/def/" ;
  dct:conformsTo profiles:skos_shared, profiles:vocprez_ogc ;
.
```