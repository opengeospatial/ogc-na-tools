# Tutorials

## How to create a JSON-LD uplift context definition

`ogc.na.ingest_json`, the JSON-LD uplift module, can be used to convert JSON documents
to JSON-LD, specially when those conversions are not straighforward (i.e., it is hard or
even impossible to define a 1:1 relationship between the JSON structure and the desired
RDF). `ingest_json` uses a JSON document and a JSON-LD uplift context definition 
as its input and generates 2 outputs:

* An uplifted JSON-LD version of the input after applying transformations, classes and contexts.
* An RDF [Graph](https://rdflib.readthedocs.io/en/stable/_modules/rdflib/graph.html) with the parsed
JSON-LD.

JSON-LD uplift context definitions are created using [YAML](https://yaml.org/). YAML is a superset
of JSON, making it easy to convert YAML to JSON (e.g., for a JSON-LD
`@context` block), while at the same time several offering user-friendly
features (such as comments or easy-to-read multiline text blocks).

An uplift context definition is an object with 4 keys:

* `transform` can either be a single [jq](https://stedolan.github.io/jq/) expression
or a list of those. jq is a sed-like tool for parsing and manipulating JSON. 
The [jq play](https://jqplay.org/) tool is very useful to test jq transformations.
* `types` is a map of [jsonpath-ng](https://pypi.org/project/jsonpath-ng/) paths to
RDF classes. This is a convenience option to easily add types instead of having to 
do so by using the more cumbersome `transform` above. `types` entries will be applied
after the `transform`s, not on the original JSON document.
* `base` is an optional string to define the base RDF URI that will be used for the output.
* `context` is a map of jsonpath-ng path to JSON-LD `@context`. It will be used to inject
`@context` blocks either globally or for specific nodes. `context` is applied after `transform`
and `types`.

If there is more than one `transform` entry, they will be chained (the output for the first one
will be used as the input for the second one, and so on).  

The special jsonpath-ng paths `$` and `.` can be used (in `types` and `context`) to refer to 
the root object.

All entries are optional (in the extreme case of an empty definition, no operations wil be performed
on the input JSON document, and it will be parsed as JSON-LD as is). 

Let us start with a sample JSON document with the following content:

```json
{
  "job1": {
    "label": "Develop software",
    "author": "Doe, John",
    "status": "done"
  },
  "job2": {
    "label": "Deploy production version",
    "author": "Smith, Jane",
    "status": "in-progress"
  }
}
```

We want to convert it to RDF by:

1. Assigning URIs to the job identifiers (their key) in the `http://example.com/job/<id>` form.
2. Making the `author`s into `foaf:Person` with their respective `foaf:name`.
3. Using `rdf:label` and `dc:creator` for `label` and `author`, respectively.
4. Using the `http://example.com/status#` vocabulary for `status`es.

### Assigning URIs to jobs

We will start by turning the key -> value mapping into an array, adding the key as `@id`. This can be achieved with
a `transform`:

```yaml
transform:
  - '[to_entries | .[] | {"@id": .key} + .value]'
```

`to_entries` will transform the key -> value mappings into `{"key": "<key>", "value": { ... }}` objects. We can then
use the `.[]` object iterator to visit each object, and then convert it into its value plus the `@id`. We wrap the 
result in `[` and `]` so that the result is an array.

We can then set the `@base` that will be used in the transform:

```yaml
base: 'http://example.com/job/'
```

### Converting authors

This can be achieved with another jq `transform`:

```yaml
transform:
  - '[to_entries | .[] | {"@id": .key} + .value]'
  - '[.[] | .author = {"name": .author}]' 
```

This converts the string `author` field into an object with a `name` property containing its previous value.
We then add a type, by using a path that searches for all `author` descendants of the root object:

```yaml
types:
  '$..author': 'Person'
```

### Adding the @context

Finally, we add the necessary JSON-LD context for properties. The resulting full context definition is:

```yaml
transform:
  - '[to_entries | .[] | {"@id": .key} + .value]'
  - '[.[] | .author = {"name": .author}]'

types:
  '$..author': 'Person'

base: 'http://example.com/job/'

context:
  '$':
    '@base': 'http://example.com/job/'
    rdfs: 'http://www.w3.org/2000/01/rdf-schema#'
    foaf: 'http://xmlns.com/foaf/0.1/'
    dc: 'http://purl.org/dc/elements/1.1/'
    statusvoc: 'http://example.com/status#'
    label: 'rdfs:label'
    author: 'dc:creator'
    name: 'foaf:name'
    Person: 'foaf:person'
    status:
      '@id': 'statusvoc:status'
      '@type': '@vocab'
      '@context':
        '@vocab': 'http://example.com/status#'
```

Which, after applying it to our input document, is converted into the following Turtle (provenance
metadata, using the [PROV-O ontology](https://www.w3.org/TR/prov-o/), is automatically added):

```
@prefix dc: <http://purl.org/dc/elements/1.1/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix ns1: <http://xmlns.com/foaf/0.1/> .
@prefix ns2: <http://example.com/status#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<http://example.com/job/job1> rdfs:label "Develop software" ;
    ns2:status ns2:done ;
    dc:creator [ a ns1:person ;
            ns1:name "Doe, John" ] .

<http://example.com/job/job2> rdfs:label "Deploy production version" ;
    ns2:status ns2:in-progress ;
    dc:creator [ a ns1:person ;
            ns1:name "Smith, Jane" ] .

[] a prov:Activity ;
    prov:endedAtTime "2023-01-19T09:58:25.108552"^^xsd:dateTime ;
    prov:startedAtTime "2023-01-19T09:58:24.674490"^^xsd:dateTime ;
    prov:used [ a prov:Entity ;
            rdfs:label "JSON document" ;
            dct:format "application/json" ],
        [ a prov:Entity ;
            rdfs:label "Context definition" ;
            dct:format "text/yaml" ] ;
    prov:wasAssociatedWith [ a prov:Agent,
                <https://schema.org/SoftwareApplication> ;
            rdfs:label "OGC-NA tools" ;
            dct:hasVersion "0.1.dev42+geab204d" ;
            rdfs:seeAlso <https://github.com/opengeospatial/ogc-na-tools> ] .
```

Alternatively, for the `author` type, we could have used a `transform` (adding the `@type` property to the second
entry) or used a scoped `@context` (using `$..author` as the `context` key).

### Chaining JSON-LD uplifts

`ingest_json` can also work with already uplifted JSON-LD documents:

- If the root node has a `@graph` property, all transformations (jq operations) and paths will be anchored to it instead
of the root node itself. If this is not desired, `path-scope: document` can be declared in the uplift definition.
- When injecting `context`s, if an existing JSON-LD `@context` in the node, the new context will be either prepended
(by default) or appended to it; this can be controlled by adding a new uplift property `context-position` with the value
`before` or `after`, respectively. Note that prepended context will have lower precedence than appended context.