import unittest

from rdflib import Graph, URIRef

from ogc.na import util

PREFIXES = """
@prefix ex: <http://example.com/> .
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
"""

CLOSURE = PREFIXES + "ex:spatial a skos:Concept ."

DATA = PREFIXES + "ex:a ex:dim ex:spatial ."

SHAPES = PREFIXES + """
ex:Shape a sh:NodeShape ;
    sh:targetSubjectsOf ex:dim ;
    sh:property [ sh:path ex:dim ; sh:class skos:Concept ] .
"""

RULES = PREFIXES + """
ex:Rule a sh:NodeShape ;
    sh:targetSubjectsOf ex:dim ;
    sh:rule [
        a sh:SPARQLRule ;
        sh:prefixes ex: ;
        sh:construct \"\"\"
            CONSTRUCT { $this ex:spatialThing true }
            WHERE { $this ex:dim ?d . ?d a skos:Concept }
        \"\"\"
    ] .
ex: sh:declare [ sh:prefix "ex" ; sh:namespace "http://example.com/"^^<http://www.w3.org/2001/XMLSchema#anyURI> ] ,
    [ sh:prefix "skos" ; sh:namespace "http://www.w3.org/2004/02/skos/core#"^^<http://www.w3.org/2001/XMLSchema#anyURI> ] .
"""


def _g(ttl: str) -> Graph:
    return Graph().parse(data=ttl, format='turtle')


class ShaclClosureTest(unittest.TestCase):

    def test_validate_with_closure_instances(self):
        data, closure = _g(DATA), _g(CLOSURE)
        before = len(data)

        self.assertFalse(util.validate(data, _g(SHAPES)).result)
        self.assertTrue(util.validate(data, _g(SHAPES), extra=closure).result)
        self.assertEqual(before, len(data), 'input graph must not be modified')

    def test_entail_with_closure_instances(self):
        data, closure = _g(DATA), _g(CLOSURE)
        result = util.entail(data, _g(RULES), extra=closure, inplace=False)

        self.assertEqual(1, len(list(result.triples((None, URIRef('http://example.com/spatialThing'), None)))))
        self.assertEqual(0, len(list(result.triples((None, None, URIRef('http://www.w3.org/2004/02/skos/core#Concept'))))),
                         'closure triples must be removed from the result')


if __name__ == '__main__':
    unittest.main()
