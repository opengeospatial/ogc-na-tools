import unittest
from datetime import datetime
from pathlib import Path

from rdflib import Graph

from ogc.na.provenance import FileProvenanceMetadata, ProvenanceMetadata, generate_provenance

THIS_DIR = Path(__file__).parent
DATA_DIR = THIS_DIR / 'data'

# Local copy of the SHACL shapes declared for the ogc.ogc-utils.prov bblock
# (https://ogcincubator.github.io/cross-domain-model/_sources/prov/shapes.shacl),
# kept offline so this test doesn't depend on network access.
PROV_SHAPES = DATA_DIR / 'prov-shacl-shapes.ttl'


class ProvenanceShaclComplianceTest(unittest.TestCase):
    """
    Validates the RDF graphs produced by generate_provenance() against the
    SHACL shapes declared for the ogc.ogc-utils.prov bblock, so a change to
    provenance.py that breaks compliance is caught by the test suite.
    """

    def _validate(self, g: Graph):
        try:
            from pyshacl import validate
        except ImportError:
            self.skipTest('pyshacl is not installed')

        shapes = Graph().parse(PROV_SHAPES, format='turtle')
        conforms, _, results_text = validate(g, shacl_graph=shapes)
        self.assertTrue(conforms, results_text)

    def test_full_metadata_conforms(self):
        metadata = ProvenanceMetadata(
            used=[FileProvenanceMetadata(uri='https://example.org/input.json',
                                          mime_type='application/json')],
            generated=[FileProvenanceMetadata(uri='https://example.org/output.jsonld',
                                               mime_type='application/ld+json')],
            start=datetime(2026, 1, 1, 10, 0, 0),
            end=datetime(2026, 1, 1, 10, 5, 0),
            batch_activity_id='batch-123',
            activity_label='Test run',
            comment='A test comment',
        )
        g = generate_provenance(metadata=metadata, module_name='test_module')
        self._validate(g)

    def test_minimal_metadata_conforms(self):
        metadata = ProvenanceMetadata(
            used=[FileProvenanceMetadata(uri='https://example.org/input.json')],
            generated=[FileProvenanceMetadata(uri='https://example.org/output.jsonld')],
            end_auto=True,
        )
        g = generate_provenance(metadata=metadata, module_name='test_module')
        self._validate(g)


if __name__ == '__main__':
    unittest.main()
