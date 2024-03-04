import unittest
from pathlib import Path

from ogc.na import annotate_schema
from ogc.na.annotate_schema import SchemaAnnotator

THIS_DIR = Path(__file__).parent
DATA_DIR = THIS_DIR / 'data'


def deep_get(dct, *keys):
    for key in keys:
        dct = dct.get(key)
        if dct is None:
            return None
    return dct


class AnnotateSchemaTest(unittest.TestCase):

    def test_resolve_ref_url_full(self):
        ref = 'http://www.example.com/path/to/ref'
        self.assertEqual(annotate_schema.resolve_ref(ref), (None, ref))

    def test_resolve_ref_url_relative(self):
        ref = '/path/to/ref'
        base_url = 'http://www.example.com/base/url'
        self.assertEqual(annotate_schema.resolve_ref(ref, base_url=base_url),
                         (None, 'http://www.example.com/path/to/ref'))

        ref = 'relative/ref'
        self.assertEqual(annotate_schema.resolve_ref(ref, base_url=base_url),
                         (None, 'http://www.example.com/base/relative/ref'))

        ref = '../relative/ref'
        self.assertEqual(annotate_schema.resolve_ref(ref, base_url=base_url),
                         (None, 'http://www.example.com/relative/ref'))

    def test_resolve_ref_filename(self):
        ref = '/tmp/relative/test'
        fn_from = '/var/lib/from.yml'

        self.assertEqual(annotate_schema.resolve_ref(ref, fn_from),
                         (Path(ref), None))

        ref = 'child/ref'
        self.assertEqual(annotate_schema.resolve_ref(ref, fn_from),
                         (Path(fn_from).parent / ref, None))

        ref = '../child/ref2'
        result = annotate_schema.resolve_ref(ref, fn_from)
        self.assertEqual(result[0].resolve(), Path(fn_from).parent.joinpath(ref).resolve(), None)
        self.assertIsNone(result[1])

    def test_annotate_no_follow_refs(self):
        annotator = SchemaAnnotator()
        schema = annotator.process_schema(DATA_DIR / 'sample-schema.yml').schema

        self.assertEqual(deep_get(schema, 'properties', 'propA', 'x-jsonld-id'), 'http://example.com/props/a')
        self.assertEqual(deep_get(schema, 'properties', 'propB', 'x-jsonld-id'), 'http://example.com/props/b')
        self.assertEqual(deep_get(schema, 'properties', 'propC', 'x-jsonld-id'), None)
        self.assertEqual(deep_get(schema, 'properties', 'propD', 'x-jsonld-id'), 'http://example.com/props/d')

    def test_annotate_provided_context(self):
        annotator = SchemaAnnotator()
        schema = annotator.process_schema(DATA_DIR / 'sample-schema.yml', default_context={
                                        '@context': {
                                            'another': 'http://example.net/another/',
                                            'propA': 'another:a',
                                            'propC': 'another:c'
                                        }
                                    }).schema

        self.assertEqual(deep_get(schema, 'properties', 'propA', 'x-jsonld-id'), 'http://example.com/props/a')
        self.assertEqual(deep_get(schema, 'properties', 'propC', 'x-jsonld-id'), 'http://example.net/another/c')

    def test_vocab(self):
        annotator = SchemaAnnotator()
        vocab = 'http://example.com/vocab#'
        schema = annotator.process_schema(DATA_DIR / 'schema-vocab.yml', default_context={
            '@context': {
                '@vocab': vocab,
                'propA': 'test',
                'propB': '@id',
                'propC': 'http://www.another.com/',
            }
        }).schema

        self.assertEqual(deep_get(schema, 'properties', 'propA', 'x-jsonld-id'), vocab + 'test')
        self.assertEqual(deep_get(schema, 'properties', 'propB', 'x-jsonld-id'), '@id')
        self.assertEqual(deep_get(schema, 'properties', 'propC', 'x-jsonld-id'), 'http://www.another.com/')
        self.assertEqual(deep_get(schema, 'properties', 'propD', 'x-jsonld-id'), vocab + 'propD')
