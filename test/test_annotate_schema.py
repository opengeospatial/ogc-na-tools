import unittest
from pathlib import Path

from rich import json

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

    def test_resolve_ref_root(self):
        ref = f'{annotate_schema.REF_ROOT_MARKER}tmp/relative/test'
        ref_root = Path('/var/lib/root')

        self.assertEqual(annotate_schema.resolve_ref(ref, ref_root=ref_root),
                         (ref_root / 'tmp/relative/test', None))

        self.assertEqual(annotate_schema.resolve_ref(ref, ref_root=None),
                         (Path() / 'tmp/relative/test', None))

    def test_annotate_follow_refs(self):
        annotator = SchemaAnnotator(fn=DATA_DIR / 'sample-schema.yml', follow_refs=True)
        schemas = annotator.schemas
        self.assertEqual({*schemas.keys()},
                          {Path(DATA_DIR / 'sample-schema.yml'), Path(DATA_DIR / 'sample-schema-prop-c.yml')})
        full = schemas[Path(DATA_DIR / 'sample-schema.yml')].schema
        prop_c = schemas[Path(DATA_DIR / 'sample-schema-prop-c.yml')].schema

        self.assertEqual(deep_get(full, 'properties', 'propA', 'x-jsonld-id'), 'http://example.com/props/a')
        self.assertEqual(deep_get(full, 'properties', 'propB', 'x-jsonld-id'), 'http://example.com/props/b')
        self.assertEqual(deep_get(full, 'properties', 'propC', 'x-jsonld-id'), None)
        self.assertEqual(deep_get(full, 'properties', 'propD', 'x-jsonld-id'), 'http://example.com/props/d')

        self.assertEqual(deep_get(prop_c, 'properties', 'propA', 'x-jsonld-id'), 'http://example.com/props/a')

    def test_annotate_no_follow_refs(self):
        annotator = SchemaAnnotator(fn=DATA_DIR / 'sample-schema.yml', follow_refs=False)
        schemas = annotator.schemas
        self.assertEqual({*schemas.keys()}, {Path(DATA_DIR / 'sample-schema.yml')})
        full = schemas[Path(DATA_DIR / 'sample-schema.yml')].schema

        self.assertEqual(deep_get(full, 'properties', 'propA', 'x-jsonld-id'), 'http://example.com/props/a')
        self.assertEqual(deep_get(full, 'properties', 'propB', 'x-jsonld-id'), 'http://example.com/props/b')
        self.assertEqual(deep_get(full, 'properties', 'propC', 'x-jsonld-id'), None)
        self.assertEqual(deep_get(full, 'properties', 'propD', 'x-jsonld-id'), 'http://example.com/props/d')

    def test_annotate_provided_context(self):
        annotator = SchemaAnnotator(fn=DATA_DIR / 'sample-schema.yml',
                                    follow_refs=False,
                                    context={
                                        '@context': {
                                            'another': 'http://example.net/another/',
                                            'propA': 'another:a',
                                            'propC': 'another:c'
                                        }
                                    })
        schemas = annotator.schemas
        self.assertEqual({*schemas.keys()}, {Path(DATA_DIR / 'sample-schema.yml')})
        full = schemas[Path(DATA_DIR / 'sample-schema.yml')].schema

        self.assertEqual(deep_get(full, 'properties', 'propA', 'x-jsonld-id'), 'http://example.com/props/a')
        self.assertEqual(deep_get(full, 'properties', 'propC', 'x-jsonld-id'), 'http://example.net/another/c')
