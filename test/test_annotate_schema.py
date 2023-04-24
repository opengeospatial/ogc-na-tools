import unittest
from pathlib import Path

from ogc.na import annotate_schema


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
