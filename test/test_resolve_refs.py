#!/usr/bin/env python3

import unittest
from pathlib import Path

from ogc.na import ingest_json, util

THIS_DIR = Path(__file__).parent
DATA_DIR = THIS_DIR / 'data'


class ResolveRefsTest(unittest.TestCase):

    def test_doc_with_references(self):
        fn = DATA_DIR / 'resolve_refs_data_with_refs.json'
        doc = util.load_yaml(fn)
        resolved = util.resolve_refs(fn, doc)

        referenced = util.load_yaml(DATA_DIR / 'resolve_refs_referenced_data.json')

        self.assertEqual(resolved['data'][0], referenced)
        self.assertEqual(resolved['data'][1], referenced['string'])
        self.assertEqual(resolved['data'][2], referenced['obj'])
        self.assertEqual(resolved['data'][3], referenced['list'])
        self.assertEqual(resolved['data'][4]['toNumber'], referenced['number'])
        self.assertEqual(resolved['data'][4]['deep'], referenced['path1']['path2']['path3'])

    def test_root_reference(self):
        fn = DATA_DIR / 'resolve_refs_data_with_refs.json'
        doc = {'$ref': 'resolve_refs_referenced_data.json#/path1/path2', 'another': 'property'}
        resolved = util.resolve_refs(fn, doc)

        referenced = util.load_yaml(DATA_DIR / 'resolve_refs_referenced_data.json')

        self.assertEqual(resolved['path3'], referenced['path1']['path2']['path3'])
        self.assertIsNone(resolved.get('another'))
        self.assertEqual(len(resolved), 1)
