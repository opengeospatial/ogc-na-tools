#!/usr/bin/env python3

import unittest
from pathlib import Path

from ogc.na import ingest_json, util

THIS_DIR = Path(__file__).parent
DATA_DIR = THIS_DIR / 'data'


class IngestJsonTest(unittest.TestCase):

    def test_validate_empty_context(self):
        context = {}
        self.assertEqual(context, ingest_json.validate_context(context))

    def test_validate_valid_context(self):
        context = util.load_yaml(DATA_DIR / 'uplift_context_valid.yml')
        self.assertEqual(context, ingest_json.validate_context(context))
