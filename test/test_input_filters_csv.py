#!/usr/bin/env python3

import unittest
from io import BytesIO
from pathlib import Path

from ogc.na.input_filters import csv

THIS_DIR = Path(__file__).parent
DATA_DIR = THIS_DIR / 'data'

with open(DATA_DIR / 'headers.csv', 'rb') as f:
    WITH_HEADERS = f.read()
with open(DATA_DIR / 'no-headers.csv', 'rb') as f:
    NO_HEADERS = f.read()


class InputFiltersCSVTest(unittest.TestCase):

    def test_rows_objects(self):
        cfg = {
            'rows': 'dict',
            'skip-rows': 0,
            'header-row': 0,
        }
        rows = csv.apply_filter(WITH_HEADERS, cfg)[0]
        self.assertEqual(len(rows), 87)
        self.assertEqual(rows[0], {
            'Year': '1968',
            'Score': '86',
            'Title': 'Greetings',
        })
        self.assertEqual(rows[10], {
            'Year': '1977',
            'Score': '67',
            'Title': 'New York,New York',
        })

        cfg['skip-rows'] = 3
        rows = csv.apply_filter(WITH_HEADERS, cfg)[0]
        self.assertEqual(len(rows), 84)
        self.assertEqual(rows[0], {
            'Year': '1971',
            'Score': '40',
            'Title': 'Born to Win',
        })
        self.assertEqual(rows[7], {
            'Year': '1977',
            'Score': '67',
            'Title': 'New York,New York',
        })

        cfg['skip-rows'] = 0
        cfg['header-row'] = 2
        rows = csv.apply_filter(WITH_HEADERS, cfg)[0]
        self.assertEqual(len(rows), 85)
        self.assertEqual(rows[0], {
            '1970': '1970',
            '17': '73',
            'Bloody Mama': 'Hi,Mom!',
        })

    def test_rows_lists(self):
        cfg = {
            'rows': 'list',
            'skip-rows': 0,
        }
        rows = csv.apply_filter(WITH_HEADERS, cfg)[0]
        self.assertEqual(len(rows), 88)
        self.assertEqual(rows[0], ['Year', 'Score', 'Title'])
        self.assertEqual(rows[10], ['1977', '47', '1900'])
        cfg['skip-rows'] = 1
        rows = csv.apply_filter(WITH_HEADERS, cfg)[0]
        self.assertEqual(len(rows), 87)
        self.assertEqual(rows[0], ['1968', '86', "Greetings"])
        self.assertEqual(rows[3], ['1971', '40', "Born to Win"])
        cfg['header-row'] = 2  # should have no effect
        self.assertEqual(rows, csv.apply_filter(WITH_HEADERS, cfg)[0])

        cfg['skip-rows'] = 0
        rows = csv.apply_filter(NO_HEADERS, cfg)[0]
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0], ['John', 'Doe', '120 jefferson st.', 'Riverside', ' NJ', ' 08075'])
        cfg['trim-values'] = True
        rows = csv.apply_filter(NO_HEADERS, cfg)[0]
        self.assertEqual(rows[0], ['John', 'Doe', '120 jefferson st.', 'Riverside', 'NJ', '08075'])
