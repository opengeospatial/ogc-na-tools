#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests

from ogc.na import util

logger = logging.getLogger(__name__)


def download_file(url: str,
                  dest: str | Path,
                  object_diff: bool = True,
                  ignore_diff_errors: bool = True):
    if not isinstance(dest, Path):
        dest = Path(dest)
    r = requests.get(url)
    r.raise_for_status()
    overwrite = True
    if dest.is_file() and object_diff:
        try:
            newcontent = util.load_yaml(content=r.content)
            oldcontent = util.load_yaml(filename=dest)
            overwrite = newcontent != oldcontent
        except Exception as e:
            if ignore_diff_errors:
                logger.warning('Error when loading content for diff: %s', str(e))
            else:
                raise
    if overwrite:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(r.content)


def download_files(spec: dict | Iterable[dict] | str | Path,
                   object_diff: bool = True,
                   ignore_diff_errors: bool = True):

    if isinstance(spec, str) or isinstance(spec, Path):
        spec = util.load_yaml(filename=spec)

    if 'json-downloads' in spec:
        spec = spec['json-downloads']

    if not spec:
        return

    if not isinstance(spec, Iterable):
        raise ValueError('Unknown spec type: {}'.format(type(spec)))

    for entry in spec:
        entry_object_diff = entry.get('object-diff', object_diff)
        download_file(entry['url'], entry['dest'],
                      object_diff=entry_object_diff,
                      ignore_diff_errors=ignore_diff_errors)


def _process_cmdln():
    parser = argparse.ArgumentParser(
        epilog='Either a URL (with an optional destination) or a --spec must be provided.'
    )

    parser.add_argument(
        "url",
        nargs='?',
        help="URL to download",
    )

    parser.add_argument(
        "destination",
        nargs='?',
        help="Destination file to write",
    )

    parser.add_argument(
        "--disable-diff",
        action='store_true',
        help="Disable object diff",
    )

    parser.add_argument(
        "--fail-on-diff-error",
        action='store_true',
        help="Fail when errors are found while performing object diffs",
    )

    parser.add_argument(
        "--spec",
        help="Load files to download from specification in file",
    )

    args = parser.parse_args()

    if args.url:
        dest = args.destination or os.path.basename(urlparse(args.url).path)
        if not dest:
            raise ValueError('Destination file not provided and cannot be inferred')
        download_file(args.url, dest,
                      object_diff=not args.disable_diff,
                      ignore_diff_errors=not args.fail_on_diff_error)
    elif args.spec:
        download_files(spec=args.spec)
    else:
        parser.print_usage()


if __name__ == '__main__':

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format='%(asctime)s,%(msecs)d %(levelname)-5s [%(filename)s:%(lineno)d] %(message)s',
    )

    _process_cmdln()
