"""
SPARQL Graph Store Protocol operations
"""
from __future__ import annotations

import argparse
import getpass
import sys
from io import IOBase
from pathlib import Path
from typing import Generator, IO

import requests
from rdflib import Graph


class GraphStore:
    """
    Encapsulates Graph Store Protocol configuration for executing operations.
    """

    def __init__(self, url: str, auth_details: tuple[str, str] | None = None):
        """
        Constructs a new GraphStore
        :param url: SPARQL Graph Store Protocol URL
        :param auth_details: tuple in the form ('username', 'password') for authentication
        """
        self._url = url
        self.auth_details = auth_details
        self.put = self.replace
        self.post = self.add

    def _post_or_put(self, method: str, graph_uri, source: str | bytes | Path, format: str = 'text/turtle'):
        if graph_uri:
            params = {'graph': str(graph_uri)}
        else:
            params = 'default'

        if isinstance(source, Path):
            with open(source, 'r') as f:
                data = f.read()
        elif isinstance(source, IO) or isinstance(source, IOBase):
            data = source.read()
        else:
            data = source

        if isinstance(data, str):
            data = data.encode('utf-8')

        method = getattr(requests, method)
        r = method(
            self._url,
            params=params,
            headers={
                'Content-type': format,
            },
            auth=self.auth_details,
            data=data,
        )

        if isinstance(data, Generator):
            data.close()

        r.raise_for_status()

    def delete(self, graph_uri: str | None, ignore_404=True):
        """
        Deletes a graph from the Graph Store
        :param graph_uri: URI for the graph (if None, the default graph will be used)
        :param ignore_404: Whether to ignore HTTP 404 errors (otherwise, an Exception will be thrown)
        :return:
        """
        if graph_uri:
            params = {'graph': str(graph_uri)}
        else:
            params = 'default'

        r = requests.delete(
            self._url,
            params=params,
            auth=self.auth_details,
        )
        if not (ignore_404 and r.status_code == 404):
            r.raise_for_status()

    def replace(self, graph_uri: str | None, source: str | bytes | Path, format: str = 'text/turtle'):
        """
        Replaces the data for a Graph Store graph with the provided source (HTTP PUT operation)
        :param graph_uri: URI for the graph (if None, the default graph will be used)
        :param source: Source data or file name
        :param format: Media type to provide to the Graph Store
        :return:
        """
        self._post_or_put('put', graph_uri, source, format)

    def add(self, graph_uri: str | None, source: str | bytes | Path, format: str = 'text/turtle'):
        """
        Adds data from the provided source to a Graph Store graph (HTTP PUT operation)
        :param graph_uri: URI for the graph (if None, the default graph will be used)
        :param source: Source data or file name
        :param format: Media type to provide to the Graph Store
        :return:
        """
        self._post_or_put('post', graph_uri, source, format)

    def get(self, graph_uri) -> Graph:
        """
        Retrieves the data from a graph in the Graph Store
        :param graph_uri: URI for the graph (if None, the default graph will be used)
        :return: An [RDFLib Graph][rdflib.Graph]
        """
        if graph_uri:
            params = {'graph': str(graph_uri)}
        else:
            params = 'default'

        r = requests.get(
            self._url,
            params=params,
            auth=self.auth_details,
        )
        r.raise_for_status()
        g = Graph().parse(r.content)
        return g


def _main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'graph_store',
        metavar='GRAPH-STORE',
        help='Graph Store Protocol endpoint',
    )

    parser.add_argument(
        'operation',
        choices=['get', 'add', 'replace', 'delete', 'post', 'put'],
        help='Operation to perform'
    )

    parser.add_argument(
        'graph_uri',
        metavar='GRAPH-URI',
        nargs='?',
        help='Graph URI',
    )

    parser.add_argument(
        '--data',
        help='Data for add/post and replace/put operations. If "-", read from stdin',
    )

    parser.add_argument(
        '--data-file',
        help='Data file for add/post and replace/put operations. If "-", read from stdin',
    )

    parser.add_argument(
        '-u',
        '--username',
        help='Username for HTTP authentication',
    )

    parser.add_argument(
        '-p',
        '--password',
        help='Password for HTTP authentication',
    )

    parser.add_argument(
        '-P',
        '--request-password',
        action='store_true',
        help='Request password from the user interactively',
    )

    args = parser.parse_args()

    if args.request_password:
        password = getpass.getpass("Password: ")
    else:
        password = args.password

    auth = (args.username, password) if args.username else None
    gs = GraphStore(args.graph_store, auth_details=auth)
    if args.operation in ('add', 'replace', 'post', 'put'):
        if not (args.data or args.data_file):
            parser.error('Operation requires either --data or --data-file')
        if args.data and args.data_file:
            parser.error('Only one of --data, --data-file must be provided')
        if args.data == '-':
            data = sys.stdin
        elif args.data:
            data = args.data
        else:
            data = Path(args.data_file)

        getattr(gs, args.operation)(args.graph_uri, source=data)
    elif args.operation == 'delete':
        gs.delete(args.graph_uri)
    else:
        print(gs.get(args.graph_uri).serialize(format='ttl'))


if __name__ == '__main__':
    _main()
