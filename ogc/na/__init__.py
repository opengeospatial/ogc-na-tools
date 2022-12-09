"""
This module contains all the Naming Authority tools and libraries.
"""
try:
    from ._version import __version__, __version_tuple__
except ImportError:
    try:
        import setuptools_scm
        __version__ = setuptools_scm.get_version()
        del setuptools_scm
    except Exception:
        __version__ = '0.0.0'

__all__ = ['ingest_json', 'update_vocabs', 'util', '__version__', '__url__']

__url__ = 'https://github.com/opengeospatial/ogc-na-tools'
