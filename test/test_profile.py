import unittest
from pathlib import Path

from rdflib import URIRef, Namespace

from ogc.na.profile import ProfileRegistry

THIS_DIR = Path(__file__).parent
DATA_DIR = THIS_DIR / 'data'

EX = Namespace('http://example.org/prof/')


class ProfileTest(unittest.TestCase):

    def test_empty_profile_registry(self):
        empty = DATA_DIR / 'empty.ttl'
        registry = ProfileRegistry(empty)
        self.assertFalse(registry.profiles)

    def test_build_cyclic_profile_chain(self):
        registry = ProfileRegistry(DATA_DIR / 'profile_tree_cyclic.ttl')
        with self.assertRaises(ValueError):
            registry.build_profile_chain((EX.a, EX.c), recursive=True)
        chain = registry.build_profile_chain((EX.a, EX.c), sort=False)
        self.assertEqual(len(chain), 4)
        chain = registry.build_profile_chain((EX.a, EX.c), sort=False, recursive=False)
        self.assertEqual(len(chain), 2)
        chain = registry.build_profile_chain((EX.a, EX.p, EX.q, EX.d), sort=False, recursive=False)
        self.assertEqual(len(chain), 2)

    def test_build_profile_chain(self):
        registry = ProfileRegistry(DATA_DIR / 'profile_tree.ttl')

        seq = (EX.f, EX.a)
        chain = registry.build_profile_chain(seq)
        self.assertSequenceEqual(chain, seq)

        seq = (EX.a, EX.f)
        chain = registry.build_profile_chain(seq)
        self.assertSequenceEqual(chain, seq)

        seq = (EX.e, EX.d)
        chain = registry.build_profile_chain(seq, recursive=False)
        self.assertSequenceEqual(chain, seq[::-1])

        seq = (EX.e, EX.d)
        chain = registry.build_profile_chain(seq, recursive=False, sort=False)
        self.assertSequenceEqual(chain, seq)

        chain = registry.build_profile_chain((EX.e, EX.f))
        self.assertEqual(len(chain), 5)  # All but EX.c
        for a, b in (
                (EX.a, EX.b),
                (EX.b, EX.d),
                (EX.b, EX.e),
                (EX.d, EX.e),
        ):
            self.assertLess(chain.index(a), chain.index(b))
