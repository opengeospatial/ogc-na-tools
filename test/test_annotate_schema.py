import json
import unittest
from pathlib import Path

from rdflib import Graph, URIRef, Namespace

from ogc.na import annotate_schema
from ogc.na.annotate_schema import SchemaAnnotator, ContextBuilder, SchemaResolver
from ogc.na.util import load_yaml

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

        self.assertEqual(deep_get(schema, 'properties', 'propB', 'x-jsonld-id'), '@id')
        self.assertEqual(deep_get(schema, 'properties', 'propC', 'x-jsonld-id'), 'http://www.another.com/')

        builder = ContextBuilder(DATA_DIR / 'schema-vocab.yml', contents=schema)
        instance = {
            **builder.context,
            'propA': 'valueA',
            'propB': 'https://example.com',
            'propC': 'valueC',
            'propD': 'valueD',
        }
        g = Graph().parse(data=json.dumps(instance), format='json-ld')
        resource = URIRef(instance['propB'])
        vocab = Namespace(vocab)
        self.assertEqual(str(g.value(resource, vocab.test)), 'valueA')
        self.assertEqual(str(g.value(resource, URIRef('http://www.another.com/'))), 'valueC')
        self.assertEqual(str(g.value(resource, vocab.propD)), 'valueD')

    def test_top_level_keywords(self):
        annotator = SchemaAnnotator()
        vocab = 'http://example.com/vocab#'
        base = 'http://example.net/'
        schema = annotator.process_schema(DATA_DIR / 'sample-schema-prop-c.yml', default_context={
            '@context': {
                '@base': base,
                '@vocab': vocab,
            }
        }).schema

        self.assertEqual(schema.get('x-jsonld-vocab'), vocab)
        self.assertEqual(schema.get('x-jsonld-base'), base)

        builder = ContextBuilder('http://example.com/schema.yaml', contents=schema)

        self.assertEqual(deep_get(builder.context, '@context', '@vocab'), vocab)
        self.assertEqual(deep_get(builder.context, '@context', '@base'), base)

    def test_schema_anchors(self):
        with open(DATA_DIR / 'schema-anchors.json') as f:
            schema = json.load(f)
        anchors = SchemaResolver._find_anchors(schema)
        self.assertSetEqual({'name', 'age', 'innerProp'}, set(anchors.keys()))

        self.assertEqual(SchemaResolver._get_branch(schema, '#/$defs/name'), anchors.get('name'))
        self.assertEqual(SchemaResolver._get_branch(schema, '#/$defs/age'), anchors.get('age'))
        self.assertEqual(SchemaResolver._get_branch(schema, '#/$defs/deep/properties/inner'),
                         anchors.get('innerProp'))

    def test_defs_annotation(self):
        annotator = SchemaAnnotator()
        orig_schema = load_yaml(DATA_DIR / 'annotate-defs-schema.yml')
        schema = annotator.process_schema(DATA_DIR / 'annotate-defs-schema.yml', contents=orig_schema).schema
        vocab = 'http://example.com/props/'
        self.assertEqual(deep_get(schema, '$defs', 'objectA', 'properties', 'propA', 'x-jsonld-id'),
                         vocab + 'a')
        self.assertEqual(deep_get(schema, '$defs', 'objectB', 'properties', 'propB', 'x-jsonld-id'),
                         vocab + 'b')

        orig_schema = load_yaml(DATA_DIR / 'annotate-defs-schema.yml')
        only_defs_schema = {k: v for k, v in orig_schema.items() if k in ('$schema', '$defs', 'x-jsonld-context')}
        schema = annotator.process_schema(DATA_DIR / 'annotate-defs-schema.yml', contents=only_defs_schema).schema
        self.assertEqual(deep_get(schema, '$defs', 'objectA', 'properties', 'propA', 'x-jsonld-id'),
                         vocab + 'a')
        self.assertEqual(deep_get(schema, '$defs', 'objectB', 'properties', 'propB', 'x-jsonld-id'),
                         vocab + 'b')

    def test_nested_context_file_ref(self):
        # Bug: resolve_inner uses the outer `ctx` closure variable instead of `inner_ctx`
        # when a context term's @context is a file path reference to a different file.
        # This causes a ContextLoadError (or wrong annotation) instead of loading the nested file.
        annotator = SchemaAnnotator()
        schema = annotator.process_schema(DATA_DIR / 'schema-nested-context-ref.yml').schema

        self.assertEqual(deep_get(schema, 'properties', 'propOuter', 'x-jsonld-id'),
                         'http://example.com/outer')
        self.assertEqual(deep_get(schema, 'properties', 'propContainer', 'properties', 'propInner', 'x-jsonld-id'),
                         'http://example.com/inner')

    def test_binding_bubbling(self):
        ctx_builder = ContextBuilder(DATA_DIR / 'binding-bubbling/root-schema.yaml')
        self.assertIn('propA1', ctx_builder.context['@context'])
        self.assertIn('propA21', ctx_builder.context['@context'])
        self.assertIn('propB1', ctx_builder.context['@context'])
        self.assertIn('propParent1', ctx_builder.context['@context'])
        self.assertNotIn('propExt1', ctx_builder.context['@context'])
        self.assertNotIn('propExt2', ctx_builder.context['@context'])

        # Same as propC/$ref case but the external ref is one level inside allOf —
        # local_refs_only is not forwarded to allOf processing, so external terms leak through
        ctx_builder = ContextBuilder(DATA_DIR / 'binding-bubbling/allof-no-binding-schema.yaml')
        self.assertNotIn('propExt1', ctx_builder.context['@context'])
        self.assertNotIn('propExt2', ctx_builder.context['@context'])

        ctx_builder = ContextBuilder(DATA_DIR / 'binding-bubbling/vocab-schema.yaml')
        self.assertIn('propParent1', ctx_builder.context['@context'])
        self.assertIn('propParent2', ctx_builder.context['@context'])
        self.assertIn('propParent21', ctx_builder.context['@context']['propParent2']['@context'])
        self.assertNotIn('propExt1', ctx_builder.context['@context'])
        self.assertNotIn('propExt2', ctx_builder.context['@context'])

    def test_null_vocab_annotator(self):
        # @vocab: null in a nested @context should be written as x-jsonld-vocab: null on the property,
        # and nested properties without explicit mappings should not receive x-jsonld-id.
        annotator = SchemaAnnotator()
        schema = annotator.process_schema(DATA_DIR / 'schema-null-vocab.yml').schema

        # Root schema gets @vocab from the context
        self.assertEqual(schema.get('x-jsonld-vocab'), 'http://example.com/vocab#')
        # container is explicitly mapped in the context
        self.assertEqual(deep_get(schema, 'properties', 'container', 'x-jsonld-id'),
                         'http://example.com/container')
        # container's nested @context has @vocab: null — must be propagated
        self.assertIsNone(deep_get(schema, 'properties', 'container', 'x-jsonld-vocab'))
        self.assertIn('x-jsonld-vocab', schema['properties']['container'])
        # explicitProp is mapped inside the nested @context
        self.assertEqual(deep_get(schema, 'properties', 'container', 'properties', 'explicitProp', 'x-jsonld-id'),
                         'http://example.com/explicit')
        # innerProp is not mapped anywhere — must NOT get a vocab-derived annotation
        self.assertIsNone(deep_get(schema, 'properties', 'container', 'properties', 'innerProp', 'x-jsonld-id'))

    def test_null_vocab_context_builder(self):
        # x-jsonld-vocab: null on a property must stop @vocab from propagating into its sub-properties.
        ctx_builder = ContextBuilder(DATA_DIR / 'schema-null-vocab-builder.yml')
        root_ctx = ctx_builder.context['@context']

        # Root @vocab is present
        self.assertEqual(root_ctx.get('@vocab'), 'http://example.com/vocab#')
        # container is in the root context with its @id
        self.assertIn('container', root_ctx)
        container_entry = root_ctx['container']
        self.assertEqual(container_entry.get('@id'), 'http://example.com/container')
        # The null vocab must be represented inside the scoped @context of container
        container_scoped_ctx = container_entry.get('@context', {})
        self.assertIn('@vocab', container_scoped_ctx)
        self.assertIsNone(container_scoped_ctx['@vocab'])
        # explicitProp is in container's scoped context
        self.assertIn('explicitProp', container_scoped_ctx)
        # innerProp must NOT appear in root context or container's context (no vocab propagation)
        self.assertNotIn('innerProp', root_ctx)
        self.assertNotIn('innerProp', container_scoped_ctx)