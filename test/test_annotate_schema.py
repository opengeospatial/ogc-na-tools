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

    def test_anchor_ref_inner_context(self):
        # Regression: $ref: "#anchor" (a $anchor-style ref, not a JSON Pointer #/ ref)
        # was not followed during property traversal, so $defs entries referenced this way
        # were never annotated with the inner @context of the containing array property.
        # The properties ended up in x-jsonld-extra-terms instead of on the $defs schema.
        annotator = SchemaAnnotator()
        schema = annotator.process_schema(
            DATA_DIR / 'anchor-ref-inner-context/schema.yaml').schema

        # Top-level property with inner @context
        self.assertEqual(deep_get(schema, 'properties', 'items', 'x-jsonld-id'),
                         'http://example.com/items')
        # $defs/item properties must be annotated via the inner @context of 'items'
        self.assertEqual(deep_get(schema, '$defs', 'item', 'properties', 'itemCode', 'x-jsonld-id'),
                         'http://example.com/code')
        self.assertEqual(deep_get(schema, '$defs', 'item', 'properties', 'itemLabel', 'x-jsonld-id'),
                         'http://example.com/label')
        # Must not leak into extra-terms
        extra = schema.get('x-jsonld-extra-terms', {})
        self.assertNotIn('itemCode', extra)
        self.assertNotIn('itemLabel', extra)

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

    def test_allof_inherited_binding_propagation(self):
        # Regression: a property (e.g. 'features') that has no x-jsonld-id in the
        # root schema but receives its binding via allOf was incorrectly flagged as
        # "truly unbound", causing local_refs_only=True.  That blocked external $refs
        # inside the property's sub-schema (items.anyOf, etc.) from contributing their
        # annotations to the context — so properties like 'topology' and 'name' (which
        # come from an external $ref inside features.items.anyOf) were silently dropped.
        #
        # The fix: before setting local_refs_only=True, also check onto_context for an
        # already-present binding contributed by a prior allOf pass.  If such a binding
        # exists the property is NOT truly naked and external refs should be followed.
        #
        # Concretely mirrors the topo-feature-collection / topo-feature pattern where
        # features.items.anyOf[0] -> topo-feature/schema.yaml contains topology/@id.
        ctx_builder = ContextBuilder(DATA_DIR / 'allof-inherited-binding/root-schema.yaml')
        ctx = ctx_builder.context['@context']

        # 'features' binding arrives via allOf -> collection-schema.yaml
        self.assertIn('features', ctx)

        # 'topology' and 'name' come from feature-schema.yaml (external anyOf $ref
        # inside features.items); they should be hoisted to the root context because
        # 'features' has no explicit x-jsonld-id in the root schema.
        self.assertIn('topology', ctx)
        self.assertIn('name', ctx)

        # 'naked' has no x-jsonld-id and no allOf-inherited binding, so its external
        # $ref (naked-schema.yaml / 'forbidden') must NOT bubble into the root context.
        self.assertNotIn('forbidden', ctx)

    def test_allof_sibling_binding_propagation(self):
        # Regression: a property ('features') that has no x-jsonld-id in an allOf branch
        # gets its binding from a *sibling* allOf branch (allOf[0] -> collection-schema).
        #
        # Schema shape:
        #   allOf:
        #     - $ref: collection-schema.yaml   # binds features: https://example.com/features
        #     - properties:
        #         features:
        #           items:
        #             $ref: feature-schema.yaml  # contributes topology, name
        #         naked:
        #           $ref: naked-schema.yaml      # no binding anywhere → must stay blocked
        #
        # Without sibling_context, allOf[1] is processed with an empty local onto_context,
        # so 'features' looks unbound → local_refs_only=True → items.$ref is blocked and
        # topology/name are silently dropped.
        #
        # The fix: pass the accumulated outer onto_context as sibling_context to each allOf
        # branch call.  read_properties falls through to sibling_context when onto_context
        # has no entry for the property, so the allOf[0] binding is found and
        # local_refs_only stays False.
        ctx_builder = ContextBuilder(DATA_DIR / 'allof-sibling-binding/root-schema.yaml')
        ctx = ctx_builder.context['@context']

        # 'features' binding from allOf[0] -> collection-schema.yaml
        self.assertIn('features', ctx)

        # 'topology' and 'name' come from feature-schema.yaml referenced via
        # features.items.$ref in allOf[1]; they should appear in the output context.
        self.assertIn('topology', ctx)
        self.assertIn('name', ctx)

        # 'naked' has no binding in any allOf branch, so its $ref (naked-schema.yaml /
        # 'forbidden') must NOT bubble into the root context.
        self.assertNotIn('forbidden', ctx)

    def test_unannotated_prop_follows_external_ref(self):
        # Regression: without prop_context['@id'] = UNDEFINED for unannotated properties,
        # local_refs_only is incorrectly set to True, blocking external $ref traversal and
        # preventing child properties of unannotated properties from being collected.
        ctx_builder = ContextBuilder(DATA_DIR / 'unannotated-ref-child/root-schema.yaml')
        # root-schema has @vocab; parent-schema disables it (x-jsonld-vocab: null), so
        # propContainer (in parent-schema, unannotated, from_schema != root_schema) falls
        # into the else branch where local_refs_only depends on '@id' being in prop_context.
        # Without prop_context['@id'] = UNDEFINED, prop_context has len=1 and empty @context,
        # so the property is never added to the context at all.
        # With the fix, local_refs_only=False → child-schema.yaml is followed, propNested
        # appears in propContainer's scoped context, and compact_branch keeps it (root @vocab).
        # (Checking visited_properties is insufficient — the else branch always traverses
        # blocked refs for resolved_properties, so it always passes regardless.)
        root_ctx = ctx_builder.context['@context']
        self.assertIn('propContainer', root_ctx)
        self.assertIn('propNested', root_ctx['propContainer']['@context'])

    def test_curie_property_annotation(self):
        # Properties named in prefix:local form should receive x-jsonld-id set to the
        # expanded full URI during annotation (the prefix is resolved from the context).
        annotator = SchemaAnnotator()
        schema = annotator.process_schema(DATA_DIR / 'curie-property/schema.yaml').schema

        # ex:name -> http://example.com/name (prefix ex = http://example.com/)
        self.assertEqual(
            deep_get(schema, 'properties', 'ex:name', 'x-jsonld-id'),
            'http://example.com/name',
        )
        # ex:container is also a CURIE property and should get the same treatment
        self.assertEqual(
            deep_get(schema, 'properties', 'ex:container', 'x-jsonld-id'),
            'http://example.com/container',
        )
        # normalProp is an ordinary named property; annotation comes from the context mapping
        self.assertEqual(
            deep_get(schema, 'properties', 'normalProp', 'x-jsonld-id'),
            'http://example.com/normal',
        )
        # ex:typed has an explicit context entry with @type but no @id — the @id must
        # be synthesized from CURIE expansion rather than raising an error
        self.assertEqual(
            deep_get(schema, 'properties', 'ex:typed', 'x-jsonld-id'),
            'http://example.com/typed',
        )
        self.assertEqual(
            deep_get(schema, 'properties', 'ex:typed', 'x-jsonld-type'),
            '@id',
        )

    def test_curie_property_context_builder(self):
        # CURIE-named properties must not appear as explicit terms in the built context —
        # JSON-LD expands them via the prefix definition and an explicit entry would conflict.
        # Nested bindings of a CURIE property must be hoisted to the parent context.
        ctx_builder = ContextBuilder(DATA_DIR / 'curie-property/schema-builder.yaml')
        ctx = ctx_builder.context['@context']

        # The prefix definition must be present so CURIE expansion works
        self.assertIn('ex', ctx)

        # CURIE-named properties must NOT appear as explicit terms
        self.assertNotIn('ex:name', ctx)
        self.assertNotIn('ex:container', ctx)

        # normalProp has an explicit context mapping and must appear
        self.assertIn('normalProp', ctx)

        # child is nested under ex:container in the schema but its binding should be
        # hoisted to the root context (since ex:container itself is not emitted)
        self.assertIn('child', ctx)

        # ex:typed has @type but no @id in its context entry; the annotation must survive
        # (the @id is implied by CURIE expansion and must not appear explicitly)
        self.assertIn('ex:typed', ctx)
        typed_entry = ctx['ex:typed']
        self.assertIsInstance(typed_entry, dict)
        self.assertNotIn('@id', typed_entry)
        self.assertEqual(typed_entry.get('@type'), '@id')

    def test_resolve_context_array_term_override(self):
        # Later entries in a context array must override terms defined by earlier entries.
        # Regression: resolved_ctx was never updated in the loop, so only the last entry
        # survived and all earlier entries were discarded.
        resolved = annotate_schema.resolve_context([
            {'termA': 'http://example.com/a', 'termB': 'http://example.com/b'},
            {'termA': 'http://example.com/a-override'},
        ])
        # termA from the second entry must win
        self.assertEqual(resolved.context['termA'], 'http://example.com/a-override')
        # termB from the first entry must survive (not discarded)
        self.assertEqual(resolved.context['termB'], 'http://example.com/b')

    def test_resolve_context_dict_wrapping_array(self):
        # A context passed as {"@context": [...]} must not crash with AttributeError when
        # the inner @context value is a list (was calling .keys() on the list directly).
        resolved = annotate_schema.resolve_context({
            '@context': [
                {'termA': 'http://example.com/a', 'termB': 'http://example.com/b'},
                {'termA': 'http://example.com/a-override'},
            ]
        })
        self.assertEqual(resolved.context['termA'], 'http://example.com/a-override')
        self.assertEqual(resolved.context['termB'], 'http://example.com/b')

    def test_import_basic(self):
        # @import pre-populates the context with the imported terms; local terms override.
        ctx_file = DATA_DIR / 'context-import' / 'with-import.jsonld'
        resolved = annotate_schema.resolve_context(ctx_file)
        # termA must be the local override, not the value from base.jsonld
        self.assertEqual(resolved.context['termA'], 'http://example.org/override/termA')
        # termB comes entirely from the imported base context (CURIE-expanded)
        self.assertEqual(resolved.context['termB'], 'http://example.org/termB')
        # termC is a local-only term
        self.assertEqual(resolved.context['termC'], 'http://example.org/termC')

    def test_import_relative_path_from_subdirectory(self):
        # @import with a relative path must resolve relative to the importing file,
        # not the working directory.  child-with-import.jsonld is in sub/ and
        # references ../base.jsonld, which must resolve to context-import/base.jsonld.
        ctx_file = DATA_DIR / 'context-import' / 'sub' / 'child-with-import.jsonld'
        resolved = annotate_schema.resolve_context(ctx_file)
        self.assertEqual(resolved.context['termA'], 'http://example.org/termA')
        self.assertEqual(resolved.context['termB'], 'http://example.org/termB')
        self.assertEqual(resolved.context['termD'], 'http://example.org/termD')

    def test_import_nested_raises(self):
        # JSON-LD 1.1: an @import-referenced context MUST NOT itself contain @import.
        # nested-import.jsonld imports with-import.jsonld, which has @import — must error.
        ctx_file = DATA_DIR / 'context-import' / 'nested-import.jsonld'
        with self.assertRaises(annotate_schema.ContextLoadError):
            annotate_schema.resolve_context(ctx_file)