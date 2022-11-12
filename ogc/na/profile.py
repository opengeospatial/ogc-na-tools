#!/usr/bin/env python3
import re
from typing import Union, Sequence, Optional, Generator, Any, cast
from rdflib import Graph, RDF, PROF, OWL, URIRef, DCTERMS, Namespace

from ogc.na import util
from pathlib import Path

from ogc.na.validation import ProfileValidationReport, ProfilesValidationReport

PROFROLE = Namespace('http://www.w3.org/ns/dx/prof/role/')

PROFILES_QUERY = re.sub(r' {2,}|\n', ' ', """
    PREFIX prof: <http://www.w3.org/ns/dx/prof/>
    PREFIX profrole: <http://www.w3.org/ns/dx/prof/role/>
    PREFIX shacl: <http://www.w3.org/ns/shacl#>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    CONSTRUCT {
        ?profile a prof:Profile ;
            prof:hasToken ?token ;
            prof:isProfileOf ?ancestor ;
            prof:hasResource ?resource ;
            owl:sameAs ?sameAs ;
            .
        ?resource prof:hasRole ?role ;
            prof:hasArtifact ?artifact ;
            .
    } WHERE {
        __SERVICE__ {
            { ?profile a prof:Profile } UNION { ?other prof:isProfileOf ?profile }
            ?profile prof:hasToken ?token ;
                prof:hasResource ?resource ;
                .
            OPTIONAL {
                { ?profile owl:sameAs+ ?sameAs} UNION { ?sameAs owl:sameAs+ ?profile }
            }
            OPTIONAL { ?profile prof:isProfileOf+ ?ancestor }
            OPTIONAL {
                ?resource prof:hasRole ?role ;
                    dct:conformsTo shacl: ;
                    prof:hasArtifact ?artifact ;
                    .
                FILTER(?role IN (profrole:entailment, 
                                 profrole:validation,
                                 profrole:entailment-closure,
                                 profrole:validation-closure))
            }
        }
    }
""")


def find_profiles(g: Graph) -> Generator[URIRef, Any, None]:
    return (o for s, o in g.subject_objects(DCTERMS.conformsTo) if isinstance(o, URIRef))


class Profile:

    def __init__(self, token: str, profile_of: list[URIRef]):
        self.token = token
        self.profile_of = profile_of
        self.artifacts: dict[URIRef, list[str]] = {}

    def add_artifact(self, role: URIRef, href: URIRef):
        self.artifacts.setdefault(role, []).append(href)

    def get_artifacts(self, role: URIRef) -> list[URIRef]:
        return self.artifacts.get(role, [])


class ProfileRegistry:

    def __init__(self, srcs: Union[str, Path, Sequence[Union[str, Path]]],
                 local_artifact_mappings: dict[str, Union[str, Path]] = None):

        if isinstance(srcs, str) or not isinstance(srcs, Sequence):
            self._srcs = (srcs,)
        else:
            self._srcs = srcs

        self._local_artifact_mappings: dict[str, Union[str, Path]] = local_artifact_mappings or {}
        self._profiles: dict[URIRef, Profile] = {}
        self._load_profiles()
        # Cache of { profile: { role: Graph } }
        self._graphs: dict[URIRef, dict[URIRef, Graph]] = {}

    def _load_profiles(self):
        g: Graph = Graph()
        for src in self._srcs:
            if isinstance(src, str) and src.startswith('sparql:'):
                endpoint = src[len('sparql:'):]
                assert util.isurl(endpoint)
                s = g.query(PROFILES_QUERY.replace('__SERVICE__', f"SERVICE <{endpoint}>")).graph
                util.copy_triples(s, g)
            else:
                g.parse(src)

        # resolve recursive isProfileOf and sameAs
        g = g.query(PROFILES_QUERY.replace('__SERVICE__', '')).graph

        for profile_ref in cast(list[URIRef], g.subjects(RDF.type, PROF.Profile)):

            if profile_ref in self._profiles:
                # do not parse duplicate profiles
                continue

            token = str(g.value(profile_ref, PROF.hasToken))
            profile_of: list[URIRef] = cast(list[URIRef], list(g.objects(profile_ref, PROF.isProfileOf)))

            profile = Profile(token, profile_of)

            for resource_ref in g.objects(profile_ref, PROF.hasResource):
                for artifact_ref in g.objects(resource_ref, PROF.hasArtifact):
                    role_ref = g.value(artifact_ref, PROF.hasRole)
                    profile.add_artifact(role_ref, cast(URIRef, artifact_ref))

            self._profiles[profile_ref] = profile
            for same_as_ref in g.objects(profile_ref, OWL.sameAs):
                self._profiles[cast(URIRef, same_as_ref)] = profile

    def _apply_mappings(self, uri: str) -> str:
        """
        Returns the longest match in self._local_artifact_mappings (prefixes)
        for a given URI, or the URI itself if not found
        """

        if uri in self._local_artifact_mappings:
            return str(self._local_artifact_mappings[uri])

        matchedlocal = None
        matchedpath = uri
        for l, p in self._local_artifact_mappings.items():
            if uri.startswith(l) and (matchedlocal is None or len(matchedlocal) < len(l)):
                matchedlocal, matchedpath = l, Path(str(p) + uri[len(l):])
        return str(matchedpath)

    def get_graph(self, profile: URIRef, role: URIRef) -> Optional[Graph]:
        if profile not in self._profiles:
            return None

        prof_graphs = self._graphs.setdefault(profile, {})
        g = prof_graphs.get(role)
        if not g:
            g = Graph()
            for artifact_ref in self._profiles[profile].get_artifacts(role):
                g.parse(self._apply_mappings(artifact_ref))
            prof_graphs[role] = g
        return g

    def entail(self, g: Graph, profiles: Optional[Sequence[URIRef]] = None,
               inplace: bool = True) -> Graph:
        if not inplace:
            g = util.copy_triples(g)

        for profile in profiles or find_profiles(g):
            rules = self.get_graph(profile, PROFROLE.entailment)
            extra = self.get_graph(profile, PROFROLE['entailment-closure'])
            g = util.entail(g, rules, extra or None, True)

        return g

    def validate(self, g: Graph, profiles: Optional[Sequence[URIRef]] = None) -> ProfilesValidationReport:
        result = ProfilesValidationReport()
        for profile_ref in profiles or find_profiles(g):
            profile = self._profiles.get(profile_ref)
            if not profile:
                # should we fail?
                continue
            rules = self.get_graph(profile_ref, PROFROLE.validation)
            extra = self.get_graph(profile_ref, PROFROLE['validation-closure'])
            result.add(ProfileValidationReport(profile_ref, profile.token, util.validate(g, rules, extra)))
        return result
