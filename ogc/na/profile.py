#!/usr/bin/env python3
"""
This is a support module for parsing [profile](https://www.w3.org/TR/dx-prof/)
metadata and applying entailment, validation and annotation operations
to RDF graphs.

Conformance to a given profile is declared by using
[`dcterms:conformsTo`](https://www.dublincore.org/specifications/dublin-core/dcmi-terms/#http://purl.org/dc/terms/conformsTo).

This module uses the following [resource roles](https://www.w3.org/TR/dx-prof/#Class:ResourceRole)
(where the `profrole` prefix is [http://www.w3.org/ns/dx/prof/role/](http://www.w3.org/ns/dx/prof/role/)):

* `profrole:entailment` for entailment operations (needs to conform to SHACL).
* `profrole:entailment-closure` is used as extra ontological information for entailment.
* `profrole:validation` for validation operations (needs to conform to SHACL).
* `profrole:validation-closure` is used as extra ontological information for validation.
* `profrole:annotation` is loaded as additional ontological annotation data.

"""
import itertools
import logging
from collections import deque
from typing import Union, Sequence, Optional, Generator, Any, cast
from rdflib import Graph, RDF, PROF, OWL, URIRef, DCTERMS, Namespace

from ogc.na import util
from pathlib import Path

from ogc.na.validation import ProfileValidationReport, ProfilesValidationReport

PROFROLE = Namespace('http://www.w3.org/ns/dx/prof/role/')

PROFILES_QUERY = """
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
                                 profrole:validation))
            } 
            OPTIONAL {
                ?resource prof:hasRole ?role ;
                    prof:hasArtifact ?artifact ;
                    .
                FILTER(?role IN (profrole:entailment-closure,
                                 profrole:validation-closure,
                                 profrole:annotation))
            }
        }
    }
"""

logger = logging.getLogger('domain_config')


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
                 local_artifact_mappings: dict[str, Union[str, Path]] = None,
                 ignore_artifact_errors=False):

        assert srcs is not None
        if isinstance(srcs, str) or not isinstance(srcs, Sequence):
            self._srcs = (srcs,)
        else:
            self._srcs = srcs

        self._local_artifact_mappings: dict[str, Union[str, Path]] = {}
        if local_artifact_mappings:
            self._local_artifact_mappings = {u: Path(p) for u, p in local_artifact_mappings.items()}
        logger.debug("Using local artifact mappings: %s", self._local_artifact_mappings)
        self._profiles: dict[URIRef, Profile] = {}
        self._load_profiles()
        # Cache of { profile: { role: Graph } }
        self._graphs: dict[URIRef, dict[URIRef, Graph]] = {}

        self.ignore_artifact_errors = ignore_artifact_errors

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
                role_ref = g.value(resource_ref, PROF.hasRole)
                for artifact_ref in g.objects(resource_ref, PROF.hasArtifact):
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
                matchedlocal, matchedpath = l, p / uri[len(l):]
        return str(matchedpath)

    def get_artifacts(self, profile: URIRef, role: URIRef) -> Optional[list[Union[str, Path]]]:
        if profile not in self._profiles:
            return None

        result = []
        for artifact_ref in self._profiles[profile].get_artifacts(role):
            result.append(self._apply_mappings(artifact_ref))
        return result

    def get_graph(self, profile: URIRef, role: URIRef) -> Optional[Graph]:
        if profile not in self._profiles:
            return None

        prof_graphs = self._graphs.setdefault(profile, {})
        g = prof_graphs.get(role)
        if not g:
            g = Graph()
            for artifact in self.get_artifacts(profile, role):
                try:
                    g.parse(artifact)
                except Exception as e:
                    if self.ignore_artifact_errors:
                        logger.warning("Error when retrieving or parsing artifact %s: %s",
                                       artifact, str(e))
                    else:
                        raise Exception(f"Error when retrieving or parsing artifact {artifact}") from e

            prof_graphs[role] = g
        return g

    def entail(self, g: Graph,
               additional_profiles: Optional[Sequence[URIRef]] = None,
               inplace: bool = True,
               recursive: bool = True) -> Graph:
        if not inplace:
            g = util.copy_triples(g)

        profiles = deque(find_profiles(g))
        if additional_profiles:
            profiles.extend(additional_profiles)
        seen = set()
        while profiles:
            profile_ref = profiles.popleft()
            rules = self.get_graph(profile_ref, PROFROLE.entailment)
            extra = self.get_graph(profile_ref, PROFROLE['entailment-closure'])
            g = util.entail(g, rules, extra or None, True)
            seen.add(profile_ref)

            profile = self._profiles.get(profile_ref)
            if recursive and profile and profile.profile_of:
                profiles.extend(profile.profile_of)

        return g

    def validate(self, g: Graph,
                 additional_profiles: Optional[Sequence[URIRef]] = None,
                 recursive: bool = True) -> ProfilesValidationReport:
        result = ProfilesValidationReport()
        profiles = deque(find_profiles(g))
        if additional_profiles:
            profiles.extend(additional_profiles)
        seen = set()
        while profiles:
            profile_ref = profiles.popleft()
            if profile_ref in seen:
                continue
            seen.add(profile_ref)
            logger.debug("Validating with %s", str(profile_ref))
            profile = self._profiles.get(profile_ref)
            if not profile:
                logger.warning("Profile %s not found", profile_ref)
                # should we fail?
                continue
            rules = self.get_graph(profile_ref, PROFROLE.validation)
            extra = self.get_graph(profile_ref, PROFROLE['validation-closure'])
            result.add(ProfileValidationReport(profile_ref, profile.token, util.validate(g, rules, extra)))
            logger.debug("Adding validation results for %s", profile_ref)

            if recursive and profile.profile_of:
                profiles.extend([pof for pof in profile.profile_of if pof not in result])

        return result


    def get_annotations(self, g: Graph, additional_profiles: Optional[Sequence[URIRef]] = None) -> dict[Path, Graph]:
        result = {}
        profiles = find_profiles(g)
        if additional_profiles:
            profiles = itertools.chain(profiles, additional_profiles)
        for profile_ref in profiles:
            artifacts = self.get_artifacts(profile_ref, PROFROLE.annotation)
            for artifact in artifacts:
                result[artifact] = Graph().parse(artifact)
        return result
