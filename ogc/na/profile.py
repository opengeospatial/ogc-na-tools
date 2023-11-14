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
from __future__ import annotations
import itertools
import logging
from collections import deque
from typing import Union, Sequence, Optional, Generator, Any, cast, Iterable
from rdflib import Graph, RDF, PROF, OWL, URIRef, DCTERMS, Namespace, RDFS

from ogc.na import util
from pathlib import Path

from ogc.na.validation import ProfileValidationReport, ProfilesValidationReport
from ogc.na.models import ValidationReport

PROFROLE = Namespace('http://www.w3.org/ns/dx/prof/role/')

ROLE_ENTAILMENT = PROFROLE.entailment
ROLE_ENTAILMENT_CLOSURE = PROFROLE['entailment-closure']
ROLE_VALIDATION = PROFROLE.validation
ROLE_VALIDATION_CLOSURE = PROFROLE['validation-closure']
ROLE_ANNOTATION = PROFROLE.annotation
ROLE_SEMANTIC_UPLIFT = PROFROLE['semantic-uplift']

PROFILES_QUERY = """
    PREFIX prof: <http://www.w3.org/ns/dx/prof/>
    PREFIX profrole: <http://www.w3.org/ns/dx/prof/role/>
    PREFIX shacl: <http://www.w3.org/ns/shacl#>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    CONSTRUCT {
        ?profile a prof:Profile ;
            prof:hasToken ?token ;
            prof:isProfileOf ?ancestor ;
            prof:hasResource ?resource ;
            owl:sameAs ?sameAs ;
            rdfs:label ?label ;
            .
        ?resource prof:hasRole ?role ;
            dct:conformsTo shacl: ;
            prof:hasArtifact ?artifact ;
            .
    } WHERE {
        __SERVICE__ {
            { ?profile a prof:Profile } UNION { ?other prof:isProfileOf ?profile }
            ?profile prof:hasToken ?token .
            OPTIONAL {
                { ?profile owl:sameAs+ ?sameAs } UNION { ?sameAs owl:sameAs+ ?profile }
            }
            OPTIONAL { ?profile rdfs:label ?label }
            OPTIONAL { ?profile prof:isProfileOf ?ancestor }
            OPTIONAL {
                ?profile prof:hasResource ?resource .
                ?resource prof:hasRole ?role ;
                    dct:conformsTo shacl: ;
                    prof:hasArtifact ?artifact
                OPTIONAL {
                    ?resource prof:hasRole ?role ;
                        prof:hasArtifact ?artifact
                }
            } 
        }
    }
"""

logger = logging.getLogger('ogc.na.profile')


def find_profiles(g: Graph) -> Generator[URIRef, Any, None]:
    return (o for s, o in g.subject_objects(DCTERMS.conformsTo) if isinstance(o, URIRef))


class ArtifactError(Exception):
    pass


class Profile:

    def __init__(self, uri: URIRef, token: str, profile_of: list[URIRef], label: str | None = None):
        self.uri = uri
        self.token = token
        self.label = label
        self.profile_of = [p for p in profile_of if p != uri]
        self.artifacts: dict[URIRef, list[str]] = {}

    def add_artifact(self, role: URIRef, href: URIRef):
        self.artifacts.setdefault(role, []).append(href)

    def get_artifacts(self, role: URIRef) -> list[URIRef]:
        return self.artifacts.get(role, [])

    def __repr__(self):
        return f"Profile({str(self.uri)},token={self.token}" \
               f",profileOf=[{','.join(str(p) for p in self.profile_of)}]" \
               f",roles=[{','.join(str(k) for k in self.artifacts.keys())}])"


class ProfileRegistry:

    def __init__(self, srcs: str | Path | Iterable[str | Path],
                 local_artifact_mappings: dict[str, str | Path] = None,
                 ignore_artifact_errors=False):

        assert srcs is not None
        if isinstance(srcs, str) or not isinstance(srcs, Iterable):
            self._srcs = (srcs,)
        else:
            self._srcs = srcs

        self._local_artifact_mappings: dict[str, Union[str, Path]] = {}
        if local_artifact_mappings:
            self._local_artifact_mappings = {u: Path(p) for u, p in local_artifact_mappings.items()}
        logger.debug("Using local artifact mappings: %s", self._local_artifact_mappings)
        self.profiles: dict[URIRef, Profile] = {}
        self._load_profiles()
        # Cache of { profile: { role: Graph } }
        self._graphs: dict[URIRef, dict[URIRef,
                           tuple[Graph, set[Union[str, Path]], set[Union[str, Path]]]]] = {}

        self.ignore_artifact_errors = ignore_artifact_errors

    def build_profile_chain(self, profiles: Sequence[URIRef | str],
                            recursive: bool = True,
                            sort: bool = True) -> list[URIRef]:
        if not profiles:
            return []

        if not sort:
            # Only known profiles and remove duplicates
            known = {URIRef(p): True for p in profiles if p in self.profiles}
            if recursive:
                pending = set(known)
                while pending:
                    prof = self.profiles.get(pending.pop())
                    if prof:
                        for prof_of in prof.profile_of or ():
                            if prof_of not in known:
                                pending.add(prof_of)
                            known[prof_of] = True
            return list(known)

        # Otherwise, sort DAG
        # 1. Build dependency tree
        dependencies: dict[URIRef, set[URIRef] | None] = {}
        pending = deque(profiles)  # using a deque to try and preserve as much of the original order as possible
        while pending:
            prof_uri = pending.popleft()
            if prof_uri in dependencies:
                # skip if already processed
                continue
            prof = self.profiles.get(prof_uri)
            if not prof:
                # skip if unknown
                continue
            prof_deps = [d for d in self.profiles.get(prof_uri).profile_of if d in self.profiles]
            if not prof_deps:
                # has no dependencies
                dependencies[prof_uri] = None
            if not recursive:
                # non-recursive => only work with provided profile list
                prof_deps = [d for d in prof_deps if d in profiles]
            else:
                for p in prof_deps:
                    if p not in pending:
                        pending.appendleft(p)
            dependencies[prof_uri] = set(prof_deps)

        result: list[URIRef] = []
        # 2. Sort dependencies
        while True:
            if not dependencies:
                break
            removed = {}
            for parent_uri, child_uris in dependencies.items():
                if not child_uris:
                    removed[parent_uri] = True
            if not removed:
                dependencies_str = '; '.join(
                    f"{p} <- {', '.join(str(c) for c in cs)}" for p, cs in dependencies.items())
                raise ValueError(f'Cycle detected in profile DAG, cannot sort: {dependencies_str}')
            for rem in removed:
                del dependencies[rem]
                result.append(rem)
            removed = set(removed)
            for child_uris in dependencies.values():
                child_uris -= removed

        return result

    def _load_profiles(self):
        logger.debug("Loading profiles from %s", [str(x) for x in self._srcs])
        g: Graph = Graph()
        for src in self._srcs:
            if isinstance(src, str) and src.startswith('sparql:'):
                endpoint = src[len('sparql:'):]
                logger.info("Fetching profiles from SPARQL endpoint %s", endpoint)
                assert util.is_url(endpoint, http_only=True)
                s = g.query(PROFILES_QUERY.replace('__SERVICE__', f"SERVICE <{endpoint}>")).graph
                util.copy_triples(s, g)
            else:
                g.parse(src)

        # resolve recursive isProfileOf and sameAs
        g = g.query(PROFILES_QUERY.replace('__SERVICE__', '')).graph

        for profile_ref in cast(list[URIRef], g.subjects(RDF.type, PROF.Profile)):

            if profile_ref in self.profiles:
                # do not parse duplicate profiles
                continue

            token = str(g.value(profile_ref, PROF.hasToken))
            label = g.value(profile_ref, RDFS.label)
            profile_of: list[URIRef] = cast(list[URIRef], list(g.objects(profile_ref, PROF.isProfileOf)))

            profile = Profile(profile_ref, token, profile_of, label=str(label) if label else None)

            for resource_ref in g.objects(profile_ref, PROF.hasResource):
                role_ref = g.value(resource_ref, PROF.hasRole)
                if not role_ref:
                    continue
                for artifact_ref in g.objects(resource_ref, PROF.hasArtifact):
                    profile.add_artifact(role_ref, cast(URIRef, artifact_ref))

            self.profiles[profile_ref] = profile
            for same_as_ref in g.objects(profile_ref, OWL.sameAs):
                self.profiles[cast(URIRef, same_as_ref)] = profile

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Profiles loaded: %s", [str(p) for p in self.profiles])
        else:
            logger.info(f"Loaded {len(self.profiles)} profiles")

    def _apply_mappings(self, uri: str) -> Path | str:
        """
        Returns the longest match in self._local_artifact_mappings (prefixes)
        for a given URI, or the URI itself if not found
        """

        if uri in self._local_artifact_mappings:
            return self._local_artifact_mappings[uri]

        matchedlocal = None
        matchedpath = uri
        for l, p in self._local_artifact_mappings.items():
            if uri.startswith(l) and (matchedlocal is None or len(matchedlocal) < len(l)):
                matchedlocal, matchedpath = l, p / uri[len(l):]
        return matchedpath

    def get_artifacts(self, profile: URIRef | str, role: URIRef) -> set[str | Path] | None:
        if not isinstance(profile, URIRef):
            profile = URIRef(profile)
        if profile not in self.profiles:
            return None

        return set(self._apply_mappings(artifact_ref) for artifact_ref in self.profiles[profile].get_artifacts(role))

    def get_graph(self, profile: URIRef | str, role: URIRef) \
            -> tuple[Graph | None, set[str | Path] | None, set[str | Path] | None]:
        if not isinstance(profile, URIRef):
            profile = URIRef(profile)
        if profile not in self.profiles:
            return None, None, None

        prof_graphs = self._graphs.setdefault(profile, {})

        if role in prof_graphs:
            return prof_graphs[role]

        g = Graph()
        artifacts = set()
        failed_artifacts = set()
        for artifact in self.get_artifacts(profile, role):
            try:
                g.parse(artifact)
                artifacts.add(artifact)
            except Exception as e:
                if self.ignore_artifact_errors:
                    logger.warning("Error when retrieving or parsing artifact %s: %s",
                                   artifact, str(e))
                    failed_artifacts.add(artifact)
                else:
                    raise Exception(f"Error when retrieving or parsing artifact {artifact}") from e

            prof_graphs[role] = g, artifacts, failed_artifacts
        return g, artifacts, failed_artifacts

    def entail(self, g: Graph,
               additional_profiles: Optional[Sequence[str | URIRef]] = None,
               inplace: bool = True,
               recursive: bool = True) -> tuple[Graph, set[Union[str, Path]]]:
        if not inplace:
            g = util.copy_triples(g)

        profiles = deque(find_profiles(g))
        if additional_profiles:
            profiles.extend(p if isinstance(p, URIRef) else URIRef(p) for p in additional_profiles)

        profiles = self.build_profile_chain(profiles, recursive=recursive)

        artifacts = set()
        for profile_ref in profiles:
            logger.info('Entailing with %s', profile_ref)
            rules, rules_artifacts, failed_artifacts = self.get_graph(profile_ref, ROLE_ENTAILMENT)
            extra, extra_artifacts, failed_artifacts = self.get_graph(profile_ref, ROLE_ENTAILMENT_CLOSURE)
            if rules_artifacts:
                artifacts.update(rules_artifacts)
            if extra_artifacts:
                artifacts.update(extra_artifacts)
            g = util.entail(g, rules, extra or None, True)

        return g, artifacts

    def validate(self, g: Graph,
                 additional_profiles: Sequence[str | URIRef] | None = None,
                 recursive: bool = True, log_artifact_errors: bool = False) -> ProfilesValidationReport:
        result = ProfilesValidationReport()
        profiles = deque(find_profiles(g))
        if additional_profiles:
            profiles.extend(p if isinstance(p, URIRef) else URIRef(p) for p in additional_profiles)

        profiles = self.build_profile_chain(profiles, recursive=recursive, sort=False)

        for profile_ref in profiles:
            logger.info("Validating with %s", str(profile_ref))
            profile = self.profiles.get(profile_ref)
            if not profile:
                logger.warning("Profile %s not found", profile_ref)
                # should we fail?
                continue
            rules, rules_artifacts, failed_rules_artifacts = self.get_graph(profile_ref, ROLE_VALIDATION)
            extra, extra_artifacts, failed_extra_artifacts = self.get_graph(profile_ref, ROLE_VALIDATION_CLOSURE)
            failed_artifacts = failed_rules_artifacts | failed_extra_artifacts
            try:
                prof_result = util.validate(g, rules, extra)
            except Exception as e:
                if log_artifact_errors:
                    err_text = f"Error performing SHACL validation: {e}\n"
                    if rules_artifacts:
                        err_text += 'Used rules artifacts:\n' + '\n - '.join((str(s) for s in rules_artifacts))
                    if extra_artifacts:
                        err_text += 'Used extra artifacts:\n' + '\n - '.join((str(s) for s in extra_artifacts))
                    prof_result = ValidationReport((False, Graph(), err_text))
                else:
                    all_artifacts = {
                        'rules': [str(a) for a in rules_artifacts],
                        'extra': [str(a) for a in extra_artifacts],
                    }
                    raise ArtifactError('Error performing SHACL validation', all_artifacts) from e

            prof_result.used_resources = set(itertools.chain(rules_artifacts or [], extra_artifacts or []))
            if failed_artifacts:
                prof_result.text += "\n# Failed artifacts\n" + '\n'.join(str(a) for a in failed_artifacts) + '\n'
            result.add(ProfileValidationReport(profile_ref, profile.token, prof_result))
            logger.debug("Adding validation results for %s", profile_ref)

        return result

    def get_annotations(self, g: Graph, additional_profiles: Sequence[URIRef | str] | None = None) -> dict[Path, Graph]:
        result = {}
        profiles = find_profiles(g)
        if additional_profiles:
            profiles = itertools.chain(profiles, additional_profiles)
        for profile_ref in profiles:
            artifacts = self.get_artifacts(profile_ref, ROLE_ANNOTATION)
            for artifact in artifacts:
                result[artifact] = Graph().parse(artifact)
        return result

    def has_profile(self, uri: str | URIRef) -> bool:
        if isinstance(uri, str):
            uri = URIRef(uri)
        return uri in self.profiles
