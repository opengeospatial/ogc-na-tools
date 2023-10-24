#!/usr/bin/env python3
"""
This module defines auxiliary classes to represent [pySHACL](https://github.com/RDFLib/pySHACL)
validation reports.
"""
from __future__ import annotations
from pathlib import Path
from typing import Union
from urllib.parse import urlsplit
from urllib.request import urlopen

import jsonschema
import requests
from rdflib import URIRef, Graph

from ogc.na import util
from ogc.na.models import ValidationReport


class ProfileValidationReport:
    """
    Validation report for a given [profile](https://www.w3.org/TR/dx-prof/).
    """

    def __init__(self, profile_uri: URIRef, profile_token: str, report: ValidationReport):
        """
        :param profile_uri: URI for the profile
        :param profile_token: Token for the profile
        :param report: [ValidationReport][ogc.na.validation.ValidationReport]
        """
        self.profile_uri = profile_uri
        self.profile_token = profile_token
        self.report = report

    @property
    def used_resources(self) -> set[Union[str, Path]]:
        return self.report.used_resources

    @used_resources.setter
    def used_resources(self, ur: set[Union[str, Path]]):
        self.used_resources = ur


class ProfilesValidationReport:
    """
    Class to aggregate several [ProfileValidationReport][ogc.na.validation.ProfileValidationReport]'s
    coming from different profiles.

    Results are exposed through the following fields:

    * `reports`: list of [validation reports][ogc.na.validation.ProfileValidationReport]
    * `result`: `True` if all validations passed, otherwise `False`
    * `graph`: union of all SHACL validation report [Graph][rdflib.Graph]s
    * `text`: full report text coming from all validation results (separated by profile)
    """

    def __init__(self, profile_reports: list[ProfileValidationReport] = None):
        """
        :param profile_reports: list of initial [validation reports][ogc.na.validation.ProfileValidationReport]
        """
        self.reports: list[ProfileValidationReport] = []
        self.result = True
        self.graph = Graph()
        self.text = ''
        if profile_reports:
            for profile_report in self.reports:
                self.add(profile_report)

    def add(self, profile_report: ProfileValidationReport):
        """
        Add a new [validation report][ogc.na.validation.ProfileValidationReport].

        :param profile_report:
        """
        self.reports.append(profile_report)
        self.result &= profile_report.report.result
        util.copy_triples(profile_report.report.graph, self.graph)
        if profile_report.report.text:
            if self.text:
                self.text += '\n'
            self.text += (f"=== {profile_report.profile_token} "
                          f"({profile_report.profile_uri}) ===\n"
                          f"{profile_report.report.text}")

    def __contains__(self, item) -> bool:
        return any(r.profile_uri == item for r in self.reports)

    @property
    def used_resources(self):
        return set(r for report in self.reports for r in report.used_resources)


class YamlSchemaRefResolver(jsonschema.validators.RefResolver):

    def resolve_remote(self, uri):
        scheme = urlsplit(uri).scheme

        if scheme in self.handlers:
            result = self.handlers[scheme](uri)
        elif scheme in ["http", "https"]:
            result = util.load_yaml(content=requests.get(uri).content)
        else:
            # Otherwise, pass off to urllib and assume utf-8
            with urlopen(uri) as url:
                result = util.load_yaml(content=url.read().decode("utf-8"))

        if self.cache_remote:
            self.store[uri] = result
        return result
