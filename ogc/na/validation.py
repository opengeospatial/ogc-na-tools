#!/usr/bin/env python3

from rdflib import URIRef, Graph

from ogc.na import util


class ValidationReport:

    def __init__(self, pyshacl_result: tuple):
        self.result, self.graph, self.text = pyshacl_result


class ProfileValidationReport:

    def __init__(self, profile_uri: URIRef, profile_token: str, report: ValidationReport):
        self.profile_uri = profile_uri
        self.profile_token = profile_token
        self.report = report


class ProfilesValidationReport:

    def __init__(self, profile_reports: list[ProfileValidationReport] = None):
        self.reports = []
        self.result = True
        self.graph = Graph()
        self.text = ''
        if profile_reports:
            for profile_report in self.reports:
                self.add(profile_report)

    def add(self, profile_report: ProfileValidationReport):
        self.reports.append(profile_report)
        self.result &= profile_report.report.result
        util.copy_triples(profile_report.report.graph, self.graph)
        if profile_report.report.text:
            if self.text:
                self.text += '\n'
            self.text += (f"=== {profile_report.profile_token} "
                          f"({profile_report.profile_uri}) ===\n"
                          f"{profile_report.report.text}")
