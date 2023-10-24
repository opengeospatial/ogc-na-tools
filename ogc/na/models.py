from __future__ import annotations

from pathlib import Path
from typing import Iterable, Union


class ValidationReport:
    """
    Validation report from a single validation result.

    Structures a pySHACL tuple report into `result`, `graph` and `text`
    fields.
    """

    def __init__(self, pyshacl_result: tuple,
                 used_resources: Iterable[Union[str, Path]] = None):
        """
        :param pyshacl_result: result from executing [pyshacl.validate]
        """
        self.result, self.graph, self.text = pyshacl_result
        self.used_resources: set[Union[str, Path]] = set(used_resources) if used_resources else set()
