#!/usr/bin/env python3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Union


@dataclass
class FileProvenanceMetadata:
    filename: Union[str, Path] = None
    uri: str = None
    mime_type: str = None


@dataclass
class ProvenanceMetadata:
    context: FileProvenanceMetadata = None
    doc: FileProvenanceMetadata = None
    output: FileProvenanceMetadata = None
    start: datetime = None,
    end: datetime = None,
    root_directory: Union[str, Path] = None,
    base_uri: str = None,
    batch_activity_id: str = None
