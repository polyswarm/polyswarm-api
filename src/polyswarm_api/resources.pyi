from datetime import datetime
from enum import Enum
from typing import (
    Any,
    Collection,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

from typing_extensions import Literal

from polyswarm_api import core, exceptions, settings

SHA1Digest = str
SHA256Digest = str
MD5Digest = str

TagsT = Collection[str]


class Engine(core.BaseJsonResource):
    address: str
    name: Optional[str]

    def __init__(self, content: Any, api: Optional[Any] = ...) -> None:
        ...


class MetadataMapping(core.BaseJsonResource):
    ...


class ToolMetadata(core.BaseJsonResource):
    ...


class Metadata(core.BaseJsonResource):
    id: str
    sha1: SHA1Digest
    sha256: SHA256Digest
    md5: MD5Digest
    ssdeep: Optional[str]
    tlsh: Optional[str]
    domains: Collection[str]
    ipv4: Collection[str]
    ipv6: Collection[str]
    urls: Collection[str]

    def __init__(self, content: Any, api: Optional[Any] = ...) -> None:
        ...

    def __contains__(self, item: Any):
        ...

    def __getattr__(self, name: Any):
        ...


class ArtifactInstance(core.BaseJsonResource, core.Hashable):
    id: str
    artifact_id: str
    assertions: Collection[Assertion]
    country: Optional[str]
    created: datetime
    extended_type: Optional[str]
    failed: bool
    filename: Optional[str]
    first_seen: datetime
    last_scanned: datetime
    last_seen: datetime
    mimetype: Optional[str]
    permalink: str
    polyscore: Optional[float]
    sha1: SHA1Digest
    sha256: SHA256Digest
    md5: MD5Digest
    size: Optional[int]
    type: Literal["FILE", "URL"]
    votes: Collection[Vote]
    window_closed: bool

    def __init__(self, content: Any, api: Optional[Any] = ...) -> None:
        ...

    @classmethod
    def search_hash(cls, api: Any, hash_value: Any, hash_type: Any):
        ...

    @classmethod
    def search_url(cls, api: Any, url: Any):
        ...

    @classmethod
    def list_scans(cls, api: Any, hash_value: Any):
        ...

    @classmethod
    def submit(
        cls,
        api: Any,
        artifact: Any,
        artifact_name: Any,
        artifact_type: Any,
        scan_config: Optional[Any] = ...
    ):
        ...

    @classmethod
    def rescan(cls, api: Any, hash_value: Any, hash_type: Any, scan_config: Optional[Any] = ...):
        ...

    @classmethod
    def rescan_id(cls, api: Any, submission_id: Any, scan_config: Optional[Any] = ...):
        ...

    @classmethod
    def lookup_uuid(cls, api: Any, submission_id: Any):
        ...

    @classmethod
    def metadata_rerun(
        cls, api: Any, hashes: Any, analyses: Optional[Any] = ..., skip_es: Optional[Any] = ...
    ):
        ...

    @property
    def malicious_assertions(self):
        ...

    @property
    def benign_assertions(self):
        ...

    @property
    def valid_assertions(self):
        ...

    @property
    def filenames(self):
        ...


class ArtifactArchive(core.BaseJsonResource):
    id: str
    community: str
    created: datetime
    uri: str


class Hunt(core.BaseJsonResource):
    id: str
    created: datetime
    status: str
    active: bool
    ruleset_name: Optional[str]

    def __init__(self, content: Any, api: Optional[Any] = ...) -> None:
        ...


class LiveHunt(Hunt):
    ...


class HistoricalHunt(Hunt):
    ...


class HuntResult(core.BaseJsonResource):
    id: str
    rule_name: str
    tags: TagsT
    created: datetime
    sha256: SHA256Digest
    historicalscan_id: Any = ...
    livescan_id: Any = ...
    artifact: ArtifactInstance

    def __init__(self, content: Any, api: Optional[Any] = ...) -> None:
        ...


class LiveHuntResult(HuntResult):
    ...


class HistoricalHuntResult(HuntResult):
    ...


def all_hashes(file_handle: Any, algorithms: Any = ...):
    ...


class LocalHandle(core.BaseResource):
    handle: Any = ...

    def __init__(
        self, content: Any, api: Optional[Any] = ..., handle: Optional[Any] = ..., **kwargs: Any
    ) -> None:
        ...

    @classmethod
    def download(cls, api: Any, hash_value: Any, hash_type: Any, handle: Optional[Any] = ...):
        ...

    @classmethod
    def download_archive(cls, api: Any, u: Any, handle: Optional[Any] = ...):
        ...

    def __getattr__(self, name: Any):
        ...


class LocalArtifact(LocalHandle, core.Hashable):
    sha256: Any = ...
    sha1: Any = ...
    md5: Any = ...
    analyzed: bool = ...
    artifact_type: Any = ...
    artifact_name: Any = ...

    def __init__(
        self,
        handle: Any,
        artifact_name: Optional[Any] = ...,
        artifact_type: Optional[Any] = ...,
        api: Optional[Any] = ...,
        analyze: bool = ...
    ) -> None:
        ...

    @classmethod
    def from_path(
        cls,
        api: Any,
        path: Any,
        artifact_type: Optional[Any] = ...,
        analyze: bool = ...,
        create: bool = ...,
        artifact_name: Optional[Any] = ...,
        **kwargs: Any
    ):
        ...

    @classmethod
    def from_content(
        cls,
        api: Any,
        content: Any,
        artifact_name: Optional[Any] = ...,
        artifact_type: Optional[Any] = ...,
        analyze: bool = ...
    ):
        ...

    def analyze_artifact(self, force: bool = ...) -> None:
        ...


class YaraRuleset(core.BaseJsonResource):
    yara: Any
    name: Optional[str]
    id: str
    description: Optional[str]
    created: datetime
    modified: datetime
    deleted: bool


class TagLink(core.BaseJsonResource):
    id: str
    sha256: SHA256Digest
    description: Optional[str]
    created: datetime
    updated: datetime
    first_seen: datetime
    tags: TagsT
    deleted: bool


class Tag(core.BaseJsonResource):
    id: str
    created: datetime
    updated: datetime
    name: str


class MalwareFamily(core.BaseJsonResource):
    id: str
    created: datetime
    updated: datetime
    name: str
    emerging: datetime


####


class Assertion(core.BaseJsonResource):
    author: str
    author_name: str
    bid: int
    engine_name: Optional[str]
    mask: bool
    scanfile: ArtifactInstance
    metadata: Mapping[str, Any]
    verdict: bool


class Vote(core.BaseJsonResource):
    scanfile: ArtifactInstance
    arbiter: str
    vote: str


class ArtifactType(Enum):
    FILE: int = ...
    URL: int = ...

    @staticmethod
    def parse(value: Any):
        ...

    @staticmethod
    def to_string(artifact_type: Any):
        ...

    def decode_content(self, content: Any):
        ...


class Hash(core.Hashable):
    def __init__(self, hash_: Any, hash_type: Optional[Any] = ..., validate_hash: bool = ...) -> None:
        ...

    @classmethod
    def from_hashable(cls, hash_: Any, hash_type: Optional[Any] = ...):
        ...

    def __hash__(self) -> Any:
        ...
