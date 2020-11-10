import json
from typing import (
    Any,
    ClassVar,
    Dict,
    Generic,
    Mapping,
    Optional,
    Type,
    TypeVar,
)

import requests
from typing_extensions import Literal

from .api import PolyswarmAPI

JSONDecodeError = ValueError
logger: Any


class PolyswarmSession(requests.Session):
    def __init__(self, key: Any, retries: Any, user_agent: Any = ...) -> None:
        ...

    def requests_retry_session(
        self, retries: Any = ..., backoff_factor: Any = ..., status_forcelist: Any = ...
    ) -> None:
        ...

    def set_auth(self, key: Any) -> None:
        ...

    def set_user_agent(self, ua: Any) -> None:
        ...


class RequestParamsEncoder(json.JSONEncoder):
    def default(self, obj: Any):
        ...


class PolyswarmRequest:
    api_instance: Any = ...
    session: Any = ...
    timeout: Any = ...
    request_parameters: Any = ...
    result_parser: Any = ...
    raw_result: Any = ...
    status_code: Any = ...
    status: Any = ...
    errors: Any = ...
    total: Any = ...
    limit: Any = ...
    offset: Any = ...
    order_by: Any = ...
    direction: Any = ...
    has_more: Any = ...
    parser_kwargs: Any = ...

    def __init__(
        self,
        api_instance: Any,
        request_parameters: Any,
        key: Optional[Any] = ...,
        result_parser: Optional[Any] = ...,
        **kwargs: Any
    ) -> None:
        ...

    def result(self):
        ...

    def execute(self):
        ...

    def parse_result(self, result: Any) -> None:
        ...

    def __iter__(self) -> Any:
        ...

    def consume_results(self) -> None:
        ...

    def next_page(self):
        ...


C = TypeVar('C')
T = TypeVar('T', bound='BaseResource')


class BaseResource(Generic[C]):
    api: PolyswarmAPI
    _content: C

    def __init__(self, content: C, *args: Any, **kwargs: Any) -> None:
        ...

    @classmethod
    def parse_result(cls: Type[T], api: PolyswarmAPI, content: C, **kwargs) -> T:
        ...


class BaseJsonResource(BaseResource[Mapping]):
    RESOURCE_ENDPOINT: ClassVar[Optional[str]] = None
    RESOURCE_ID_KEY: ClassVar[str] = 'id'

    json: Mapping

    def __int__(self) -> int:
        ...

    def _get(self, path, default=None, content=None):
        ...

    @classmethod
    def parse_result_list(cls, api_instance: Any, json_data: Any, **kwargs: Any):
        ...

    @classmethod
    def create(cls, api: PolyswarmAPI, **kwargs: Any):
        ...

    @classmethod
    def get(cls, api: PolyswarmAPI, **kwargs: Any):
        ...

    @classmethod
    def update(cls, api: PolyswarmAPI, **kwargs: Any):
        ...

    @classmethod
    def delete(cls, api: PolyswarmAPI, **kwargs: Any):
        ...

    @classmethod
    def list(cls, api: PolyswarmAPI, **kwargs: Any):
        ...


HashableDigestTypes = Literal["sha256", "sha1", "md5"]


class Hashable:
    SUPPORTED_HASH_TYPES: ClassVar[Dict[HashableDigestTypes, bool]]

    _hash: Optional[str]
    _hash_type: Optional[HashableDigestTypes]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        ...

    @property
    def hash(self):
        ...

    @hash.setter
    def hash(self, value: Any) -> None:
        ...

    @property
    def hash_type(self):
        ...

    def validate(self) -> None:
        ...

    def resolve_hash_type(self):
        ...

    @property
    def raw(self):
        ...

    def __eq__(self, other: Any) -> Any:
        ...


def is_hex(value: Any):
    ...


def is_valid_sha1(value: Any):
    ...


def is_valid_md5(value: Any):
    ...


def is_valid_sha256(value: Any):
    ...


def parse_isoformat(date_string: Any):
    ...
