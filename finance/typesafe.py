from __future__ import annotations

import json
import re
from builtins import int as integer
from builtins import str as string
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Iterator, Protocol, TypeVar, cast

from requests.models import Response

_AnyType = TypeVar("_AnyType")


def not_none(optional: _AnyType | None) -> _AnyType:
    assert optional is not None
    return optional


def re_groups(match: re.Match[str] | None) -> tuple[str, ...]:
    return cast(tuple[str, ...], not_none(match).groups())


def attributes(typ: object) -> dict[str, object]:
    return cast(dict[str, object], typ.__dict__)


if TYPE_CHECKING:

    class _JSONArray(list[JSONType], Protocol):  # type: ignore  # noqa: F821 - false positive
        __class__: type[list[JSONType]]  # type: ignore

    class _JSONObject(dict[str, JSONType], Protocol):  # type: ignore  # noqa: F821 - false positive
        __class__: type[dict[str, JSONType]]  # type: ignore

    JSONType = str | int | bool | Decimal | _JSONArray | _JSONObject | None  # noqa: WPS465 - false positive

    _JSONType = TypeVar("_JSONType", bound=JSONType)
else:
    JSONType = object


class JSON:
    def __init__(self, body: JSONType):
        self.body = body

    @classmethod
    def loads(cls, json_str: str | bytes) -> JSON:
        return cls(cast(JSONType, json.loads(json_str, parse_float=Decimal)))

    def dumps(self) -> str:
        return json.dumps(self.body)

    @classmethod
    def response(cls, json_response: Response) -> JSON:
        return cls(cast(JSONType, json_response.json()))

    @property
    def str(self) -> str:
        assert isinstance(self.body, str)
        return self.body

    @property
    def int(self) -> integer:
        assert isinstance(self.body, integer)
        return self.body

    @property
    def decimal(self) -> Decimal:
        return self.body if isinstance(self.body, Decimal) else Decimal(self.str)

    def __str__(self) -> string:
        return str(self.body)

    def __iter__(self) -> Iterator[JSON]:
        return iter(self._as_array())

    def __getitem__(self, key: integer | string) -> JSON:
        return self._as_array()[key] if isinstance(key, integer) else self._as_object()[key]

    def __contains__(self, key: string) -> bool:
        return key in self._as_object()

    def get(self, key: string) -> JSON | None:
        return self._as_object().get(key)

    def strptime(self, _format: string) -> datetime:
        return datetime.strptime(self.str, _format)

    def _as_array(self) -> list[JSON]:
        assert isinstance(self.body, list)
        return [JSON(entry) for entry in self.body]

    def _as_object(self) -> dict[string, JSON]:
        assert isinstance(self.body, dict)
        return {key: JSON(child_value) for key, child_value in cast(dict[str, JSONType], self.body).items()}
