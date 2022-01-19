from __future__ import annotations

import json
import re
from builtins import int as integer
from builtins import str as string
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Iterator, Protocol, TypeVar, cast

from requests.models import Response

_AnyT = TypeVar("_AnyT")


def not_none(optional: _AnyT | None) -> _AnyT:
    assert optional is not None
    return optional


def re_groups(match: re.Match[str] | None) -> tuple[str, ...]:
    return cast(tuple[str, ...], not_none(match).groups())


if TYPE_CHECKING:

    class JSONObject(dict[str, JSONType], Protocol):  # type: ignore  # noqa: F821 - false positive
        __class__: type[dict[str, _JSONType]]  # type: ignore

    class _JSONArray(list[JSONType], Protocol):  # type: ignore  # noqa: F821 - false positive
        __class__: type[list[_JSONType]]  # type: ignore

    _JSONType = str | int | bool | Decimal | _JSONArray | JSONObject | None  # noqa: WPS465 - false positive

    _JSONT = TypeVar("_JSONT", bound=_JSONType)
else:
    JSONObject = object
    _JSONType = object


class JSON:
    def __init__(self, body: _JSONType):
        self.body = body

    @classmethod
    def loads(cls, json_str: str | bytes) -> JSON:
        return cls(cast(_JSONType, json.loads(json_str, parse_float=Decimal)))

    def dumps(self) -> str:
        return json.dumps(self.body)

    @classmethod
    def response(cls, json_response: Response) -> JSON:
        return cls(cast(_JSONType, json_response.json(parse_float=Decimal)))

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
        if isinstance(self.body, Decimal):
            return self.body
        if isinstance(self.body, int):
            return Decimal(self.int)
        return Decimal(self.str)

    def __str__(self) -> string:
        return str(self.body)

    def __bool__(self) -> bool:
        return bool(self.body)

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
        return {key: JSON(child_value) for key, child_value in cast(dict[str, _JSONType], self.body).items()}
