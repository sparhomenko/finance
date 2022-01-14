from __future__ import annotations

import gzip
from base64 import b64decode, b64encode
from dataclasses import Field, dataclass, field, fields
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum, auto, unique
from io import BytesIO
from os import environ
from secrets import token_bytes
from types import MappingProxyType
from typing import Callable, Final, Generic, TypeVar, cast
from urllib.parse import ParseResult, urlparse, urlunparse
from uuid import uuid4
from xml.etree import ElementTree

import dacite
import inflection
from bpylist2 import archiver
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from more_itertools import one
from requests import post, request

from finance.core import BEGINNING, Account, AccountType, Category, Line, Transaction
from finance.typesafe import JSON, JSONType, not_none

_KEY_SIZE: Final = 16
_CATEGORIES: Final = MappingProxyType(
    {
        Category.CHILDREN: "Child/Dependent Expenses",
        Category.FEE: "Service Charges/Fees",
        Category.ENTERTAINMENT: "Entertainment",
        Category.GROCERIES: "Groceries",
        Category.HEALTHCARE: "Medical/Healthcare",
        Category.HOME: "Home Maintenance",
        Category.INSURANCE: "Insurance",
        Category.INTEREST_INCOME: "Interest Income",
        Category.INTEREST: "Interest Paid",
        Category.PENSION_CONTRIBUTION: "Retirement Contributions",
        Category.PERSONAL_CARE: "Fitness/Personal Care",
        Category.RESTAURANTS: "Dining/Restaurants",
        Category.SALARY: "Paychecks/Wages",
        Category.TAX: "Taxes",
        Category.TRANSPORT: "Travel",
        Category.UTILITIES: "Utilities",
    },
)
_AnyObjectT = TypeVar("_AnyObjectT", covariant=True)


@dataclass
class _Converter(Generic[_AnyObjectT]):
    obj_type: type[_AnyObjectT]
    parse: Callable[[str], _AnyObjectT]
    unparse: Callable[[_AnyObjectT], str] = str


class _Object:
    @classmethod
    def from_element(cls, converters: dict[str, _Converter[object]], element: ElementTree.Element) -> _Object:
        elements: dict[ElementTree.Element, object] = {}
        for field_element in element.findall("field"):
            attr: object | None
            if field_element.get("null") or field_element.text is None or field_element.text.endswith("(null)"):
                attr = None
            else:
                if enum_class_name := field_element.get("enum"):
                    attr = _Enum.from_name(enum_class_name, field_element.text)
                else:
                    attr = converters[not_none(field_element.get("type"))].parse(field_element.text)
            elements[field_element] = attr
        for record_element in element.findall("record"):
            elements[record_element] = cls.from_element(converters, record_element)
        for collection_element in element.findall("collection"):
            subelements = []
            for record_element in collection_element.findall("record"):
                subelements.append(cls.from_element(converters, record_element))
            elements[collection_element] = subelements
        attrs = {_banktivity_to_python(not_none(element.get("name"))): attr for element, attr in elements.items()}
        return dacite.core.from_dict(not_none(_Object.subclass(not_none(element.get("type")))), attrs, dacite.config.Config(check_types=False))

    def to_element(self, converters: dict[str, _Converter[object]], tag: str) -> ElementTree.Element:
        element = ElementTree.Element(tag, {"type": self.class_name()})
        for attr_name, attr_value in cast(dict[str, object], self.__dict__).items():
            if attr_name == "id" or attr_value is None:
                continue
            if isinstance(attr_value, _Enum):
                subelement = attr_value.to_element(converters, "field")
            elif isinstance(attr_value, _TransactionType):
                subelement = attr_value.to_element(converters, "record")
            elif isinstance(attr_value, list):
                subelement = ElementTree.Element("collection", {"type": "array"})
                for record in attr_value:
                    assert isinstance(record, _Object)
                    subsubelement = record.to_element(converters, "record")
                    subsubelement.set("name", "element")
                    subelement.append(subsubelement)
            else:
                element_type, converter = next(converter for converter in converters.items() if isinstance(attr_value, converter[1].obj_type))
                subelement = ElementTree.Element("field", {"type": element_type})
                subelement.text = converter.unparse(attr_value)
            subelement.set("name", _python_to_banktivity(attr_name))
            element.append(subelement)
        return element

    @classmethod
    def class_name(cls) -> str:
        return cls._convert(cls.__name__, there=True)

    @classmethod
    def subclass(cls: _ObjectTypeT, name: str) -> _ObjectTypeT | None:
        for subclass in cls.__subclasses__():
            if subclass.__name__ == cls._convert(name, there=False):
                return subclass
            if subsubclass := subclass.subclass(name):
                return subsubclass
        return None

    @classmethod
    def _convert(cls, name: str, there: bool) -> str:
        return name.removeprefix("_") if there else f"_{name}"


_ObjectTypeT = TypeVar("_ObjectTypeT", bound=type[_Object])


class _Enum(_Object, Enum):
    @classmethod
    def from_name(cls, class_name: str, name: str) -> _Enum | str:
        if subclass := _Enum.subclass(class_name):
            return subclass[inflection.underscore(name).upper()]
        return name

    def to_element(self, _: dict[str, _Converter[object]], tag: str) -> ElementTree.Element:
        element = ElementTree.Element(tag, {"enum": self.class_name()})
        element.text = inflection.dasherize(self.name).lower()
        return element

    @classmethod
    def _convert(cls, name: str, there: bool) -> str:
        prefix = "IGGCSyncAccounting"
        return f"{prefix}{super()._convert(name, there)}" if there else super()._convert(name.removeprefix(prefix), there)


@dataclass
class _Entity(_Object):
    id: str = field(default_factory=lambda: str(uuid4()).upper())


@dataclass
class _Currency(_Entity):
    name: str | None = None
    code: str | None = None


@unique
class _AccountClass(_Enum):
    CURRENT = auto()
    CREDIT_CARD = auto()
    CHECKING = auto()
    SAVINGS = auto()
    MORTGAGE = auto()
    EXPENSE = auto()
    REVENUE = auto()
    REAL_ESTATE = auto()
    LIABILITY = auto()


@unique
class _AccountType(_Enum):
    ASSET = auto()
    LIABILITY = auto()
    INCOME = auto()
    EXPENSE = auto()


@unique
class _AccountSubtype(_Enum):
    ASSET = auto()
    CHECKING = auto()
    CREDIT_CARD = auto()
    SAVINGS = auto()
    LIABILITY = auto()
    MORTGAGE = auto()


@dataclass
class _Account(_Entity):
    TYPES = {
        AccountType.CURRENT: (_AccountClass.CURRENT, _AccountType.ASSET, _AccountSubtype.CHECKING),
        AccountType.SAVINGS: (_AccountClass.SAVINGS, _AccountType.ASSET, _AccountSubtype.SAVINGS),
        AccountType.CREDIT_CARD: (_AccountClass.CREDIT_CARD, _AccountType.LIABILITY, _AccountSubtype.CREDIT_CARD),
        AccountType.LIABILITY: (_AccountClass.LIABILITY, _AccountType.LIABILITY, _AccountSubtype.LIABILITY),
        AccountType.MORTGAGE: (_AccountClass.MORTGAGE, _AccountType.LIABILITY, _AccountSubtype.MORTGAGE),
        AccountType.PROPERTY: (_AccountClass.REAL_ESTATE, _AccountType.ASSET, _AccountSubtype.ASSET),
    }

    name: str | None = None
    note: str | None = None
    currency: _Currency | None = None
    account_class: _AccountClass | None = None
    type: _AccountType | None = None
    subtype: _AccountSubtype | None = None
    bank_account_number: str | None = None
    bank_routing_number: str | None = None
    institution_name: str | None = None
    institution_site: ParseResult | None = None


@dataclass
class _Recurrence:
    months_of_the_year: list[int] | None = None
    weeks_of_the_year: list[int] | None = None
    set_positions: list[int] | None = None
    days_of_the_week: list[int] | None = None
    days_of_the_month: list[int] | None = None
    days_of_the_year: list[int] | None = None
    frequency: int = 8
    absolute: bool = False
    anchor_index: int = 1
    interval: int = 1

    def encode_archive(self, archive: archiver.ArchivingObject) -> None:
        for datafield in cast(tuple[Field[_Recurrence], ...], fields(self)):
            archive.encode(_python_to_banktivity(datafield.name), cast(object, getattr(self, datafield.name)))

    @classmethod
    def decode_archive(cls, archive: archiver.ArchivedObject) -> _Recurrence:
        kwargs = {_banktivity_to_python(field): archive.decode(field) for field in archive.object if field != "$class"}
        return _Recurrence(**kwargs)  # type: ignore


@dataclass
class _LoanInfo(_Entity):
    interest_rate: Decimal | None = None
    loan_account: _Account | None = None
    minimum_principal_and_interest: Decimal | None = None
    payment_interval_data: _Recurrence = _Recurrence(days_of_the_month=[1])
    payments_per_year = 12


@dataclass
class _GroupItem(_Object):
    group_id: str
    group_type: str = "IGGCAccountingPrimaryAccount"


@dataclass
class _Group(_Entity):
    name: str | None = None
    ordered_items: list[_GroupItem] = field(default_factory=list)


@dataclass
class _TransactionTypeV2(_Entity):
    """No fields currently needed"""


@unique
class _TransactionBaseType(_Enum):
    DEPOSIT = auto()
    WITHDRAWAL = auto()
    TRANSFER = auto()
    CHECK = auto()
    BUY = auto()
    SELL = auto()
    BUY_TO_OPEN = auto()
    BUY_TO_CLOSE = auto()
    SELL_TO_OPEN = auto()
    SELL_TO_CLOSE = auto()
    MOVE_SHARES_IN = auto()
    MOVE_SHARES_OUT = auto()
    TRANSFER_SHARES = auto()
    SLPIT_SHARES = auto()
    MISC_INV_INCOME = auto()
    DIVIDEND = auto()
    CAP_GAINS_SHORT = auto()
    CAP_GAINS_LONG = auto()
    INTREST_INCOME = auto()
    RETURN_OF_CAPITAL = auto()


@dataclass
class _TransactionType(_Object):
    base_type: _TransactionBaseType | None = None
    transaction_type: _TransactionTypeV2 | None = None


@dataclass
class _Transaction(_Entity):
    transaction_type: _TransactionType | None = None
    title: str | None = None
    note: str | None = None
    date: datetime | None = None
    currency: _Currency | None = None
    adjustment: bool = False
    check_number: int | None = None
    line_items: list[_LineItem] | None = None


@dataclass
class _LineItem(_Object):
    account: _Account | None = None
    account_amount: Decimal = Decimal(0)
    transaciton_amount: Decimal = Decimal(0)
    identifier: str = field(default_factory=lambda: str(uuid4()).upper())
    sort_index: int = 0
    cleared: bool = True
    memo: str | None = None


@dataclass
class _LineItemSource(_Object):
    """No fields currently needed"""


@dataclass
class _SecurityLineItem(_Object):
    """No fields currently needed"""


class Document:
    def __init__(self, name: str, password: str, credentials: tuple[str, str] = (environ["BANKTIVITY_LOGIN"], environ["BANKTIVITY_PASSWORD"])):
        self._url = "https://apollo.iggnetservices.com/apollo"
        self._token = self._login(*credentials)
        filter_func: Callable[[JSON], bool] = lambda doc: doc["name"].str == name
        doc = one(filter(filter_func, self._api("documents")["documents"]))
        self._key = self._decrypt_key(password, doc["keyData"].str)
        self._url = f"{self._url}/documents/{doc['id']}"
        self._converters: dict[str, _Converter[object]] = {
            "string": _Converter(str, lambda _: _),
            "bool": _Converter(bool, lambda text: text == "yes", lambda attr: "yes" if attr else "no"),
            "int": _Converter(int, int),
            "decimal": _Converter(Decimal, Decimal),
            "date": _Converter[datetime](datetime, lambda text: datetime.strptime(text, "%Y-%m-%dT%H:%M:%S%z"), lambda attr: attr.isoformat(timespec="seconds")),
            "url": _Converter[ParseResult](ParseResult, urlparse, urlunparse),
            "data": _Converter(_Recurrence, lambda text: archiver.unarchive(b64decode(text)), lambda attr: b64encode(archiver.archive(attr)).decode()),
            "reference": _Converter[_Entity](_Entity, lambda text: self._entities[cast(tuple[str, str], tuple(text.split(":")))], lambda attr: f"{attr.class_name()}:{attr.id}"),
        }

    def load(self) -> None:
        self._sync_token = self._api("entities/status")["syncToken"].str
        self._entities: dict[tuple[str, str], _Entity] = {}
        self._currencies: dict[str, _Currency] = {}
        self._groups: dict[str, _Group] = {}
        self._accounts = {}
        for entity_type in ("Currency", "Account", "LoanInfo", "Group", "TransactionTypeV2", "Transaction"):
            entities = self._api("entities", query={"type": entity_type}).get("entities")
            if entities:
                for entity_json in entities:
                    entity = self._from_json(entity_json)
                    self._entities[entity_type, entity.id] = entity
                    if isinstance(entity, _Currency):
                        self._currencies[not_none(entity.code)] = entity
                    elif isinstance(entity, _Group):
                        self._groups[not_none(entity.name)] = entity
                    elif isinstance(entity, _Account):
                        self._accounts[entity.name] = entity
        self._default_currency = self._currencies["EUR"]
        self._transaction_type_deposit = self._transaction_type("Deposit")
        self._transaction_type_withdrawal = self._transaction_type("Withdrawal")
        self._transaction_type_transfer = self._transaction_type("Transfer")

        self._created: list[_Entity] = []
        self._updated: list[_Entity] = []
        self._deleted: list[_Entity] = []

    def save(self) -> None:
        self._api(
            "entities/entity",
            json=JSON(
                {
                    "syncToken": self._sync_token,
                    "create": list(map(self._to_json, self._created)),
                    "update": list(map(self._to_json, self._updated)),
                    "delete": list(map(self._to_json, self._deleted)),
                },
            ),
        )
        self._created = []
        self._updated = []
        self._deleted = []

    def clear(self) -> None:
        for key, entity in list(self._entities.items()):
            is_account = isinstance(entity, _Account) and entity.account_class not in {_AccountClass.REVENUE, _AccountClass.EXPENSE}
            is_group = isinstance(entity, _Group) and not entity.id.startswith("com.iggsoftware.accounting.group.")
            is_other = isinstance(entity, (_Transaction, _LoanInfo))
            if is_account or is_group or is_other:
                self._entities.pop(key)
                self._deleted.append(entity)
                if isinstance(entity, _Account):
                    self._accounts.pop(entity.name)
                if isinstance(entity, _Group):
                    self._groups.pop(entity.name)
            elif isinstance(entity, _Group) and entity.name == "Accounts":
                entity.ordered_items.clear()
                self._updated.append(entity)

    def create_account(self, account: Account) -> _Account:
        account_type = _Account.TYPES[account.type]
        entity = _Account(
            name=account.name,
            note=account.description,
            currency=self._default_currency,
            bank_account_number=account.number,
            bank_routing_number=account.routing_number,
            institution_name=account.bank_name,
            institution_site=urlparse(account.bank_site) if account.bank_site else None,
            account_class=account_type[0],
            type=account_type[1],
            subtype=account_type[2],
        )
        self._created.append(entity)
        self._accounts[account.name] = entity

        if account.interest_rate is not None:
            self._created.append(_LoanInfo(loan_account=entity, interest_rate=account.interest_rate, minimum_principal_and_interest=account.monthly_payment))

        group_name = account.group or "Accounts"
        group = self._groups.get(group_name, None)
        if group is None:
            group = _Group(name=group_name)
            self._created.append(group)
            self._groups[group_name] = group
            root = self._groups["Accounts"]
            root.ordered_items.append(_GroupItem(group.id, "IGGCAccountingGroup"))
            self._updated.append(root)
        else:
            self._updated.append(group)
        group.ordered_items.append(_GroupItem(entity.id))

        if account.initial_balance:
            self.create_transaction(Transaction(BEGINNING - timedelta(days=1), "STARTING BALANCE", "BALANCE ADJUSTMENT", [Line(account, account.initial_balance)]))
        return entity

    def create_transaction(self, transaction: Transaction) -> _Transaction:
        lines = []
        account_lines: dict[str, _LineItem] = {}

        def account_line(account: str, amount: Decimal, cleared: bool, memo: str | None) -> None:
            line = account_lines.get(account, None)
            if line:
                line.account_amount += amount
                line.transaciton_amount += amount
                line.memo = memo
            else:
                line = _LineItem(self._accounts[account], amount, amount, cleared=cleared, memo=memo)
                account_lines[account] = line
                lines.append(line)

        transfer = False
        total = Decimal(0)
        for line in transaction.lines:
            account_line(line.account.name, line.amount, transaction.cleared, line.description)
            if line.counter_account:
                account_line(line.counter_account.name, -line.amount, transaction.cleared, line.description)
                transfer = True
            else:
                total += line.amount
                account = self._accounts[_CATEGORIES[line.category]] if line.category else None
                lines.append(_LineItem(account, -line.amount, -line.amount, cleared=transaction.cleared, memo=line.description))
        if transfer:
            transaction_type = self._transaction_type_transfer
        elif total > 0:
            transaction_type = self._transaction_type_deposit
        else:
            transaction_type = self._transaction_type_withdrawal
        entity = _Transaction(
            currency=self._default_currency,
            date=transaction.date,
            transaction_type=transaction_type,
            title=transaction.payee,
            note=transaction.description,
            line_items=lines,
            check_number=transaction.number,
        )
        self._created.append(entity)
        return entity

    def _login(self, login: str, password: str) -> str:
        headers = {"Content-Type": "application/xml"}
        response = post(
            "https://auth.iggnetservices.com/auth/sessions",
            ElementTree.tostring(ElementTree.Element("session", {"login": login, "password": password})),
            headers=headers,
        )
        status = not_none(ElementTree.fromstring(response.text).find("status"))
        if int(not_none(not_none(status.find("code")).text)) > 0:
            raise ValueError(not_none(status.find("description")).text)
        token = cast(object, response.cookies["igg_authenticity_token"])
        assert isinstance(token, str)
        return token

    def _decrypt_key(self, password: str, encrypted: str) -> bytes:
        buf = BytesIO(b64decode(encrypted))
        assert buf.read(2) == b"\x01\x01"
        hashed = PBKDF2HMAC(hashes.SHA1(), _KEY_SIZE, buf.read(8), 1701).derive(password.encode())  # noqa: S303 - have to follow Banktivity's choice of SHA-1
        key = BytesIO(self._decrypt(buf, hashed))
        assert key.read(4) == b"Lisa"
        return key.read()

    def _api(self, endpoint: str, query: dict[str, str] | None = None, body: dict[str, str] | None = None, json: JSON | None = None) -> JSON:
        method = "POST" if body or json else "GET"
        headers = {"IGG-Authorization": self._token}
        response = request(method, f"{self._url}/{endpoint}", headers=headers, params=query, data=body, json=json.body if json else None)
        response.raise_for_status()
        return JSON.response(response)

    def _encrypt(self, plaintext: bytes) -> bytes:
        iv = token_bytes(_KEY_SIZE)
        padder = PKCS7(_KEY_SIZE * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        encryptor: CipherContext = Cipher(algorithms.AES(self._key), modes.CBC(iv)).encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def _decrypt(self, encrypted: BytesIO, key: bytes | None = None) -> bytes:
        decryptor: CipherContext = Cipher(algorithms.AES(key or self._key), modes.CBC(encrypted.read(_KEY_SIZE))).decryptor()
        decrypted_data = decryptor.update(encrypted.read()) + decryptor.finalize()
        unpadder = PKCS7(_KEY_SIZE * 8).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def _from_json(self, entity_json: JSON) -> _Entity:
        entity_xml_str = gzip.decompress(self._decrypt(BytesIO(b64decode(entity_json["data"].str))))
        element = not_none(ElementTree.fromstring(entity_xml_str))
        entity = _Object.from_element(self._converters, element)
        assert isinstance(entity, _Entity)
        entity.id = not_none(element.get("id"))
        return entity

    def _to_json(self, entity: _Entity) -> JSONType:
        element = entity.to_element(self._converters, "entity")
        element.set("id", entity.id)
        entity_xml_str = ElementTree.tostring(element)
        encoded = b64encode(self._encrypt(gzip.compress(entity_xml_str))).decode()
        return {"id": entity.id, "type": not_none(element.get("type")), "data": encoded}

    def _transaction_type(self, name: str) -> _TransactionType:
        entity = self._entities["TransactionTypeV2", f"XXX-{name}-ID"]
        assert isinstance(entity, _TransactionTypeV2)
        return _TransactionType(
            base_type=_TransactionBaseType[name.upper()],
            transaction_type=entity,
        )


archiver.update_class_map({"IGGFDateRecurrenceRule": _Recurrence})


def _banktivity_to_python(name: str) -> str:
    return inflection.underscore(name)


def _python_to_banktivity(name: str) -> str:
    return inflection.camelize(name, uppercase_first_letter=False).replace("Id", "ID")
