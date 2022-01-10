from __future__ import annotations

import gzip
from abc import ABC
from base64 import b64decode, b64encode
from dataclasses import Field, dataclass, field, fields
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum, unique
from io import BytesIO
from os import environ
from secrets import token_bytes
from typing import Callable, Generic, TypeVar, cast
from urllib.parse import ParseResult, urlparse, urlunparse
from uuid import uuid4
from xml.etree import ElementTree

import dacite
from bpylist2 import archiver
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from inflection import camelize, underscore
from more_itertools import one
from requests import post, request

from finance.core import BEGINNING
from finance.core import Account as CAccount
from finance.core import Category as CCategory
from finance.core import Transaction as CTransaction
from finance.typesafe import JSON, JSONType, attributes, not_none

KEY_SIZE = 16
ObjectType = TypeVar("ObjectType", covariant=True)


@dataclass
class Converter(Generic[ObjectType]):
    obj_type: type[ObjectType]
    parse: Callable[[str], ObjectType]
    unparse: Callable[[ObjectType], str] = str


class Document:
    CATEGORIES = {
        CCategory.CHILDREN: "Child/Dependent Expenses",
        CCategory.FEE: "Service Charges/Fees",
        CCategory.ENTERTAINMENT: "Entertainment",
        CCategory.GROCERIES: "Groceries",
        CCategory.HEALTHCARE: "Medical/Healthcare",
        CCategory.HOME: "Home Maintenance",
        CCategory.INSURANCE: "Insurance",
        CCategory.INTEREST_INCOME: "Interest Income",
        CCategory.INTEREST: "Interest Paid",
        CCategory.PENSION_CONTRIBUTION: "Retirement Contributions",
        CCategory.PERSONAL_CARE: "Fitness/Personal Care",
        CCategory.RESTAURANTS: "Dining/Restaurants",
        CCategory.SALARY: "Paychecks/Wages",
        CCategory.TAX: "Taxes",
        CCategory.TRANSPORT: "Travel",
        CCategory.UTILITIES: "Utilities",
    }

    @dataclass
    class Object(ABC):
        """Parent abstract class for all serialised Banktivity objects"""

    @dataclass
    class Entity(Object):
        id: str = field(default_factory=lambda: str(uuid4()).upper())

    @dataclass
    class Currency(Entity):
        name: str | None = None
        code: str | None = None

    @dataclass
    class Account(Entity):
        @unique
        class IGGCSyncAccountingAccountClass(Enum):
            CURRENT = "current"
            CREDIT_CARD = "credit-card"
            CHECKING = "checking"
            SAVINGS = "savings"
            MORTGAGE = "mortgage"
            EXPENSE = "expense"
            REVENUE = "revenue"
            REAL_ESTATE = "real-estate"
            LIABILITY = "liability"

        @unique
        class IGGCSyncAccountingAccountType(Enum):
            ASSET = "asset"
            LIABILITY = "liability"
            INCOME = "income"
            EXPENSE = "expense"

        @unique
        class IGGCSyncAccountingAccountSubtype(Enum):
            ASSET = "asset"
            CHECKING = "checking"
            CREDIT_CARD = "credit-card"
            SAVINGS = "savings"
            LIABILITY = "liability"
            MORTGAGE = "mortgage"

        TYPES = {
            CAccount.Type.CURRENT: (IGGCSyncAccountingAccountClass.CURRENT, IGGCSyncAccountingAccountType.ASSET, IGGCSyncAccountingAccountSubtype.CHECKING),
            CAccount.Type.SAVINGS: (IGGCSyncAccountingAccountClass.SAVINGS, IGGCSyncAccountingAccountType.ASSET, IGGCSyncAccountingAccountSubtype.SAVINGS),
            CAccount.Type.CREDIT_CARD: (IGGCSyncAccountingAccountClass.CREDIT_CARD, IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.CREDIT_CARD),
            CAccount.Type.LIABILITY: (IGGCSyncAccountingAccountClass.LIABILITY, IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.LIABILITY),
            CAccount.Type.MORTGAGE: (IGGCSyncAccountingAccountClass.MORTGAGE, IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.MORTGAGE),
            CAccount.Type.PROPERTY: (IGGCSyncAccountingAccountClass.REAL_ESTATE, IGGCSyncAccountingAccountType.ASSET, IGGCSyncAccountingAccountSubtype.ASSET),
        }

        name: str | None = None
        note: str | None = None
        currency: Document.Currency | None = None
        account_class: IGGCSyncAccountingAccountClass | None = None
        type: IGGCSyncAccountingAccountType | None = None
        subtype: IGGCSyncAccountingAccountSubtype | None = None
        bank_account_number: str | None = None
        bank_routing_number: str | None = None
        institution_name: str | None = None
        institution_site: ParseResult | None = None

    @dataclass
    class LoanInfo(Entity):
        @dataclass
        class Recurrence:
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
                for datafield in cast(tuple[Field[Document.LoanInfo], ...], fields(self)):
                    archive.encode(python_to_banktivity(datafield.name), cast(object, getattr(self, datafield.name)))

            @classmethod
            def decode_archive(cls, archive: archiver.ArchivedObject) -> Document.LoanInfo.Recurrence:
                kwargs = {banktivity_to_python(field): archive.decode(field) for field in archive.object if field != "$class"}
                return Document.LoanInfo.Recurrence(**kwargs)  # type: ignore

        interest_rate: Decimal | None = None
        loan_account: Document.Account | None = None
        minimum_principal_and_interest: Decimal | None = None
        payment_interval_data: Recurrence = Recurrence(days_of_the_month=[1])
        payments_per_year = 12

    @dataclass
    class GroupItem(Object):
        group_id: str
        group_type: str = "IGGCAccountingPrimaryAccount"

    @dataclass
    class Group(Entity):
        name: str | None = None
        ordered_items: list["Document.GroupItem"] = field(default_factory=list)

    @dataclass
    class TransactionTypeV2(Entity):
        """No fields currently needed"""

    @dataclass
    class TransactionType(Object):
        @unique
        class IGGCSyncAccountingTransactionBaseType(Enum):
            DEPOSIT = "deposit"
            WITHDRAWAL = "withdrawal"
            TRANSFER = "transfer"

        base_type: IGGCSyncAccountingTransactionBaseType | None = None
        transaction_type: Document.TransactionTypeV2 | None = None

    @dataclass
    class Transaction(Entity):
        transaction_type: Document.TransactionType | None = None
        title: str | None = None
        note: str | None = None
        date: datetime | None = None
        currency: Document.Currency | None = None
        adjustment: bool = False
        check_number: int | None = None
        line_items: list[Document.LineItem] | None = None

    @dataclass
    class LineItem(Object):
        account: Document.Account | None = None
        account_amount: Decimal = Decimal(0)
        transaciton_amount: Decimal = Decimal(0)
        identifier: str = field(default_factory=lambda: str(uuid4()).upper())
        sort_index: int = 0
        cleared: bool = True
        memo: str | None = None

    @dataclass
    class LineItemSource(Object):
        """No fields currently needed"""

    @dataclass
    class SecurityLineItem(Object):
        """No fields currently needed"""

    def __init__(self, name: str, password: str, credentials: tuple[str, str] = (environ["BANKTIVITY_LOGIN"], environ["BANKTIVITY_PASSWORD"])):
        self.url = "https://apollo.iggnetservices.com/apollo"
        self.token = self.login(*credentials)
        filter_func: Callable[[JSON], bool] = lambda doc: doc["name"].str == name
        doc = one(filter(filter_func, self.api("documents")["documents"]))
        self.key = self.decrypt_key(password, doc["keyData"].str)
        self.url = f"{self.url}/documents/{doc['id']}"
        self.converters: dict[str, Converter[object]] = {
            "string": Converter(str, lambda _: _),
            "bool": Converter(bool, lambda text: text == "yes", lambda attr: "yes" if attr else "no"),
            "int": Converter(int, int),
            "decimal": Converter(Decimal, Decimal),
            "date": Converter[datetime](datetime, lambda text: datetime.strptime(text, "%Y-%m-%dT%H:%M:%S%z"), lambda attr: attr.isoformat(timespec="seconds")),
            "url": Converter[ParseResult](ParseResult, urlparse, urlunparse),
            "data": Converter(Document.LoanInfo.Recurrence, lambda text: archiver.unarchive(b64decode(text)), lambda attr: b64encode(archiver.archive(attr)).decode()),
            "reference": Converter[Document.Entity](Document.Entity, lambda text: self.entities[cast(tuple[str, str], tuple(text.split(":")))], lambda attr: f"{attr.__class__.__name__}:{attr.id}"),
        }

    def login(self, login: str, password: str) -> str:
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

    def decrypt_key(self, password: str, encrypted: str) -> bytes:
        buf = BytesIO(b64decode(encrypted))
        assert buf.read(2) == b"\x01\x01"
        hashed = PBKDF2HMAC(hashes.SHA1(), KEY_SIZE, buf.read(8), 1701).derive(password.encode())  # noqa: S303 - have to follow Banktivity's choice of SHA-1
        key = BytesIO(self.decrypt(buf, hashed))
        assert key.read(4) == b"Lisa"
        return key.read()

    def api(self, endpoint: str, query: dict[str, str] | None = None, body: dict[str, str] | None = None, json: JSON | None = None) -> JSON:
        method = "POST" if body or json else "GET"
        headers = {"IGG-Authorization": self.token}
        response = request(method, f"{self.url}/{endpoint}", headers=headers, params=query, data=body, json=json.body if json else None)
        response.raise_for_status()
        return JSON.response(response)

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = token_bytes(KEY_SIZE)
        padder = PKCS7(KEY_SIZE * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        encryptor: CipherContext = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt(self, encrypted: BytesIO, key: bytes | None = None) -> bytes:
        decryptor: CipherContext = Cipher(algorithms.AES(key or self.key), modes.CBC(encrypted.read(KEY_SIZE))).decryptor()
        decrypted_data = decryptor.update(encrypted.read()) + decryptor.finalize()
        unpadder = PKCS7(KEY_SIZE * 8).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def parse_object(self, element: ElementTree.Element) -> Object:
        elements: dict[ElementTree.Element, object] = {}
        entity_type = cast(type, attributes(self.__class__)[not_none(element.get("type"))])
        assert issubclass(entity_type, Document.Object)
        for field_element in element.findall("field"):
            attr: object | None
            if field_element.get("null") or field_element.text is None or field_element.text.endswith("(null)"):
                attr = None
            else:
                if enum_type_name := field_element.get("enum"):
                    if enum_type := cast(type, attributes(entity_type).get(enum_type_name)):
                        assert issubclass(enum_type, Enum)
                        attr = enum_type(field_element.text)
                    else:
                        attr = field_element.text
                else:
                    attr = self.converters[not_none(field_element.get("type"))].parse(field_element.text)
            elements[field_element] = attr
        for record_element in element.findall("record"):
            elements[record_element] = self.parse_object(record_element)
        for collection_element in element.findall("collection"):
            elements[collection_element] = list(map(self.parse_object, collection_element.findall("record")))
        attrs = {banktivity_to_python(not_none(element.get("name"))): attr for element, attr in elements.items()}
        attrs["id"] = element.get("id")
        return dacite.core.from_dict(entity_type, attrs, dacite.config.Config(check_types=False))

    def parse_entity(self, entity_json: JSON) -> Entity:
        entity_xml_str = gzip.decompress(self.decrypt(BytesIO(b64decode(entity_json["data"].str))))
        entity = self.parse_object(not_none(ElementTree.fromstring(entity_xml_str)))
        assert isinstance(entity, Document.Entity)
        return entity

    def load(self) -> None:
        self.sync_token = self.api("entities/status")["syncToken"].str
        self.entities: dict[tuple[str, str], Document.Entity] = {}
        self.currencies: dict[str, Document.Currency] = {}
        self.groups: dict[str, Document.Group] = {}
        self.accounts = {}
        for entity_type in ("Currency", "Account", "LoanInfo", "Group", "TransactionTypeV2", "Transaction"):
            entities = self.api("entities", query={"type": entity_type}).get("entities")
            if entities:
                for entity_json in entities:
                    entity = self.parse_entity(entity_json)
                    self.entities[entity_type, entity.id] = entity
                    if isinstance(entity, Document.Currency):
                        self.currencies[not_none(entity.code)] = entity
                    elif isinstance(entity, Document.Group):
                        self.groups[not_none(entity.name)] = entity
                    elif isinstance(entity, Document.Account):
                        self.accounts[entity.name] = entity
        self.default_currency = self.currencies["EUR"]
        self.transaction_type_deposit = self.transaction_type("Deposit")
        self.transaction_type_withdrawal = self.transaction_type("Withdrawal")
        self.transaction_type_transfer = self.transaction_type("Transfer")

        self.created: list[Document.Entity] = []
        self.updated: list[Document.Entity] = []
        self.deleted: list[Document.Entity] = []

    def transaction_type(self, name: str) -> TransactionType:
        entity = self.entities["TransactionTypeV2", f"XXX-{name}-ID"]
        assert isinstance(entity, Document.TransactionTypeV2)
        return Document.TransactionType(
            base_type=Document.TransactionType.IGGCSyncAccountingTransactionBaseType[name.upper()],
            transaction_type=entity,
        )

    def unparse_object(self, name: str, banktivity_object: Object) -> ElementTree.Element:
        root_element = ElementTree.Element(name, {"type": banktivity_object.__class__.__name__})
        for attr_name, attr_value in attributes(banktivity_object).items():
            if attr_name == "id" or attr_value is None:
                continue
            if isinstance(attr_value, Document.TransactionType):
                element = self.unparse_object("record", attr_value)
            elif isinstance(attr_value, list):
                element = ElementTree.Element("collection", {"type": "array"})
                for record in attr_value:
                    subelement = self.unparse_object("record", record)
                    subelement.set("name", "element")
                    element.append(subelement)
            elif isinstance(attr_value, Enum):
                element = ElementTree.Element("field", {"enum": attr_value.__class__.__name__})
            else:
                element_type, converter = next(converter for converter in self.converters.items() if isinstance(attr_value, converter[1].obj_type))
                element = ElementTree.Element("field", {"type": element_type})
                element.text = converter.unparse(attr_value)
            element.set("name", python_to_banktivity(attr_name))
            root_element.append(element)
        return root_element

    def unparse_entity(self, entity: Entity) -> JSONType:
        element = self.unparse_object("entity", entity)
        element.set("id", entity.id)
        encoded = b64encode(self.encrypt(gzip.compress(ElementTree.tostring(element)))).decode()
        return {"id": entity.id, "type": entity.__class__.__name__, "data": encoded}

    def save(self) -> None:
        self.api(
            "entities/entity",
            json=JSON(
                {
                    "syncToken": self.sync_token,
                    "create": list(map(self.unparse_entity, self.created)),
                    "update": list(map(self.unparse_entity, self.updated)),
                    "delete": list(map(self.unparse_entity, self.deleted)),
                },
            ),
        )
        self.created = []
        self.updated = []
        self.deleted = []

    def clear(self) -> None:
        for key, entity in list(self.entities.items()):
            non_category_account = isinstance(entity, Document.Account) and entity.account_class not in {
                Document.Account.IGGCSyncAccountingAccountClass.REVENUE,
                Document.Account.IGGCSyncAccountingAccountClass.EXPENSE,
            }
            if non_category_account or key[0] in {"Transaction", "LoanInfo"}:
                self.entities.pop(key)
                self.deleted.append(entity)
                if isinstance(entity, Document.Account):
                    self.accounts.pop(entity.name)

    def create_account(self, account: CAccount) -> Account:
        account_type = Document.Account.TYPES[account.type]
        entity = Document.Account(
            name=account.name,
            note=account.description,
            currency=self.default_currency,
            bank_account_number=account.number,
            bank_routing_number=account.routing_number,
            institution_name=account.bank_name,
            institution_site=urlparse(account.bank_site) if account.bank_site else None,
            account_class=account_type[0],
            type=account_type[1],
            subtype=account_type[2],
        )
        self.created.append(entity)
        self.accounts[account.name] = entity

        if account.interest_rate is not None:
            self.created.append(Document.LoanInfo(loan_account=entity, interest_rate=account.interest_rate, minimum_principal_and_interest=account.monthly_payment))

        group_name = account.group or "Accounts"
        group = self.groups.get(group_name, None)
        if group is None:
            group = Document.Group(name=group_name)
            self.created.append(group)
            self.groups[group_name] = group
            root = self.groups["Accounts"]
            root.ordered_items.append(Document.GroupItem(group.id, "IGGCAccountingGroup"))
            self.updated.append(root)
        else:
            self.updated.append(group)
        group.ordered_items.append(Document.GroupItem(entity.id))

        if account.initial_balance:
            self.create_transaction(CTransaction(BEGINNING - timedelta(days=1), "STARTING BALANCE", "BALANCE ADJUSTMENT", [CTransaction.Line(account, account.initial_balance)]))
        return entity

    def create_transaction(self, transaction: CTransaction) -> Transaction:
        lines = []
        account_lines: dict[str, Document.LineItem] = {}

        def account_line(account: str, amount: Decimal, cleared: bool, memo: str | None) -> None:
            line = account_lines.get(account, None)
            if line:
                line.account_amount += amount
                line.transaciton_amount += amount
                line.memo = memo
            else:
                line = Document.LineItem(self.accounts[account], amount, amount, cleared=cleared, memo=memo)
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
                account = self.accounts[Document.CATEGORIES[line.category]] if line.category else None
                lines.append(Document.LineItem(account, -line.amount, -line.amount, cleared=transaction.cleared, memo=line.description))
        if transfer:
            transaction_type = self.transaction_type_transfer
        elif total > 0:
            transaction_type = self.transaction_type_deposit
        else:
            transaction_type = self.transaction_type_withdrawal
        entity = Document.Transaction(
            currency=self.default_currency,
            date=transaction.date,
            transaction_type=transaction_type,
            title=transaction.payee,
            note=transaction.description,
            line_items=lines,
            check_number=transaction.number,
        )
        self.created.append(entity)
        return entity


archiver.update_class_map({"IGGFDateRecurrenceRule": Document.LoanInfo.Recurrence})


def banktivity_to_python(name: str) -> str:
    return underscore(name)


def python_to_banktivity(name: str) -> str:
    return camelize(name, uppercase_first_letter=False).replace("Id", "ID")
