import gzip
from abc import ABC
from base64 import b64decode, b64encode
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum, unique
from io import BytesIO
from os import environ
from secrets import token_bytes
from typing import Optional
from urllib.parse import ParseResult, urlparse, urlunparse
from uuid import uuid4

import dacite
import xmltodict as xml
from bpylist2 import archiver
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from inflection import camelize, underscore
from more_itertools import one
from requests import post, request

from core import BEGINNING, Account, Category, Transaction

KEY_SIZE = 16


class Document:
    CATEGORIES = {
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
    }

    @dataclass
    class Entity(ABC):
        id: str = field(default_factory=lambda: str(uuid4()).upper())

    @dataclass
    class Currency(Entity):
        name: str = None
        code: str = None

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
            Account.Type.CURRENT: (IGGCSyncAccountingAccountClass.CURRENT, IGGCSyncAccountingAccountType.ASSET, IGGCSyncAccountingAccountSubtype.CHECKING),
            Account.Type.SAVINGS: (IGGCSyncAccountingAccountClass.SAVINGS, IGGCSyncAccountingAccountType.ASSET, IGGCSyncAccountingAccountSubtype.SAVINGS),
            Account.Type.CREDIT_CARD: (IGGCSyncAccountingAccountClass.CREDIT_CARD, IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.CREDIT_CARD),
            Account.Type.LIABILITY: (IGGCSyncAccountingAccountClass.LIABILITY, IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.LIABILITY),
            Account.Type.MORTGAGE: (IGGCSyncAccountingAccountClass.MORTGAGE, IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.MORTGAGE),
            Account.Type.PROPERTY: (IGGCSyncAccountingAccountClass.REAL_ESTATE, IGGCSyncAccountingAccountType.ASSET, IGGCSyncAccountingAccountSubtype.ASSET),
        }

        name: str = None
        note: str = None
        currency: Optional["Document.Currency"] = None
        account_class: IGGCSyncAccountingAccountClass = None
        type: IGGCSyncAccountingAccountType = None
        subtype: IGGCSyncAccountingAccountSubtype = None
        bank_account_number: str = None
        bank_routing_number: str = None
        institution_name: str = None
        institution_site: ParseResult = None

    @dataclass
    class LoanInfo(Entity):
        @dataclass
        class Recurrence:
            months_of_the_year: list = None
            weeks_of_the_year: list = None
            set_positions: list = None
            days_of_the_week: list = None
            days_of_the_month: list = None
            days_of_the_year: list = None
            frequency: int = 8
            absolute: bool = False
            anchor_index: int = 1
            interval: int = 1

            def encode_archive(self, archive):
                for datafield in fields(self):
                    archive.encode(python_to_banktivity(datafield.name), getattr(self, datafield.name))

            @classmethod
            def decode_archive(cls, archive):
                args = {banktivity_to_python(field): archive.decode(field) for field in archive.object if field != "$class"}
                return Document.LoanInfo.Recurrence(**args)

        interest_rate: Decimal = None
        loan_account: "Document.Account" = None
        minimum_principal_and_interest: Decimal = None
        payment_interval_data: Recurrence = Recurrence(days_of_the_month=[1])
        payments_per_year = 12

    @dataclass
    class GroupItem:
        group_id: str
        group_type: str = "IGGCAccountingPrimaryAccount"

    @dataclass
    class Group(Entity):
        name: str = None
        ordered_items: list["Document.GroupItem"] = field(default_factory=list)

    @dataclass
    class TransactionTypeV2(Entity):
        """No fields currently needed"""

    @dataclass
    class TransactionType:
        @unique
        class IGGCSyncAccountingTransactionBaseType(Enum):
            DEPOSIT = "deposit"
            WITHDRAWAL = "withdrawal"
            TRANSFER = "transfer"

        base_type: IGGCSyncAccountingTransactionBaseType = None
        transaction_type: "Document.TransactionTypeV2" = None

    @dataclass
    class Transaction(Entity):
        transaction_type: "Document.TransactionType" = None
        title: str = None
        note: str = None
        date: datetime = None
        currency: "Document.Currency" = None
        adjustment: bool = False
        check_number: int = None
        line_items: list["Document.LineItem"] = None

    @dataclass
    class LineItem:
        account: Optional["Document.Account"] = None
        account_amount: Decimal = None
        transaciton_amount: Decimal = None
        identifier: str = field(default_factory=lambda: str(uuid4()).upper())
        sort_index: int = 0
        cleared: bool = True
        memo: str = None

    @dataclass
    class LineItemSource:
        """No fields currently needed"""

    @dataclass
    class SecurityLineItem:
        """No fields currently needed"""

    def __init__(self, name, password, credentials=(environ["BANKTIVITY_LOGIN"], environ["BANKTIVITY_PASSWORD"])):
        self.url = "https://apollo.iggnetservices.com/apollo"
        self.token = self.login(*credentials)
        doc = one(filter(lambda doc: doc["name"] == name, self.api("documents")["documents"]))
        self.key = self.decrypt_key(password, doc["keyData"])
        self.url += f"/documents/{doc['id']}"

    def login(self, login, password):
        response = post(
            "https://auth.iggnetservices.com/auth/sessions",
            data=xml.unparse({"session": {"@login": login, "@password": password}}),
            headers={"Content-Type": "application/xml"},
        )
        status = xml.parse(response.text)["response"]["status"]
        if int(status["code"]) > 0:
            raise ValueError(status["description"])
        return response.cookies["igg_authenticity_token"]

    def decrypt_key(self, password, data):
        data = BytesIO(b64decode(data))
        assert data.read(2) == b"\x01\x01"
        hashed = PBKDF2HMAC(hashes.SHA1(), KEY_SIZE, data.read(8), 1701).derive(password.encode())  # noqa: S303 - have to follow Banktivity's choice of SHA-1
        key = BytesIO(self.decrypt(data, hashed))
        assert key.read(4) == b"Lisa"
        return key.read()

    def api(self, endpoint, **args):
        method = "POST" if "data" in args or "json" in args else "GET"
        response = request(method, f"{self.url}/{endpoint}", headers={"IGG-Authorization": self.token}, **args)
        response.raise_for_status()
        return response.json()

    def encrypt(self, plaintext):
        iv = token_bytes(KEY_SIZE)
        padder = PKCS7(KEY_SIZE * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt(self, data, key=None):
        decryptor = Cipher(algorithms.AES(key or self.key), modes.CBC(data.read(KEY_SIZE))).decryptor()
        decrypted_data = decryptor.update(data.read()) + decryptor.finalize()
        unpadder = PKCS7(KEY_SIZE * 8).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def child_list(self, parent, name):
        value = parent.get(name, [])
        return value if isinstance(value, list) else [value]

    def parse_object(self, entity):
        data = {"id": entity.get("@id")}
        klass = self.__class__.__dict__[entity["@type"]]
        for entity_field in self.child_list(entity, "field"):
            text = entity_field.get("#text")
            enum_class = entity_field.get("@enum")
            if enum_class:
                enum_class = klass.__dict__.get(enum_class)
                value = text if enum_class is None else enum_class(text)
            elif "@null" in entity_field:
                value = None
            else:
                field_type = entity_field["@type"]
                match field_type:
                    case "string":
                        value = text
                    case "bool":
                        value = text == "yes"
                    case "int":
                        value = int(text)
                    case "decimal":
                        value = Decimal(text)
                    case "date":
                        value = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S%z")
                    case "url":
                        value = urlparse(text)
                    case "reference":
                        parts = tuple(text.split(":"))
                        value = None if parts[1] == "(null)" else self.entities[parts]
                    case "data":
                        value = archiver.unarchive(b64decode(text))
                    case _:
                        raise TypeError(field_type)
            data[entity_field["@name"]] = value
        for record in self.child_list(entity, "record"):
            data[record["@name"]] = self.parse_object(record)
        for collection in self.child_list(entity, "collection"):
            data[collection["@name"]] = list(map(self.parse_object, self.child_list(collection, "record")))
        data = {banktivity_to_python(name): value for name, value in data.items()}
        return dacite.from_dict(klass, data, dacite.Config(check_types=False))

    def parse_entity(self, entity):
        xml_str = gzip.decompress(self.decrypt(BytesIO(b64decode(entity["data"]))))
        return self.parse_object(xml.parse(xml_str)["entity"])

    def load(self):
        self.sync_token = self.api("entities/status")["syncToken"]
        self.entities = {}
        self.currencies = {}
        self.groups = {}
        self.accounts = {}
        for entity_type in ("Currency", "Account", "LoanInfo", "Group", "TransactionTypeV2", "Transaction"):
            for entity in self.api("entities", params={"type": entity_type}).get("entities", []):
                entity = self.parse_entity(entity)
                self.entities[(entity_type, entity.id)] = entity
                if entity_type == "Currency":
                    self.currencies[entity.code] = entity
                elif entity_type == "Group":
                    self.groups[entity.name] = entity
                elif entity_type == "Account":
                    self.accounts[entity.name] = entity
        self.default_currency = self.currencies["EUR"]
        self.transaction_type_deposit = Document.TransactionType(
            base_type=Document.TransactionType.IGGCSyncAccountingTransactionBaseType.DEPOSIT,
            transaction_type=self.entities[("TransactionTypeV2", "XXX-Deposit-ID")],
        )
        self.transaction_type_withdrawal = Document.TransactionType(
            base_type=Document.TransactionType.IGGCSyncAccountingTransactionBaseType.WITHDRAWAL,
            transaction_type=self.entities[("TransactionTypeV2", "XXX-Withdrawal-ID")],
        )
        self.transaction_type_transfer = Document.TransactionType(
            base_type=Document.TransactionType.IGGCSyncAccountingTransactionBaseType.TRANSFER,
            transaction_type=self.entities[("TransactionTypeV2", "XXX-Transfer-ID")],
        )

        self.created = []
        self.updated = []
        self.deleted = []

    def unparse_object(self, obj):
        result = {"@type": obj.__class__.__name__, "field": [], "record": [], "collection": []}
        for name, value in obj.__dict__.items():
            if name == "id" or value is None:
                continue
            el_type = "field"
            el = {}
            if isinstance(value, str):
                el["@type"] = "string"
                el["#text"] = value
            elif isinstance(value, bool):
                el["@type"] = "bool"
                el["#text"] = "yes" if value else "no"
            elif isinstance(value, int):
                el["@type"] = "int"
                el["#text"] = str(value)
            elif isinstance(value, Decimal):
                el["@type"] = "decimal"
                el["#text"] = str(value)
            elif isinstance(value, datetime):
                assert value.tzinfo
                el["@type"] = "date"
                el["#text"] = value.isoformat(timespec="seconds")
            elif isinstance(value, ParseResult):
                el["@type"] = "url"
                el["#text"] = urlunparse(value)
            elif isinstance(value, Document.TransactionType):
                el_type = "record"
                el = self.unparse_object(value)
            elif isinstance(value, list):
                el_type = "collection"
                el["@type"] = "array"
                items = []
                for item in value:
                    item = self.unparse_object(item)
                    item["@name"] = "element"
                    items.append(item)
                el["record"] = items
            elif isinstance(value, Enum):
                el["@enum"] = value.__class__.__name__
                el["#text"] = value.value
            elif isinstance(value, Document.LoanInfo.Recurrence):
                el["@type"] = "data"
                el["#text"] = b64encode(archiver.archive(value))
            elif isinstance(value, Document.Entity):
                el["@type"] = "reference"
                el["#text"] = f"{value.__class__.__name__}:{value.id}"
            else:
                raise TypeError(type(value))
            el["@name"] = python_to_banktivity(name)
            result[el_type].append(el)
        return result

    def unparse_entity(self, entity):
        data = self.unparse_object(entity)
        data["@id"] = entity.id
        data = b64encode(self.encrypt(gzip.compress(xml.unparse({"entity": data}).encode()))).decode()
        return {"id": entity.id, "type": entity.__class__.__name__, "data": data}

    def save(self):
        self.api(
            "entities/entity",
            json={
                "syncToken": self.sync_token,
                "create": list(map(self.unparse_entity, self.created)),
                "update": list(map(self.unparse_entity, self.updated)),
                "delete": list(map(self.unparse_entity, self.deleted)),
            },
        )
        self.created = []
        self.updated = []
        self.deleted = []

    def clear(self):
        for key, entity in list(self.entities.items()):
            non_category_account = key[0] == "Account" and entity.account_class not in {
                Document.Account.IGGCSyncAccountingAccountClass.REVENUE,
                Document.Account.IGGCSyncAccountingAccountClass.EXPENSE,
            }
            if non_category_account or key[0] in {"Transaction", "LoanInfo"}:
                self.entities.pop(key)
                self.deleted.append(entity)
                if key[0] == "Account":
                    self.accounts.pop(entity.name)

    def create_account(self, account):
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
            self.create_transaction(Transaction(BEGINNING - timedelta(days=1), "STARTING BALANCE", "BALANCE ADJUSTMENT", [Transaction.Line(entity, account.initial_balance)]))
        return entity

    def create_transaction(self, transaction):
        lines = []
        account_lines = {}

        def account_line(account, amount, cleared, memo):
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
        total = 0
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


def banktivity_to_python(name):
    return underscore(name)


def python_to_banktivity(name):
    return camelize(name, uppercase_first_letter=False).replace("Id", "ID")
