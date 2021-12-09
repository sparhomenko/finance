import abc
import base64
import dataclasses
import datetime
import decimal
import enum
import gzip
import hashlib
import io
import os
import secrets
import typing
import urllib
import uuid

import bpylist2.archiver
import bpylist2.archive_types
import Crypto.Cipher.AES
import Crypto.Util.Padding
import dacite
import requests
import xmltodict

import core

KEY_SIZE = 16


class Document:
    CATEGORIES = {
        core.Transaction.Line.Category.CHILDREN:             'Child/Dependent Expenses',
        core.Transaction.Line.Category.FEE:                  'Service Charges/Fees',
        core.Transaction.Line.Category.GROCERIES:            'Groceries',
        core.Transaction.Line.Category.HEALTHCARE:           'Medical/Healthcare',
        core.Transaction.Line.Category.INTEREST_INCOME:      'Interest Income',
        core.Transaction.Line.Category.INTEREST:             'Interest Paid',
        core.Transaction.Line.Category.PENSION_CONTRIBUTION: 'Retirement Contributions',
        core.Transaction.Line.Category.PERSONAL_CARE:        'Fitness/Personal Care',
        core.Transaction.Line.Category.SALARY:               'Paychecks/Wages',
        core.Transaction.Line.Category.TAKEAWAY:             'Dining/Restaurants',
        core.Transaction.Line.Category.TAX:                  'Taxes',
        core.Transaction.Line.Category.UTILITIES:            'Utilities'
    }

    @dataclasses.dataclass
    class Entity(abc.ABC):
        id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()).upper())

    @dataclasses.dataclass
    class Currency(Entity):
        name: str = None
        code: str = None

    @dataclasses.dataclass
    class Account(Entity):
        @enum.unique
        class IGGCSyncAccountingAccountClass(enum.Enum):
            CURRENT = 'current'
            CREDIT_CARD = 'credit-card'
            CHECKING = 'checking'
            SAVINGS = 'savings'
            MORTGAGE = 'mortgage'
            EXPENSE = 'expense'
            REVENUE = 'revenue'
            REAL_ESTATE = 'real-estate'

        @enum.unique
        class IGGCSyncAccountingAccountType(enum.Enum):
            ASSET = 'asset'
            LIABILITY = 'liability'
            INCOME = 'income'
            EXPENSE = 'expense'

        @enum.unique
        class IGGCSyncAccountingAccountSubtype(enum.Enum):
            ASSET = 'asset'
            CHECKING = 'checking'
            CREDIT_CARD = 'credit-card'
            SAVINGS = 'savings'
            MORTGAGE = 'mortgage'

        TYPES = {
            core.Account.Type.CURRENT:     (IGGCSyncAccountingAccountClass.CURRENT,     IGGCSyncAccountingAccountType.ASSET,     IGGCSyncAccountingAccountSubtype.CHECKING),
            core.Account.Type.SAVINGS:     (IGGCSyncAccountingAccountClass.SAVINGS,     IGGCSyncAccountingAccountType.ASSET,     IGGCSyncAccountingAccountSubtype.SAVINGS),
            core.Account.Type.CREDIT_CARD: (IGGCSyncAccountingAccountClass.CREDIT_CARD, IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.CREDIT_CARD),
            core.Account.Type.MORTGAGE:    (IGGCSyncAccountingAccountClass.MORTGAGE,    IGGCSyncAccountingAccountType.LIABILITY, IGGCSyncAccountingAccountSubtype.MORTGAGE),
            core.Account.Type.PROPERTY:    (IGGCSyncAccountingAccountClass.REAL_ESTATE, IGGCSyncAccountingAccountType.ASSET,     IGGCSyncAccountingAccountSubtype.ASSET)
        }

        name: str = None
        note: str = None
        currency: typing.Optional['Document.Currency'] = None
        accountClass: IGGCSyncAccountingAccountClass = None
        type: IGGCSyncAccountingAccountType = None
        subtype: IGGCSyncAccountingAccountSubtype = None
        bankAccountNumber: str = None
        bankRoutingNumber: str = None
        institutionName: str = None
        institutionSite: urllib.parse.ParseResult = None

    @dataclasses.dataclass
    class LoanInfo(Entity):
        @dataclasses.dataclass
        class Recurrence(bpylist2.archive_types.DataclassArchiver):
            monthsOfTheYear: list = None
            weeksOfTheYear: list = None
            setPositions: list = None
            daysOfTheWeek: list = None
            daysOfTheMonth: list = None
            daysOfTheYear: list = None
            frequency: int = 8
            absolute: bool = False
            anchorIndex: int = 1
            interval: int = 1
        interestRate: decimal.Decimal = None
        loanAccount: 'Document.Account' = None
        minimumPrincipalAndInterest: decimal.Decimal = None
        paymentIntervalData: Recurrence = Recurrence(daysOfTheMonth=[1])
        paymentsPerYear = 12

        bpylist2.archiver.update_class_map({'IGGFDateRecurrenceRule': Recurrence})

    @dataclasses.dataclass
    class GroupItem:
        groupID: str
        groupType: str = 'IGGCAccountingPrimaryAccount'

    @dataclasses.dataclass
    class Group(Entity):
        name: str = None
        orderedItems: list['Document.GroupItem'] = dataclasses.field(default_factory=list)

    @dataclasses.dataclass
    class TransactionTypeV2(Entity):
        pass

    @dataclasses.dataclass
    class TransactionType:
        @enum.unique
        class IGGCSyncAccountingTransactionBaseType(enum.Enum):
            DEPOSIT = 'deposit'
            WITHDRAWAL = 'withdrawal'
            TRANSFER = 'transfer'

        baseType: IGGCSyncAccountingTransactionBaseType = None
        transactionType: 'Document.TransactionTypeV2' = None

    @dataclasses.dataclass
    class Transaction(Entity):
        transactionType: 'Document.TransactionType' = None
        title: str = None
        note: str = None
        date: datetime.datetime = None
        currency: 'Document.Currency' = None
        adjustment: bool = False
        checkNumber: int = None
        lineItems: list['Document.LineItem'] = None

    @dataclasses.dataclass
    class LineItem:
        account: typing.Optional['Document.Account'] = None
        accountAmount: decimal = None
        transacitonAmount: decimal = None
        identifier: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()).upper())
        sortIndex: int = 0
        cleared: bool = True
        memo: str = None

    @dataclasses.dataclass
    class LineItemSource:
        pass

    @dataclasses.dataclass
    class SecurityLineItem:
        pass

    def __init__(self, name, password, credentials=(os.environ['BANKTIVITY_LOGIN'], os.environ['BANKTIVITY_PASSWORD'])):
        self.url = 'https://apollo.iggnetservices.com/apollo'
        self.token = self.login(*credentials)
        [doc] = filter(lambda doc: doc['name'] == name, self.api('documents')['documents'])
        self.key = self.decrypt_key(password, doc['keyData'])
        self.url += f"/documents/{doc['id']}"

    def login(self, login, password):
        response = requests.post(
            'https://auth.iggnetservices.com/auth/sessions',
            data=xmltodict.unparse({'session': {'@login': login, '@password': password}}),
            headers={'Content-Type': 'application/xml'}
        )
        status = xmltodict.parse(response.text)['response']['status']
        if int(status['code']) > 0:
            raise ValueError(status['description'])
        return response.cookies['igg_authenticity_token']

    def decrypt_key(self, password, data):
        data = io.BytesIO(base64.b64decode(data))
        assert data.read(2) == b'\x01\x01'
        hash = hashlib.pbkdf2_hmac('sha1', password.encode(), data.read(8), 1701, KEY_SIZE)
        key = io.BytesIO(self.decrypt(data, hash))
        assert key.read(4) == b'Lisa'
        return key.read()

    def api(self, endpoint, **args):
        method = 'POST' if 'data' in args or 'json' in args else 'GET'
        response = requests.request(method, f'{self.url}/{endpoint}', headers={'IGG-Authorization': self.token}, **args)
        response.raise_for_status()
        return response.json()

    def cipher(self, iv, key=None):
        key = key or self.key
        assert len(key) == KEY_SIZE
        return Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, IV=iv)

    def encrypt(self, data):
        iv = secrets.token_bytes(KEY_SIZE)
        cipher = self.cipher(iv)
        return iv + cipher.encrypt(Crypto.Util.Padding.pad(data, cipher.block_size))

    def decrypt(self, data, key=None):
        cipher = self.cipher(data.read(KEY_SIZE), key)
        return Crypto.Util.Padding.unpad(cipher.decrypt(data.read()), cipher.block_size)

    def child_list(self, parent, name):
        value = parent.get(name, [])
        return value if type(value) == list else [value]

    def parse_object(self, entity):
        data = {'id': entity.get('@id')}
        klass = self.__class__.__dict__[entity['@type']]
        for field in self.child_list(entity, 'field'):
            text = field.get('#text')
            if '@enum' in field:
                enum_class = klass.__dict__.get(field['@enum'])
                value = text if enum_class is None else enum_class(text)
            elif '@null' in field:
                value = None
            else:
                field_type = field['@type']
                match field_type:
                    case 'string':
                        value = text
                    case 'bool':
                        value = text == 'yes'
                    case 'int':
                        value = int(text)
                    case 'decimal':
                        value = decimal.Decimal(text)
                    case 'date':
                        value = datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%S%z')
                    case 'url':
                        value = urllib.parse.urlparse(text)
                    case 'reference':
                        parts = tuple(text.split(':'))
                        value = None if parts[1] == '(null)' else self.entities[parts]
                    case 'data':
                        value = bpylist2.archiver.unarchive(base64.b64decode(text))
                    case _:
                        raise TypeError(field_type)
            data[field['@name']] = value
        for record in self.child_list(entity, 'record'):
            data[record['@name']] = self.parse_object(record)
        for collection in self.child_list(entity, 'collection'):
            data[collection['@name']] = list(map(self.parse_object, self.child_list(collection, 'record')))
        return dacite.from_dict(klass, data, dacite.Config(check_types=False))

    def parse_entity(self, entity):
        xml = gzip.decompress(self.decrypt(io.BytesIO(base64.b64decode(entity['data']))))
        result = self.parse_object(xmltodict.parse(xml)['entity'])
        return result

    def load(self):
        self.sync_token = self.api('entities/status')['syncToken']
        self.entities = {}
        self.currencies = {}
        self.groups = {}
        self.accounts = {}
        for entity_type in ['Currency', 'Account', 'LoanInfo', 'Group', 'TransactionTypeV2', 'Transaction']:
            for entity in self.api('entities', params={'type': entity_type}).get('entities', []):
                entity = self.parse_entity(entity)
                self.entities[(entity_type, entity.id)] = entity
                if entity_type == 'Currency':
                    self.currencies[entity.code] = entity
                elif entity_type == 'Group':
                    self.groups[entity.name] = entity
                elif entity_type == 'Account':
                    self.accounts[entity.name] = entity
        self.default_currency = self.currencies['EUR']
        self.transaction_type_deposit = Document.TransactionType(
            baseType=Document.TransactionType.IGGCSyncAccountingTransactionBaseType.DEPOSIT,
            transactionType=self.entities[('TransactionTypeV2', 'XXX-Deposit-ID')]
        )
        self.transaction_type_withdrawal = Document.TransactionType(
            baseType=Document.TransactionType.IGGCSyncAccountingTransactionBaseType.WITHDRAWAL,
            transactionType=self.entities[('TransactionTypeV2', 'XXX-Withdrawal-ID')]
        )
        self.transaction_type_transfer = Document.TransactionType(
            baseType=Document.TransactionType.IGGCSyncAccountingTransactionBaseType.TRANSFER,
            transactionType=self.entities[('TransactionTypeV2', 'XXX-Transfer-ID')]
        )

        self.created = []
        self.updated = []
        self.deleted = []

    def unparse_object(self, object):
        result = {'@type': object.__class__.__name__, 'field': [], 'record': [], 'collection': []}
        for name, value in object.__dict__.items():
            if name == 'id' or value is None:
                continue
            el_type = 'field'
            el = {}
            if type(value) == str:
                el['@type'] = 'string'
                el['#text'] = value
            elif type(value) == bool:
                el['@type'] = 'bool'
                el['#text'] = 'yes' if value else 'no'
            elif type(value) == int:
                el['@type'] = 'int'
                el['#text'] = str(value)
            elif type(value) == decimal.Decimal:
                el['@type'] = 'decimal'
                el['#text'] = str(value)
            elif type(value) == datetime.datetime:
                assert value.tzinfo
                el['@type'] = 'date'
                el['#text'] = value.isoformat(timespec='seconds')
            elif type(value) == urllib.parse.ParseResult:
                el['@type'] = 'url'
                el['#text'] = urllib.parse.urlunparse(value)
            elif type(value) == Document.TransactionType:
                el_type = 'record'
                el = self.unparse_object(value)
            elif type(value) == list:
                el_type = 'collection'
                el['@type'] = 'array'
                items = []
                for item in value:
                    item = self.unparse_object(item)
                    item['@name'] = 'element'
                    items.append(item)
                el['record'] = items
            elif isinstance(value, enum.Enum):
                el['@enum'] = value.__class__.__name__
                el['#text'] = value.value
            elif isinstance(value, bpylist2.archive_types.DataclassArchiver):
                el['@type'] = 'data'
                el['#text'] = base64.b64encode(bpylist2.archiver.archive(value))
            elif isinstance(value, Document.Entity):
                el['@type'] = 'reference'
                el['#text'] = f'{value.__class__.__name__}:{value.id}'
            else:
                raise TypeError(type(value))
            el['@name'] = name
            result[el_type].append(el)
        return result

    def unparse_entity(self, entity):
        data = self.unparse_object(entity)
        data['@id'] = entity.id
        data = base64.b64encode(self.encrypt(gzip.compress(xmltodict.unparse({'entity': data}).encode()))).decode()
        return {'id': entity.id, 'type': entity.__class__.__name__, 'data': data}

    def save(self):
        self.api('entities/entity', json={
            'syncToken': self.sync_token,
            'create': list(map(self.unparse_entity, self.created)),
            'update': list(map(self.unparse_entity, self.updated)),
            'delete': list(map(self.unparse_entity, self.deleted))
        })
        self.created = []
        self.updated = []
        self.deleted = []

    def clear(self):
        for key, entity in list(self.entities.items()):
            if key[0] == 'Account' and entity.accountClass not in [Document.Account.IGGCSyncAccountingAccountClass.REVENUE, Document.Account.IGGCSyncAccountingAccountClass.EXPENSE] or key[0] in ['Transaction', 'LoanInfo']:
                del self.entities[key]
                self.deleted.append(entity)
                if key[0] == 'Account':
                    del self.accounts[entity.name]

    def create_account(self, a):
        typ = Document.Account.TYPES[a.type]
        account = Document.Account(
            name=a.name,
            note=a.description,
            currency=self.default_currency,
            bankAccountNumber=a.number,
            bankRoutingNumber=a.routing_number,
            institutionName=a.bank_name,
            institutionSite=urllib.parse.urlparse(a.bank_site) if a.bank_site else None,
            accountClass=typ[0],
            type=typ[1],
            subtype=typ[2]
        )
        self.created.append(account)
        self.accounts[a.name] = account

        if a.interest_rate is not None:
            self.created.append(Document.LoanInfo(
                loanAccount=account,
                interestRate=a.interest_rate,
                minimumPrincipalAndInterest=a.monthly_payment
            ))

        group_name = a.group or 'Accounts'
        group = self.groups.get(group_name, None)
        if group is None:
            group = Document.Group(name=group_name)
            self.created.append(group)
            self.groups[group_name] = group
            root = self.groups['Accounts']
            root.orderedItems.append(Document.GroupItem(group.id, 'IGGCAccountingGroup'))
            self.updated.append(root)
        else:
            self.updated.append(group)
        group.orderedItems.append(Document.GroupItem(account.id))

        self.create_transaction(core.Transaction(
            core.BEGINNING - datetime.timedelta(days=1),
            'STARTING BALANCE',
            'BALANCE ADJUSTMENT',
            [core.Transaction.Line(account, a.initial_balance)],
        ))
        return account

    def create_transaction(self, t, adjustment=False):
        lines = []
        account_lines = {}

        def account_line(a, amount, cleared, memo):
            line = account_lines.get(a, None)
            if line:
                line.accountAmount += amount
                line.transacitonAmount += amount
                line.memo = memo
            else:
                line = Document.LineItem(self.accounts[a], amount, amount, cleared=cleared, memo=memo)
                account_lines[a] = line
                lines.append(line)

        transfer = False
        sum = 0
        for line in t.lines:
            account_line(line.account.name, line.amount, t.cleared, line.description)
            if line.counter_account:
                account_line(line.counter_account.name, -line.amount, t.cleared, line.description)
                transfer = True
            else:
                sum += line.amount
                account = self.accounts[Document.CATEGORIES[line.category]] if line.category else None
                lines.append(Document.LineItem(account, -line.amount, -line.amount, cleared=t.cleared, memo=line.description))
        if transfer:
            transaction_type = self.transaction_type_transfer
        elif sum < 0:
            transaction_type = self.transaction_type_withdrawal
        else:
            transaction_type = self.transaction_type_deposit
        transaction = Document.Transaction(
            currency=self.default_currency,
            date=t.date,
            transactionType=transaction_type,
            title=t.payee,
            note=t.description,
            lineItems=lines,
            checkNumber=t.number,
            adjustment=adjustment
        )
        self.created.append(transaction)
        return transaction
