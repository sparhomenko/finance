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
import uuid

import Crypto.Cipher.AES
import Crypto.Util.Padding
import dacite
import requests
import xmltodict

KEY_SIZE = 16


class Document:
    @dataclasses.dataclass
    class Entity(abc.ABC):
        id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()).upper())

    @dataclasses.dataclass
    class Currency(Entity):
        name: str = None
        code: str = None

    @dataclasses.dataclass
    class Account(Entity):
        class IGGCSyncAccountingAccountType(enum.Enum):
            ASSET = 'asset'
            INCOME = 'income'
            EXPENSE = 'expense'

        class IGGCSyncAccountingAccountSubtype(enum.Enum):
            CHECKING = 'checking'

        name: str = None
        currency: typing.Optional['Document.Currency'] = None
        type: IGGCSyncAccountingAccountType = IGGCSyncAccountingAccountType.ASSET
        subtype: IGGCSyncAccountingAccountSubtype = IGGCSyncAccountingAccountSubtype.CHECKING

    @dataclasses.dataclass
    class GroupItem:
        groupID: str
        groupType: str = 'IGGCAccountingPrimaryAccount'

    @dataclasses.dataclass
    class Group(Entity):
        name: str = None
        orderedItems: list['Document.GroupItem'] = None

    @dataclasses.dataclass
    class TransactionTypeV2(Entity):
        pass

    @dataclasses.dataclass
    class TransactionType:
        class IGGCSyncAccountingTransactionBaseType(enum.Enum):
            DEPOSIT = 'deposit'
            WITHDRAWAL = 'withdrawal'

        baseType: IGGCSyncAccountingTransactionBaseType = None
        transactionType: 'Document.TransactionTypeV2' = None

    @dataclasses.dataclass
    class Transaction(Entity):
        transactionType: 'Document.TransactionType' = None
        note: str = None
        date: datetime.datetime = None
        currency: 'Document.Currency' = None
        lineItems: list['Document.LineItem'] = None

    @dataclasses.dataclass
    class LineItem:
        account: typing.Optional['Document.Account'] = None
        accountAmount: decimal = None
        transacitonAmount: decimal = None
        identifier: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()).upper())
        sortIndex: int = 0

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
                    case 'reference':
                        value = self.entities[tuple(text.split(':'))]
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
        return self.parse_object(xmltodict.parse(xml)['entity'])

    def load(self):
        self.sync_token = self.api('entities/status')['syncToken']
        self.entities = {}
        self.currencies = {}
        self.accounts = {}
        for entity_type in ['Currency', 'Account', 'Group', 'TransactionTypeV2', 'Transaction']:
            for entity in self.api('entities', params={'type': entity_type}).get('entities', []):
                entity = self.parse_entity(entity)
                self.entities[(entity_type, entity.id)] = entity
                if entity_type == 'Currency':
                    self.currencies[entity.code] = entity
                elif entity_type == 'Account':
                    self.accounts[entity.name] = entity
        self.default_currency = self.currencies['EUR']
        self.transaction_type_withdrawal = Document.TransactionType(
            baseType=Document.TransactionType.IGGCSyncAccountingTransactionBaseType.WITHDRAWAL,
            transactionType=self.entities[('TransactionTypeV2', 'XXX-Withdrawal-ID')]
        )

        self.created = []
        self.updated = []

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
            'update': list(map(self.unparse_entity, self.updated))
        })
        self.created = []
        self.updated = []

    def create_account(self, name):
        account = Document.Account(name=name, currency=self.currencies['EUR'])
        self.created.append(account)
        group = self.entities[('Group', 'com.iggsoftware.accounting.group.accounts')]
        group.orderedItems.append(Document.GroupItem(account.id))
        self.updated.append(group)
        return account

    def create_transaction(self, account, amount, **args):
        transaction = Document.Transaction(
            currency=self.default_currency,
            date=datetime.datetime.now(tz=datetime.timezone.utc),
            transactionType=self.transaction_type_withdrawal,
            lineItems=[
                Document.LineItem(account=account, accountAmount=amount, transacitonAmount=amount),
                Document.LineItem(accountAmount=-amount, transacitonAmount=-amount)
            ], **args
        )
        self.created.append(transaction)
        return transaction
