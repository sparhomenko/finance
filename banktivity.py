import abc
import base64
import dataclasses
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
        name: str
        id: str = str(uuid.uuid4()).upper()

    @dataclasses.dataclass
    class Currency(Entity):
        code: str = None

    @dataclasses.dataclass
    class Account(Entity):
        class IGGCSyncAccountingAccountType(enum.Enum):
            ASSET = 'asset'
            INCOME = 'income'
            EXPENSE = 'expense'

        class IGGCSyncAccountingAccountSubtype(enum.Enum):
            CHECKING = 'checking'

        currency: typing.Optional['Document.Currency'] = None
        type: IGGCSyncAccountingAccountType = IGGCSyncAccountingAccountType.ASSET
        subtype: IGGCSyncAccountingAccountSubtype = IGGCSyncAccountingAccountSubtype.CHECKING

    @dataclasses.dataclass
    class GroupItem:
        groupID: str
        groupType: str = 'IGGCAccountingPrimaryAccount'

    @dataclasses.dataclass
    class Group(Entity):
        orderedItems: list['Document.GroupItem'] = None

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
                    case 'decimal':
                        value = decimal.Decimal(text)
                    case 'reference':
                        value = self.entity_by_id[tuple(text.split(':'))]
                    case _:
                        raise TypeError(field_type)
            data[field['@name']] = value
        for collection in self.child_list(entity, 'collection'):
            assert collection['@type'] == 'array'
            data[collection['@name']] = list(map(self.parse_object, self.child_list(collection, 'record')))
        return dacite.from_dict(klass, data, dacite.Config(check_types=False))

    def parse_entity(self, entity):
        xml = gzip.decompress(self.decrypt(io.BytesIO(base64.b64decode(entity['data']))))
        return self.parse_object(xmltodict.parse(xml)['entity'])

    def load(self):
        self.sync_token = self.api('entities/status')['syncToken']
        self.entity_by_id = {}
        self.entity_by_name = {}
        for entity_type in ['Currency', 'Account', 'Group']:
            for entity in self.api('entities', params={'type': entity_type})['entities']:
                entity = self.parse_entity(entity)
                self.entity_by_id[(entity_type, entity.id)] = entity
                self.entity_by_name[(entity_type, entity.name)] = entity
        self.created = []
        self.updated = []

    def unparse_object(self, object):
        fields = []
        collections = []
        for name, value in object.__dict__.items():
            if name == 'id' or value is None:
                continue
            e = {'@name': name}
            elements = fields
            if type(value) == str:
                e['@type'] = 'string'
                e['#text'] = value
            elif type(value) == list:
                e['@type'] = 'array'
                e['record'] = map(self.unparse_object, value)
                elements = collections
            elif isinstance(value, enum.Enum):
                e['@enum'] = value.__class__.__name__
                e['#text'] = value.value
            elif isinstance(value, Document.Entity):
                e['@type'] = 'reference'
                e['#text'] = f'{value.__class__.__name__}:{value.id}'
            else:
                raise TypeError(type(value))
            elements.append(e)
        return {'@type': object.__class__.__name__, 'field': fields, 'collection': collections}

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
        account = Document.Account(name=name, currency=self.entity_by_name[('Currency', 'Euro')])
        self.created.append(account)
        group = self.entity_by_id[('Group', 'com.iggsoftware.accounting.group.accounts')]
        group.orderedItems.append(Document.GroupItem(account.id))
        self.updated.append(group)
        return account
