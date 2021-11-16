import Cryptodome.Cipher.AES
import Cryptodome.Util.Padding
import base64
import hashlib
import io
import os
import requests
import xmltodict


KEY_SIZE = 16


def check(response):
    response.raise_for_status()
    return response


def open_doc(name, key, login=os.environ['BANKTIVITY_LOGIN'], password=os.environ['BANKTIVITY_PASSWORD']):
    login_response = check(requests.post(
        'https://auth.iggnetservices.com/auth/sessions',
        data=xmltodict.unparse({'session': {'@login': login, '@password': password}}),
        headers={'Content-Type': 'application/xml'}
    ))
    status = xmltodict.parse(login_response.text)['response']['status']
    if int(status['code']) > 0:
        raise ValueError(status['description'])
    token = login_response.cookies['igg_authenticity_token']
    docs = check(requests.get(
        'https://apollo.iggnetservices.com/apollo/documents',
        headers={'IGG-Authorization': token}
    )).json()['documents']
    [doc] = filter(lambda doc: doc['name'] == name, docs)

    data = io.BytesIO(base64.b64decode(doc['keyData']))
    assert data.read(2) == b'\x01\x01'
    hash = hashlib.pbkdf2_hmac('sha1', key.encode(), data.read(8), 1701, KEY_SIZE)
    cypher = Cryptodome.Cipher.AES.new(hash, Cryptodome.Cipher.AES.MODE_CBC, IV=data.read(KEY_SIZE))
    key = io.BytesIO(Cryptodome.Util.Padding.unpad(cypher.decrypt(data.read()), KEY_SIZE))
    assert key.read(4) == b'Lisa'
    return [doc['id'], key.read()]
