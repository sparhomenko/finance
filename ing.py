import base64
import datetime
import decimal
import hashlib
import hmac
import json
import re
import secrets
import urllib.parse

import Crypto.Cipher.AES
import Crypto.Cipher.PKCS1_v1_5
import Crypto.Hash.SHA256
import Crypto.PublicKey.RSA
import Crypto.Util.Padding
import pytz
import requests
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import core

NO_IV = bytearray(16)
SESSION_COUNTER = 500
CLIENT_ID = '6863015b-b70c-42c9-856b-5e26949bd378'
SRP_N = bytes.fromhex("""
    eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5
    d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c
    05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3
""")


class Profile:
    def __init__(self, id, device_id, key, pin):
        self.session = requests.Session()
        self.session.headers = {'X-Capability': 'proxy-protocol-version:2.0'}
        self.auth_key = None
        self.auth_key = self.login1_srp(id, pin, device_id)
        self.auth_key = self.login2_rsa(Crypto.PublicKey.RSA.import_key(key))
        self.proxy_key, self.hmac_key = self.login3_ecdh()
        self.access_token = self.login4_oauth()

    def login1_srp(self, id, pin, device_id):
        vars = self.auth_api('getVariables', 'getVariablesResponseEnvelope', {'profileId': id})
        identity = f'{id}:{pin[0]}{pin[1]}{pin[2]}'
        salt = bytes.fromhex(vars['srpSalt'])
        server_key = bytes.fromhex(vars['serverSrpKey'])
        client_public_value, client_key, client_proof = self.srp6a(identity, salt, server_key)
        self.auth_api('api/means/mpin/evidence', 'evidenceMessage', json={
            'clientDeviceIdEvidence': self.b64(self.hash(self.hash(device_id[0].encode()), server_key)),
            'clientEvidenceMessage': client_proof.hex(),
            'clientPublicValue': client_public_value.hex(),
            'appInstanceRuntimeInfo': {
                'deviceBindingId': device_id[1],
                'deviceBindingIdEvidence': self.b64(self.hash(device_id[1].encode(), server_key))
            }
        })
        return client_key[:16]

    def login2_rsa(self, private_key):
        session_counter = self.encrypt(self.auth_key, str(SESSION_COUNTER)).hex()
        encrypted_auth_key = bytes.fromhex(self.auth_api('getSessionKey', 'getSessionKeyResponseEnvelope', {'sessionCounter': session_counter})['sessionKey'])
        return Crypto.Cipher.PKCS1_v1_5.new(private_key).decrypt(encrypted_auth_key, '')

    def login3_ecdh(self):
        private_key = asymmetric.ec.generate_private_key(asymmetric.ec.SECP256R1())
        auth_response = requests.post('https://api.mobile.ing.nl/security/means/bootstrap/v2/key-agreement', json={
            'authenticationContext': {'clientId': CLIENT_ID, 'scopes': ['personal_data']},
            'clientPublicKey': self.b64(private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            'serverSigningKeyId': '20201202',
            'clientNonce': self.b64(secrets.token_bytes(64))
        }).json()
        salt = base64.b64decode(auth_response['serverNonce'])
        server_public_key = serialization.load_der_public_key(base64.b64decode(auth_response['serverPublicKey']))
        derived_key = HKDF(hashes.SHA256(), 32+64, salt, None).derive(private_key.exchange(asymmetric.ec.ECDH(), server_public_key))
        self.access_token = auth_response['authenticationResponse']['accessTokens']['accessToken']
        return self.split(derived_key, 32)

    def login4_oauth(self):
        agreement_id = self.auth_api('getSubscriptions', 'getSubscriptionsResponseEnvelope')['subscriptions'][0]['agreementId']
        return self.auth_api('api/access-token-v2', 'accessTokens', {'clientId': CLIENT_ID}, True)[agreement_id]['accessToken']

    def srp6a(self, Ip, s, B):  # https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol#Example_code_in_Python
        def to_i(b):
            return int.from_bytes(b, 'big')

        def to_b(i, n=128):
            return i.to_bytes(n, 'big')

        N = to_i(SRP_N)
        g = 2
        k = to_i(self.hash(SRP_N, to_b(g)))
        x = to_i(self.hash(s, self.hash(Ip.encode())))
        a = to_i(secrets.token_bytes(32))
        A = to_b(pow(g, a, N))
        u = self.hash(A, B)
        S_c = to_b(pow(to_i(B) - k * pow(g, x, N), a + to_i(u) * x, N))
        S_c1, S_c2 = zip(*(S_c[i:i+2] for i in range(0, 128, 2)))
        K_c = bytes([i for sl in zip(self.hash(bytes(S_c1)), self.hash(bytes(S_c2))) for i in sl])
        M_c = self.hash(to_b(to_i(self.hash(SRP_N)) ^ to_i(self.hash(bytes([g]))), 32), self.hash(u), s, A, B, K_c)
        return (A, K_c, M_c)

    def split(self, b, i):
        return (b[:i], b[i:])

    def encrypt(self, key, s, iv=NO_IV):
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=iv)
        return cipher.encrypt(Crypto.Util.Padding.pad(s.encode(), 16))

    def decrypt(self, key, b, iv=NO_IV):
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=iv)
        return Crypto.Util.Padding.unpad(cipher.decrypt(b), 16).decode()

    def hash(self, *values):
        result = hashlib.sha256()
        for value in values:
            result.update(value)
        return result.digest()

    def b64(self, b):
        return base64.b64encode(b).decode()

    def proxy_api(self, path, query):
        body = json.dumps({'method': 'GET', 'path': path, 'query': query}).replace('/', '\\/')
        iv = secrets.token_bytes(16)
        data = self.encrypt(self.proxy_key, body, iv) + iv
        hashed = hmac.new(self.hmac_key, data, hashlib.sha512).digest()
        response = requests.post('https://api.mobile.ing.nl/proxy', data + hashed, headers={'Authorization': f'Bearer {self.access_token}'})
        if not 200 <= response.status_code < 300:
            raise ValueError(response.text())
        data, iv = self.split(response.content[:-64], -16)
        response = json.loads(self.decrypt(self.proxy_key, data, iv))
        if not 200 <= response['status'] < 300:
            raise ValueError(response)
        return json.loads(base64.b64decode(response['content']), parse_float=decimal.Decimal)

    def auth_api(self, endpoint, envelope_key, params={}, proxy=False, **args):
        method = 'POST' if 'json' in args else 'GET'
        request = self.session.prepare_request(requests.Request(method, f'https://services.ing.nl/mb/authentication/{endpoint}', params=params, **args))
        if proxy:
            parsed = urllib.parse.urlparse(request.url)
            response = self.proxy_api(parsed.path, parsed.query)
        else:
            response = self.session.send(request)
            if not 200 <= response.status_code < 300:
                raise ValueError(response.text())
            response = response.json()
        response = response['securityProxyResponseEnvelope']
        if response['resultCode'] != 'OK':
            raise ValueError(response)
        self.session.params['session'] = response['session']
        response = response['apiResponse']
        if self.auth_key is not None:
            response = self.decrypt(self.auth_key, bytes.fromhex(response))
        response = json.loads(response)[envelope_key]
        if type(response) == dict and response.get('returnCode', 'OK') != 'OK':
            raise ValueError(response)
        return response

    def fetch_link(self, entity, rel):
        link = next(filter(lambda l: l['rel'] == rel, entity['_links']), None)
        if link is not None:
            path, query = link['href'].split('?') if '?' in link['href'] else (link['href'], None)
            return self.proxy_api(path, query)
        else:
            return None

    def load(self, blacklist=[]):
        accounts = []
        types = 'CURRENT,CARD,SAVINGS,MORTGAGE'
        for agreement in self.proxy_api('/agreements', f'agreementTypes={types}')['agreements']:
            number = agreement['commercialId']['value']
            if number in blacklist:
                continue
            name = agreement.get('displayAlias', agreement.get('holderName'))
            if name == 'Nanny':
                continue
            agreement_type = agreement['type']
            if agreement_type in ['MORTGAGE', 'CARD']:
                agreement = self.fetch_link(agreement, 'expensiveDetails')
            balance = decimal.Decimal(agreement['balance']['value'])
            typ = {
                'CURRENT': core.Account.Type.CURRENT,
                'SAVINGS': core.Account.Type.SAVINGS,
                'CARD': core.Account.Type.CREDIT_CARD,
                'MORTGAGE': core.Account.Type.MORTGAGE
            }[agreement_type]
            account = core.Account(number, name, typ, balance, 'ING', 'https://www.ing.nl/', 'INGBNL2A')
            if agreement_type == 'MORTGAGE':
                account.initial_balance *= -1
                parts = agreement['loanParts']
                agreement_interest_rate = parts[0]['interestRate']
                account.interest_rate = agreement_interest_rate['percentage'] / 100
                loan_to_value = decimal.Decimal(re.search(r' ([\d\.]+)%', agreement_interest_rate['explanation']['message'])[1]) / 100
                original_amount = sum(map(lambda p: decimal.Decimal(p['originalAmount']['value']), parts))
                original_value = original_amount / loan_to_value
                account.description = f'Loan to value: {loan_to_value * 100:.3f}% of {original_value:.2f}'
                account.monthly_payment = sum(map(lambda p: decimal.Decimal(p['recentPayment']['amount']['value']), parts))
            accounts.append(account)

            more = True
            next = (agreement, 'transactions')
            while more:
                response = self.fetch_link(*next)
                if response is None:
                    break
                next = (response, 'next')
                for transaction in response['transactions']:
                    t = core.Account.Transaction(
                        account,
                        datetime.datetime.strptime(transaction['executionDate'], '%Y-%m-%d').replace(tzinfo=pytz.timezone('Europe/Amsterdam')),
                        transaction['subject'],
                        ' '.join(transaction.get('subjectLines', [])),
                        not transaction.get('reservation', False),
                        [core.Account.Transaction.Line(decimal.Decimal(transaction['amount']['value']))]
                    )
                    if 'counterAccount' in transaction and transaction['counterAccount']['accountNumber']['type'] == 'IBAN':
                        t.counter_account_number = transaction['counterAccount']['accountNumber']['value']
                    self.beautify_card_payment(transaction, t)
                    self.beautify_omschrijving(transaction, t)
                    self.beautify_credit_card(transaction, t)
                    self.beautify_aflossing(agreement, transaction, t)
                    self.beautify_creditcard_incasso(transaction, t)
                    self.beautify_ing_betaalverzoek(transaction, t)
                    self.beautify_hypotheken(transaction, t)
                    self.beautify_abnamro_tikkie(transaction, t)
                    self.beautify_savings_transfer(transaction, t)
                    if t.counter_account_number is not None and t.matcher is None:
                        t.matcher = lambda t, c: c.account.number == t.counter_account_number and c.lines[0].amount == -t.lines[0].amount
                    if not account.transaction(t):
                        more = False
        return accounts

    def beautify_card_payment(self, transaction, t):
        if transaction['type']['id'] == 'BA':
            t.lines[0].description = t.description
            lines = transaction['subjectLines']
            line = lines[1]
            assert line.startswith('Pasvolgnr: ')
            line = line.removeprefix('Pasvolgnr: ')
            card, date = line.split(' ', 1)
            t.number = int(card)
            t.date = datetime.datetime.strptime(date, '%d-%m-%Y %H:%M').replace(tzinfo=pytz.timezone('Europe/Amsterdam'))
            t.description = lines[2]

    def beautify_omschrijving(self, transaction, t):
        if transaction['type']['id'] in ['IC', 'OV', 'ID', 'GT']:
            t.lines[0].description = t.description
            t.description = None
            decription_goes_on = False
            for line in transaction['subjectLines']:
                if line.startswith('Omschrijving: '):
                    t.description = line.removeprefix('Omschrijving: ').rstrip()
                    decription_goes_on = True
                elif line.startswith('IBAN: '):
                    decription_goes_on = False
                elif line.startswith('Datum/Tijd:'):
                    t.date = datetime.datetime.strptime(line.removeprefix('Datum/Tijd: '), '%d-%m-%Y %H:%M:%S').replace(tzinfo=pytz.timezone('Europe/Amsterdam'))
                elif decription_goes_on:
                    t.description += f' {line.rstrip()}'

    def beautify_credit_card(self, transaction, t):
        if transaction['type']['id'] == 'AFSCHRIJVING':
            t.payee = transaction['merchant']['name']
            if 'sourceAmount' in transaction:
                fee = decimal.Decimal(transaction['fee']['value'])
                t.lines[0].amount -= fee
                t.lines[0].description = f"{transaction['sourceAmount']['value']} {transaction['sourceAmount']['currency']} * {transaction['exchangeRate']}"
                t.lines.append(core.Account.Transaction.Line(fee, core.Account.Transaction.Line.Category.FEE, 'Currency exchange fee'))

    def beautify_savings_transfer(self, transaction, t):
        if t.payee.startswith('Oranje spaarrekening '):
            t.counter_account_number = t.payee.removeprefix('Oranje spaarrekening ')

    def beautify_aflossing(self, agreement, transaction, t):
        if transaction['type']['id'] == 'MAANDELIJKSE AFLOSSING':
            t.counter_account_number = agreement['referenceAgreement']['number']

    def beautify_creditcard_incasso(self, transaction, t):
        if t.payee.startswith('INCASSO CREDITCARD ACCOUNTNR '):
            t.matcher = lambda t, c: c.account.type == core.Account.Type.CREDIT_CARD and c.lines[0].amount == -t.lines[0].amount

    def beautify_hypotheken(self, transaction, t):
        if t.payee == 'ING Hypotheken':
            t.counter_account_number = re.search(r'INZAKE HYP.NR. (.*)', t.description)[1]

    def beautify_ing_betaalverzoek(self, transaction, t):
        if t.payee == 'ING Bank NV Betaalverzoek':
            if t.is_withdrawal():
                t.payee, t.description = re.match(r' (.*)[A-Z]{2}\d{2}[A-Z]{4}\d{10} \d* (.*) ING Betaalverzoek', t.description).groups()
            else:
                t.payee, t.description = re.match(r'Betaling van (.*) [A-Z]{2}\d{2}[A-Z]{4}\d{10} (.*)', t.description).groups()

    def beautify_abnamro_tikkie(self, transaction, t):
        if t.payee == 'ABN AMRO Bank NV':
            t.payee = re.match(r'\d+ \d+ (.*) [A-Z]{2}\d{2}[A-Z]{4}\d{10}', t.description)[1]
            t.description = None
        if t.payee == 'AAB INZ RETAIL IDEAL BET':
            t.description, t.payee = re.match(r'Tikkie ID \d+, (.*), (.*), [A-Z]{2}\d{2}[A-Z]{4}\d{10}', t.description).groups()
