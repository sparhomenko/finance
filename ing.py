import hmac
import json
import re
from base64 import b64decode, b64encode
from datetime import datetime
from decimal import ROUND_DOWN, Decimal
from hashlib import sha256, sha512
from itertools import chain
from secrets import token_bytes
from urllib.parse import urlparse

import srp
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Padding
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pytz import timezone
from requests import Request, Session, post

from core import Account, Transaction

NO_IV = bytearray(16)
SESSION_COUNTER = 500
CLIENT_ID = "6863015b-b70c-42c9-856b-5e26949bd378"


class Profile:
    class SRPClient(srp.User):
        def __init__(self, username, password):
            srp.rfc5054_enable()
            super().__init__(username, password, srp.SHA256, srp.NG_1024)

        def process_challenge(self, salt, server_public_value):
            super().process_challenge(salt, server_public_value)
            session = self.S.to_bytes(128, "big")
            self.K = bytes(chain.from_iterable(zip(self.hash_class(session[::2]).digest(), self.hash_class(session[1::2]).digest())))  # noqa: WPS111
            srp.rfc5054_enable(False)
            return srp._pysrp.calculate_M(self.hash_class, self.N, self.g, self.u.to_bytes(32, "big"), self.s, self.A, self.B, self.K)  # noqa: WPS437

    def __init__(self, profile_id, device_id, key, pin):
        self.session = Session()
        self.session.headers = {"X-Capability": "proxy-protocol-version:2.0"}
        self.auth_key = None
        self.auth_key = self.login1_srp6a(profile_id, pin, device_id)
        self.auth_key = self.login2_rsa(RSA.import_key(key))
        self.proxy_key, self.hmac_key = self.login3_ecdh()
        self.access_token = self.login4_oauth()

    def login1_srp6a(self, profile_id, pin, device_id):
        variables = self.auth_api("getVariables", "getVariablesResponseEnvelope", {"profileId": profile_id})
        salt = bytes.fromhex(variables["srpSalt"])
        server_key = bytes.fromhex(variables["serverSrpKey"])

        client = Profile.SRPClient(profile_id, "".join(pin))
        _, public = client.start_authentication()
        evidence = client.process_challenge(salt, server_key)

        self.auth_api(
            "api/means/mpin/evidence",
            "evidenceMessage",
            json={
                "clientDeviceIdEvidence": self.b64(self.hash(self.hash(device_id[0].encode()), server_key)),
                "clientEvidenceMessage": evidence.hex(),
                "clientPublicValue": public.hex(),
                "appInstanceRuntimeInfo": {"deviceBindingId": device_id[1], "deviceBindingIdEvidence": self.b64(self.hash(device_id[1].encode(), server_key))},
            },
        )
        return client.K[:16]

    def login2_rsa(self, private_key):
        session_counter = self.encrypt(self.auth_key, str(SESSION_COUNTER)).hex()
        encrypted_auth_key = bytes.fromhex(self.auth_api("getSessionKey", "getSessionKeyResponseEnvelope", {"sessionCounter": session_counter})["sessionKey"])
        return PKCS1_v1_5.new(private_key).decrypt(encrypted_auth_key, "")

    def login3_ecdh(self):
        private_key = asymmetric.ec.generate_private_key(asymmetric.ec.SECP256R1())
        auth_response = post(
            "https://api.mobile.ing.nl/security/means/bootstrap/v2/key-agreement",
            json={
                "authenticationContext": {"clientId": CLIENT_ID, "scopes": ["personal_data"]},
                "clientPublicKey": self.b64(private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
                "serverSigningKeyId": "20201202",
                "clientNonce": self.b64(token_bytes(64)),
            },
        ).json()
        salt = b64decode(auth_response["serverNonce"])
        server_public_key = serialization.load_der_public_key(b64decode(auth_response["serverPublicKey"]))
        derived_key = HKDF(hashes.SHA256(), 32 + 64, salt, None).derive(private_key.exchange(asymmetric.ec.ECDH(), server_public_key))
        self.access_token = auth_response["authenticationResponse"]["accessTokens"]["accessToken"]
        return self.split(derived_key, 32)

    def login4_oauth(self):
        agreement_id = self.auth_api("getSubscriptions", "getSubscriptionsResponseEnvelope")["subscriptions"][0]["agreementId"]
        return self.auth_api("api/access-token-v2", "accessTokens", {"clientId": CLIENT_ID}, proxy=True)[agreement_id]["accessToken"]

    def split(self, obj, index):
        return (obj[:index], obj[index:])

    def encrypt(self, key, plaintext, iv=NO_IV):
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.encrypt(Padding.pad(plaintext.encode(), 16))

    def decrypt(self, key, encrypted, iv=NO_IV):
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return Padding.unpad(cipher.decrypt(encrypted), 16).decode()

    def hash(self, *values):
        result = sha256()
        for value in values:
            result.update(value)
        return result.digest()

    def b64(self, data):
        return b64encode(data).decode()

    def proxy_api(self, path, query):
        body = json.dumps({"method": "GET", "path": path, "query": query}).replace("/", r"\/")
        iv = token_bytes(16)
        data = self.encrypt(self.proxy_key, body, iv) + iv
        hashed = hmac.new(self.hmac_key, data, sha512).digest()
        response = post("https://api.mobile.ing.nl/proxy", data + hashed, headers={"Authorization": f"Bearer {self.access_token}"})
        if not 200 <= response.status_code < 300:
            raise ValueError(response.text())
        data, iv = self.split(response.content[:-64], -16)
        response = json.loads(self.decrypt(self.proxy_key, data, iv))
        if not 200 <= response["status"] < 300:
            raise ValueError(response)
        return json.loads(b64decode(response["content"]), parse_float=Decimal)

    def auth_api(self, endpoint, envelope_key, params=None, proxy=False, **args):
        method = "POST" if "json" in args else "GET"
        request = self.session.prepare_request(Request(method, f"https://services.ing.nl/mb/authentication/{endpoint}", params=params, **args))
        if proxy:
            parsed = urlparse(request.url)
            response = self.proxy_api(parsed.path, parsed.query)
        else:
            response = self.session.send(request)
            if not 200 <= response.status_code < 300:
                raise ValueError(response.text())
            response = response.json()
        response = response["securityProxyResponseEnvelope"]
        if response["resultCode"] != "OK":
            raise ValueError(response)
        self.session.params["session"] = response["session"]
        response = response["apiResponse"]
        if self.auth_key is not None:
            response = self.decrypt(self.auth_key, bytes.fromhex(response))
        response = json.loads(response)[envelope_key]
        if isinstance(response, dict) and response.get("returnCode", "OK") != "OK":
            raise ValueError(response)
        return response

    def fetch_link(self, entity, rel):
        link = next(filter(lambda link: link["rel"] == rel, entity["_links"]), None)
        if link is not None:
            path, query = link["href"].split("?") if "?" in link["href"] else (link["href"], None)
            return self.proxy_api(path, query)
        return None

    def load(self, blacklist=()):
        accounts = []
        types = "CURRENT,CARD,SAVINGS,MORTGAGE"
        for agreement in self.proxy_api("/agreements", f"agreementTypes={types}")["agreements"]:
            number = agreement["commercialId"]["value"]
            if number in blacklist:
                continue
            name = agreement.get("displayAlias", agreement.get("holderName"))
            agreement_type = agreement["type"]
            if agreement_type in {"MORTGAGE", "CARD"}:
                agreement = self.fetch_link(agreement, "expensiveDetails")
            balance = Decimal(agreement["balance"]["value"])
            typ = {"CURRENT": Account.Type.CURRENT, "SAVINGS": Account.Type.SAVINGS, "CARD": Account.Type.CREDIT_CARD, "MORTGAGE": Account.Type.MORTGAGE}[agreement_type]
            account = Account(number, name, typ, balance, "ING", "https://www.ing.nl/", "INGBNL2A")
            if agreement_type == "MORTGAGE":
                account.initial_balance *= -1
                parts = agreement["loanParts"]
                agreement_interest_rate = parts[0]["interestRate"]
                account.interest_rate = agreement_interest_rate["percentage"] / 100
                loan_to_value = Decimal(re.search(r" ([\d\.]+)%", agreement_interest_rate["explanation"]["message"])[1]) / 100
                original_amount = sum(map(lambda part: Decimal(part["originalAmount"]["value"]), parts))
                original_value = original_amount / loan_to_value
                account.description = f"Loan to value: {loan_to_value * 100:.3f}% of {original_value:.2f}"
                account.monthly_payment = sum(map(lambda part: Decimal(part["recentPayment"]["amount"]["value"]), parts))
                account.matcher = match_mortgage_payment
            accounts.append(account)

            more = True
            next_link = (agreement, "transactions")
            while more:
                response = self.fetch_link(*next_link)
                if response is None:
                    break
                next_link = (response, "next")
                for data in response["transactions"]:
                    transaction = Transaction(
                        datetime.strptime(data["executionDate"], "%Y-%m-%d").replace(tzinfo=timezone("Europe/Amsterdam")),
                        data["subject"],
                        " ".join(data.get("subjectLines", [])),
                        [Transaction.Line(account, Decimal(data["amount"]["value"]))],
                        not data.get("reservation", False),
                    )
                    if "counterAccount" in data and data["counterAccount"]["accountNumber"]["type"] == "IBAN":
                        transaction.lines[0].counter_account_number = data["counterAccount"]["accountNumber"]["value"]
                    self.beautify_card_payment(data, transaction)
                    self.beautify_omschrijving(data, transaction)
                    self.beautify_credit_card(data, transaction)
                    self.beautify_aflossing(agreement, data, transaction)
                    self.beautify_creditcard_incasso(data, transaction)
                    self.beautify_ing_betaalverzoek(data, transaction)
                    self.beautify_hypotheken(data, transaction)
                    self.beautify_abnamro_tikkie(data, transaction)
                    self.beautify_savings_transfer(data, transaction)
                    self.beautify_sns_betaalverzoek(data, transaction)
                    if not transaction.complete():
                        more = False
        return accounts

    def beautify_card_payment(self, data, transaction):
        if data["type"]["id"] == "BA":
            transaction.lines[0].description = transaction.description
            lines = data["subjectLines"]
            line = lines[1]
            assert line.startswith("Pasvolgnr: ")
            line = line.removeprefix("Pasvolgnr: ")
            card, date = line.split(" ", 1)
            transaction.number = int(card)
            transaction.date = datetime.strptime(date, "%d-%m-%Y %H:%M").replace(tzinfo=timezone("Europe/Amsterdam"))
            transaction.description = lines[2]

    def beautify_omschrijving(self, data, transaction):
        if data["type"]["id"] in {"IC", "OV", "ID", "GT"}:
            transaction.lines[0].description = transaction.description
            transaction.description = None
            decription_goes_on = False
            for line in data["subjectLines"]:
                if line.startswith("Omschrijving: "):
                    transaction.description = line.removeprefix("Omschrijving: ").rstrip()
                    decription_goes_on = True
                elif line.startswith("IBAN: "):
                    decription_goes_on = False
                elif line.startswith("Datum/Tijd:"):
                    transaction.date = datetime.strptime(line.removeprefix("Datum/Tijd: "), "%d-%m-%Y %H:%M:%S").replace(tzinfo=timezone("Europe/Amsterdam"))
                elif decription_goes_on:
                    transaction.description += f" {line.rstrip()}"

    def beautify_credit_card(self, data, transaction):
        if data["type"]["id"] == "AFSCHRIJVING":
            transaction.payee = data["merchant"]["name"]
            source_amount = data.get("sourceAmount")
            if source_amount:
                fee = Decimal(data["fee"]["value"])
                transaction.lines[0].amount -= fee
                transaction.lines[0].description = f"{source_amount['value']} {source_amount['currency']} * {data['exchangeRate']}"
                transaction.lines.append(Transaction.Line(transaction.lines[0].account, fee, Transaction.Line.Category.FEE, "Currency exchange fee"))

    def beautify_savings_transfer(self, data, transaction):
        if transaction.payee.startswith("Oranje spaarrekening "):
            transaction.lines[0].counter_account_number = transaction.payee.removeprefix("Oranje spaarrekening ")

    def beautify_aflossing(self, agreement, data, transaction):
        if data["type"]["id"] == "MAANDELIJKSE AFLOSSING":
            transaction.lines[0].ext_account_number = agreement["id"][:3]
            transaction.lines[0].counter_account_number = agreement["referenceAgreement"]["number"]

    def beautify_creditcard_incasso(self, data, transaction):
        if transaction.payee.startswith("INCASSO CREDITCARD ACCOUNTNR "):
            transaction.lines[0].counter_account_number = transaction.payee.removeprefix("INCASSO CREDITCARD ACCOUNTNR ")

    def beautify_hypotheken(self, data, transaction):
        if transaction.payee == "ING Hypotheken":
            transaction.lines[0].counter_account_number = re.search("INZAKE HYP.NR. (.+)", transaction.description)[1]

    def beautify_ing_betaalverzoek(self, data, transaction):
        if transaction.payee == "ING Bank NV Betaalverzoek":
            if transaction.lines[0].amount < 0:
                transaction.payee, transaction.description = re.match(r" (.+)[A-Z]{2}\d{2}[A-Z]{4}\d{10} \d+ (.+) ING Betaalverzoek", transaction.description).groups()
            else:
                transaction.payee, transaction.description = re.match(r"Betaling van (.+) [A-Z]{2}\d{2}[A-Z]{4}\d{10} (.+)", transaction.description).groups()

    def beautify_abnamro_tikkie(self, data, transaction):
        if transaction.payee == "ABN AMRO Bank NV":
            transaction.payee = re.match(r"\d+ \d+ (.+) [A-Z]{2}\d{2}[A-Z]{4}\d{10}", transaction.description)[1]
            transaction.description = None
        if transaction.payee == "AAB INZ RETAIL IDEAL BET":
            transaction.description, transaction.payee = re.match(r"Tikkie ID \d+, (.+), (.+), [A-Z]{2}\d{2}[A-Z]{4}\d{10}", transaction.description).groups()

    def beautify_sns_betaalverzoek(self, data, transaction):
        if transaction.payee == "SNS Betaalverzoek":
            transaction.payee, transaction.description = re.match(r"(.+) \d+ [A-Z]{2}\d{2}[A-Z]{4}\d{10} (.+)", transaction.description).groups()


def match_mortgage_payment(account, transaction, line):
    monthly_interest_rate = account.interest_rate / 12
    repayment = ((-account.monthly_payment - account.initial_balance * monthly_interest_rate) / (monthly_interest_rate + 1) * 100).to_integral_value(ROUND_DOWN) / 100
    interest = line.amount - repayment
    return Transaction(
        transaction.date,
        account.bank_name,
        None,
        [
            Transaction.Line(account, -line.amount, counter_account_number=line.account.number),
            Transaction.Line(account, interest, Transaction.Line.Category.INTEREST, "Interest"),
        ],
    )
