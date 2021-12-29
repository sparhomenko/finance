import re
from base64 import b64decode, b64encode
from collections.abc import Iterable
from datetime import datetime
from decimal import ROUND_DOWN, Decimal
from secrets import token_bytes
from typing import Callable, SupportsIndex
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import srp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7, PaddingContext
from more_itertools import distribute, interleave
from requests import Request, Session, post

from core import Account, Category, Transaction
from typesafe import JSON, not_none, re_groups

NO_IV = bytearray(16)
SESSION_COUNTER = 500
CLIENT_ID = "6863015b-b70c-42c9-856b-5e26949bd378"


def after_prefix(text: str, prefix: str) -> str | None:
    return text.removeprefix(prefix) if text.startswith(prefix) else None


def before_suffix(text: str, suffix: str) -> str | None:
    return text.removesuffix(suffix) if text.endswith(suffix) else None


class Profile:
    class SRPClient(srp.User):
        def __init__(self, username: str, password: str):
            srp.rfc5054_enable()
            super().__init__(username, password, srp.SHA256, srp.NG_1024)

        def process_challenge(self, salt: bytes, server_public_value: bytes) -> bytes:
            super().process_challenge(salt, server_public_value)
            hash_function: Callable[[Iterable[SupportsIndex]], bytes] = lambda part: self.hash_class(bytes(part)).digest()
            self.K = bytes(interleave(*map(hash_function, distribute(2, self.S.to_bytes(128, "big")))))  # noqa: WPS111
            srp.rfc5054_enable(False)
            return srp._mod.calculate_M(self.hash_class, self.N, self.g, self.u.to_bytes(32, "big"), self.s, self.A, self.B, self.K)  # noqa: WPS437

    def __init__(self, profile_id: str, device_id: tuple[str, str], key: str, pin: tuple[str, str, str]):
        self.session = Session()
        self.session.headers.clear()
        self.session.headers["X-Capability"] = "proxy-protocol-version:2.0"
        self.auth_key = None
        self.auth_key = self.login1_srp6a(profile_id, pin, device_id)
        private_key = serialization.load_pem_private_key(key.encode(), None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        self.auth_key = self.login2_rsa(private_key)
        self.proxy_key, self.hmac_key = self.login3_ecdh()
        self.access_token = self.login4_oauth()

    def login1_srp6a(self, profile_id: str, pin: tuple[str, str, str], device_id: tuple[str, str]) -> bytes:
        variables = self.auth_api("getVariables", "getVariablesResponseEnvelope", {"profileId": profile_id})
        salt = bytes.fromhex(variables["srpSalt"].str)
        server_key = bytes.fromhex(variables["serverSrpKey"].str)

        client = Profile.SRPClient(profile_id, "".join(pin))
        _, public = client.start_authentication()
        evidence = client.process_challenge(salt, server_key)

        self.auth_api(
            "api/means/mpin/evidence",
            "evidenceMessage",
            json=JSON(
                {
                    "clientDeviceIdEvidence": self.b64(self.hash(self.hash(device_id[0].encode()), server_key)),
                    "clientEvidenceMessage": evidence.hex(),
                    "clientPublicValue": public.hex(),
                    "appInstanceRuntimeInfo": {"deviceBindingId": device_id[1], "deviceBindingIdEvidence": self.b64(self.hash(device_id[1].encode(), server_key))},
                },
            ),
        )
        return client.K[:16]

    def login2_rsa(self, private_key: rsa.RSAPrivateKey) -> bytes:
        session_counter = self.encrypt(not_none(self.auth_key), str(SESSION_COUNTER)).hex()
        encrypted_auth_key = bytes.fromhex(self.auth_api("getSessionKey", "getSessionKeyResponseEnvelope", {"sessionCounter": session_counter})["sessionKey"].str)
        return private_key.decrypt(encrypted_auth_key, padding.PKCS1v15())

    def login3_ecdh(self) -> tuple[bytes, bytes]:
        private_key = ec.generate_private_key(ec.SECP256R1())
        auth_response = JSON.response(
            post(
                "https://api.mobile.ing.nl/security/means/bootstrap/v2/key-agreement",
                json=JSON(
                    {
                        "authenticationContext": {"clientId": CLIENT_ID, "scopes": ["personal_data"]},
                        "clientPublicKey": self.b64(private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
                        "serverSigningKeyId": "20201202",
                        "clientNonce": self.b64(token_bytes(64)),
                    },
                ).body,
            ),
        )
        salt = b64decode(auth_response["serverNonce"].str)
        server_public_key = serialization.load_der_public_key(b64decode(auth_response["serverPublicKey"].str))
        assert isinstance(server_public_key, ec.EllipticCurvePublicKey)
        derived_key = HKDF(hashes.SHA256(), 32 + 64, salt, None).derive(private_key.exchange(ec.ECDH(), server_public_key))
        self.access_token = auth_response["authenticationResponse"]["accessTokens"]["accessToken"].str
        return self.split(derived_key, 32)

    def login4_oauth(self) -> str:
        agreement_id = self.auth_api("getSubscriptions", "getSubscriptionsResponseEnvelope")["subscriptions"][0]["agreementId"].str
        return self.auth_api("api/access-token-v2", "accessTokens", {"clientId": CLIENT_ID}, proxy=True)[agreement_id]["accessToken"].str

    def split(self, obj: bytes, index: int) -> tuple[bytes, bytes]:
        return (obj[:index], obj[index:])

    def encrypt(self, key: bytes, plaintext: str, iv: bytes = NO_IV) -> bytes:
        padder: PaddingContext = PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, key: bytes, encrypted_data: bytes, iv: bytes = NO_IV) -> bytes:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder: PaddingContext = PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def hash(self, *values: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        for value in values:
            digest.update(value)
        return digest.finalize()

    def b64(self, data: bytes) -> str:
        return b64encode(data).decode()

    def proxy_api(self, path: str, query: str | None) -> JSON:
        body = JSON({"method": "GET", "path": path, "query": query}).dumps().replace("/", r"\/")
        iv = token_bytes(16)
        data = self.encrypt(self.proxy_key, body, iv) + iv
        hmac = HMAC(self.hmac_key, hashes.SHA512())
        hmac.update(data)
        hashed = hmac.finalize()
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = post("https://api.mobile.ing.nl/proxy", data + hashed, headers=headers)
        response.raise_for_status()
        data, iv = self.split(response.content[:-64], -16)
        json_body = JSON.loads(self.decrypt(self.proxy_key, data, iv))
        if json_body["status"].int not in range(200, 400):
            raise ValueError(body)
        return JSON.loads(b64decode(json_body["content"].str))

    def auth_api(self, endpoint: str, envelope_key: str, params: dict[str, str] | None = None, proxy: bool = False, json: JSON | None = None) -> JSON:
        method = "POST" if json else "GET"
        request = self.session.prepare_request(Request(method, f"https://services.ing.nl/mb/authentication/{endpoint}", params=params, json=json.body if json else None))
        if proxy:
            parsed = urlparse(not_none(request.url))
            response = self.proxy_api(parsed.path, parsed.query)
        else:
            full_response = self.session.send(request)
            full_response.raise_for_status()
            response = JSON.response(full_response)
        response = response["securityProxyResponseEnvelope"]
        if response["resultCode"].str != "OK":
            raise ValueError(response)
        self.session.params = {"session": response["session"].str}
        encoded_response = response["apiResponse"].str
        if self.auth_key is not None:
            encoded_response = self.decrypt(self.auth_key, bytes.fromhex(encoded_response)).decode()
        return JSON.loads(encoded_response)[envelope_key]

    def fetch_link(self, entity: JSON, rel: str) -> JSON | None:
        filter_func: Callable[[JSON], bool] = lambda link: link["rel"].str == rel
        link = next(filter(filter_func, entity["_links"]), None)
        if link is not None:
            href = link["href"].str
            path, query = href.split("?") if "?" in href else (href, None)
            return self.proxy_api(not_none(path), query)
        return None

    def load(self, blacklist: Iterable[str] = ()) -> list[Account]:
        accounts = []
        types = "CURRENT,CARD,SAVINGS,MORTGAGE"
        for agreement in self.proxy_api("/agreements", f"agreementTypes={types}")["agreements"]:
            number = agreement["commercialId"]["value"].str
            if number in blacklist:
                continue
            name = (agreement.get("displayAlias") or agreement.get("holderName") or agreement["accountId"]).str
            agreement_type = agreement["type"].str
            if agreement_type in {"MORTGAGE", "CARD"}:
                agreement = not_none(self.fetch_link(agreement, "expensiveDetails"))
            balance = agreement["balance"]["value"].decimal
            typ = {"CURRENT": Account.Type.CURRENT, "SAVINGS": Account.Type.SAVINGS, "CARD": Account.Type.CREDIT_CARD, "MORTGAGE": Account.Type.MORTGAGE}[agreement_type]
            account = Account(number, name, typ, balance, "ING", "https://www.ing.nl/", "INGBNL2A")
            if agreement_type == "MORTGAGE":
                account.initial_balance *= -1
                parts = agreement["loanParts"]
                agreement_interest_rate = parts[0]["interestRate"]
                account.interest_rate = agreement_interest_rate["percentage"].decimal / 100
                loan_to_value = Decimal(re_groups(re.search(r" ([\d\.]+)%", agreement_interest_rate["explanation"]["message"].str))[0]) / 100
                amount_func: Callable[[JSON], Decimal] = lambda part: part["originalAmount"]["value"].decimal
                original_amount = sum(map(amount_func, parts), Decimal(0))
                original_value = original_amount / loan_to_value
                account.description = f"Loan to value: {loan_to_value * 100:.3f}% of {original_value:.2f}"
                payment_func: Callable[[JSON], Decimal] = lambda part: part["recentPayment"]["amount"]["value"].decimal
                account.monthly_payment = sum(map(payment_func, parts), Decimal(0))
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
                    subject_lines = data.get("subjectLines")
                    transaction = Transaction(
                        data["executionDate"].strptime("%Y-%m-%d").replace(tzinfo=ZoneInfo("Europe/Amsterdam")),
                        data["subject"].str,
                        " ".join([line.str for line in subject_lines]) if subject_lines else None,
                        [Transaction.Line(account, data["amount"]["value"].decimal)],
                        not data.get("reservation"),
                    )
                    if "counterAccount" in data and data["counterAccount"]["accountNumber"]["type"].str == "IBAN":
                        transaction.lines[0].counter_account_number = data["counterAccount"]["accountNumber"]["value"].str
                    self.beautify_card_payment(data, transaction)
                    self.beautify_omschrijving(data, transaction)
                    self.beautify_credit_card(data, transaction)
                    self.beautify_aflossing(agreement, data, transaction)
                    self.beautify_creditcard_incasso(transaction)
                    self.beautify_ing_betaalverzoek(transaction)
                    self.beautify_hypotheken(transaction)
                    self.beautify_abnamro_tikkie(transaction)
                    self.beautify_savings_transfer(transaction)
                    self.beautify_sns_betaalverzoek(transaction)
                    self.beautify_payment_processors(transaction)
                    self.beautify_thuisbezorgd(transaction)
                    self.beautify_kosten(account, transaction)
                    self.beautify_amazon(transaction)
                    self.beautify_paypal(transaction)
                    if not transaction.complete():
                        more = False
        return accounts

    def beautify_card_payment(self, data: JSON, transaction: Transaction) -> None:
        if data["type"]["id"].str == "BA":
            transaction.lines[0].description = transaction.description
            lines = data["subjectLines"]
            line = lines[1].str
            line = not_none(after_prefix(line, "Pasvolgnr: "))
            card, date = line.split(" ", 1)
            transaction.number = int(card)
            transaction.date = datetime.strptime(date, "%d-%m-%Y %H:%M").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
            transaction.description = lines[2].str

    def beautify_omschrijving(self, data: JSON, transaction: Transaction) -> None:
        if data["type"]["id"].str in {"IC", "OV", "ID", "GT"}:
            transaction.lines[0].description = transaction.description
            transaction.description = ""
            decription_goes_on = False
            for line_json in data["subjectLines"]:
                line = line_json.str
                if suffix := after_prefix(line, "Omschrijving: "):
                    transaction.description = suffix.rstrip()
                    decription_goes_on = True
                elif line.startswith("IBAN: "):
                    decription_goes_on = False
                elif date_str := after_prefix(line, "Datum/Tijd: "):
                    transaction.date = datetime.strptime(date_str, "%d-%m-%Y %H:%M:%S").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
                elif decription_goes_on:
                    transaction.description += f" {line.rstrip()}"

    def beautify_credit_card(self, data: JSON, transaction: Transaction) -> None:
        if data["type"]["id"].str == "AFSCHRIJVING":
            transaction.payee = data["merchant"]["name"].str
            if source_amount := data.get("sourceAmount"):
                fee = data["fee"]["value"].decimal
                transaction.lines[0].amount -= fee
                transaction.lines[0].description = f"{source_amount['value']} {source_amount['currency']} * {data['exchangeRate']}"
                transaction.lines.append(Transaction.Line(transaction.lines[0].account, fee, Category.FEE, "Currency exchange fee"))

    def beautify_savings_transfer(self, transaction: Transaction) -> None:
        if suffix := after_prefix(not_none(transaction.payee), "Oranje spaarrekening "):
            transaction.lines[0].counter_account_number = suffix

    def beautify_aflossing(self, agreement: JSON, data: JSON, transaction: Transaction) -> None:
        if data["type"]["id"].str == "MAANDELIJKSE AFLOSSING":
            transaction.lines[0].ext_account_number = agreement["id"].str[:3]
            transaction.lines[0].counter_account_number = agreement["referenceAgreement"]["number"].str

    def beautify_creditcard_incasso(self, transaction: Transaction) -> None:
        if suffix := after_prefix(not_none(transaction.payee), "INCASSO CREDITCARD ACCOUNTNR "):
            transaction.lines[0].counter_account_number = suffix

    def beautify_hypotheken(self, transaction: Transaction) -> None:
        if transaction.payee == "ING Hypotheken":
            transaction.lines[0].counter_account_number = re_groups(re.search("INZAKE HYP.NR. (.+)", not_none(transaction.description)))[0]

    def beautify_ing_betaalverzoek(self, transaction: Transaction) -> None:
        if transaction.payee == "ING Bank NV Betaalverzoek":
            if transaction.lines[0].amount < 0:
                transaction.payee, transaction.description = re_groups(re.match(r" (.+)[A-Z]{2}\d{2}[A-Z]{4}\d{10} \d+ (.+) ING Betaalverzoek", not_none(transaction.description)))
            else:
                transaction.payee, transaction.description = re_groups(re.match(r"Betaling van (.+) [A-Z]{2}\d{2}[A-Z]{4}\d{10} (.+)", not_none(transaction.description)))

    def beautify_abnamro_tikkie(self, transaction: Transaction) -> None:
        if transaction.payee == "ABN AMRO Bank NV":
            transaction.payee = re_groups(re.match(r"\d+ \d+ (.+) [A-Z]{2}\d{2}[A-Z]{4}\d{10}", not_none(transaction.description)))[0]
            transaction.description = None
        if transaction.payee == "AAB INZ RETAIL IDEAL BET":
            transaction.description, transaction.payee = re_groups(re.match(r"Tikkie ID \d+, (.+), (.+), [A-Z]{2}\d{2}[A-Z]{4}\d{10}", not_none(transaction.description)))

    def beautify_sns_betaalverzoek(self, transaction: Transaction) -> None:
        if transaction.payee == "SNS Betaalverzoek":
            transaction.payee, transaction.description = re_groups(re.match(r"(.+) \d+ [A-Z]{2}\d{2}[A-Z]{4}\d{10} (.+)", not_none(transaction.description)))

    def beautify_payment_processors(self, transaction: Transaction) -> None:
        assert transaction.payee
        if payee := after_prefix(transaction.payee, "iZ "):
            transaction.payee = payee.removeprefix("*")
            transaction.description = None
        elif payee := after_prefix(transaction.payee, "ZTL"):
            transaction.payee = payee
            transaction.description = None
        elif payee := after_prefix(transaction.payee, "CCV"):
            transaction.payee = payee
            transaction.description = None
        elif payee := before_suffix(transaction.payee, " via Mollie"):
            transaction.payee = payee
            transaction.description = re_groups(re.match(r"\w+ \d+ (.*)", not_none(transaction.description)))[0]
        elif payee := before_suffix(transaction.payee, " via Ingenico"):
            transaction.payee = payee
            transaction.description = None
        elif payee := before_suffix(transaction.payee, " via MultiSafepay"):
            transaction.payee = payee
            transaction.description = None

    def beautify_thuisbezorgd(self, transaction: Transaction) -> None:
        if transaction.payee == "Thuisbezorgd.nl via Takeaway.com":
            transaction.payee = "Thuisbezorgd.nl"
            transaction.description = re_groups(re.match(".* bestelling (.*) via", not_none(transaction.description)))[0]
        elif transaction.payee == "Thuisbezorgd.nl ThuisB":
            transaction.payee = "Thuisbezorgd.nl"

    def beautify_kosten(self, account: Account, transaction: Transaction) -> None:
        if not_none(transaction.payee).startswith("Kosten "):
            transaction.payee = account.bank_name
            transaction.description = " ".join(re_groups(re.match("(.*) {2,}(.*) {2,}.*", not_none(transaction.description))))
            transaction.lines[0].category = Category.FEE

    def beautify_amazon(self, transaction: Transaction) -> None:
        payee = not_none(transaction.payee)
        if payee in {"Amazon EU SARL", "Amazon.de", "AMAZON PAYMENTS EUROPE S.C.A.", "AMAZON EU S.A R.L., NIEDERLASSUNG DEUTSCHLAND"} or payee.startswith("AMZN Mktp DE"):
            transaction.payee = "Amazon"
            transaction.lines[0].ext_account_number = "*"
            transaction.lines[0].counter_account_number = "amazon"

    def beautify_paypal(self, transaction: Transaction) -> None:
        if transaction.payee == "PayPal (Europe) S.a.r.l. et Cie., S.C.A." and not_none(transaction.payee).startswith("PAYPAL *"):
            transaction.payee = "PayPal"
            transaction.lines[0].ext_account_number = "*"
            transaction.lines[0].counter_account_number = "paypal"


def match_mortgage_payment(account: Account, transaction: Transaction, line: Transaction.Line) -> Transaction:
    monthly_interest_rate = not_none(account.interest_rate) / 12
    repayment = ((-not_none(account.monthly_payment) - account.initial_balance * monthly_interest_rate) / (monthly_interest_rate + 1) * 100).to_integral_value(ROUND_DOWN) / 100
    interest = line.amount - repayment
    return Transaction(
        transaction.date,
        account.bank_name,
        None,
        [
            Transaction.Line(account, -line.amount, counter_account_number=line.account.number),
            Transaction.Line(account, interest, Category.INTEREST, "Interest", tax_year=transaction.date.year),
        ],
    )
