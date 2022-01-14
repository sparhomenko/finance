import re
from base64 import b64decode, b64encode
from collections.abc import Iterable
from datetime import datetime
from decimal import ROUND_DOWN, Decimal
from secrets import token_bytes
from typing import Callable, Final, SupportsIndex
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

from finance.core import Account, AccountType, Category, Line, Loader, Transaction
from finance.typesafe import JSON, not_none, re_groups

_NO_IV: Final = bytearray(16)
_SESSION_COUNTER: Final = 500
_CLIENT_ID: Final = "6863015b-b70c-42c9-856b-5e26949bd378"


def _after_prefix(text: str, prefix: str) -> str | None:
    return text.removeprefix(prefix) if text.startswith(prefix) else None


def _before_suffix(text: str, suffix: str) -> str | None:
    return text.removesuffix(suffix) if text.endswith(suffix) else None


class _SRPClient(srp.User):
    def __init__(self, username: str, password: str):
        srp.rfc5054_enable()
        super().__init__(username, password, srp.SHA256, srp.NG_1024)

    def process_challenge(self, salt: bytes, server_public_value: bytes) -> bytes:
        super().process_challenge(salt, server_public_value)
        hash_function: Callable[[Iterable[SupportsIndex]], bytes] = lambda part: self.hash_class(bytes(part)).digest()
        self.K = bytes(interleave(*map(hash_function, distribute(2, self.S.to_bytes(128, "big")))))  # noqa: WPS111
        srp.rfc5054_enable(False)
        return srp._mod.calculate_M(self.hash_class, self.N, self.g, self.u.to_bytes(32, "big"), self.s, self.A, self.B, self.K)  # noqa: WPS437


class Profile(Loader):
    def __init__(self, profile_id: str, device_id: tuple[str, str], key: str, pin: tuple[str, str, str], blacklist: Iterable[str] = ()):
        self._session = Session()
        self._session.headers.clear()
        self._session.headers["X-Capability"] = "proxy-protocol-version:2.0"
        self._auth_key = None
        self._auth_key = self._login1_srp6a(profile_id, pin, device_id)
        private_key = serialization.load_pem_private_key(key.encode(), None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        self._auth_key = self._login2_rsa(private_key)
        self._proxy_key, self._hmac_key = self._login3_ecdh()
        self._access_token = self._login4_oauth()
        self._blacklist = blacklist

    def load(self) -> list[Account]:
        accounts = []
        types = "CURRENT,CARD,SAVINGS,MORTGAGE"
        for agreement in self._proxy_api("/agreements", f"agreementTypes={types}")["agreements"]:
            number = agreement["commercialId"]["value"].str
            if number in self._blacklist:
                continue
            name = (agreement.get("displayAlias") or agreement.get("holderName") or agreement["accountId"]).str
            agreement_type = agreement["type"].str
            if agreement_type in {"MORTGAGE", "CARD"}:
                agreement = not_none(self._fetch_link(agreement, "expensiveDetails"))
            balance = agreement["balance"]["value"].decimal
            typ = {"CURRENT": AccountType.CURRENT, "SAVINGS": AccountType.SAVINGS, "CARD": AccountType.CREDIT_CARD, "MORTGAGE": AccountType.MORTGAGE}[agreement_type]
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
                account.matcher = _match_mortgage_payment
            accounts.append(account)

            more = True
            next_link = (agreement, "transactions")
            while more:
                response = self._fetch_link(*next_link)
                if response is None:
                    break
                next_link = (response, "next")
                for json in response["transactions"]:
                    subject_lines = json.get("subjectLines")
                    transaction = Transaction(
                        json["executionDate"].strptime("%Y-%m-%d").replace(tzinfo=ZoneInfo("Europe/Amsterdam")),
                        json["subject"].str,
                        " ".join(line.str for line in subject_lines) if subject_lines else None,
                        [Line(account, json["amount"]["value"].decimal)],
                        not json.get("reservation"),
                    )
                    if "counterAccount" in json and json["counterAccount"]["accountNumber"]["type"].str == "IBAN":
                        transaction.lines[0].counter_account_number = json["counterAccount"]["accountNumber"]["value"].str
                    self._beautify_card_payment(json, transaction)
                    self._beautify_omschrijving(json, transaction)
                    self._beautify_credit_card(json, transaction)
                    self._beautify_aflossing(agreement, json, transaction)
                    self._beautify_creditcard_incasso(transaction)
                    self._beautify_ing_betaalverzoek(transaction)
                    self._beautify_hypotheken(transaction)
                    self._beautify_abnamro_tikkie(transaction)
                    self._beautify_savings_transfer(transaction)
                    self._beautify_sns_betaalverzoek(transaction)
                    self._beautify_payment_processors(transaction)
                    self._beautify_thuisbezorgd(transaction)
                    self._beautify_kosten(account, transaction)
                    self._beautify_amazon(transaction)
                    self._beautify_paypal(transaction)
                    if not transaction.complete():
                        more = False
        return accounts

    def _login1_srp6a(self, profile_id: str, pin: tuple[str, str, str], device_id: tuple[str, str]) -> bytes:
        variables = self._auth_api("getVariables", "getVariablesResponseEnvelope", {"profileId": profile_id})
        salt = bytes.fromhex(variables["srpSalt"].str)
        server_key = bytes.fromhex(variables["serverSrpKey"].str)

        client = _SRPClient(profile_id, "".join(pin))
        _, public = client.start_authentication()
        evidence = client.process_challenge(salt, server_key)

        self._auth_api(
            "api/means/mpin/evidence",
            "evidenceMessage",
            json=JSON(
                {
                    "clientDeviceIdEvidence": self._b64(self._hash(self._hash(device_id[0].encode()), server_key)),
                    "clientEvidenceMessage": evidence.hex(),
                    "clientPublicValue": public.hex(),
                    "appInstanceRuntimeInfo": {"deviceBindingId": device_id[1], "deviceBindingIdEvidence": self._b64(self._hash(device_id[1].encode(), server_key))},
                },
            ),
        )
        return client.K[:16]

    def _login2_rsa(self, private_key: rsa.RSAPrivateKey) -> bytes:
        session_counter = self._encrypt(not_none(self._auth_key), str(_SESSION_COUNTER)).hex()
        encrypted_auth_key = bytes.fromhex(self._auth_api("getSessionKey", "getSessionKeyResponseEnvelope", {"sessionCounter": session_counter})["sessionKey"].str)
        return private_key.decrypt(encrypted_auth_key, padding.PKCS1v15())

    def _login3_ecdh(self) -> tuple[bytes, bytes]:
        private_key = ec.generate_private_key(ec.SECP256R1())
        auth_response = JSON.response(
            post(
                "https://api.mobile.ing.nl/security/means/bootstrap/v2/key-agreement",
                json=JSON(
                    {
                        "authenticationContext": {"clientId": _CLIENT_ID, "scopes": ["personal_data"]},
                        "clientPublicKey": self._b64(private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
                        "serverSigningKeyId": "20201202",
                        "clientNonce": self._b64(token_bytes(64)),
                    },
                ).body,
            ),
        )
        salt = b64decode(auth_response["serverNonce"].str)
        server_public_key = serialization.load_der_public_key(b64decode(auth_response["serverPublicKey"].str))
        assert isinstance(server_public_key, ec.EllipticCurvePublicKey)
        derived_key = HKDF(hashes.SHA256(), 32 + 64, salt, None).derive(private_key.exchange(ec.ECDH(), server_public_key))
        self._access_token = auth_response["authenticationResponse"]["accessTokens"]["accessToken"].str
        return self._split(derived_key, 32)

    def _login4_oauth(self) -> str:
        agreement_id = self._auth_api("getSubscriptions", "getSubscriptionsResponseEnvelope")["subscriptions"][0]["agreementId"].str
        return self._auth_api("api/access-token-v2", "accessTokens", {"clientId": _CLIENT_ID}, proxy=True)[agreement_id]["accessToken"].str

    def _split(self, bytes_data: bytes, index: int) -> tuple[bytes, bytes]:
        return (bytes_data[:index], bytes_data[index:])

    def _encrypt(self, key: bytes, plaintext: str, iv: bytes = _NO_IV) -> bytes:
        padder: PaddingContext = PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def _decrypt(self, key: bytes, encrypted_data: bytes, iv: bytes = _NO_IV) -> bytes:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder: PaddingContext = PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def _hash(self, *values_to_hash: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        for value_to_hash in values_to_hash:
            digest.update(value_to_hash)
        return digest.finalize()

    def _b64(self, bytes_to_encode: bytes) -> str:
        return b64encode(bytes_to_encode).decode()

    def _proxy_api(self, path: str, query: str | None) -> JSON:
        body = JSON({"method": "GET", "path": path, "query": query}).dumps().replace("/", r"\/")
        iv = token_bytes(16)
        encrypted = self._encrypt(self._proxy_key, body, iv) + iv
        hmac = HMAC(self._hmac_key, hashes.SHA512())
        hmac.update(encrypted)
        hashed = hmac.finalize()
        headers = {"Authorization": f"Bearer {self._access_token}"}
        response = post("https://api.mobile.ing.nl/proxy", encrypted + hashed, headers=headers)
        response.raise_for_status()
        encrypted, iv = self._split(response.content[:-64], -16)
        json_body = JSON.loads(self._decrypt(self._proxy_key, encrypted, iv))
        if json_body["status"].int not in range(200, 400):
            raise ValueError(body)
        return JSON.loads(b64decode(json_body["content"].str))

    def _auth_api(self, endpoint: str, envelope_key: str, query: dict[str, str] | None = None, proxy: bool = False, json: JSON | None = None) -> JSON:
        method = "POST" if json else "GET"
        request = self._session.prepare_request(Request(method, f"https://services.ing.nl/mb/authentication/{endpoint}", params=query, json=json.body if json else None))
        if proxy:
            parsed = urlparse(not_none(request.url))
            response = self._proxy_api(parsed.path, parsed.query)
        else:
            full_response = self._session.send(request)
            full_response.raise_for_status()
            response = JSON.response(full_response)
        response = response["securityProxyResponseEnvelope"]
        if response["resultCode"].str != "OK":
            raise ValueError(response)
        self._session.params = {"session": response["session"].str}
        encoded_response = response["apiResponse"].str
        if self._auth_key is not None:
            encoded_response = self._decrypt(self._auth_key, bytes.fromhex(encoded_response)).decode()
        return JSON.loads(encoded_response)[envelope_key]

    def _fetch_link(self, entity: JSON, rel: str) -> JSON | None:
        filter_func: Callable[[JSON], bool] = lambda link: link["rel"].str == rel
        link = next(filter(filter_func, entity["_links"]), None)
        if link is not None:
            href = link["href"].str
            path, query = href.split("?") if "?" in href else (href, None)
            return self._proxy_api(not_none(path), query)
        return None

    def _beautify_card_payment(self, json: JSON, transaction: Transaction) -> None:
        if json["type"]["id"].str == "BA":
            transaction.lines[0].description = transaction.description
            lines = json["subjectLines"]
            line = lines[1].str
            line = not_none(_after_prefix(line, "Pasvolgnr: "))
            card, date = line.split(" ", 1)
            transaction.number = int(card)
            transaction.date = datetime.strptime(date, "%d-%m-%Y %H:%M").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
            transaction.description = lines[2].str

    def _beautify_omschrijving(self, json: JSON, transaction: Transaction) -> None:
        if json["type"]["id"].str in {"IC", "OV", "ID", "GT"}:
            transaction.lines[0].description = transaction.description
            transaction.description = ""
            decription_goes_on = False
            for line_json in json["subjectLines"]:
                line = line_json.str
                if suffix := _after_prefix(line, "Omschrijving: "):
                    transaction.description = suffix.rstrip()
                    decription_goes_on = True
                elif line.startswith("IBAN: "):
                    decription_goes_on = False
                elif date_str := _after_prefix(line, "Datum/Tijd: "):
                    transaction.date = datetime.strptime(date_str, "%d-%m-%Y %H:%M:%S").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
                elif decription_goes_on:
                    transaction.description = f"{transaction.description} {line.rstrip()}"

    def _beautify_credit_card(self, json: JSON, transaction: Transaction) -> None:
        if json["type"]["id"].str == "AFSCHRIJVING":
            transaction.payee = json["merchant"]["name"].str
            if source_amount := json.get("sourceAmount"):
                fee = json["fee"]["value"].decimal
                transaction.lines[0].amount -= fee
                transaction.lines[0].description = f"{source_amount['value']} {source_amount['currency']} * {json['exchangeRate']}"
                transaction.lines.append(Line(transaction.lines[0].account, fee, Category.FEE, "Currency exchange fee"))

    def _beautify_savings_transfer(self, transaction: Transaction) -> None:
        if suffix := _after_prefix(not_none(transaction.payee), "Oranje spaarrekening "):
            transaction.lines[0].counter_account_number = suffix

    def _beautify_aflossing(self, agreement: JSON, json: JSON, transaction: Transaction) -> None:
        if json["type"]["id"].str == "MAANDELIJKSE AFLOSSING":
            transaction.lines[0].ext_account_number = agreement["id"].str[:3]
            transaction.lines[0].counter_account_number = agreement["referenceAgreement"]["number"].str

    def _beautify_creditcard_incasso(self, transaction: Transaction) -> None:
        if suffix := _after_prefix(not_none(transaction.payee), "INCASSO CREDITCARD ACCOUNTNR "):
            transaction.lines[0].counter_account_number = suffix

    def _beautify_hypotheken(self, transaction: Transaction) -> None:
        if transaction.payee == "ING Hypotheken":
            transaction.lines[0].counter_account_number = re_groups(re.search("INZAKE HYP.NR. (.+)", not_none(transaction.description)))[0]

    def _beautify_ing_betaalverzoek(self, transaction: Transaction) -> None:
        if transaction.payee == "ING Bank NV Betaalverzoek":
            if transaction.lines[0].amount < 0:
                transaction.payee, transaction.description = re_groups(re.match(r" (.+)[A-Z]{2}\d{2}[A-Z]{4}\d{10} \d+ (.+) ING Betaalverzoek", not_none(transaction.description)))
            else:
                transaction.payee, transaction.description = re_groups(re.match(r"Betaling van (.+) [A-Z]{2}\d{2}[A-Z]{4}\d{10} (.+)", not_none(transaction.description)))

    def _beautify_abnamro_tikkie(self, transaction: Transaction) -> None:
        if transaction.payee == "ABN AMRO Bank NV":
            transaction.payee = re_groups(re.match(r"\d+ \d+ (.+) [A-Z]{2}\d{2}[A-Z]{4}\d{10}", not_none(transaction.description)))[0]
            transaction.description = None
        if transaction.payee == "AAB INZ RETAIL IDEAL BET":
            transaction.description, transaction.payee = re_groups(re.match(r"Tikkie ID \d+, (.+), (.+), [A-Z]{2}\d{2}[A-Z]{4}\d{10}", not_none(transaction.description)))

    def _beautify_sns_betaalverzoek(self, transaction: Transaction) -> None:
        if transaction.payee == "SNS Betaalverzoek":
            transaction.payee, transaction.description = re_groups(re.match(r"(.+) \d+ [A-Z]{2}\d{2}[A-Z]{4}\d{10} (.+)", not_none(transaction.description)))

    def _beautify_payment_processors(self, transaction: Transaction) -> None:
        assert transaction.payee
        if payee := _after_prefix(transaction.payee, "iZ "):
            transaction.payee = payee.removeprefix("*")
            transaction.description = None
        elif payee := _after_prefix(transaction.payee, "ZTL"):
            transaction.payee = payee
            transaction.description = None
        elif payee := _after_prefix(transaction.payee, "CCV"):
            transaction.payee = payee
            transaction.description = None
        elif payee := _before_suffix(transaction.payee, " via Mollie"):
            transaction.payee = payee
            transaction.description = re_groups(re.match(r"\w+ \d+ (.*)", not_none(transaction.description)))[0]
        elif payee := _before_suffix(transaction.payee, " via Ingenico"):
            transaction.payee = payee
            transaction.description = None
        elif payee := _before_suffix(transaction.payee, " via MultiSafepay"):
            transaction.payee = payee
            transaction.description = None

    def _beautify_thuisbezorgd(self, transaction: Transaction) -> None:
        if transaction.payee == "Thuisbezorgd.nl via Takeaway.com":
            transaction.payee = "Thuisbezorgd.nl"
            transaction.description = re_groups(re.match(".* bestelling (.*) via", not_none(transaction.description)))[0]
        elif transaction.payee == "Thuisbezorgd.nl ThuisB":
            transaction.payee = "Thuisbezorgd.nl"

    def _beautify_kosten(self, account: Account, transaction: Transaction) -> None:
        if not_none(transaction.payee).startswith("Kosten "):
            transaction.payee = account.bank_name
            transaction.description = " ".join(re_groups(re.match("(.*) {2,}(.*) {2,}.*", not_none(transaction.description))))
            transaction.lines[0].category = Category.FEE

    def _beautify_amazon(self, transaction: Transaction) -> None:
        payee = not_none(transaction.payee)
        if payee in {"Amazon EU SARL", "Amazon.de", "AMAZON PAYMENTS EUROPE S.C.A.", "AMAZON EU S.A R.L., NIEDERLASSUNG DEUTSCHLAND"} or payee.startswith("AMZN Mktp DE"):
            transaction.payee = "Amazon"
            transaction.lines[0].ext_account_number = "*"
            transaction.lines[0].counter_account_number = "amazon"

    def _beautify_paypal(self, transaction: Transaction) -> None:
        if transaction.payee == "PayPal (Europe) S.a.r.l. et Cie., S.C.A." and not_none(transaction.payee).startswith("PAYPAL *"):
            transaction.payee = "PayPal"
            transaction.lines[0].ext_account_number = "*"
            transaction.lines[0].counter_account_number = "paypal"


def _match_mortgage_payment(account: Account, transaction: Transaction, line: Line) -> Transaction:
    monthly_interest_rate = not_none(account.interest_rate) / 12
    repayment = ((-not_none(account.monthly_payment) - account.initial_balance * monthly_interest_rate) / (monthly_interest_rate + 1) * 100).to_integral_value(ROUND_DOWN) / 100
    interest = line.amount - repayment
    return Transaction(
        transaction.date,
        account.bank_name,
        None,
        [
            Line(account, -line.amount, counter_account_number=line.account.number),
            Line(account, interest, Category.INTEREST, "Interest", tax_year=transaction.date.year),
        ],
    )
