import re
from base64 import b64encode
from types import MappingProxyType
from typing import Final
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from requests import Session

from finance.core import BEGINNING, Account, AccountType, Amount, Line
from finance.core import Loader as BaseLoader
from finance.core import Transaction
from finance.typesafe import JSON, JSONObject, re_groups

_PUBLIC_KEY: Final = serialization.load_pem_public_key(
    b"""
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArm6Tt3NaZcmHZgBXAqE5A4MS+be76n4ObLC1PBlD5JOroH0YlX0E
/lkYZMtYzGODlLSm1pR/kr0ta0sK++n5OtH1Vz+GayQ6GZw6VdWFg0FnQQOL7p8U
s/vJ98QREZ4pqQc9YCuLEuo2z0eTNu9bTF3uC921qpUM8+l2EWTqFDJrvxa296QJ
z4/EewY/xgA8A8bwLpzW6jTeMpSRCE+q4NnTojkM1jUDqzDaXCorsGmcb8XOo7DX
z/8YsH3JUrs3OADIiQcIRPfUdbNDGATNwFEF4zV+12GgICAiA4o0v6xz45/KW2Bw
ZP7JY0P6NnYdOmWoq96gRs84FfIF47d8WQIDAQAB
-----END RSA PUBLIC KEY-----""",
)
_PAGE_SIZE: Final = 100
_PAYEES: Final = MappingProxyType(
    {
        'РУП "МИНСКЭНЕРГО" филиал "Энергосбыт" Минское отделение по сбыту электроэнергии': "Минскэнерго",
        "Гродненский филиал РУП БЕЛТЕЛЕКОМ": "Белтелеком",
        'Унитарное предприятие по оказанию услуг "A1"': "A1",
        'РУП "Белтелеком"': "Белтелеком",
        'ОАО "Небанковская кредитно-финансовая организация "ЕРИП"': "EРИП",
        "Комиссия банка": "Альфа-Банк Беларусь",
    },
)


class Loader(BaseLoader):
    def __init__(self, device_id: str, token: str):
        self.session = Session()
        self.session.headers["X-Client-App"] = "Android/8.4.5"
        self.session.headers["User-Agent"] = "okhttp/4.9.1"
        assert isinstance(_PUBLIC_KEY, rsa.RSAPublicKey)
        encrypted_device_id = b64encode(_PUBLIC_KEY.encrypt(device_id.encode(), padding.PKCS1v15())).decode()
        device_status = self._api("CheckDeviceStatus", {"deviceId": encrypted_device_id})
        self.session.headers["X-Session-ID"] = device_status["sessionId"].str
        login = self._api("LoginByToken", {"token": b64encode(token.encode()).decode(), "tokenType": "PIN", "deviceId": encrypted_device_id})
        assert login["status"].str == "OK"
        self._api("Desktop", {"deviceId": device_id})

    def load(self) -> list[Account]:
        accounts = []
        for product in self._api("Products", {"type": "ACCOUNT"})["items"]:
            product_id = product["id"].str
            account = Account(
                product["info"]["description"].str.replace(" ", ""),
                product["info"]["title"].str,
                AccountType.CURRENT,
                Amount(product["info"]["amount"]["amount"].decimal, product["info"]["amount"]["currency"].str),
                "Альфа-Банк Беларусь",
                "https://www.alfabank.by/",
                "ALFABY2X",
            )
            offset = 0
            total = 999999
            request: JSONObject = {"objectId": product_id, "type": "ACCOUNT", "pageSize": _PAGE_SIZE}
            more = True
            while more and offset < total:
                request["offset"] = offset
                response = self._api("History", request)
                total = response["totalItems"].int
                offset += _PAGE_SIZE
                for json in response["items"]:
                    date = json["date"].strptime("%Y%m%d%H%M%S").replace(tzinfo=ZoneInfo("Europe/Minsk"))
                    if date < BEGINNING:
                        more = False
                    else:
                        payee = json["info"]["title"].str
                        description = json["description"].str
                        line_description = None
                        if transaction_id := json.get("id"):
                            details = self._api("History/Receipt", {"transactionId": transaction_id.str})
                            assert details["status"].str == "OK"
                            if receipt := details["receipt"].str:
                                lines: dict[str, str] = {}
                                for line in receipt.split("<br>"):
                                    parts = line.split(": ", 1)
                                    if len(parts) == 1:
                                        key = next(reversed(lines.keys()))
                                        lines[key] = f"{lines[key]} {line}"
                                    else:
                                        assert len(parts) == 2
                                        lines[parts[0].rstrip(' "')] = parts[1].lstrip()
                                description = "; ".join([": ".join(parts) for parts in lines.items()])
                                if receiver := lines.get("Получатель платежа"):
                                    match = re_groups(re.match('"(.*)", УНП .* БИК [A-Z0-9]+ (.*)', receiver))
                                    line_description = description
                                    payee, description = match
                                    if number := lines.get("Лицевой счет"):
                                        description = f"{description} {number}"
                                    if number := lines.get("Номер абонента"):
                                        description = f"{description} {number}"
                                    if number := lines.get("Номер телефона"):
                                        description = f"{description} {number}"
                                    if period := lines.get("Период"):
                                        description = f"{description} за {period}"
                        if payee_alias := _PAYEES.get(payee):
                            payee = payee_alias
                        amount = Amount(json["info"]["amount"]["amount"].decimal, json["info"]["amount"]["currency"].str)
                        Transaction(date, payee, description, [Line(account, amount, description=line_description)]).complete()
            accounts.append(account)
        return accounts

    def _api(self, endpoint: str, json: JSONObject) -> JSON:
        response = self.session.post(f"https://insync2.alfa-bank.by/mBank256/v28/{endpoint}", json=json)
        response.raise_for_status()
        return JSON.response(response)
