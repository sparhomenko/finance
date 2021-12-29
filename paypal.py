from datetime import datetime, timedelta
from decimal import Decimal

import requests
from requests.auth import HTTPBasicAuth

from core import BEGINNING, Account, Transaction


class Loader:
    def __init__(self, client_id, client_secret):
        self.url = "https://api-m.paypal.com"
        token = requests.post(f"{self.url}/v1/oauth2/token", data={"grant_type": "client_credentials"}, auth=HTTPBasicAuth(client_id, client_secret)).json()["access_token"]
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

    def load(self):
        account = Account("paypal", "PayPal", Account.Type.CURRENT, Decimal(0), "PayPal", "https://paypal.com")
        transactions = {}
        start = BEGINNING
        while start < datetime.now(BEGINNING.tzinfo):
            end = start + timedelta(days=31)
            entries = self.session.get(
                f"{self.url}/v1/reporting/transactions",
                params={
                    "start_date": start.isoformat(timespec="milliseconds"),
                    "end_date": end.isoformat(timespec="milliseconds"),
                    "fields": "transaction_info,payer_info,cart_info",
                },
            ).json()["transaction_details"]
            start = end

            for entry in entries:
                info = entry["transaction_info"]
                assert info["transaction_amount"]["currency_code"] == "EUR"
                date = datetime.strptime(info["transaction_initiation_date"], "%Y-%m-%dT%H:%M:%S%z").astimezone(BEGINNING.tzinfo)
                amount = Decimal(info["transaction_amount"]["value"])
                top_up = info["transaction_event_code"] in {"T0300", "T0700"}
                transaction = transactions.setdefault(info["paypal_reference_id" if top_up else "transaction_id"], Transaction(date, None, None, [None]))
                assert transaction.date == date
                if top_up:
                    transaction.lines[0] = Transaction.Line(account, amount, counter_account_number="*")
                else:
                    transaction.payee = entry["payer_info"]["payer_name"]["alternate_full_name"]
                    if items := entry["cart_info"].get("item_details", None):
                        accumulated = 0
                        salex_tax = -Decimal(info.get("sales_tax_amount", {}).get("value", 0))
                        shipping = -Decimal(info.get("shipping_amount", {}).get("value", 0))
                        fees = salex_tax + shipping
                        fee_coefficient = 1 + fees / (amount - fees)
                        for item in items:
                            item_amount = round(-Decimal(item["item_amount"]["value"]) * fee_coefficient, 2)
                            accumulated += item_amount
                            transaction.lines.append(Transaction.Line(account, item_amount, None, item.get("item_name", None)))
                        assert accumulated == amount
                    else:
                        transaction.lines.append(Transaction.Line(account, amount))
        for transaction in transactions.values():
            transaction.complete()
        return [account]
