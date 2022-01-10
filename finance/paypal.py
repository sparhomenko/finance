from datetime import datetime, timedelta
from decimal import Decimal

import requests
from requests.auth import HTTPBasicAuth

from finance.core import BEGINNING, Account, Transaction
from finance.typesafe import JSON


class Loader:
    def __init__(self, client_id: str, client_secret: str):
        self.url = "https://api-m.paypal.com"
        token = JSON.response(requests.post(f"{self.url}/v1/oauth2/token", data={"grant_type": "client_credentials"}, auth=HTTPBasicAuth(client_id, client_secret)))["access_token"]
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

    def load(self) -> list[Account]:
        account = Account("paypal", "PayPal", Account.Type.CURRENT, Decimal(0), "PayPal", "https://paypal.com")
        transactions: dict[str, Transaction] = {}
        start = BEGINNING
        while start < datetime.now(BEGINNING.tzinfo):
            end = start + timedelta(days=31)
            entries = JSON.response(
                self.session.get(
                    f"{self.url}/v1/reporting/transactions",
                    params={
                        "start_date": start.isoformat(timespec="milliseconds"),
                        "end_date": end.isoformat(timespec="milliseconds"),
                        "fields": "transaction_info,payer_info,cart_info",
                    },
                ),
            )["transaction_details"]
            start = end

            for entry in entries:
                transaction_info = entry["transaction_info"]
                assert transaction_info["transaction_amount"]["currency_code"].str == "EUR"
                date = transaction_info["transaction_initiation_date"].strptime("%Y-%m-%dT%H:%M:%S%z").astimezone(BEGINNING.tzinfo)
                amount = transaction_info["transaction_amount"]["value"].decimal
                top_up = transaction_info["transaction_event_code"].str in {"T0300", "T0700"}
                transaction = transactions.setdefault(transaction_info["paypal_reference_id" if top_up else "transaction_id"].str, Transaction(date, None, None, []))
                assert transaction.date == date
                if top_up:
                    transaction.lines.insert(0, Transaction.Line(account, amount, counter_account_number="*"))
                else:
                    transaction.payee = entry["payer_info"]["payer_name"]["alternate_full_name"].str
                    if lines := entry["cart_info"].get("item_details"):
                        accumulated = Decimal(0)
                        salex_tax = -transaction_info["sales_tax_amount"]["value"].decimal if "sales_tax_amount" in transaction_info else Decimal(0)
                        shipping = -transaction_info["shipping_amount"]["value"].decimal if "shipping_amount" in transaction_info else Decimal(0)
                        fees = salex_tax + shipping
                        fee_coefficient = 1 + fees / (amount - fees)
                        for line in lines:
                            item_amount = round(-line["item_amount"]["value"].decimal * fee_coefficient, 2)
                            accumulated += item_amount
                            description = line.get("item_name")
                            transaction.lines.append(Transaction.Line(account, item_amount, None, description.str if description else None))
                        assert accumulated == amount
                    else:
                        transaction.lines.append(Transaction.Line(account, amount))
        for transaction in transactions.values():
            transaction.complete()
        return [account]
