from datetime import datetime, timedelta

import requests
from requests.auth import HTTPBasicAuth

from finance.core import BEGINNING, Account, AccountType, Amount, Line
from finance.core import Loader as BaseLoader
from finance.core import Transaction
from finance.typesafe import JSON


class Loader(BaseLoader):
    def __init__(self, client_id: str, client_secret: str):
        self._url = "https://api-m.paypal.com"
        token = JSON.response(requests.post(f"{self._url}/v1/oauth2/token", data={"grant_type": "client_credentials"}, auth=HTTPBasicAuth(client_id, client_secret)))["access_token"]
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Bearer {token}"

    def load(self) -> list[Account]:
        account = Account("paypal", "PayPal", AccountType.CURRENT, Amount(), "PayPal", "https://paypal.com")
        transactions: dict[str, Transaction] = {}
        start = BEGINNING
        while start < datetime.now(BEGINNING.tzinfo):
            end = start + timedelta(days=31)
            entries = JSON.response(
                self._session.get(
                    f"{self._url}/v1/reporting/transactions",
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
                amount = Amount(transaction_info["transaction_amount"]["value"].decimal)
                top_up = transaction_info["transaction_event_code"].str in {"T0300", "T0700"}
                transaction = transactions.setdefault(transaction_info["paypal_reference_id" if top_up else "transaction_id"].str, Transaction(date, None, None, []))
                assert transaction.date == date
                if top_up:
                    transaction.lines.insert(0, Line(account, amount, counter_account_number="*"))
                else:
                    transaction.payee = entry["payer_info"]["payer_name"]["alternate_full_name"].str
                    if lines := entry["cart_info"].get("item_details"):
                        accumulated = Amount()
                        salex_tax = Amount(-transaction_info["sales_tax_amount"]["value"].decimal) if "sales_tax_amount" in transaction_info else Amount()
                        shipping = Amount(-transaction_info["shipping_amount"]["value"].decimal) if "shipping_amount" in transaction_info else Amount()
                        fees = salex_tax + shipping
                        fee_coefficient = Amount(1) + fees / (amount - fees)
                        for line in lines:
                            item_amount = Amount(round(-line["item_amount"]["value"].decimal * fee_coefficient.amount, 2))
                            accumulated += item_amount
                            description = line.get("item_name")
                            transaction.lines.append(Line(account, item_amount, None, description.str if description else None))
                        assert accumulated == amount
                    else:
                        transaction.lines.append(Line(account, amount))
        for transaction in transactions.values():
            transaction.complete()
        return [account]
