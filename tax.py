from decimal import Decimal

from core import Account, Transaction, transactions


class Loader:
    def __init__(self, house):
        self.house = house

    def load(self):
        return [Account("NL36INGB0003445588", "Belastingdienst", Account.Type.LIABILITY, Decimal(0), "Belastingdienst", "https://www.belastingdienst.nl/", matcher=match_any)]

    def calculate(self):
        year = 2021

        box1 = Decimal(0)
        for transaction in transactions:
            for line in transaction.lines:
                if line.tax_year == year:
                    box1 += line.amount

        woz = min(self.house.value.items(), key=lambda item: abs(item[0] - year))[1]
        assert 75000 < woz < 1110000
        notional_rental_value = woz * Decimal("0.005")
        box1 += notional_rental_value

        assert box1 > 68508
        return 68508 * Decimal("0.371") + (box1 - 68508) * Decimal(0.495)


def match_any(account, matching_transaction, matching_line):
    return Transaction(matching_transaction.date, account.bank_name, None, [Transaction.Line(account, -matching_line.amount, counter_account_number=matching_line.account.number)])
