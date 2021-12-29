from decimal import Decimal
from typing import Callable

from core import Account, Transaction, transactions
from woz import Property


class Loader:
    def __init__(self, house: Property):
        self.house = house

    def load(self) -> list[Account]:
        return [Account("NL36INGB0003445588", "Belastingdienst", Account.Type.LIABILITY, Decimal(0), "Belastingdienst", "https://www.belastingdienst.nl/", matcher=match_any)]

    def calculate(self) -> Decimal:
        year = 2021

        box1 = Decimal(0)
        for transaction in transactions:
            for line in transaction.lines:
                if line.tax_year == year:
                    box1 += line.amount

        closest_year: Callable[[tuple[int, Decimal]], int] = lambda item: abs(item[0] - year)
        woz = min(self.house.value.items(), key=closest_year)[1]
        assert 75000 < woz < 1110000
        notional_rental_value = woz * Decimal("0.005")
        box1 += notional_rental_value

        assert box1 > 68508
        return 68508 * Decimal("0.371") + (box1 - 68508) * Decimal(0.495)


def match_any(account: Account, matching_transaction: Transaction, matching_line: Transaction.Line) -> Transaction:
    return Transaction(
        matching_transaction.date,
        matching_transaction.payee,
        matching_transaction.description,
        [
            Transaction.Line(account, -matching_line.amount, counter_account_number=matching_line.account.number),
        ],
    )
