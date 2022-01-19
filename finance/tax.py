from typing import Callable

from finance.core import Account, AccountType, Amount, Line
from finance.core import Loader as BaseLoader
from finance.core import Transaction, transactions
from finance.woz import Property


class Loader(BaseLoader):
    def __init__(self, house: Property):
        self._house = house

    def load(self) -> list[Account]:
        return [Account("NL36INGB0003445588", "Belastingdienst", AccountType.LIABILITY, Amount(), "Belastingdienst", "https://www.belastingdienst.nl/", matcher=_match_any)]

    def calculate(self) -> Amount:
        year = 2021

        box1 = Amount()
        for transaction in transactions:
            for line in transaction.lines:
                if line.tax_year == year:
                    box1 += line.amount

        closest_year: Callable[[tuple[int, Amount]], int] = lambda house_value: abs(house_value[0] - year)
        woz = min(self._house.valuation.items(), key=closest_year)[1]
        assert 75000 < woz < 1110000
        notional_rental_value = woz * Amount("0.005")
        box1 += notional_rental_value

        assert box1 > 68508
        return Amount("0.371") * 68508 + (box1 - 68508) * Amount("0.495")


def _match_any(account: Account, matching_transaction: Transaction, matching_line: Line) -> Transaction:
    return Transaction(
        matching_transaction.date,
        matching_transaction.payee,
        matching_transaction.description,
        [
            Line(account, -matching_line.amount, counter_account_number=matching_line.account.number),
        ],
    )
