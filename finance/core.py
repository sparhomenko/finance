from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum, auto, unique
from itertools import chain
from typing import Callable, Final
from zoneinfo import ZoneInfo

BEGINNING: Final = datetime(2021, 11, 1, tzinfo=ZoneInfo("Europe/Amsterdam"))


@unique
class AccountType(Enum):
    CURRENT = auto()
    CREDIT_CARD = auto()
    SAVINGS = auto()
    LIABILITY = auto()
    PROPERTY = auto()
    MORTGAGE = auto()


class Amount:
    def __init__(self, amount: int | str | Decimal = 0, currency: str = "EUR"):
        self.amount = Decimal(amount)
        self.currency = currency

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Amount):
            return self.amount == other.amount and self.currency == other.currency
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.amount, self.currency))

    def __neg__(self) -> Amount:
        return Amount(-self.amount, self.currency)

    def __add__(self, other: _Amount) -> Amount:
        return Amount(self.amount + self._as_amount(other), self.currency)

    def __sub__(self, other: _Amount) -> Amount:
        return Amount(self.amount - self._as_amount(other), self.currency)

    def __mul__(self, other: _Amount) -> Amount:
        return Amount(self.amount * self._as_amount(other), self.currency)

    def __truediv__(self, other: _Amount) -> Amount:
        return Amount(self.amount / self._as_amount(other), self.currency)

    def __lt__(self, other: _Amount) -> bool:
        return self.amount < self._as_amount(other)

    def __gt__(self, other: _Amount) -> bool:
        return self.amount > self._as_amount(other)

    def _as_amount(self, other: _Amount) -> int | Decimal:
        if isinstance(other, Amount):
            assert self.currency == other.currency
            return other.amount
        return other


_Amount = int | Decimal | Amount


@dataclass
class Account:
    number: str
    name: str
    type: AccountType
    initial_balance: Amount
    bank_name: str
    bank_site: str | None
    routing_number: str | None = None
    description: str | None = None
    interest_rate: Decimal | None = None
    monthly_payment: Decimal | None = None
    group: str | None = None
    matcher: Callable[[Account, Transaction, Line], Transaction] | None = None
    tax_base: Decimal = field(default_factory=lambda: Decimal(0))

    def __str__(self) -> str:
        return f"{self.number}"

    def complete(self) -> None:
        if self.matcher:
            for match in list(chain.from_iterable(_matches.values())):
                matched_transaction, matched_line = match
                if matched_line.counter_account_number == self.number:
                    if transaction := self.matcher(self, matched_transaction, matched_line):
                        transaction.complete(must_have=True)


@unique
class Category(Enum):
    CHILDREN = auto()
    ENTERTAINMENT = auto()
    FEE = auto()
    GROCERIES = auto()
    HEALTHCARE = auto()
    HOME = auto()
    INSURANCE = auto()
    INTEREST = auto()
    INTEREST_INCOME = auto()
    PENSION_CONTRIBUTION = auto()
    PERSONAL_CARE = auto()
    RESTAURANTS = auto()
    SALARY = auto()
    TAX = auto()
    TRANSPORT = auto()
    UTILITIES = auto()


@dataclass
class Line:
    RULES = {
        "Adobe Systems Software Ireland LTD": Category.ENTERTAINMENT,
        "Bagel  Beans .*": Category.RESTAURANTS,
        "Basic Fit Nederland B.V.": Category.PERSONAL_CARE,
        "Cafe Goos": Category.RESTAURANTS,
        "circle lunchro.*": Category.RESTAURANTS,
        "CLASSPASS.COM.*": Category.PERSONAL_CARE,
        "CZ Groep Zorgverzekeraar": Category.HEALTHCARE,
        "De Elfentuin": Category.CHILDREN,
        "Feduzzis Mercato": Category.GROCERIES,
        "Getir": Category.GROCERIES,
        "GM Gelato Natural": Category.RESTAURANTS,
        "Greenwheels": Category.TRANSPORT,
        "Head Enlight Distr": Category.PERSONAL_CARE,
        "HELLOFRESH": Category.GROCERIES,
        "NABU CASA - HA CLOUD": Category.HOME,
        "NATIONALE-NEDERLANDEN": Category.INSURANCE,
        "O DONNELS": Category.RESTAURANTS,
        "Park Kiosk BEA": Category.RESTAURANTS,
        "PARTOU BV": Category.CHILDREN,
        "Patisserie Tout": Category.GROCERIES,
        "QUIP NYC INC.": Category.HEALTHCARE,
        "Rente": Category.INTEREST_INCOME,
        "Ridammerhoeve": Category.RESTAURANTS,
        "Rocket Delivery B.V.": Category.RESTAURANTS,
        "Russian Gymnasium Amsterdam": Category.CHILDREN,
        "SHURGARD NEDERLAND B.V.": Category.UTILITIES,
        "Sophie Eats": Category.RESTAURANTS,
        "Spotify AB": Category.ENTERTAINMENT,
        "T-MOBILE NETHERLANDS B.V.": Category.UTILITIES,
        "TAF BV": Category.INSURANCE,
        "TELE2": Category.UTILITIES,
        "Thuisbezorgd.nl": Category.RESTAURANTS,
        "TLS BV inz. OV-Chipkaart": Category.TRANSPORT,
        "TrompkaasMaasstraat": Category.GROCERIES,
        "Van Vessem  Le Pati": Category.GROCERIES,
        "Vattenfall Klantenservice N.V.": Category.UTILITIES,
        "VVE Geleenstraat 31 - 33": Category.UTILITIES,
        "Waternet/Gem. Amsterdam": Category.UTILITIES,
        "ZIGGO SERVICES BV": Category.UTILITIES,
        r"ALBERT HEIJN \d+": Category.GROCERIES,
        r"Coop Supermarkt \d+": Category.GROCERIES,
        r"Gall  Gall \d+": Category.GROCERIES,
        r"UBER\s+\*EATS.*": Category.RESTAURANTS,
    }

    account: Account
    amount: Amount
    category: Category | None = None
    description: str | None = None
    counter_account_number: str | None = None
    counter_account: Account | None = None
    _ext_account_number: str | None = None
    tax_year: int | None = None

    def __str__(self) -> str:
        return f"{self.amount:8} {self.description or '':8.8}"

    def merge(self, other: Line) -> None:
        assert self.amount == -other.amount
        assert self.counter_account_number == other.ext_account_number
        assert other.counter_account_number == self.ext_account_number
        self.counter_account = other.account  # noqa: WPS601 - https://github.com/wemake-services/wemake-python-styleguide/issues/1926
        # TODO: should we merge descriptions?

    @property
    def ext_account_number(self) -> str:
        return self._ext_account_number or self.account.number

    @ext_account_number.setter
    def ext_account_number(self, ext_account_number: str) -> None:
        self._ext_account_number = ext_account_number  # noqa: WPS601 - https://github.com/wemake-services/wemake-python-styleguide/issues/1926


@dataclass
class Transaction:
    date: datetime
    payee: str | None
    description: str | None
    lines: list[Line]
    cleared: bool = True
    number: int | None = None

    def __str__(self) -> str:
        return f"{self.date.strftime('%Y-%m-%d %H:%M:%S')} {self.payee:40.40} ({self.description:40.40}) [{', '.join(map(str, self.lines)):40.40}]"

    def complete(self, must_have: bool = False) -> bool:
        if self.date < BEGINNING and not must_have:
            return False
        for line in list(self.lines):
            line.account.initial_balance -= line.amount
            if line.counter_account_number:
                match_list = _matches.get((line.counter_account_number, line.ext_account_number, -line.amount), [])
                close_matches: list[tuple[timedelta, _MatchCandidate]] = [(delta, match) for match in match_list if (delta := abs(match[0].date - self.date)) < timedelta(weeks=3)]
                if close_matches:
                    match = min(close_matches, key=lambda match: match[0])[1]  # type: ignore
                    match_list.remove(match)
                    matched_transaction, matched_line = match
                    line.merge(matched_line)
                    matched_transaction.lines.remove(matched_line)
                    self._merge(matched_transaction)
                    transactions.remove(matched_transaction)
                else:
                    _matches[line.ext_account_number, line.counter_account_number, line.amount].append((self, line))
            if line.counter_account is None and line.category is None:
                for rule in Line.RULES.items():
                    if self.payee and re.match(rule[0], self.payee):
                        line.category = rule[1]
                        break
        transactions.append(self)
        return True

    def _merge(self, other: Transaction) -> None:
        self.date = min(self.date, other.date)
        self.lines += other.lines
        if len(self.lines) == 1:
            self.payee = None


class Loader(ABC):
    @abstractmethod
    def load(self) -> list[Account]:
        """No body for an abstract class"""


def load_accounts(loaders: list[Loader]) -> list[Account]:
    accounts: list[Account] = sum([loader.load() for loader in loaders], [])
    for account in accounts:
        account.complete()
    return accounts


transactions: list[Transaction] = []
_MatchKey = tuple[str, str, Amount]
_MatchCandidate = tuple[Transaction, Line]
_matches: dict[_MatchKey, list[_MatchCandidate]] = defaultdict(list)
