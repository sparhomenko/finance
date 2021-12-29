from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum, auto, unique
from itertools import chain
from typing import Callable
from zoneinfo import ZoneInfo

BEGINNING = datetime(2021, 11, 1, tzinfo=ZoneInfo("Europe/Amsterdam"))


@dataclass
class Account:
    @unique
    class Type(Enum):
        CURRENT = auto()
        CREDIT_CARD = auto()
        SAVINGS = auto()
        LIABILITY = auto()
        PROPERTY = auto()
        MORTGAGE = auto()

    number: str
    name: str
    type: Type
    initial_balance: Decimal
    bank_name: str
    bank_site: str | None
    routing_number: str | None = None
    description: str | None = None
    interest_rate: Decimal | None = None
    monthly_payment: Decimal | None = None
    group: str | None = None
    matcher: Callable[["Account", "Transaction", "Transaction.Line"], "Transaction"] | None = None
    tax_base: Decimal = field(default_factory=lambda: Decimal(0))

    def __str__(self) -> str:
        return f"{self.number}"

    def complete(self) -> None:
        if self.matcher:
            for match in list(chain.from_iterable(matches.values())):
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
class Transaction:
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
        amount: Decimal
        category: Category | None = None
        description: str | None = None
        counter_account_number: str | None = None
        counter_account: Account | None = None
        ext_account_number: str | None = None
        tax_year: int | None = None

        def __str__(self) -> str:
            return f"{self.amount:8} {self.description or '':8.8}"

        def merge(self, other: Transaction.Line) -> None:
            assert self.amount == -other.amount
            assert self.counter_account_number == other.get_ext_account_number()
            assert other.counter_account_number == self.get_ext_account_number()
            self.counter_account = other.account
            # TODO: should we merge descriptions?

        def get_ext_account_number(self) -> str:
            return self.ext_account_number or self.account.number

    date: datetime
    payee: str | None
    description: str | None
    lines: list[Line]
    cleared: bool = True
    number: int | None = None

    def __str__(self) -> str:
        return f"{self.date.strftime('%Y-%m-%d %H:%M:%S')} {self.payee:15.15} [{', '.join(map(str, self.lines)):100.100}]"

    def merge(self, other: Transaction) -> None:
        self.date = min(self.date, other.date)
        self.lines += other.lines
        if len(self.lines) == 1:
            self.payee = None

    def complete(self, must_have: bool = False) -> bool:
        if self.date < BEGINNING and not must_have:
            return False
        for line in list(self.lines):
            line.account.initial_balance -= line.amount
            if line.counter_account_number:
                match_list = matches.get((line.counter_account_number, line.get_ext_account_number(), -line.amount), [])
                close_matches: list[tuple[timedelta, MatchCandidate]] = [(delta, match) for match in match_list if (delta := abs(match[0].date - self.date)) < timedelta(weeks=3)]
                if close_matches:
                    match = min(close_matches, key=lambda match: match[0])[1]  # type: ignore
                    match_list.remove(match)
                    matched_transaction, matched_line = match
                    line.merge(matched_line)
                    matched_transaction.lines.remove(matched_line)
                    self.merge(matched_transaction)
                    transactions.remove(matched_transaction)
                else:
                    matches[(line.get_ext_account_number(), line.counter_account_number, line.amount)].append((self, line))
            if line.counter_account is None and line.category is None:
                for rule in Transaction.Line.RULES.items():
                    if self.payee and re.match(rule[0], self.payee):
                        line.category = rule[1]
                        break
        transactions.append(self)
        return True


transactions: list[Transaction] = []
MatchKey = tuple[str, str, Decimal]
MatchCandidate = tuple[Transaction, Transaction.Line]
matches: dict[MatchKey, list[MatchCandidate]] = defaultdict(list)
