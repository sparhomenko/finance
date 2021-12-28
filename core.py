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

transactions = []
matches = defaultdict(list)


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
    bank_site: str
    routing_number: str = None
    description: str = None
    interest_rate: Decimal = None
    monthly_payment: Decimal = None
    group: str = None
    matcher: Callable[["Account", "Transaction", "Transaction.Line"], "Transaction"] = None
    tax_base: Decimal = field(default_factory=lambda: Decimal(0))

    def complete(self):
        if self.matcher:
            for match in list(chain.from_iterable(matches.values())):
                matched_transaction, matched_line = match
                if matched_line.counter_account_number == self.number:
                    if transaction := self.matcher(self, matched_transaction, matched_line):
                        transaction.complete(must_have=True)


@unique
class Category(Enum):
    CHILDREN = auto()
    FEE = auto()
    GROCERIES = auto()
    HEALTHCARE = auto()
    INSURANCE = auto()
    INTEREST = auto()
    INTEREST_INCOME = auto()
    PENSION_CONTRIBUTION = auto()
    PERSONAL_CARE = auto()
    RESTAURANTS = auto()
    SALARY = auto()
    TAX = auto()
    UTILITIES = auto()


@dataclass
class Transaction:
    @dataclass
    class Line:
        RULES = {
            "Bagel  Beans .*": Category.RESTAURANTS,
            "Basic Fit Nederland B.V.": Category.PERSONAL_CARE,
            "Cafe Goos": Category.RESTAURANTS,
            "circle lunchro.*": Category.RESTAURANTS,
            "CLASSPASS.COM.*": Category.PERSONAL_CARE,
            "CZ Groep Zorgverzekeraar": Category.HEALTHCARE,
            "De Elfentuin": Category.CHILDREN,
            "Getir": Category.GROCERIES,
            "Head Enlight Distr": Category.PERSONAL_CARE,
            "HELLOFRESH": Category.GROCERIES,
            "NATIONALE-NEDERLANDEN": Category.INSURANCE,
            "PARTOU BV": Category.CHILDREN,
            "Rente": Category.INTEREST_INCOME,
            "Rocket Delivery B.V.": Category.RESTAURANTS,
            "Russian Gymnasium Amsterdam": Category.CHILDREN,
            "SHURGARD NEDERLAND B.V.": Category.UTILITIES,
            "Sophie Eats": Category.RESTAURANTS,
            "T-MOBILE NETHERLANDS B.V.": Category.UTILITIES,
            "TELE2": Category.UTILITIES,
            "Thuisbezorgd.nl": Category.RESTAURANTS,
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
        category: Category = None
        description: str = None
        counter_account_number: str = None
        counter_account: Account = None
        ext_account_number: str = None
        tax_year: int = None

        def merge(self, other: "Transaction"):
            assert self.amount == -other.amount
            assert self.counter_account_number == other.get_ext_account_number()
            assert other.counter_account_number == self.get_ext_account_number()
            self.counter_account = other.account
            # TODO: should we merge descriptions?

        def get_ext_account_number(self):
            return self.ext_account_number or self.account.number

    date: datetime
    payee: str
    description: str
    lines: list[Line]
    cleared: bool = True
    number: int = None

    def merge(self, other):
        self.date = min(self.date, other.date)
        self.lines += other.lines
        if len(self.lines) == 1:
            self.payee = None

    def complete(self, must_have=False):
        if self.date < BEGINNING and not must_have:
            return False
        for line in list(self.lines):
            line.account.initial_balance -= line.amount
            if line.counter_account_number:
                match_list = matches.get((line.counter_account_number, line.get_ext_account_number(), -line.amount), [])
                close_matches = [(delta, match) for match in match_list if (delta := abs(match[0].date - self.date)) < timedelta(weeks=3)]
                if close_matches:
                    match = min(close_matches, key=lambda match: match[0])[1]
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
                    if re.match(rule[0], self.payee):
                        line.category = rule[1]
                        break
        transactions.append(self)
        return True
