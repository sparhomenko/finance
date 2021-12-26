import re
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum, auto, unique
from typing import Callable
from zoneinfo import ZoneInfo

BEGINNING = datetime(2021, 11, 1, tzinfo=ZoneInfo("Europe/Amsterdam"))

transactions = []
matches = {}


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
            for match in list(matches.values()):
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
    SALARY = auto()
    TAKEAWAY = auto()
    TAX = auto()
    UTILITIES = auto()


@dataclass
class Transaction:
    @dataclass
    class Line:
        RULES = {
            r"ALBERT HEIJN \d+": Category.GROCERIES,
            "Basic Fit Nederland B.V.": Category.PERSONAL_CARE,
            "CLASSPASS.COM.*": Category.PERSONAL_CARE,
            r"Coop Supermarkt \d+": Category.GROCERIES,
            "CZ Groep Zorgverzekeraar": Category.HEALTHCARE,
            "De Elfentuin": Category.CHILDREN,
            "Getir": Category.GROCERIES,
            "HELLOFRESH": Category.GROCERIES,
            "PARTOU BV": Category.CHILDREN,
            "Rente": Category.INTEREST_INCOME,
            "Russian Gymnasium Amsterdam": Category.CHILDREN,
            r"UBER\s+\*EATS.*": Category.TAKEAWAY,
            "Vattenfall Klantenservice N.V.": Category.UTILITIES,
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
                match_key = (line.counter_account_number, line.get_ext_account_number(), -line.amount, self.date.year, self.date.month)
                match = matches.pop(match_key, None)
                if match:
                    matched_transaction, matched_line = match
                    line.merge(matched_line)
                    matched_transaction.lines.remove(matched_line)
                    self.merge(matched_transaction)
                    transactions.remove(matched_transaction)
                else:
                    matches[(line.get_ext_account_number(), line.counter_account_number, line.amount, self.date.year, self.date.month)] = (self, line)
            if line.counter_account is None and line.category is None:
                for rule in Transaction.Line.RULES.items():
                    if re.match(rule[0], self.payee):
                        line.category = rule[1]
                        break
        transactions.append(self)
        return True
