import dataclasses
import datetime
import decimal
import enum
import re
import typing

import pytz

BEGINNING = datetime.datetime(2021, 11, 1, tzinfo=pytz.timezone('Europe/Amsterdam'))
candidates = []


@dataclasses.dataclass
class Account:
    class Type(enum.Enum):
        CURRENT = 0
        CREDIT_CARD = 1
        SAVINGS = 2
        MORTGAGE = 3
        PROPERTY = 4

    @dataclasses.dataclass
    class Transaction:
        @dataclasses.dataclass
        class Line:
            class Category(enum.Enum):
                CHILDREN = 0
                GROCERIES = 1
                FEE = 2
                HEALTHCARE = 3
                INTEREST = 4
                INTEREST_INCOME = 5
                TAKEAWAY = 6
                UTILITIES = 7

            RULES = {
                r'De Elfentuin': Category.CHILDREN,
                r'PARTOU BV': Category.CHILDREN,
                r'Russian Gymnasium Amsterdam': Category.CHILDREN,
                r'ALBERT HEIJN \d+': Category.GROCERIES,
                r'Getir': Category.GROCERIES,
                r'HELLOFRESH': Category.GROCERIES,
                r'Coop Supermarkt \d+': Category.GROCERIES,
                r'UBER\s+\*EATS.*': Category.TAKEAWAY,
                r'CZ Groep Zorgverzekeraar': Category.HEALTHCARE,
                r'Rente': Category.INTEREST_INCOME,
                r'Vattenfall Klantenservice N.V.': Category.UTILITIES
            }

            amount: decimal.Decimal
            category: Category = None
            description: str = None

        account: 'Account'
        date: datetime.datetime
        payee: str
        description: str
        cleared: bool = True
        lines: list[Line] = dataclasses.field(default_factory=list)
        number: int = None
        counter_account_number = None
        matcher: typing.Callable[[typing.Any], bool] = None
        counter_account: 'Account' = None

        def total(self):
            return sum(map(lambda l: l.amount, self.lines))

        def is_withdrawal(self):
            return self.total() < 0

    number: str
    name: str
    type: Type
    initial_balance: decimal.Decimal
    bank_name: str
    bank_site: str
    routing_number: str = None
    description: str = None
    interest_rate: decimal.Decimal = None
    monthly_payment: decimal.Decimal = None
    transactions: list[Transaction] = dataclasses.field(default_factory=list)
    group: str = None

    def transaction(self, transaction):
        if not transaction.date >= BEGINNING:
            return False
        self.initial_balance -= transaction.total()
        if transaction.matcher is not None:
            for candidate in candidates:
                if transaction.matcher(transaction, candidate) and candidate.matcher(candidate, transaction):
                    candidate.date = max(transaction.date, candidate.date)
                    candidate.payee = None
                    candidate.description = ' '.join(filter(None, [transaction.description, candidate.description]))
                    candidate.counter_account = transaction.account
                    candidates.remove(candidate)
                    return True
            candidates.append(transaction)
        if transaction.lines[0].category is None:
            for rule in Account.Transaction.Line.RULES.items():
                if re.match(rule[0], transaction.payee):
                    transaction.lines[0].category = rule[1]
                    break
        self.transactions.append(transaction)
        return True

    def finish_load(self):
        matches = list(filter(lambda c: c.counter_account_number == self.number, candidates))
        if matches:
            if self.type == Account.Type.MORTGAGE:
                matches.sort(key=lambda m: m.date, reverse=True)
                monthly_interest_rate = self.interest_rate / 12
                for match in matches:
                    match.counter_account = self
                    repayment = ((-self.monthly_payment - self.initial_balance * monthly_interest_rate) / (monthly_interest_rate + 1) * 100).to_integral_value(decimal.ROUND_DOWN) / 100
                    match.lines.append(Account.Transaction.Line(repayment, None, 'Repayment'))
                    match.lines[0].amount -= repayment
                    match.lines[0].category = Account.Transaction.Line.Category.INTEREST
                    self.initial_balance += repayment
            else:
                print(f'Unmatched transactions for account {self.name}:')
                for match in matches:
                    print(f'{match.date} {match.payee} {match.total()}')
