from decimal import Decimal

from core import Account, Category, Transaction


class Loader:
    def load(self):
        return [Account("NL36INGB0003445588", "Belastingdienst", Account.Type.LIABILITY, Decimal(0), "Belastingdienst", "https://www.belastingdienst.nl/", matcher=match_any)]


def match_any(account, matching_transaction, matching_line):
    for line in matching_transaction.lines:
        if line.category in {Category.SALARY, Category.PENSION_CONTRIBUTION, Category.INSURANCE}:
            account.tax_base += line.amount
    return Transaction(matching_transaction.date, account.bank_name, None, [Transaction.Line(account, -matching_line.amount, counter_account_number=matching_line.account.number)])
