import re
from datetime import datetime
from decimal import Decimal

from pdfminer.high_level import extract_pages
from pdfminer.layout import LAParams, LTTextContainer
from pytz import timezone

from core import Account, Transaction


class Loader():
    def __init__(self, path, name, number):
        self.path = path
        self.name = name
        self.number = number

    def load(self):
        month = 11
        year = 2021
        period = f"{year}_{month:02}"

        for page in extract_pages(f"{self.path}/6083_{period}_Payslip.pdf", laparams=LAParams(line_margin=-1)):
            is_table = False
            headers = []
            table = {}
            for element in page:
                if isinstance(element, LTTextContainer):
                    text = element.get_text().removesuffix("\n")
                    parts = re.split(" {2,}", text)
                    if parts[0] == "Table Wage":
                        is_table = True
                        headers = parts
                    elif parts[0] == "Cumulative Amounts":
                        is_table = False
                    elif is_table:
                        row = {}
                        text = text[34:]
                        for index, pos in enumerate(range(0, len(text), 13)):
                            amount = text[pos : pos + 13].strip().replace(",", "")
                            if amount:
                                negative = amount.endswith("-")
                                if negative:
                                    amount = amount.removesuffix("-")
                                amount = Decimal(amount)
                                if negative:
                                    amount = -amount
                                row[headers[index]] = Decimal(amount)
                        table[parts[0]] = row

        iban = list(table.keys())[-1]
        salary = table["Salary"]["Payment"]
        holiday = table["Holiday allowance"]["Payment"]
        pension = table["Pension Contribution"]["Payment"]
        disability_gap_insurance = table["WIA-Gap insurance"]["Payment"]
        disability_surplus_insurance = table["WIA-Surplus insurance"]["Payment"]
        gross = table["Total Gross"]["Table Wage"]
        assert gross == salary + holiday + pension + disability_gap_insurance + disability_surplus_insurance
        tax = table["Wage Tax [Loonheffing]"]["Table Wage"]
        wfh = table["WFH allowance"]["Payment"]
        payment = table["Payable Amount"]["Payment"]
        assert payment == gross + tax + wfh

        account = Account(self.number, self.name, Account.Type.CURRENT, Decimal(0), self.name, None)
        Transaction(
            datetime(year, month, 25, tzinfo=timezone("Europe/Amsterdam")),
            self.name,
            f"Payslip {period}",
            [
                Transaction.Line(account, salary, Transaction.Line.Category.SALARY, "Salary"),
                Transaction.Line(account, holiday, Transaction.Line.Category.SALARY, "Holiday pay"),
                Transaction.Line(account, pension, Transaction.Line.Category.PENSION_CONTRIBUTION, "Pension premium"),
                Transaction.Line(account, disability_gap_insurance, Transaction.Line.Category.INSURANCE, "WIA-Gap insurance premium"),
                Transaction.Line(account, disability_surplus_insurance, Transaction.Line.Category.INSURANCE, "WIA-Surplus insurance premium"),
                Transaction.Line(account, tax, Transaction.Line.Category.TAX, "Wage tax"),
                Transaction.Line(account, wfh, Transaction.Line.Category.SALARY, "WFH allowance"),
                Transaction.Line(account, -payment, None, "Salary payment", iban),
            ],
        ).complete()
        return [account]
