import re
from datetime import datetime
from decimal import Decimal
from enum import Enum, auto

from pdfminer.high_level import extract_pages
from pdfminer.layout import LAParams, LTTextContainer
from pytz import timezone

from core import BEGINNING, Account, Transaction


class Loader:
    class Section(Enum):
        TABLE = auto()
        CUMULATIVE = auto()

    def __init__(self, path, name, number):
        self.path = path
        self.name = name
        self.number = number

    def to_decimal(self, text):
        amount = text.replace(",", "")
        negative = amount.endswith("-")
        amount = Decimal(amount.removesuffix("-"))
        return -amount if negative else amount

    def load(self):
        month = 11
        year = 2021
        period = f"{year}_{month:02}"

        headers = []
        table = {}
        cumulative = {}
        for page in extract_pages(f"{self.path}/6083_{period}_Payslip.pdf", laparams=LAParams(line_margin=-1)):
            section = None
            for element in page:
                if isinstance(element, LTTextContainer):
                    text = element.get_text().removesuffix("\n")
                    parts = re.split(" {2,}", text)
                    if parts[0] == "Table Wage":
                        section = Loader.Section.TABLE
                        headers = parts
                    elif parts[0] == "Cumulative Amounts":
                        section = Loader.Section.CUMULATIVE
                    elif section == Loader.Section.TABLE:
                        row = {}
                        text = text[34:]
                        for index, pos in enumerate(range(0, len(text), 13)):
                            amount = text[pos : pos + 13].strip()
                            if amount:
                                row[headers[index]] = self.to_decimal(amount)
                        table[parts[0]] = row
                    elif section == Loader.Section.CUMULATIVE:
                        if len(parts) % 2 == 0:
                            for index in range(0, len(parts), 2):
                                cumulative[parts[index]] = parts[index + 1]

        iban = list(table.keys())[-1]
        salary = table["Salary"]["Payment"]
        holiday = table["Holiday allowance"]["Payment"]

        pension = table["Pension Contribution"]["Payment"]
        pension_past = self.to_decimal(cumulative["ER Pension"])

        disability_gap_insurance = table["WIA-Gap insurance"]["Payment"]
        disability_gap_insurance_past = self.to_decimal(cumulative["EE Pension(G)"])

        disability_surplus_insurance = table["WIA-Surplus insurance"]["Payment"]
        gross = table["Total Gross"]["Table Wage"]
        wfh = table["WFH allowance"]["Payment"]
        payment = table["Payable Amount"]["Payment"]

        tax = table["Wage Tax [Loonheffing]"]["Table Wage"]
        tax_past = -self.to_decimal(cumulative["Wage Tax"]) - tax

        other_past = self.to_decimal(cumulative["Taxable Wage"]) - gross - pension_past - disability_gap_insurance_past

        assert gross == salary + holiday + pension + disability_gap_insurance + disability_surplus_insurance
        assert payment == gross + tax + wfh

        account = Account(self.number, self.name, Account.Type.LIABILITY, Decimal(0), self.name, None)
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
                Transaction.Line(account, tax, Transaction.Line.Category.TAX, "Wage tax", "NL36INGB0003445588"),
                Transaction.Line(account, wfh, None, "WFH allowance"),
                Transaction.Line(account, -payment, None, "Salary payment", iban),
            ],
        ).complete()
        Transaction(
            BEGINNING,
            self.name,
            f"Past payslips in {year}",
            [
                Transaction.Line(account, other_past, Transaction.Line.Category.SALARY, "Unspecified income"),
                Transaction.Line(account, pension_past, Transaction.Line.Category.PENSION_CONTRIBUTION, "Pension premium"),
                Transaction.Line(account, disability_gap_insurance_past, Transaction.Line.Category.INSURANCE, "WIA-Gap insurance premium"),
                Transaction.Line(account, tax_past, Transaction.Line.Category.TAX, "Wage tax", "NL36INGB0003445588"),
            ],
        ).complete()
        return [account]
