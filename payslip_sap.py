import re
from datetime import datetime
from decimal import Decimal
from enum import Enum, auto
from os import listdir
from zoneinfo import ZoneInfo

from more_itertools import one
from pdfminer.high_level import extract_pages
from pdfminer.layout import LAParams, LTTextContainer

from core import BEGINNING, Account, Category, Transaction
from typesafe import re_groups


class Loader:
    class Section(Enum):
        HEADER = auto()
        TABLE = auto()
        CUMULATIVE = auto()

    def __init__(self, path: str, name: str, number: str):
        self.path = path
        self.name = name
        self.number = number

    def to_decimal(self, text: str) -> Decimal:
        amount_str = text.replace(",", "")
        negative = amount_str.endswith("-")
        amount = Decimal(amount_str.removesuffix("-"))
        return -amount if negative else amount

    def load(self) -> list[Account]:
        account = Account(self.number, self.name, Account.Type.LIABILITY, Decimal(0), self.name, None)
        for file in sorted(listdir(self.path)):
            match = re.match(r"\d+_(\d{4})_(\d{2})_Payslip.pdf", file)
            if not match:
                continue
            groups = re_groups(match)
            year = int(groups[0])
            month = int(groups[1])
            if year < BEGINNING.year:
                continue
            header_lines = []
            table_headers = []
            table = {}
            cumulative = {}
            section = Loader.Section.HEADER
            page = one(extract_pages(f"{self.path}/{file}", laparams=LAParams(line_margin=-1)))
            for element in page:
                if isinstance(element, LTTextContainer):
                    text = element.get_text().removesuffix("\n")
                    parts: list[str] = re.split(" {2,}", text)
                    if parts[0] == "Table Wage":
                        section = Loader.Section.TABLE
                        table_headers = parts
                    elif parts[0] == "Cumulative Amounts":
                        section = Loader.Section.CUMULATIVE
                    elif section == Loader.Section.HEADER:
                        header_lines.append(parts)
                    elif section == Loader.Section.TABLE:
                        row = {}
                        text = text[34:]
                        for index, pos in enumerate(range(0, len(text), 13)):
                            amount = text[pos : pos + 13].strip()
                            if amount:
                                row[table_headers[index]] = self.to_decimal(amount)
                        table[parts[0]] = row
                    elif section == Loader.Section.CUMULATIVE:
                        if len(parts) % 2 == 0:
                            for index in range(0, len(parts), 2):
                                cumulative[parts[index]] = parts[index + 1]

            date_str = header_lines[0][2]
            assert date_str.startswith("Print date: ")
            date = datetime.strptime(date_str.removeprefix("Print date: "), "%d.%m.%Y").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
            assert date.year == year
            assert date.month == month

            iban = list(table.keys())[-1]
            salary = table["Salary"]["Payment"]
            holiday = table["Holiday allowance"]["Payment"]
            bonus = table.get("Annual Booking Bonus", {}).get("Spec.Payment", Decimal(0))
            pension = table["Pension Contribution"]["Payment"]
            disability_gap_insurance = table["WIA-Gap insurance"]["Payment"]
            disability_surplus_insurance = table["WIA-Surplus insurance"]["Payment"]
            gross = table["Total Gross"]["Table Wage"]
            wfh = table["WFH allowance"]["Payment"]
            booking = table.get("Booking Benefit (Nett)", {}).get("Payment", Decimal(0))
            payment = table["Payable Amount"]["Payment"]
            tax = table["Wage Tax [Loonheffing]"]["Payment"]

            assert gross == salary + holiday + pension + disability_gap_insurance + disability_surplus_insurance
            assert payment == gross + bonus + tax + wfh + booking

            lines = [
                Transaction.Line(account, salary, Category.SALARY, "Salary", tax_year=year),
                Transaction.Line(account, holiday, Category.SALARY, "Holiday pay", tax_year=year),
            ]
            if bonus:
                lines.append(Transaction.Line(account, bonus, Category.SALARY, "Annual bonus", tax_year=year))
            lines += [
                Transaction.Line(account, pension, Category.PENSION_CONTRIBUTION, "Pension premium", tax_year=year),
                Transaction.Line(account, disability_gap_insurance, Category.INSURANCE, "WIA-Gap insurance premium", tax_year=year),
                Transaction.Line(account, disability_surplus_insurance, Category.INSURANCE, "WIA-Surplus insurance premium", tax_year=year),
                Transaction.Line(account, tax, Category.TAX, "Wage tax", "NL36INGB0003445588"),
                Transaction.Line(account, wfh, Category.SALARY, "WFH allowance"),
            ]
            if booking:
                lines.append(Transaction.Line(account, booking, None, "Booking benefit"))
            lines.append(Transaction.Line(account, -payment, None, "Salary payment", iban))
            Transaction(date, self.name, f"Payslip {date.strftime('%B %Y')}", lines).complete(must_have=True)
        return [account]
