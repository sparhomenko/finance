from datetime import datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from bs4 import BeautifulSoup
from requests import Session

from core import BEGINNING, Account, Category, Transaction


class Loader:
    def __init__(self, email, password, name, number):
        self.name = name
        self.number = number

        self.session = Session()
        self.session.post(
            "https://bonsenreuling.nmbrs.nl/applications/Common/Login.aspx",
            data={
                "ctl00$ContentPlaceHolder2$txtEmail": email,
                "ctl00$ContentPlaceHolder2$txtPassword": password,
                "__EVENTTARGET": "ctl00$ContentPlaceHolder2$btnLogin",
            },
        )
        assert "formsauth" in self.session.cookies

    def parse_headers(self, table):
        cells = filter(lambda cell: cell.text.strip(), table.find_all(("th", "td")))
        result = {}
        cells = list(cells)
        for index in range(0, len(cells), 2):
            title = cells[index].text.rstrip(":")
            value = cells[index + 1].text.strip()
            result[title] = None if value == "-" else value
        return result

    def parse_rows(self, table):
        result = {}
        headers = []
        for th in table.find_all("th"):
            headers.append(th.text)
        for tr in table.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) == len(headers):
                title = tds[0].text
                if title != "":
                    row = {}
                    for index, header in enumerate(headers[1:], 1):
                        text = tds[index].text
                        if text:
                            row[header] = self.to_decimal(text)
                    result[title] = row
        return result

    def to_decimal(self, text):
        return Decimal(text.replace(".", "").replace(",", "."))

    def load(self):
        year = 2021
        month = 11
        period = f"{year}-{month}-M"
        response = self.session.get("https://bonsenreuling.nmbrs.nl/handlers/Popups/PopupHandler.ashx", params={"action": "LoadPopup", "id": 292, "args": period})
        assert response.headers["Content-Type"] == "text/plain; charset=utf-8"

        html = BeautifulSoup(response.json()["content"], "html.parser")
        content = self.parse_rows(html.find_all(class_="tblPayslipContent")[1])
        reservation = self.parse_rows(html.find(class_="tblPayslipResContent"))
        cumulative = self.parse_headers(html.find(class_="tblPayslipCumContent"))

        iban = html.find(style="background-color:#ccc;").text.removeprefix("Account number IBAN: ")

        salary = content["Gross Salary"]["Payment"]
        salary_past = content["Gross Salary"]["Cumulative"] - salary

        pension = -content["Deduction Pension premium"]["Retention"]
        pension_past = content["Deduction Pension premium"]["Cumulative"] - pension

        payment = content["Net payment"]["Payment"]

        holiday = reservation["Holiday pay"]["Res"]
        holiday_total = reservation["Holiday pay"]["Balance"]

        tax = -content["Wage tax Table"]["Retention"]
        tax_past = -self.to_decimal(cumulative["Tax"]) - tax

        other_past = self.to_decimal(cumulative["Fiscal wage"]) - salary_past - pension_past

        assert payment == salary + pension + tax

        account = Account(self.number, self.name, Account.Type.LIABILITY, holiday_total, self.name, None)
        Transaction(
            datetime(year, month, 25, tzinfo=ZoneInfo("Europe/Amsterdam")),
            self.name,
            f"Payslip {period}",
            [
                Transaction.Line(account, salary, Category.SALARY, "Salary"),
                Transaction.Line(account, holiday, Category.SALARY, "Holiday pay"),
                Transaction.Line(account, pension, Category.PENSION_CONTRIBUTION, "Pension premium"),
                Transaction.Line(account, tax, Category.TAX, "Wage tax", "NL36INGB0003445588"),
                Transaction.Line(account, -payment, None, "Salary payment", iban),
            ],
        ).complete()
        Transaction(
            BEGINNING,
            self.name,
            f"Past payslips in {year}",
            [
                Transaction.Line(account, salary_past, Category.SALARY, "Salary"),
                Transaction.Line(account, other_past, Category.SALARY, "Unspecified income"),
                Transaction.Line(account, pension_past, Category.PENSION_CONTRIBUTION, "Pension premium"),
                Transaction.Line(account, tax_past, Category.TAX, "Wage tax", "NL36INGB0003445588"),
            ],
        ).complete()

        return [account]
