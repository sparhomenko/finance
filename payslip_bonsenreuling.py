from datetime import datetime
from decimal import Decimal

from bs4 import BeautifulSoup
from pytz import timezone
from requests import Session

from core import Account, Transaction


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

    def parse_headers(self, cells):
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
                        if text != "":
                            row[header] = text
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

        iban = html.find(style="background-color:#ccc;").text.removeprefix("Account number IBAN: ")
        salary = self.to_decimal(content["Gross Salary"]["Payment"])
        pension = -self.to_decimal(content["Deduction Pension premium"]["Retention"])
        tax = -self.to_decimal(content["Wage tax Table"]["Retention"])
        payment = self.to_decimal(content["Net payment"]["Payment"])
        assert payment == salary + pension + tax

        holiday = self.to_decimal(reservation["Holiday pay"]["Res"])
        holiday_balance = self.to_decimal(reservation["Holiday pay"]["Balance"])

        account = Account(self.number, self.name, Account.Type.CURRENT, holiday_balance, self.name, None)
        Transaction(
            datetime(year, month, 25, tzinfo=timezone("Europe/Amsterdam")),
            self.name,
            f"Payslip {period}",
            [
                Transaction.Line(account, salary, Transaction.Line.Category.SALARY, "Salary"),
                Transaction.Line(account, holiday, Transaction.Line.Category.SALARY, "Holiday pay"),
                Transaction.Line(account, pension, Transaction.Line.Category.PENSION_CONTRIBUTION, "Pension premium"),
                Transaction.Line(account, tax, Transaction.Line.Category.TAX, "Wage tax"),
                Transaction.Line(account, -payment, None, "Salary payment", iban),
            ],
        ).complete()
        return [account]
