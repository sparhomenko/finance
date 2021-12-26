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
        year = BEGINNING.year
        month = 0
        account = Account(self.number, self.name, Account.Type.LIABILITY, Decimal(0), self.name, None)
        while True:
            month += 1
            if month > 12:
                month = 1
                year += 1
            period = f"{year}-{month}-M"
            response = self.session.get("https://bonsenreuling.nmbrs.nl/handlers/Popups/PopupHandler.ashx", params={"action": "LoadPopup", "id": 292, "args": period})
            assert response.headers["Content-Type"] == "text/plain; charset=utf-8"

            html = BeautifulSoup(response.json()["content"], "html.parser")
            content = html.find_all(class_="tblPayslipContent")
            if not content:
                break
            content = self.parse_rows(content[1])
            reservation = self.parse_rows(html.find(class_="tblPayslipResContent"))

            iban = html.find(style="background-color:#ccc;").text.removeprefix("Account number IBAN: ")
            salary = content["Gross Salary"]["Payment"]
            pension = -content["Deduction Pension premium"]["Retention"]
            holiday_payment = content.get("Holiday pay", {}).get("Payment", 0)
            payment = content["Net payment"]["Payment"]
            holiday = reservation["Holiday pay"]["Res"]
            tax = -content["Wage tax Table"]["Retention"] - content.get("Wage tax BT", {}).get("Retention", 0)

            assert payment == salary + holiday_payment + pension + tax

            date = datetime(year, month, 25, tzinfo=ZoneInfo("Europe/Amsterdam"))
            lines = [
                Transaction.Line(account, salary, Category.SALARY, "Salary", tax_year=year),
                Transaction.Line(account, holiday, Category.SALARY, "Holiday pay", tax_year=year if month <= 5 else year + 1),
                Transaction.Line(account, pension, Category.PENSION_CONTRIBUTION, "Pension premium", tax_year=year),
                Transaction.Line(account, tax, Category.TAX, "Wage tax", "NL36INGB0003445588"),
                Transaction.Line(account, -payment, None, "Salary payment", iban),
            ]
            Transaction(date, self.name, f"Payslip {date.strftime('%B %Y')}", lines).complete(must_have=True)

        account.initial_balance = Decimal(0)
        return [account]
