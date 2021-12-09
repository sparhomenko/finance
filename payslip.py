import datetime
import decimal
import re

import bs4
import pytz
import requests

import core


class PayslipLoader():
    def __init__(self, email, password, name, number):
        self.name = name
        self.number = number

        self.session = requests.Session()
        self.session.post('https://bonsenreuling.nmbrs.nl/applications/Common/Login.aspx', data={
            'ctl00$ContentPlaceHolder2$txtEmail': email,
            'ctl00$ContentPlaceHolder2$txtPassword': password,
            '__EVENTTARGET': 'ctl00$ContentPlaceHolder2$btnLogin',
        })
        assert 'formsauth' in self.session.cookies

    def parse_headers(self, cells):
        result = {}
        cells = list(cells)
        for i in range(0, len(cells), 2):
            title = cells[i].text.rstrip(':')
            value = cells[i+1].text.strip()
            result[title] = None if value == '-' else value
        return result

    def parse_rows(self, table):
        result = {}
        headers = []
        for th in table.find_all('th'):
            headers.append(th.text)
        for tr in table.find_all('tr'):
            tds = tr.find_all('td')
            if len(tds) == len(headers):
                title = tds[0].text
                if title != '':
                    row = {}
                    for i in range(1, len(headers)):
                        text = tds[i].text
                        if text != '':
                            row[headers[i]] = text
                    result[title] = row
        return result

    def n(self, text):
        return decimal.Decimal(text.replace('.', '').replace(',', '.'))

    def load(self):
        year = 2021
        month = 11
        period = f'{year}-{month}-M'
        response = self.session.get('https://bonsenreuling.nmbrs.nl/handlers/Popups/PopupHandler.ashx', params={'action': 'LoadPopup', 'id': 292, 'args': period})
        assert response.headers['Content-Type'] == 'text/plain; charset=utf-8'

        html = bs4.BeautifulSoup(response.json()['content'], 'html.parser')
        # info = self.parse_headers(filter(lambda c: c.td is None, html.find(class_='tblPayslipHeader').find_all('td')))
        content = self.parse_rows(html.find_all(class_='tblPayslipContent')[1])
        reservation = self.parse_rows(html.find(class_='tblPayslipResContent'))
        # cumulative = self.parse_headers(filter(lambda c: c.text.strip() != '', html.find(class_='tblPayslipCumContent').find_all(['th', 'td'])))

        iban = re.match(r'Account number IBAN: (.*)', html.find(style='background-color:#ccc;').text)[1]
        gross = self.n(content['Gross Salary']['Payment'])
        pension = self.n(content['Deduction Pension premium']['Retention'])
        tax = self.n(content['Wage tax Table']['Retention'])
        net = self.n(content['Net payment']['Payment'])
        assert net == gross - pension - tax

        holiday = self.n(reservation['Holiday pay']['Res'])
        holiday_balance = self.n(reservation['Holiday pay']['Balance'])

        account = core.Account(self.number, self.name, core.Account.Type.CURRENT, holiday_balance, self.name, None)
        core.Transaction(
            datetime.datetime(year, month, 25, tzinfo=pytz.timezone('Europe/Amsterdam')),
            'EVBox',
            f'Salary period {period}',
            [
                core.Transaction.Line(account, gross,    core.Transaction.Line.Category.SALARY,               'Gross salary'),
                core.Transaction.Line(account, -pension, core.Transaction.Line.Category.PENSION_CONTRIBUTION, 'Pension premium'),
                core.Transaction.Line(account, -tax,     core.Transaction.Line.Category.TAX,                  'Wage tax'),
                core.Transaction.Line(account, -net,     None,                                                'Net salary', iban),
                core.Transaction.Line(account, holiday,  core.Transaction.Line.Category.SALARY,               'Holiday pay')
            ]
        ).complete()
        return [account]
