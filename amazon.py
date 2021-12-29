from datetime import datetime
from decimal import Decimal
from itertools import groupby
from typing import Callable
from zoneinfo import ZoneInfo

from chromedriver_binary import add_chromedriver_to_path
from pyotp import TOTP
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By

from core import Account, Transaction


class Loader:
    def __init__(self, email: str, password: str, totp_secret: str):
        add_chromedriver_to_path()

        options = Options()
        options.headless = True
        self.browser = Chrome(options=options)
        self.browser.get("https://amazon.de")

        self.browser.find_element(By.ID, "sp-cc-accept").click()
        self.browser.find_element(By.XPATH, "//span[contains(@class, 'glow-toaster-button-dismiss')]").click()
        self.browser.find_element(By.ID, "nav-link-accountList").click()
        self.browser.find_element(By.ID, "ap_email").send_keys(email)
        self.browser.find_element(By.ID, "continue").click()
        self.browser.find_element(By.ID, "ap_password").send_keys(password)
        self.browser.find_element(By.ID, "signInSubmit").click()
        self.browser.find_element(By.ID, "auth-mfa-otpcode").send_keys(TOTP(totp_secret).now())
        self.browser.find_element(By.ID, "auth-signin-button").click()
        chain = ActionChains(self.browser)
        chain.move_to_element(self.browser.find_element(By.ID, "nav-link-accountList"))
        chain.click(self.browser.find_element(By.XPATH, "//span[text() = 'Your Orders']"))
        chain.perform()

    def to_amount(self, text: str) -> Decimal:
        return Decimal(text.removeprefix("EUR ").replace(",", "."))

    def load(self) -> list[Account]:
        account = Account("amazon", "Amazon", Account.Type.CURRENT, Decimal(0), "Amazon", "https://amazon.de")
        orders = []
        for order_element in self.browser.find_elements(By.XPATH, "//*[contains(@class, ' order ')]"):
            values = order_element.find_elements(By.XPATH, ".//span[contains(@class, ' value')]")
            date = datetime.strptime(values[0].text, "%d %B %Y").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
            amount = self.to_amount(values[1].text)
            order_id = values[2].text
            orders.append((date, amount, order_id))

        group_by_key: Callable[[tuple[datetime, Decimal, str]], datetime] = lambda order: order[0]
        for date, order_group in groupby(orders, key=group_by_key):
            lines = []
            order_ids = []
            accounted = Decimal(0)
            total = Decimal(0)
            for _, order_amount, order_id in order_group:
                self.browser.get(f"https://www.amazon.de/gp/css/summary/print.html/ref=oh_aui_ajax_invoice?ie=UTF8&orderID={order_id}")
                promotion_elements = self.browser.find_elements(By.XPATH, "//tr[td[text() ='Promotion Applied:']]/td[2]")
                promotion = self.to_amount(promotion_elements[0].text.removeprefix("-")) if promotion_elements else Decimal(0)
                total += order_amount
                order_ids.append(order_id)
                for product in self.browser.find_elements(By.XPATH, "//tr[input]"):
                    name = product.find_element(By.XPATH, "./td[1]/i").text
                    amount = self.to_amount(product.find_element(By.XPATH, "./td[2]").text)
                    if promotion:
                        amount -= round(amount / (total + promotion) * promotion, 2)
                    if (count := int(product.find_element(By.XPATH, "./td[1]").text.split(" of:")[0])) > 1:
                        name = f"{count} x {name}"
                        amount *= count
                    accounted += amount
                    lines.append(Transaction.Line(account, -amount, None, name))
            assert accounted == total
            lines.append(Transaction.Line(account, total, None, "Payment", "*"))
            Transaction(date, account.bank_name, ", ".join(order_ids), lines).complete()
        return [account]
