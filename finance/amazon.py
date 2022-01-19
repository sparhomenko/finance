from datetime import datetime
from itertools import groupby
from typing import Callable
from zoneinfo import ZoneInfo

from chromedriver_binary import add_chromedriver_to_path
from pyotp import TOTP
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By

from finance.core import Account, AccountType, Amount, Line
from finance.core import Loader as BaseLoader
from finance.core import Transaction


class Loader(BaseLoader):
    def __init__(self, email: str, password: str, totp_secret: str):
        add_chromedriver_to_path()

        options = Options()
        options.headless = True
        self._browser = Chrome(options=options)
        self._browser.get("https://amazon.de")

        self._browser.find_element(By.ID, "sp-cc-accept").click()
        self._browser.find_element(By.XPATH, "//span[contains(@class, 'glow-toaster-button-dismiss')]").click()
        self._browser.find_element(By.ID, "nav-link-accountList").click()
        self._browser.find_element(By.ID, "ap_email").send_keys(email)
        self._browser.find_element(By.ID, "continue").click()
        self._browser.find_element(By.ID, "ap_password").send_keys(password)
        self._browser.find_element(By.ID, "signInSubmit").click()
        self._browser.find_element(By.ID, "auth-mfa-otpcode").send_keys(TOTP(totp_secret).now())
        self._browser.find_element(By.ID, "auth-signin-button").click()
        chain = ActionChains(self._browser)
        chain.move_to_element(self._browser.find_element(By.ID, "nav-link-accountList"))
        chain.click(self._browser.find_element(By.XPATH, "//span[text() = 'Your Orders']"))
        chain.perform()

    def load(self) -> list[Account]:
        account = Account("amazon", "Amazon", AccountType.CURRENT, Amount(0), "Amazon", "https://amazon.de")
        orders = []
        for order_element in self._browser.find_elements(By.XPATH, "//*[contains(@class, ' order ')]"):
            elements = order_element.find_elements(By.XPATH, ".//span[contains(@class, ' value')]")
            date = datetime.strptime(elements[0].text, "%d %B %Y").replace(tzinfo=ZoneInfo("Europe/Amsterdam"))
            amount = self._to_amount(elements[1].text)
            order_id = elements[2].text
            orders.append((date, amount, order_id))

        group_by_key: Callable[[tuple[datetime, Amount, str]], datetime] = lambda order: order[0]
        for date, order_group in groupby(orders, key=group_by_key):
            lines = []
            order_ids = []
            accounted = Amount()
            total = Amount()
            for _, order_amount, order_id in order_group:
                self._browser.get(f"https://www.amazon.de/gp/css/summary/print.html/ref=oh_aui_ajax_invoice?ie=UTF8&orderID={order_id}")
                promotion_elements = self._browser.find_elements(By.XPATH, "//tr[td[text() ='Promotion Applied:']]/td[2]")
                promotion = self._to_amount(promotion_elements[0].text.removeprefix("-")) if promotion_elements else Amount()
                total += order_amount
                order_ids.append(order_id)
                for product in self._browser.find_elements(By.XPATH, "//tr[input]"):
                    name = product.find_element(By.XPATH, "./td[1]/i").text
                    amount = self._to_amount(product.find_element(By.XPATH, "./td[2]").text)
                    if promotion:
                        amount -= Amount(round((amount / (total + promotion) * promotion).amount, 2))
                    if (count := int(product.find_element(By.XPATH, "./td[1]").text.split(" of:")[0])) > 1:
                        name = f"{count} x {name}"
                        amount *= count
                    accounted += amount
                    lines.append(Line(account, -amount, None, name))
            assert accounted == total
            lines.append(Line(account, total, None, "Payment", "*"))
            Transaction(date, account.bank_name, ", ".join(order_ids), lines).complete()
        return [account]

    def _to_amount(self, text: str) -> Amount:
        return Amount(text.removeprefix("EUR ").replace(",", "."))
