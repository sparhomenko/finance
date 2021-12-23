from datetime import datetime
from decimal import Decimal
from urllib.parse import urlunparse
from zoneinfo import ZoneInfo

from pytest import raises

from banktivity import Document
from core import Account, Transaction

DOC = "Test"
PASSWORD = "ZkzbFhr*!z9DWmuD2JXLadgr"
DOC = Document(DOC, PASSWORD)
DOC.load()


def test_account():
    data = Account("Test Number", "Test", Account.Type.CURRENT, Decimal(42), "Test Bank", "https://test.com", "Test BIC", "Test Description")

    DOC.create_account(data)
    DOC.save()
    DOC.load()

    result = DOC.accounts[data.name]
    assert result.name == data.name
    assert result.note == data.description
    assert result.currency.code == "EUR"
    assert result.accountClass == Document.Account.IGGCSyncAccountingAccountClass.CURRENT
    assert result.type == Document.Account.IGGCSyncAccountingAccountType.ASSET
    assert result.subtype == Document.Account.IGGCSyncAccountingAccountSubtype.CHECKING
    assert result.bankAccountNumber == data.number
    assert result.bankRoutingNumber == data.routing_number
    assert result.institutionName == data.bank_name
    assert urlunparse(result.institutionSite) == data.bank_site
    transaction = next(filter(lambda transaction: transaction[0][0] == "Transaction" and transaction[1].lineItems[0].account == result, DOC.entities.items()))[1]
    assert transaction.currency.code == "EUR"
    assert transaction.transactionType.baseType == Document.TransactionType.IGGCSyncAccountingTransactionBaseType.DEPOSIT
    assert transaction.title == "STARTING BALANCE"
    assert transaction.note == "BALANCE ADJUSTMENT"
    assert transaction.lineItems[0].accountAmount == transaction.lineItems[0].transacitonAmount == data.initial_balance
    assert transaction.lineItems[0].cleared
    assert transaction.lineItems[1].accountAmount == transaction.lineItems[1].transacitonAmount == -data.initial_balance
    assert transaction.adjustment


def test_transaction():
    data = Transaction(
        Account(None, "Checking", None, None, None, None),
        Decimal(-21),
        datetime(2021, 9, 13, tzinfo=ZoneInfo("Europe/Amsterdam")),
        "Test Payee",
        "Test Description",
        cleared=False,
        number=4242,
    )

    transaction_id = DOC.create_transaction(data).id
    DOC.save()
    DOC.load()

    transaction = DOC.entities[("Transaction", transaction_id)]
    assert transaction.currency.code == "EUR"
    assert transaction.date == data.date
    assert transaction.transactionType.baseType == Document.TransactionType.IGGCSyncAccountingTransactionBaseType.TRANSFER
    assert transaction.title == data.payee
    assert transaction.note == data.description
    assert transaction.lineItems[0].account.name == data.account.name
    assert transaction.lineItems[0].accountAmount == transaction.lineItems[0].transacitonAmount == data.total()
    assert not transaction.lineItems[0].cleared
    assert transaction.lineItems[1].accountAmount == transaction.lineItems[1].transacitonAmount == -data.lines[0].amount
    assert transaction.lineItems[1].memo == data.lines[0].description
    assert not transaction.lineItems[1].cleared
    assert transaction.lineItems[2].accountAmount == transaction.lineItems[2].transacitonAmount == -data.lines[1].amount
    assert transaction.lineItems[2].memo == data.lines[1].description
    assert not transaction.lineItems[2].cleared
    assert transaction.lineItems[2].account.name == data.counter_account.name
    assert not transaction.adjustment


def test_invalid_credentials():
    with raises(ValueError):
        Document(DOC, PASSWORD, ("invalid", "invalid"))


def test_invalid_doc():
    with raises(ValueError):
        Document("invalid", PASSWORD)


def test_invalid_password():
    with raises(ValueError):
        Document(DOC, "invalid")


def test_parse_object_invalid_type():
    with raises(TypeError):
        DOC.parse_object({"@type": "Account", "field": {"@type": "invalid"}})


def test_unparse_object_invalid_type():
    class Invalid:
        field = {}

    with raises(TypeError):
        DOC.unparse_object(Invalid)
