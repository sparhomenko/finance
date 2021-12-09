import decimal
import urllib.parse
from datetime import datetime

import pytest
import pytz

import core
from banktivity import Document

DOC = 'Test'
PASSWORD = 'ZkzbFhr*!z9DWmuD2JXLadgr'
DOC = Document(DOC, PASSWORD)
DOC.load()


def test_account():
    account = core.Account('Test Number', 'Test', core.Account.Type.CURRENT, decimal.Decimal(42), 'Test Bank', 'https://test.com', 'Test BIC', 'Test Description')

    DOC.create_account(account)
    DOC.save()
    DOC.load()

    a = DOC.accounts[account.name]
    assert a.name == account.name
    assert a.note == account.description
    assert a.currency.code == 'EUR'
    assert a.accountClass == Document.Account.IGGCSyncAccountingAccountClass.CURRENT
    assert a.type == Document.Account.IGGCSyncAccountingAccountType.ASSET
    assert a.subtype == Document.Account.IGGCSyncAccountingAccountSubtype.CHECKING
    assert a.bankAccountNumber == account.number
    assert a.bankRoutingNumber == account.routing_number
    assert a.institutionName == account.bank_name
    assert urllib.parse.urlunparse(a.institutionSite) == account.bank_site
    t = next(filter(lambda t: t[0][0] == 'Transaction' and t[1].lineItems[0].account == a, DOC.entities.items()))[1]
    assert t.currency.code == 'EUR'
    assert t.transactionType.baseType == Document.TransactionType.IGGCSyncAccountingTransactionBaseType.DEPOSIT
    assert t.title == 'STARTING BALANCE'
    assert t.note == 'BALANCE ADJUSTMENT'
    assert t.lineItems[0].accountAmount == t.lineItems[0].transacitonAmount == account.initial_balance
    assert t.lineItems[0].cleared
    assert t.lineItems[1].accountAmount == t.lineItems[1].transacitonAmount == -account.initial_balance
    assert t.adjustment


def test_transaction():
    transaction = core.Transaction(
        core.Account(None, 'Checking', None, None, None, None),
        decimal.Decimal(-21),
        datetime(2021, 9, 13, tzinfo=pytz.timezone('Europe/Amsterdam')),
        'Test Payee',
        'Test Description',
        False,
        4242,
        None,
        core.Account(None, 'Destination', None, None, None, None)
    )

    id = DOC.create_transaction(transaction).id
    DOC.save()
    DOC.load()

    t = DOC.entities[('Transaction', id)]
    assert t.currency.code == 'EUR'
    assert t.date == transaction.date
    assert t.transactionType.baseType == Document.TransactionType.IGGCSyncAccountingTransactionBaseType.TRANSFER
    assert t.title == transaction.payee
    assert t.note == transaction.description
    assert t.lineItems[0].account.name == transaction.account.name
    assert t.lineItems[0].accountAmount == t.lineItems[0].transacitonAmount == transaction.total()
    assert not t.lineItems[0].cleared
    assert t.lineItems[1].accountAmount == t.lineItems[1].transacitonAmount == -transaction.lines[0].amount
    assert t.lineItems[1].memo == transaction.lines[0].description
    assert not t.lineItems[1].cleared
    assert t.lineItems[2].accountAmount == t.lineItems[2].transacitonAmount == -transaction.lines[1].amount
    assert t.lineItems[2].memo == transaction.lines[1].description
    assert not t.lineItems[2].cleared
    assert t.lineItems[2].account.name == transaction.counter_account.name
    assert not t.adjustment


def test_invalid_credentials():
    with pytest.raises(ValueError):
        Document(DOC, PASSWORD, ('invalid', 'invalid'))


def test_invalid_doc():
    with pytest.raises(ValueError):
        Document('invalid', PASSWORD)


def test_invalid_password():
    with pytest.raises(ValueError):
        Document(DOC, 'invalid')


def test_parse_object_invalid_type():
    with pytest.raises(TypeError):
        DOC.parse_object({'@type': 'Account', 'field': {'@type': 'invalid'}})


def test_unparse_object_invalid_type():
    class Invalid:
        field = {}
    with pytest.raises(TypeError):
        DOC.unparse_object(Invalid)
