import decimal

import pytest

from banktivity import Document

DOC = 'Test'
PASSWORD = 'ZkzbFhr*!z9DWmuD2JXLadgr'
DOC = Document(DOC, PASSWORD)
DOC.load()


def test_account():
    name = 'Test'
    DOC.create_account(name)
    DOC.save()
    DOC.load()

    account = DOC.accounts[name]
    assert account.name == name
    assert account.currency.code == 'EUR'
    assert account.type == Document.Account.IGGCSyncAccountingAccountType.ASSET
    assert account.subtype == Document.Account.IGGCSyncAccountingAccountSubtype.CHECKING


def test_transaction():
    account = DOC.accounts['Checking']
    amount = decimal.Decimal(-1)
    note = 'Test'
    id = DOC.create_transaction(account, amount, note=note).id
    DOC.save()
    DOC.load()

    transaction = DOC.entities[('Transaction', id)]
    assert transaction.transactionType.baseType == Document.TransactionType.IGGCSyncAccountingTransactionBaseType.WITHDRAWAL
    assert transaction.note == note
    assert transaction.currency.code == 'EUR'
    assert transaction.lineItems[0].account == account
    assert transaction.lineItems[0].accountAmount == transaction.lineItems[0].transacitonAmount == amount
    assert transaction.lineItems[1].accountAmount == transaction.lineItems[1].transacitonAmount == -amount


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
