import pytest
from banktivity import Document

DOC = 'Test'
PASSWORD = 'ZkzbFhr*!z9DWmuD2JXLadgr'
DOC = Document(DOC, PASSWORD)


def test_sync():
    name = 'Test'
    DOC.load()
    DOC.create_account(name)
    DOC.save()
    DOC.load()

    account = DOC.entity_by_name[('Account', 'Test')]
    assert account.name == name
    assert account.currency.code == 'EUR'
    assert account.type == Document.Account.IGGCSyncAccountingAccountType.ASSET
    assert account.subtype == Document.Account.IGGCSyncAccountingAccountSubtype.CHECKING


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
