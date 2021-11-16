import pytest
from banktivity import open_doc

DOC = 'Test'
PASSWORD = 'ZkzbFhr*!z9DWmuD2JXLadgr'


def test_open_doc():
    [id, key] = open_doc(DOC, PASSWORD)
    assert id > 0
    assert key is not None


def test_open_doc_invalid_credentials():
    with pytest.raises(ValueError):
        open_doc(DOC, PASSWORD, 'invalid', 'invalid')


def test_open_doc_invalid_doc():
    with pytest.raises(ValueError):
        open_doc('invalid', PASSWORD)


def test_open_doc_invalid_password():
    with pytest.raises(ValueError):
        open_doc(DOC, 'invalid')
