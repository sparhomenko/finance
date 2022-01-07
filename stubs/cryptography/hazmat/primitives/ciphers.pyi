from cryptography.hazmat.primitives._cipheralgorithm import CipherAlgorithm
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from cryptography.hazmat.primitives.ciphers.modes import Mode

class Cipher(object):
    def __init__(self, algorithm: CipherAlgorithm, mode: Mode | None): ...
    def encryptor(self) -> CipherContext: ...
    def decryptor(self) -> CipherContext: ...