from hashlib import _Hash

class User:
    A: int
    B: int
    g: int
    N: int
    s: int
    S: int
    u: int
    def __init__(self, username: str, password: str, hash_alg: int, ng_type: int): ...
    def start_authentication(self) -> tuple[bytes, bytes]: ...
    def process_challenge(self, bytes_s: bytes, bytes_B: bytes) -> bytes: ...
    def hash_class(self, string: bytes) -> _Hash: ...

def rfc5054_enable(enable: bool = True) -> None: ...

SHA256: int
NG_1024: int
