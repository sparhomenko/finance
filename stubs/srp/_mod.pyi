from hashlib import _Hash
from typing import Callable

def calculate_M(hash_class: Callable[[bytes], _Hash], N: int, g: int, I: bytes, s: int, A: int, B: int, K: bytes) -> bytes: ...
