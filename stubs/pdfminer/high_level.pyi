from collections.abc import Container, Iterator
from io import IOBase
from pathlib import PurePath

from pdfminer.layout import LAParams, LTPage

def extract_pages(pdf_file: PurePath | str | IOBase, password: str = "", page_numbers: Container[int] | None = None, maxpages: int = 0, laparams: LAParams | None = None) -> Iterator[LTPage]: ...
