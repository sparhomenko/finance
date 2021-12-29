from bs4.element import Tag

class BeautifulSoup(Tag):
    def __init__(self, markup: str, features: str): ...
