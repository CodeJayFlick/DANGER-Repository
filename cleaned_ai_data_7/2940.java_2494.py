class SearchResults:
    def __init__(self, address: str, display_value: str):
        self.address = address
        self.display_value = display_value

    @property
    def display_value(self) -> str:
        return self.display_value

    @property
    def address(self) -> str:
        return self.address
