class ManualEntry:
    def __init__(self, mnemonic: str, manual_path: str, missing_manual_description: str, page_number: str):
        self.mnemonic = mnemonic
        self.manual_path = manual_path
        self.missing_manual_description = missing_manual_description
        self.page_number = page_number

    @property
    def mnemonic(self) -> str:
        return self._mnemonic

    @property
    def manual_path(self) -> str:
        return self._manual_path

    @property
    def missing_manual_description(self) -> str:
        return self._missing_manual_description

    @property
    def page_number(self) -> str:
        return self._page_number
