class WireTransfers:
    def set_funds(self, bank_account: str, amount: int) -> None:
        pass  # implement this method in your subclass

    def get_funds(self, bank_account: str) -> int:
        raise NotImplementedError("get_funds must be implemented by a subclass")

    def transfer_funds(self, amount: int, source_bank_account: str, destination_bank_account: str) -> bool:
        raise NotImplementedError("transfer_funds must be implemented by a subclass")
