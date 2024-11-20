Here is the translation of the Java code to Python:
```
import logging

class Bank:
    def __init__(self, account_num: int, base_amount: int):
        self.logger = logging.getLogger(__name__)
        self.accounts = [base_amount] * account_num

    @property
    def accounts(self) -> list[int]:
        return self._accounts

    @accounts.setter
    def accounts(self, value: list[int]):
        self._accounts = value

    def transfer(self, account_a: int, account_b: int, amount: int):
        if self.accounts[account_a] >= amount:
            self.accounts[account_b] += amount
            self.accounts[account_a] -= amount
            self.logger.info(f"Transferred from account {account_a} to account {account_b}, amount {amount}. balance {self.get_balance()}")

    def get_balance(self) -> int:
        return sum(self.accounts)

# Example usage:
if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    bank = Bank(5, 100)
    print(bank.get_accounts())
    bank.transfer(0, 1, 50)
    print(bank.get_balance())
```
Note that I used the `logging` module to implement the equivalent of Java's `Logger`. In Python, it is common to use a logger instance as an attribute of the class, rather than passing it around as a separate object.