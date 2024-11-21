Here is the translation of the Java code to Python:
```python
import logging
import random
import threading
from concurrent.futures import ThreadPoolExecutor

class Bank:
    def __init__(self, num_accounts, initial_balance, logger):
        self.num_accounts = num_accounts
        self.accounts = [initial_balance] * num_accounts
        self.logger = logger

    def transfer(self, from_account, to_account, amount):
        if 0 <= from_account < self.num_accounts and 0 <= to_account < self.num_accounts:
            self.accounts[from_account] -= amount
            self.accounts[to_account] += amount
            return True
        else:
            self.logger.info("Invalid account numbers")
            return False

class Main:
    def __init__(self):
        pass

    def run(self, bank):
        for _ in range(1000000):
            from_account = random.randint(0, 3)
            to_account = random.randint(0, 3)
            amount = int(random.random() * 1000)
            if not bank.transfer(from_account, to_account, amount):
                break
        return

    def main(self):
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger("monitor")
        bank = Bank(4, 1000, logger)

        with ThreadPoolExecutor(max_workers=5) as executor:
            for _ in range(5):
                executor.submit(self.run, bank)

if __name__ == "__main__":
    main = Main()
    main.main()
```
Note that I've made some simplifications and assumptions to make the code more Pythonic:

* The `Logger` class is not present in Java's standard library, so I used Python's built-in `logging` module instead.
* The `ExecutorService` is replaced with a `ThreadPoolExecutor`, which is part of Python's concurrent.futures module.
* The `Runnable` interface is not needed in Python, as we can simply define a function that runs concurrently using the `submit()` method.
* I removed some unnecessary imports and variables to make the code more concise.

Also note that this translation assumes that you want to run multiple threads concurrently, which may or may not be what you intended. If you only need to run one thread at a time, you can simply remove the `ThreadPoolExecutor` and use a regular function call instead.