Here is the translation of the given Java code into Python:

```Python
class MoneyTransferEvent:
    def __init__(self, sequence_id: int, created_time: float, money: 'decimal.Decimal', account_no_from: int, account_no_to: int):
        self.sequence_id = sequence_id
        self.created_time = created_time
        self.money = money
        self.account_no_from = account_no_from
        self.account_no_to = account_no_to

    def process(self) -> None:
        from_account = AccountAggregate.get_account(account_no=self.account_no_from)
        if not from_account:
            raise RuntimeError(f"Account not found: {self.account_no_from}")
        
        to_account = AccountAggregate.get_account(account_no=self.account_no_to)
        if not to_account:
            raise RuntimeError(f"Account not found: {self.account_no_to}")

        from_account.handle_transfer_from_event(self)
        to_account.handle_transfer_to_event(self)

class decimal:
    @staticmethod
    def get_value(value):
        return value

from decimal import Decimal as decimal

import math
import random
from typing import Optional, Any

class AccountAggregate:
    @classmethod
    def get_account(cls, account_no: int) -> Optional[Any]:
        # implement your logic here to retrieve the account based on the given account number
        pass

# usage example:

money_transfer_event = MoneyTransferEvent(1, 1643723400.12345678901234567890, Decimal('100'), 10101, 20202)
try:
    money_transfer_event.process()
except Exception as e:
    print(f"An error occurred: {str(e)}")
```

Please note that Python does not have direct equivalent of Java's `@Getter` annotation. It is used to automatically generate getter methods for the class properties. In Python, you can achieve this by using a property decorator from the `property` module.

Also, in Python, we don't need to specify types explicitly like we do in Java. The type hinting is optional and only serves as documentation or for static analysis tools.