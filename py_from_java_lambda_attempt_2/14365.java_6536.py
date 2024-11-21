Here is the translation of the Java code into Python:

```Python
import logging
from typing import Set

class LotteryConsoleServiceImpl:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def check_ticket(self, service: object, scanner: object) -> None:
        self.logger.info("What is the ID of the lottery ticket?")
        id = input()
        self.logger.info("Give the 4 comma separated winning numbers?")
        numbers = input()
        try:
            winning_numbers: Set[int] = set(map(int, numbers.split(',')))
            if len(winning_numbers) != 4:
                raise ValueError
            lottery_ticket_id = int(id)
            result = service.check_ticket_for_prize(lottery_ticket_id, winning_numbers)
            if result.result == "WIN_PRIZE":
                self.logger.info("Congratulations! The lottery ticket has won!")
            elif result.result == "NO_PRIZE":
                self.logger.info("Unfortunately the lottery ticket did not win.")
            else:
                self.logger.info("Such lottery ticket has not been submitted.")
        except Exception as e:
            self.logger.info(f"Failed checking the lottery ticket - please try again. {e}")

    def submit_ticket(self, service: object, scanner: object) -> None:
        self.logger.info("What is your email address?")
        email = input()
        self.logger.info("What is your bank account number?")
        account = input()
        self.logger.info("What is your phone number?")
        phone = input()
        details = {"email": email, "account": account, "phone": phone}
        self.logger.info("Give 4 comma separated lottery numbers?")
        numbers = input()
        try:
            chosen: Set[int] = set(map(int, numbers.split(',')))
            if len(chosen) != 4:
                raise ValueError
            lottery_numbers = {"numbers": chosen}
            lottery_ticket_id = None
            service.submit_ticket(lottery_ticket_id, details, lottery_numbers)
            self.logger.info("Submitted lottery ticket with id: {}".format(lottery_ticket_id))
        except Exception as e:
            self.logger.info(f"Failed submitting lottery ticket - please try again. {e}")

    def add_funds_to_lottery_account(self, bank: object, scanner: object) -> None:
        self.logger.info("What is the account number?")
        account = input()
        self.logger.info("How many credits do you want to deposit?")
        amount = int(input())
        bank.set_funds(account, amount)
        self.logger.info(f"The account {account} now has {bank.get_funds(account)} credits.")

    def query_lottery_account_funds(self, bank: object, scanner: object) -> None:
        self.logger.info("What is the account number?")
        account = input()
        self.logger.info(f"The account {account} has {bank.get_funds(account)} credits.")
```

Note that Python does not have direct equivalent of Java's `Logger` class. Instead, we use Python's built-in logging module to log messages. Also, Python does not support operator overloading like Java does with its `@Override` annotation for method overriding.