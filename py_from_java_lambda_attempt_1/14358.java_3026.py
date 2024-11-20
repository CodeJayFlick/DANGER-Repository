Here is the translation of the Java code to Python:
```
import logging

class StdOutEventLog:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def ticket_submitted(self, details: dict) -> None:
        self.logger.info("Lottery ticket for {} was submitted. Bank account {} was charged for 3 credits.".format(
            details['email'], details['bank_account']
        ))

    def ticket_did_not_win(self, details: dict) -> None:
        self.logger.info("Lottery ticket for {} was checked and unfortunately did not win this time.".format(details['email']))

    def ticket_won(self, details: dict, prize_amount: int) -> None:
        self.logger.info("Lottery ticket for {} has won! The bank account {} was deposited with {} credits.".format(
            details['email'], details['bank_account'], prize_amount
        ))

    def prize_error(self, details: dict, prize_amount: int) -> None:
        self.logger.error("Lottery ticket for {} has won! Unfortunately the bank credit transfer of {} failed.".format(
            details['email'], prize_amount
        ))

    def ticket_submit_error(self, details: dict) -> None:
        self.logger.error("Lottery ticket for {} could not be submitted because the credit transfer of 3 credits failed.".format(details['email']))
```
Note that I used Python's built-in `logging` module to implement logging functionality. The rest of the code is translated from Java to Python, using equivalent syntax and semantics where possible.

Also note that in Python, we don't need explicit getters/setters for attributes like `details`, so I removed those. Instead, I assumed that the `PlayerDetails` object has an attribute called `email` and another one called `bank_account`.