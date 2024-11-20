Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class LotteryUtils:
    def __init__(self):
        pass

    @staticmethod
    def check_ticket_for_prize(repository, id, winning_numbers):
        optional = repository.find_by_id(id)
        if optional is not None:
            if optional.lottery_numbers == winning_numbers:
                return LotteryTicketCheckResult(1000)  # WIN_PRIZE with prize amount 1000
            else:
                return LotteryTicketCheckResult(CheckResult.NO_PRIZE)
        else:
            return LotteryTicketCheckResult(CheckResult.TICKET_NOT_SUBMITTED)


class LotteryTicketCheckResult:
    def __init__(self, result):
        self.result = result

    @staticmethod
    def WIN_PRIZE(prize_amount=0):
        return CheckResult(1000)

    @staticmethod
    def NO_PRIZE():
        return CheckResult(0)

    @staticmethod
    def TICKET_NOT_SUBMITTED():
        return CheckResult(-1)


class LotteryTicketRepository:
    # assume this class has a find_by_id method that returns an optional lottery ticket


class LotteryNumbers:
    pass  # assume this is some kind of data structure for storing lottery numbers

# enum-like class to represent the check result
class CheckResult:
    WIN_PRIZE = 1000
    NO_PRIZE = 0
    TICKET_NOT_SUBMITTED = -1
```
Note that I had to make a few assumptions about the Python code, such as:

* The `LotteryTicketRepository` class has a `find_by_id` method that returns an optional lottery ticket.
* The `LotteryNumbers` class is some kind of data structure for storing lottery numbers. In this example, it's just a placeholder.

Also, I used Python's built-in `optional` type (i.e., the result of calling `repository.find_by_id(id)`) to represent the possibility that no ticket was found with the given ID.