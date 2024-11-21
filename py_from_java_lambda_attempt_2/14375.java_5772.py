Here is the equivalent Python code:

```Python
class PlayerDetails:
    def __init__(self, email: str, phone_number: str, country_code: str):
        self.email = email
        self.phone_number = phone_number
        self.country_code = country_code


class LotteryNumbers:
    @staticmethod
    def create(numbers: set) -> 'LotteryNumbers':
        return LotteryNumbers(numbers)


class LotteryTicketId:
    pass


class LotteryTicket:
    def __init__(self, ticket_id: LotteryTicketId, details: PlayerDetails, numbers: LotteryNumbers):
        self.ticket_id = ticket_id
        self.details = details
        self.numbers = numbers

    def __eq__(self, other) -> bool:
        if not isinstance(other, LotteryTicket):
            return False
        return (self.ticket_id == other.ticket_id and 
                self.details.email == other.details.email and 
                self.details.phone_number == other.details.phone_number and 
                self.details.country_code == other.details.country_code and 
                set(self.numbers) == set(other.numbers))


import unittest

class TestLotteryTicket(unittest.TestCase):

    def test_equals(self):
        details1 = PlayerDetails("bob@foo.bar", "1212-121212", "+34332322")
        numbers1 = LotteryNumbers(set([1, 2, 3, 4]))
        ticket1 = LotteryTicket(LotteryTicketId(), details1, numbers1)
        details2 = PlayerDetails("bob@foo.bar", "1212-121212", "+34332322")
        numbers2 = LotteryNumbers(set([1, 2, 3, 4]))
        ticket2 = LotteryTicket(LotteryTicketId(), details2, numbers2)
        self.assertEqual(ticket1, ticket2)
        details3 = PlayerDetails("elsa@foo.bar", "1223-121212", "+49332322")
        numbers3 = LotteryNumbers(set([1, 2, 3, 8]))
        ticket3 = LotteryTicket(LotteryTicketId(), details3, numbers3)
        self.assertNotEqual(ticket1, ticket3)


if __name__ == '__main__':
    unittest.main()
```

Note: Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the `unittest.TestCase` class and define test methods with names that start with "test".