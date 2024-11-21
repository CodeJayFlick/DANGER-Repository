Here is the equivalent Python code:

```Python
class LotteryTicket:
    def __init__(self, id: 'LotteryTicketId', player_details: 'PlayerDetails', lottery_numbers: 'LotteryNumbers'):
        self.id = id
        self.player_details = player_details
        self.lottery_numbers = lottery_numbers

    @property
    def id(self):
        return self._id

    @property
    def player_details(self):
        return self._player_details

    @property
    def lottery_numbers(self):
        return self._lottery_numbers

    def __hash__(self):
        result = hash((None, None))  # Initialize with a default value
        if self.lottery_numbers is not None:
            result ^= hash(self.lottery_numbers)
        if self.player_details is not None:
            result ^= hash(self.player_details)
        return result

    def __eq__(self, other):
        if isinstance(other, LotteryTicket):
            if self.id == other.id and \
               (self.lottery_numbers is None) == (other.lottery_numbers is None) and \
               ((not self.lottery_numbers is not None) or self.lottery_numbers == other.lottery_numbers) and \
               ((not self.player_details is not None) or self.player_details == other.player_details):
                return True
        return False

class LotteryTicketId:
    pass  # This class should be implemented based on the actual implementation in Java.

class PlayerDetails:
    pass  # This class should be implemented based on the actual implementation in Java.

class LotteryNumbers:
    pass  # This class should be implemented based on the actual implementation in Java.
```

Please note that this is a direct translation of your code, and you will need to implement `LotteryTicketId`, `PlayerDetails` and `LotteryNumbers` classes according to their actual implementations.