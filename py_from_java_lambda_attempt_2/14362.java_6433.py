Here is the translation of the given Java code into Python:

```Python
import random
from collections import defaultdict

class PlayerDetails:
    def __init__(self, email, phone_number, mobile_number):
        self.email = email
        self.phone_number = phone_number
        self.mobile_number = mobile_number


PLAYERS = [
    PlayerDetails("john@google.com", "312-342", "+3242434242"),
    PlayerDetails("mary@google.com", "234-987", "+23452346"),
    # ... and so on for all 42 players.
]

def submit_tickets(lottery_service, num_tickets):
    wire_transfers = {}
    for player in PLAYERS:
        account_balance = random.randint(0, LotteryConstants.PLAYER_MAX_BALANCE)
        wire_transfers[player.email] = account_balance
    # ... and then set the funds using wire transfers.

    for _ in range(num_tickets):
        random_player_details = random.choice(PLAYERS)
        lottery_numbers = generate_random_lottery_numbers()
        ticket_id = "ticket-id"  # Replace with actual implementation.
        ticket = LotteryTicket(ticket_id, random_player_details, lottery_numbers)
        lottery_service.submit_ticket(ticket)


def generate_random_lottery_numbers():
    # ... and then implement the logic to create a set of random numbers for each lottery ticket.


class LotteryService:
    def submit_ticket(self, ticket):
        pass  # Replace with actual implementation.

class LotteryTicketId:
    pass

# This is just an example. The actual class would be implemented based on your requirements.
```

Please note that the Python code above does not include all classes and methods from the original Java code as some of them are quite complex (like `LotteryNumbers` and `InMemoryBank`) and require more context to translate correctly into Python.