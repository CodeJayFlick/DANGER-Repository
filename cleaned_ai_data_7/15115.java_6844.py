class Room:
    def __init__(self):
        self.id = None
        self.room_type = None
        self.price = None
        self.booked = False

# You can also use dataclasses module in python which provides a simpler way to create classes that have rich comparisons and work well with the `dataclass` decorator.
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Room:
    id: int
    room_type: str
    price: int
    booked: bool = False
