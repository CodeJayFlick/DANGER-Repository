class User:
    def __init__(self, username: str):
        self.username = username

from dataclasses import dataclass, field

@dataclass(frozen=True)
class User:
    username: str
