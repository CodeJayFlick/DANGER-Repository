class Message:
    def __init__(self, message: str, priority: int):
        self.message = message
        self.priority = priority

    def __lt__(self, other):
        return self.priority < other.priority

    def __str__(self) -> str:
        return f"Message{{'message': '{self.message}', 'priority': {self.priority}}}"
