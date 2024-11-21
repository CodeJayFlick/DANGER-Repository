Here is the equivalent Python code:

```Python
class InMemoryTicketRepository:
    def __init__(self):
        self.tickets = {}

    def find_by_id(self, id: str) -> dict | None:
        return {k: v for k, v in self.tickets.items()}.get(id)

    def save(self, ticket: dict) -> str | None:
        new_id = {'id': 'new_ticket'}
        self.tickets.update({**self.tickets, **{new_id['id']: ticket}})
        return new_id['id']

    def find_all(self) -> dict:
        return self.tickets

    def delete_all(self):
        self.tickets.clear()
```

Note that Python does not have a direct equivalent to Java's `Optional` class. Instead, we can use the built-in `None` value or create our own optional type if needed.

Also note that in this translation, I've used dictionaries (`{}`) as maps and sets are not directly available in Python like they are in Java.