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
