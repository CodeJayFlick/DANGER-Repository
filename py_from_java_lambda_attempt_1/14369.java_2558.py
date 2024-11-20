Here is the equivalent Python code:

```Python
class InMemoryTicketRepositoryTest:
    def __init__(self):
        self.repository = InMemoryTicketRepository()

    def setup(self):
        self.repository.delete_all()

    @staticmethod
    def create_lottery_ticket():
        # implement this method to return a lottery ticket object
        pass

    def test_crud_operations(self):
        assert not self.repository.find_all()
        ticket = self.create_lottery_ticket()
        id = self.repository.save(ticket)
        assert id is not None
        assert len(self.repository.find_all()) == 1
        optional_ticket = self.repository.find_by_id(id)
        assert optional_ticket is not None

if __name__ == "__main__":
    test = InMemoryTicketRepositoryTest()
    test.setup()
    test.test_crud_operations()

```

Note that this Python code does not include the `LotteryTicket` class, which was used in the original Java code. You would need to implement a similar class in your Python code.

Also note that I did not translate the JUnit tests directly into Pytest or unittest. Instead, I wrote equivalent test methods using assert statements and instance variables.