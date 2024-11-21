class Filter:
    def __init__(self):
        self.next = None
        self.last = None

    def execute(self, order: str) -> str:
        pass  # This method should be implemented by subclasses

    def set_next(self, filter: 'Filter') -> None:
        if not self.next and not self.last:
            self.next = filter
        elif self.next is None:
            self.next.set_last(filter)
        else:
            raise ValueError("Cannot add a new next filter to this chain")

    def get_next(self) -> 'Filter':
        return self.next

    def set_last(self, filter: 'Filter') -> None:
        if not self.last and not self.next is None:
            self.last = filter
        elif self.last is None:
            raise ValueError("Cannot add a new last filter to this chain")
        else:
            raise ValueError("This filter has already been added as the last one")

    def get_last(self) -> 'Filter':
        return self.last
